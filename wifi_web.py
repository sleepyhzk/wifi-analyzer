#!/usr/bin/env python3
"""
wifi_web.py - Web UI quét WiFi lân cận, chạy trên localhost.

Hỗ trợ: Windows (netsh) và Linux (nmcli). Không cần cài thư viện.
Chạy:   python wifi_web.py            -> mở http://127.0.0.1:8000
        python wifi_web.py --port 9000
"""
import argparse
import collections
import concurrent.futures as cf
import html
import http.client
import ipaddress
import json
import os
import platform
import queue
import re
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import webbrowser
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from xml.sax.saxutils import escape as xesc


# ------------------------------------------------------------------ scanner
def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="ignore", timeout=30).stdout
    except FileNotFoundError:
        raise RuntimeError(f"Không tìm thấy lệnh: {cmd[0]}")


def pct_to_dbm(pct):
    return round(pct / 2 - 100)


def band_from_freq(mhz):
    if mhz < 3000:
        return "2.4 GHz"
    return "5 GHz" if mhz < 5900 else "6 GHz"


def win_trigger_scan():
    """Yêu cầu card WiFi quét lại ngay (WlanScan). netsh chỉ đọc kết quả cache nên
    nếu không gọi cái này, tín hiệu gần như đứng yên cả phút -> đồ thị phẳng lì."""
    try:
        import ctypes
        from ctypes import wintypes
        wl = ctypes.windll.wlanapi
        h, ver = wintypes.HANDLE(), wintypes.DWORD()
        if wl.WlanOpenHandle(2, None, ctypes.byref(ver), ctypes.byref(h)) != 0:
            return
        try:
            pl = ctypes.c_void_p()
            if wl.WlanEnumInterfaces(h, None, ctypes.byref(pl)) == 0 and pl.value:
                n = ctypes.c_uint32.from_address(pl.value).value
                for i in range(n):  # WLAN_INTERFACE_INFO = GUID(16) + WCHAR[256] + DWORD = 532 byte
                    guid = (ctypes.c_byte * 16).from_address(pl.value + 8 + i * 532)
                    wl.WlanScan(h, ctypes.byref(guid), None, None, None)
                wl.WlanFreeMemory(pl)
        finally:
            wl.WlanCloseHandle(h, None)
    except Exception:
        pass


def scan_windows():
    win_trigger_scan()
    out = run(["netsh", "wlan", "show", "networks", "mode=bssid"])
    nets, ssid, auth, cur = [], "", "", None
    for line in out.splitlines():
        s = line.strip()
        m = re.match(r"SSID\s+\d+\s*:\s*(.*)", s)
        if m:
            ssid, auth, cur = (m.group(1) or "<hidden>"), "", None
            continue
        m = re.match(r"BSSID\s+\d+\s*:\s*(.*)", s)
        if m:
            cur = {"ssid": ssid, "bssid": m.group(1), "security": auth}
            nets.append(cur)
            continue
        if ":" not in s:
            continue
        k, v = [x.strip() for x in s.split(":", 1)]
        k = k.lower()
        if cur is None:
            if k.startswith("authentication"):
                auth = v
        elif k == "signal":
            cur["signal_pct"] = int(v.rstrip("%") or 0)
            cur["dbm"] = pct_to_dbm(cur["signal_pct"])
        elif k == "channel":
            cur["channel"] = int(v) if v.isdigit() else v
        elif k == "band":
            cur["band"] = v
        elif k.startswith("radio"):
            cur["radio"] = v
    return mark_connected_windows(nets)


def mark_connected_windows(nets):
    out = run(["netsh", "wlan", "show", "interfaces"])
    info = {}
    for line in out.splitlines():
        if ":" not in line:
            continue
        k, v = [x.strip() for x in line.split(":", 1)]
        info.setdefault(k.lower(), v)
    bssid = (info.get("ap bssid") or info.get("bssid") or "").lower()
    live = re.sub(r"\D", "", info.get("signal", ""))
    for n in nets:
        n["connected"] = bool(bssid) and n.get("bssid", "").lower() == bssid
        if n["connected"] and live:
            n["signal_pct"] = int(live)
            n["dbm"] = pct_to_dbm(n["signal_pct"])
    return nets


def scan_linux():
    out = run(["nmcli", "-t", "-f", "IN-USE,SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY",
               "dev", "wifi", "list", "--rescan", "yes"])
    nets = []
    for line in out.splitlines():
        parts = [p.replace("\\:", ":") for p in re.split(r"(?<!\\):", line)]
        if len(parts) < 7:
            continue
        inuse, ssid, bssid, chan, freq, sig, sec = parts[:7]
        mhz = int(re.sub(r"\D", "", freq) or 0)
        pct = int(sig or 0)
        nets.append({
            "ssid": ssid or "<hidden>", "bssid": bssid, "signal_pct": pct,
            "dbm": pct_to_dbm(pct),
            "channel": int(chan) if chan.isdigit() else chan,
            "band": band_from_freq(mhz) if mhz else "",
            "security": "Open" if sec in ("", "--") else sec, "radio": "",
            "connected": inuse.strip() == "*",
        })
    return nets


_lock = threading.Lock()
_cache = {"t": 0, "data": None}


def scan():
    system = platform.system()
    if system == "Windows":
        nets = scan_windows()
    elif system == "Linux":
        nets = scan_linux()
    else:
        raise RuntimeError(f"Chưa hỗ trợ hệ điều hành: {system}")
    nets = dedupe_bssid(nets)
    saved = saved_profiles()
    for n in nets:
        n["saved"] = n["ssid"] in saved
    return nets


def dedupe_bssid(nets):
    """Gộp các dòng trùng BSSID: giữ dòng tín hiệu mạnh nhất, giữ cờ 'đang kết nối'."""
    best = {}
    for n in nets:
        k = (n.get("bssid") or "").lower()
        if not k:
            best[id(n)] = n
            continue
        o = best.get(k)
        if o is None:
            best[k] = n
        else:
            keep = n if n.get("dbm", -999) > o.get("dbm", -999) else o
            keep["connected"] = bool(n.get("connected") or o.get("connected"))
            best[k] = keep
    return list(best.values())


def cached_scan():
    # Gộp các request đồng thời và tránh quét quá dày (tối thiểu 2 giây/lần)
    with _lock:
        if time.time() - _cache["t"] > 2 or _cache["data"] is None:
            _cache["data"] = scan()
            _cache["t"] = time.time()
        return _cache["data"]


# ------------------------------------------------------------ kết nối WiFi
IS_WIN = platform.system() == "Windows"
NOWIN = subprocess.CREATE_NO_WINDOW if IS_WIN else 0


def sh(cmd, timeout=30):
    """Chạy lệnh, trả về CompletedProcess (có returncode/stdout/stderr)."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                              errors="ignore", timeout=timeout, creationflags=NOWIN)
    except FileNotFoundError:
        name = cmd[0] if isinstance(cmd, list) else cmd.split()[0]
        raise RuntimeError(f"Không tìm thấy lệnh: {name}")
    except subprocess.TimeoutExpired:
        raise RuntimeError("Lệnh chạy quá lâu (timeout)")


def saved_profiles():
    """Tên các mạng WiFi đã lưu trên máy (chỉ để gợi ý trên giao diện)."""
    try:
        if IS_WIN:
            out = sh(["netsh", "wlan", "show", "profiles"]).stdout
            return {m.group(1).strip() for m in
                    re.finditer(r"^\s*[^:\n]*Profile[^:\n]*:\s*(.+?)\s*$", out, re.M)}
        out = sh(["nmcli", "-t", "-f", "NAME,TYPE", "con", "show"]).stdout
        names = set()
        for line in out.splitlines():
            p = re.split(r"(?<!\\):", line)
            if len(p) >= 2 and ("wireless" in p[-1] or "wifi" in p[-1]):
                names.add(p[0].replace("\\:", ":"))
        return names
    except Exception:
        return set()


def win_profile_xml(ssid, sec, password):
    if password is None:
        auth, enc, key = "open", "none", ""
    else:
        if "wpa3" in sec:
            auth, enc = "WPA3SAE", "AES"
        elif "wpa2" in sec:
            auth, enc = "WPA2PSK", "AES"
        elif "wpa" in sec:
            auth, enc = "WPAPSK", "TKIP"
        else:
            auth, enc = "WPA2PSK", "AES"
        key = ("<sharedKey><keyType>passPhrase</keyType><protected>false</protected>"
               f"<keyMaterial>{xesc(password)}</keyMaterial></sharedKey>")
    s = xesc(ssid)
    return (f'<?xml version="1.0"?>'
            f'<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">'
            f'<name>{s}</name><SSIDConfig><SSID><name>{s}</name></SSID></SSIDConfig>'
            f'<connectionType>ESS</connectionType><connectionMode>manual</connectionMode>'
            f'<MSM><security><authEncryption><authentication>{auth}</authentication>'
            f'<encryption>{enc}</encryption><useOneX>false</useOneX></authEncryption>'
            f'{key}</security></MSM></WLANProfile>')


def is_open_sec(sec):
    return bool(re.search(r"open|none|^--$|^$", (sec or "").strip(), re.I))


def win_ifaces():
    """Danh sách card WiFi từ 'netsh wlan show interfaces' (mỗi card là 1 dict khoá chữ thường)."""
    blocks, cur = [], None
    for line in sh(["netsh", "wlan", "show", "interfaces"]).stdout.splitlines():
        if ":" not in line:
            continue
        k, v = [x.strip() for x in line.split(":", 1)]
        k = k.lower()
        if k == "name":
            cur = {}
            blocks.append(cur)
        if cur is not None:
            cur.setdefault(k, v)
    return blocks


def win_iface_name():
    bl = win_ifaces()
    pick = next((b for b in bl if b.get("ap bssid") or b.get("bssid")), None) or (bl[0] if bl else None)
    return pick.get("name") if pick else None


def win_profile_name(ssid):
    """Tên profile đã lưu ứng với SSID (thường trùng SSID, đôi khi có thêm ' 2')."""
    names = saved_profiles()
    if ssid in names:
        return ssid
    return next((n for n in sorted(names) if n.startswith(ssid + " ")), None)


def win_connect(ssid, sec, password):
    if '"' in ssid:
        raise RuntimeError("Tên mạng chứa dấu \" nên tool chưa kết nối được.")
    sec = (sec or "").lower()
    if "enterprise" in sec:
        raise RuntimeError("Mạng doanh nghiệp (802.1X) chưa được hỗ trợ.")
    openn = is_open_sec(sec)
    if password:
        if not 8 <= len(password) <= 63:
            raise RuntimeError("Mật khẩu WPA phải dài 8–63 ký tự.")
    xml = win_profile_xml(ssid, sec, password) if (password or openn) else None
    if xml:
        if password:  # xoá profile cũ cùng tên (có thể lưu sai mật khẩu) rồi tạo lại
            sh(f'netsh wlan delete profile name="{win_profile_name(ssid) or ssid}"')
        fd, path = tempfile.mkstemp(suffix=".xml")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(xml)
            r = sh(f'netsh wlan add profile filename="{path}" user=current')
            if r.returncode != 0:
                raise RuntimeError("Không tạo được profile WiFi: " + (r.stdout or r.stderr).strip())
        finally:
            try:
                os.unlink(path)  # xoá file chứa mật khẩu ngay
            except OSError:
                pass
    pname = win_profile_name(ssid) or ssid
    if '"' in pname:
        raise RuntimeError("Tên profile chứa dấu \" nên tool chưa kết nối được.")
    iface = win_iface_name()
    cmd = f'netsh wlan connect name="{pname}" ssid="{ssid}"'
    if iface and '"' not in iface:
        cmd += f' interface="{iface}"'
    r = sh(cmd)
    if r.returncode != 0:
        msg = (r.stdout or r.stderr).strip()
        if not password and not openn:
            msg += "  (Mạng này chưa được lưu trên máy — hãy nhập mật khẩu.)"
        raise RuntimeError(msg or "netsh connect thất bại")


def linux_connect(ssid, bssid, password):
    cmd = ["nmcli", "--wait", "25", "dev", "wifi", "connect", ssid]
    if password:
        cmd += ["password", password]
    if bssid:
        cmd += ["bssid", bssid]
    r = sh(cmd, timeout=40)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip() or "nmcli thất bại")


def wifi_current():
    """Mạng WiFi đang kết nối: {'ssid','bssid'} hoặc None."""
    if IS_WIN:
        for info in win_ifaces():
            bssid = info.get("ap bssid") or info.get("bssid")
            if bssid:
                return {"ssid": info.get("ssid", ""), "bssid": bssid}
        return None
    out = sh(["nmcli", "-t", "-f", "IN-USE,SSID,BSSID", "dev", "wifi", "list"]).stdout
    for line in out.splitlines():
        p = [x.replace("\\:", ":") for x in re.split(r"(?<!\\):", line)]
        if len(p) >= 3 and p[0].strip() == "*":
            return {"ssid": p[1], "bssid": p[2]}
    return None


def wifi_dev_linux():
    out = sh(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "dev"]).stdout
    dev = None
    for line in out.splitlines():
        p = line.split(":")
        if len(p) >= 3 and p[1] == "wifi":
            dev = dev or p[0]
            if p[2] == "connected":
                return p[0]
    return dev


def net_info():
    """IP / prefix / gateway của card WiFi đang dùng (None nếu chưa có IP)."""
    me = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        me = s.getsockname()[0]
        s.close()
    except OSError:
        pass
    try:
        if IS_WIN:
            ps = ("Get-NetIPConfiguration | Where-Object { $_.IPv4Address } | ForEach-Object { "
                  '"$($_.InterfaceAlias)|$($_.IPv4Address.IPAddress)|$($_.IPv4Address.PrefixLength)'
                  '|$($_.IPv4DefaultGateway.NextHop)" }')
            out = sh(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=20).stdout
            return pick_win_row(out, me)
        dev = wifi_dev_linux()
        if dev:
            addr = sh(["ip", "-4", "-o", "addr", "show", "dev", dev]).stdout
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", addr)
            if m:
                gw = re.search(r"default via (\d+\.\d+\.\d+\.\d+)",
                               sh(["ip", "-4", "route", "show", "default", "dev", dev]).stdout)
                return {"ip": m.group(1), "prefix": int(m.group(2)),
                        "gw": gw.group(1) if gw else None, "iface": dev}
    except RuntimeError:
        pass
    if me and not me.startswith("169.254."):
        return {"ip": me, "prefix": 24, "gw": None, "iface": ""}
    return None


def pick_win_row(out, me):
    rows = [l.strip().split("|") for l in out.splitlines() if l.count("|") == 3]
    rows = [r for r in rows if r[1] and not r[1].startswith("169.254.")]
    pick = (next((r for r in rows if re.search(r"wi-?fi|wlan|wireless|không dây", r[0], re.I)), None)
            or next((r for r in rows if r[1] == me), None) or (rows[0] if rows else None))
    if not pick:
        return None
    return {"ip": pick[1], "prefix": int(pick[2] or 24), "gw": pick[3] or None, "iface": pick[0]}


def connect(ssid, bssid, password, sec):
    if not ssid or ssid == "<hidden>":
        raise RuntimeError("Mạng ẩn (không có tên) chưa được hỗ trợ.")
    if IS_WIN:
        win_connect(ssid, sec, password)
    else:
        linux_connect(ssid, bssid, password)
    _cache["t"] = 0
    deadline, info, cur, joined = time.time() + 25, None, None, False
    while time.time() < deadline:
        cur = wifi_current()
        if cur and cur["ssid"] == ssid:
            joined = True
            info = net_info()
            if info:
                break
        time.sleep(1)
    if not info:
        if not joined:
            now = cur["ssid"] if cur else "không mạng nào"
            raise RuntimeError(f"Windows chưa vào được \"{ssid}\" sau 25 giây (hiện đang: {now}). "
                               "Thường do mật khẩu đã lưu bị sai/cũ — hãy gõ lại mật khẩu rồi bấm Kết nối "
                               "để tool tạo lại profile.")
        raise RuntimeError("Đã vào WiFi nhưng chưa nhận được địa chỉ IP (router chưa cấp DHCP "
                           "hoặc đọc IP thất bại). Thử quét lại vài giây sau.")
    _dev["raw"] = None
    return {"ssid": ssid, "ip": info["ip"], "gateway": info["gw"]}


def disconnect():
    if IS_WIN:
        r = sh(["netsh", "wlan", "disconnect"])
    else:
        dev = wifi_dev_linux()
        if not dev:
            raise RuntimeError("Không tìm thấy card WiFi.")
        r = sh(["nmcli", "dev", "disconnect", dev])
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip() or "Ngắt kết nối thất bại")
    _cache["t"] = 0
    _dev["raw"] = None


# ------------------------------------------------------- thiết bị trong mạng
MAC_RE = r"[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}"
OUI_FILES = ["oui.txt", "manuf", "/usr/share/ieee-data/oui.txt",
             "/usr/share/nmap/nmap-mac-prefixes", "/usr/share/wireshark/manuf",
             r"C:\Program Files\Wireshark\manuf", r"C:\Program Files (x86)\Wireshark\manuf"]
_IEEE = re.compile(r"^\s*([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+?)\s*$")
_GENERIC = re.compile(r"^([0-9A-Fa-f]{2}):?([0-9A-Fa-f]{2}):?([0-9A-Fa-f]{2})\s+(\S.*?)\s*$")


class Oui:
    """Tra hãng theo 3 byte đầu của MAC: file local -> cache -> (tuỳ chọn) tra online chỉ bằng 3 byte đó."""

    def __init__(self, online=True):
        self.db, self.cache, self.online = {}, {}, online
        self.q, self.queued = queue.Queue(), set()
        base = Path(__file__).resolve().parent
        self.cache_path = base / "oui_cache.json"
        for f in OUI_FILES:
            p = Path(f) if os.path.isabs(f) else base / f
            if p.exists():
                self._load(p)
        try:
            self.cache = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except Exception:
            self.cache = {}
        if online:
            threading.Thread(target=self._worker, daemon=True).start()

    def _load(self, p):
        try:
            for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("#"):
                    continue
                m = _IEEE.match(line)
                if m:
                    self.db[(m.group(1) + m.group(2) + m.group(3)).upper()] = m.group(4)
                    continue
                m = _GENERIC.match(line)
                if m:
                    self.db[(m.group(1) + m.group(2) + m.group(3)).upper()] = m.group(4).split("\t")[-1].strip()
        except OSError:
            pass

    def _worker(self):
        while True:
            key = self.q.get()
            try:
                url = "https://api.macvendors.com/" + ":".join((key[0:2], key[2:4], key[4:6]))
                req = urllib.request.Request(url, headers={"User-Agent": "wifi-analyzer"})
                with urllib.request.urlopen(req, timeout=6) as r:
                    v = r.read().decode("utf-8", "ignore").strip()
                if v and not v.startswith("{"):
                    self.cache[key] = v[:80]
                    self._save()
            except urllib.error.HTTPError as e:
                if e.code == 404:  # OUI không có trong CSDL -> đừng hỏi lại
                    self.cache[key] = ""
                    self._save()
            except Exception:
                pass
            self.queued.discard(key)
            time.sleep(1.2)  # dịch vụ miễn phí giới hạn ~1 yêu cầu/giây

    def _save(self):
        try:
            self.cache_path.write_text(json.dumps(self.cache), encoding="utf-8")
        except OSError:
            pass

    def lookup(self, mac):
        """-> (vendor hoặc None, trạng thái: ok | random | pending | unknown)"""
        if int(mac[1], 16) & 2:  # bit "locally administered" = MAC ngẫu nhiên/riêng tư
            return None, "random"
        key = mac[:8].replace(":", "").upper()
        v = self.db.get(key)
        if v is None:
            v = self.cache.get(key)
        if v is not None:
            return (v, "ok") if v else (None, "unknown")
        if self.online:
            if key not in self.queued:
                self.queued.add(key)
                self.q.put(key)
            return None, "pending"
        return None, "unknown"


OUI = None
_dev = {"raw": None, "lock": threading.Lock()}


def arp_table(net):
    if IS_WIN:
        out = sh(["arp", "-a"]).stdout
        pairs = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+(" + MAC_RE + ")", out)
    else:
        out = sh(["ip", "-4", "neigh", "show"]).stdout
        pairs = []
        for line in out.splitlines():
            m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s.*?lladdr\s+(" + MAC_RE + r")\s+(\w+)", line)
            if m and m.group(3).upper() not in ("FAILED", "INCOMPLETE"):
                pairs.append((m.group(1), m.group(2)))
    found = {}
    for ip, mac in pairs:
        mac = mac.replace("-", ":").lower()
        if int(mac[:2], 16) & 1 or mac == "00:00:00:00:00:00":  # broadcast / multicast
            continue
        try:
            if ipaddress.ip_address(ip) in net:
                found[ip] = mac
        except ValueError:
            pass
    return found


def poke(hosts):
    """Gửi 1 gói UDP tới từng IP để hệ điều hành phải hỏi ARP -> điền bảng ARP."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    for _ in range(2):
        for h in hosts:
            try:
                s.sendto(b"\0", (h, 9))
            except OSError:
                pass
        time.sleep(1.2)
    s.close()


def resolve_names(ips):
    out = {}
    ex = cf.ThreadPoolExecutor(max_workers=32)
    futs = {ex.submit(socket.gethostbyaddr, ip): ip for ip in ips}
    try:
        for f in cf.as_completed(futs, timeout=4):
            try:
                out[futs[f]] = f.result()[0].split(".")[0]
            except OSError:
                pass
    except cf.TimeoutError:
        pass
    ex.shutdown(wait=False, cancel_futures=True)
    return out


def scan_devices(deep=False):
    info = net_info()
    if not info:
        raise RuntimeError("Chưa có địa chỉ IP — hãy kết nối WiFi trước.")
    ip = info["ip"]
    net = ipaddress.ip_network(f"{ip}/{info['prefix']}", strict=False)
    if net.prefixlen < 24:  # mạng quá lớn -> chỉ quét /24 quanh IP của bạn
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
    if net.prefixlen > 30:
        raise RuntimeError("Mạng quá nhỏ để quét.")
    poke([str(h) for h in net.hosts() if str(h) != ip])
    table = arp_table(net)
    names = resolve_names(list(table))
    raw = [{"ip": a, "mac": m, "name": names.get(a, ""), "gateway": a == info["gw"], "self": False}
           for a, m in table.items()]
    raw.append({"ip": ip, "mac": None, "name": socket.gethostname(), "gateway": False, "self": True})
    if deep:
        ev = deep_identify([d["ip"] for d in raw if not d["self"]], ip)
        for d in raw:
            if d["mac"] and d["ip"] in ev:
                _ident[d["mac"]] = ev[d["ip"]]
    raw.sort(key=lambda d: ipaddress.ip_address(d["ip"]))
    return {"net": str(net), "ip": ip, "gateway": info["gw"], "iface": info["iface"],
            "devices": raw, "time": time.strftime("%H:%M:%S")}


def devices_payload(cached=False, deep=False):
    with _dev["lock"]:
        if deep or not (cached and _dev["raw"]):
            _dev["raw"] = scan_devices(deep)
        res = dict(_dev["raw"])
    devs, pending = [], False
    for d in res["devices"]:
        d = dict(d)
        if d["mac"]:
            d["vendor"], d["vstate"] = OUI.lookup(d["mac"])
            pending = pending or d["vstate"] == "pending"
            d["ident"] = identify(_ident.get(d["mac"]), d["vendor"], d["name"])
        else:
            d["vendor"], d["vstate"], d["ident"] = None, "self", None
        devs.append(d)
    res["devices"], res["pending"] = devs, pending
    res["ok"] = True
    return res


# ------------------------------------------------------------ đo ping / độ trễ
PING = {"on": False, "custom": "", "hist": {}, "hosts": {}, "targets": [], "gw": None, "gw_t": 0,
        "poll": 0, "thread": None, "err": "", "interval": 2.0}
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?$")
MS_RE = re.compile(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", re.I)


def ping_once(host):
    """Ping 1 gói, trả về ms (float) hoặc None nếu mất gói."""
    cmd = ["ping", "-n", "1", "-w", "1000", host] if IS_WIN else ["ping", "-c", "1", "-W", "1", host]
    try:
        r = sh(cmd, timeout=4)
    except RuntimeError as e:
        if "Không tìm thấy" in str(e):
            raise
        return None
    out = r.stdout or ""
    if IS_WIN:
        if "TTL=" not in out.upper():  # 'Destination unreachable' của router vẫn trả mã 0 nên phải kiểm TTL
            return None
    elif r.returncode != 0:
        return None
    m = MS_RE.search(out)
    return float(m.group(1).replace(",", ".")) if m else None


def ping_targets():
    now = time.time()
    if now - PING["gw_t"] > 30:
        try:
            i = net_info()
            PING["gw"] = i["gw"] if i else None
        except Exception:
            PING["gw"] = None
        PING["gw_t"] = now
    t = []
    if PING["gw"]:
        t.append(("router", "Router / gateway", PING["gw"]))
    t += [("net1", "Internet (Cloudflare)", "1.1.1.1"), ("net2", "Internet (Google)", "8.8.8.8")]
    if PING["custom"]:
        t.append(("custom", "Tuỳ chọn", PING["custom"]))
    return t


def ping_loop():
    PING["err"] = ""
    while PING["on"]:
        t0 = time.time()
        if t0 - PING["poll"] > 60:  # không còn ai xem -> tự dừng
            PING["on"] = False
            break
        tg = ping_targets()
        PING["targets"] = tg
        try:
            with cf.ThreadPoolExecutor(max_workers=len(tg)) as ex:
                res = list(ex.map(lambda x: ping_once(x[2]), tg))
        except RuntimeError as e:
            PING["err"] = str(e)
            PING["on"] = False
            break
        ts = time.time()
        for (k, _, host), ms in zip(tg, res):
            if PING["hosts"].get(k) != host:  # đổi mạng / đổi đích -> xoá lịch sử cũ
                PING["hist"][k] = collections.deque(maxlen=600)
                PING["hosts"][k] = host
            PING["hist"].setdefault(k, collections.deque(maxlen=600)).append((ts, ms))
        time.sleep(max(0.2, PING["interval"] - (time.time() - t0)))


def ping_stats(h):
    vals = [ms for _, ms in h]
    ok = [v for v in vals if v is not None]
    n = len(vals)
    diffs = [abs(a - b) for a, b in zip(vals, vals[1:]) if a is not None and b is not None]
    r = lambda x: round(x, 1)
    return {"sent": n, "lost": n - len(ok), "loss": r((n - len(ok)) / n * 100) if n else 0,
            "avg": r(sum(ok) / len(ok)) if ok else None, "min": r(min(ok)) if ok else None,
            "max": r(max(ok)) if ok else None, "jitter": r(sum(diffs) / len(diffs)) if diffs else 0,
            "last": vals[-1] if vals else None}


def ping_payload():
    PING["poll"] = time.time()
    out = []
    for k, name, host in PING["targets"]:
        h = list(PING["hist"].get(k, []))
        out.append({"id": k, "name": name, "host": host, "stats": ping_stats(h[-300:]),
                    "series": [ms for _, ms in h[-120:]]})
    return {"ok": True, "on": PING["on"], "err": PING["err"], "custom": PING["custom"], "targets": out}


def ping_control(on, custom, reset=False):
    custom = (custom or "").strip()
    if custom and (len(custom) > 253 or not HOST_RE.fullmatch(custom)):
        raise RuntimeError("Đích ping không hợp lệ (chỉ nhận IP hoặc tên miền, ví dụ google.com).")
    PING["custom"] = custom
    if reset:
        PING["hist"].clear()
        PING["hosts"].clear()
    PING["poll"] = time.time()
    if on:
        PING["on"] = True
        if not (PING["thread"] and PING["thread"].is_alive()):
            PING["thread"] = threading.Thread(target=ping_loop, daemon=True)
            PING["thread"].start()
            time.sleep(0.2)
    else:
        PING["on"] = False
    return ping_payload()


# ------------------------------------------------------ nhận diện thiết bị (quét sâu)
PROBE_PORTS = [22, 23, 80, 139, 443, 445, 554, 3389, 5000, 7000, 8000, 8008, 8009, 8080, 8443, 9100, 62078]
MDNS_Q = ["_services._dns-sd._udp.local", "_googlecast._tcp.local", "_airplay._tcp.local", "_raop._tcp.local",
          "_hap._tcp.local", "_ipp._tcp.local", "_printer._tcp.local", "_http._tcp.local", "_smb._tcp.local",
          "_workstation._tcp.local", "_companion-link._tcp.local", "_spotify-connect._tcp.local",
          "_device-info._tcp.local", "_rtsp._tcp.local", "_axis-video._tcp.local", "_onvif._tcp.local"]
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE
_ident = {}  # mac -> bằng chứng thu được từ lần quét sâu gần nhất


def _rd_name(m, o):
    labels, end, hops = [], None, 0
    while True:
        if o >= len(m) or hops > 40:
            raise ValueError("bad name")
        n = m[o]
        if n == 0:
            o += 1
            break
        if n & 0xC0 == 0xC0:
            if end is None:
                end = o + 2
            o = ((n & 0x3F) << 8) | m[o + 1]
            hops += 1
            continue
        o += 1
        labels.append(m[o:o + n].decode("utf-8", "replace"))
        o += n
    return ".".join(labels), (end if end is not None else o)


def parse_mdns(m):
    """Giải mã gói mDNS/DNS -> list (name, type, value)."""
    qd, an, ns, ar = struct.unpack(">4H", m[4:12])
    o, recs = 12, []
    for _ in range(qd):
        _, o = _rd_name(m, o)
        o += 4
    for _ in range(an + ns + ar):
        name, o = _rd_name(m, o)
        t, _c, _ttl, rl = struct.unpack(">HHIH", m[o:o + 10])
        o += 10
        rd = m[o:o + rl]
        val = None
        if t == 12:
            val, _ = _rd_name(m, o)
        elif t == 33 and rl >= 7:
            port = struct.unpack(">H", m[o + 4:o + 6])[0]
            tgt, _ = _rd_name(m, o + 6)
            val = (port, tgt)
        elif t == 16:
            val, i = {}, 0
            while i < len(rd):
                n = rd[i]
                s = rd[i + 1:i + 1 + n].decode("utf-8", "replace")
                i += 1 + n
                if "=" in s:
                    k, v = s.split("=", 1)
                    val[k.lower()] = v[:80]
        elif t == 1 and rl == 4:
            val = socket.inet_ntoa(rd)
        o += rl
        recs.append((name, t, val))
    return recs


def _mdns_query(names):
    q = struct.pack(">6H", 0, 0, len(names), 0, 0, 0)
    for n in names:
        q += b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\0" + struct.pack(">HH", 12, 0x8001)
    return q


def _udp(local_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for opt, val in ((socket.IP_MULTICAST_TTL, 4), (socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))):
        try:
            s.setsockopt(socket.IPPROTO_IP, opt, val)
        except OSError:
            pass
    s.bind((local_ip, 0))
    return s


def _recv_until(s, wait):
    end = time.time() + wait
    while time.time() < end:
        s.settimeout(max(0.05, end - time.time()))
        try:
            yield s.recvfrom(9000)
        except socket.timeout:
            return
        except OSError:  # Windows báo lỗi 10054 khi gói unicast trước đó bị từ chối -> bỏ qua
            continue


def mdns_scan(local_ip, ips, wait=2.5):
    res = {}
    try:
        s = _udp(local_ip)
    except OSError:
        return res
    q = _mdns_query(MDNS_Q)
    for _ in range(2):
        for dst in ["224.0.0.251"] + list(ips):
            try:
                s.sendto(q, (dst, 5353))
            except OSError:
                pass
        time.sleep(0.2)
    for data, (src, _p) in _recv_until(s, wait):
        try:
            recs = parse_mdns(data)
        except Exception:
            continue
        e = res.setdefault(src, {"services": set(), "txt": {}, "inst": [], "host": ""})
        for name, t, val in recs:
            nl = name.lower()
            if t == 12 and nl.endswith(".local"):
                if nl == "_services._dns-sd._udp.local":
                    e["services"].add(val.lower()[:-6] if val.lower().endswith(".local") else val.lower())
                elif nl.startswith("_"):
                    e["services"].add(nl[:-6])
                    inst = val.split(".")[0]
                    if inst and inst not in e["inst"] and len(e["inst"]) < 4:
                        e["inst"].append(inst[:60])
            elif t == 16 and isinstance(val, dict):
                e["txt"].update(val)
            elif t == 33 and val:
                e["host"] = val[1]
    s.close()
    return res


def ssdp_scan(local_ip, wait=2.5):
    res = {}
    try:
        s = _udp(local_ip)
    except OSError:
        return res
    msg = ('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n'
           'MX: 2\r\nST: ssdp:all\r\n\r\n').encode()
    for _ in range(2):
        try:
            s.sendto(msg, ("239.255.255.250", 1900))
        except OSError:
            pass
        time.sleep(0.15)
    for data, (src, _p) in _recv_until(s, wait):
        heads = {}
        for line in data.decode("utf-8", "ignore").split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                heads[k.strip().lower()] = v.strip()
        e = res.setdefault(src, {"server": "", "locs": [], "st": set()})
        e["server"] = heads.get("server", e["server"])[:80]
        loc = heads.get("location")
        if loc and loc not in e["locs"] and len(e["locs"]) < 3:
            e["locs"].append(loc)
        if heads.get("st"):
            e["st"].add(heads["st"][:60])
    s.close()
    return res


def fetch_upnp(ip, loc):
    """Đọc file mô tả UPnP (chỉ từ chính IP đó, trong LAN) lấy tên/hãng/model."""
    u = urlparse(loc)
    if u.scheme != "http" or u.hostname != ip:
        return {}
    try:
        c = http.client.HTTPConnection(ip, u.port or 80, timeout=2)
        c.request("GET", (u.path or "/") + ("?" + u.query if u.query else ""), headers={"User-Agent": "wifi-analyzer"})
        body = c.getresponse().read(65536)
        c.close()
    except Exception:
        return {}
    if b"<!DOCTYPE" in body.upper() or b"<!ENTITY" in body.upper():
        return {}
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return {}
    out = {}
    for el in root.iter():
        t = el.tag.rsplit("}", 1)[-1]
        if t in ("friendlyName", "manufacturer", "modelName", "modelNumber", "modelDescription", "deviceType") \
                and t not in out and el.text:
            out[t] = el.text.strip()[:80]
    return out


def tcp_open(ip, port, t=0.6):
    s = socket.socket()
    s.settimeout(t)
    try:
        s.connect((ip, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def port_scan(ips):
    res = {ip: [] for ip in ips}
    jobs = [(ip, p) for ip in ips for p in PROBE_PORTS]
    with cf.ThreadPoolExecutor(max_workers=200) as ex:
        for (ip, p), ok in zip(jobs, ex.map(lambda j: tcp_open(*j), jobs)):
            if ok:
                res[ip].append(p)
    return res


def http_banner(ip, ports):
    for p, tls in ((80, False), (8080, False), (443, True), (8443, True)):
        if p not in ports:
            continue
        try:
            c = (http.client.HTTPSConnection(ip, p, timeout=1.5, context=_CTX) if tls
                 else http.client.HTTPConnection(ip, p, timeout=1.5))
            c.request("GET", "/", headers={"User-Agent": "wifi-analyzer"})  # không theo redirect
            r = c.getresponse()
            body = r.read(4096).decode("utf-8", "ignore")
            h = {k.lower(): v for k, v in r.getheaders()}
            c.close()
        except Exception:
            continue
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        realm = re.search(r'realm="([^"]{1,60})"', h.get("www-authenticate", ""))
        return {"port": p, "server": h.get("server", "")[:60],
                "title": html.unescape(re.sub(r"\s+", " ", m.group(1))).strip()[:80] if m else "",
                "realm": realm.group(1) if realm else ""}
    return {}


def deep_identify(ips, local_ip):
    """Thu bằng chứng cho từng IP: mDNS + SSDP/UPnP + cổng mở + banner web."""
    with cf.ThreadPoolExecutor(max_workers=3) as ex:
        fm, fs, fp = ex.submit(mdns_scan, local_ip, ips), ex.submit(ssdp_scan, local_ip), ex.submit(port_scan, ips)
        mdns, ssdp, ports = fm.result(), fs.result(), fp.result()
    ev = {}
    with cf.ThreadPoolExecutor(max_workers=32) as ex:
        up = {ip: ex.submit(fetch_upnp, ip, e["locs"][0]) for ip, e in ssdp.items() if ip in ips and e["locs"]}
        ht = {ip: ex.submit(http_banner, ip, ports.get(ip, [])) for ip in ips if ports.get(ip)}
        for ip in ips:
            m = mdns.get(ip)
            s = ssdp.get(ip)
            ev[ip] = {"ports": ports.get(ip, []),
                      "mdns": {**m, "services": sorted(m["services"])} if m else {},
                      "ssdp": {"server": s["server"], "st": sorted(s["st"])[:6]} if s else {},
                      "upnp": up[ip].result() if ip in up else {},
                      "http": ht[ip].result() if ip in ht else {}}
    return ev


def identify(ev, vendor, name):
    """Từ bằng chứng suy ra loại / model / tên thân thiện (dict) hoặc None."""
    if not ev:
        return None
    m, up, ht, sd = ev.get("mdns", {}), ev.get("upnp", {}), ev.get("http", {}), ev.get("ssdp", {})
    ports, svc, txt = set(ev.get("ports", [])), set(m.get("services", [])), m.get("txt", {})
    s = " ".join([vendor or "", name or "", up.get("deviceType", ""), up.get("friendlyName", ""),
                  up.get("modelName", ""), up.get("manufacturer", ""), ht.get("title", ""), ht.get("server", ""),
                  ht.get("realm", ""), sd.get("server", ""), txt.get("md", ""), txt.get("model", ""),
                  " ".join(sd.get("st", []))]).lower()
    has = lambda *x: any(i in svc for i in x)
    rx = lambda p: re.search(p, s)
    kind, conf = None, "cao"
    if has("_googlecast._tcp") or 8009 in ports:
        kind, conf = "Chromecast / Google TV / loa Google", "cao" if has("_googlecast._tcp") else "trung bình"
    elif has("_airplay._tcp", "_raop._tcp"):
        kind = "Thiết bị AirPlay (Apple TV / loa / TV)"
    elif has("_hap._tcp"):
        kind = "Thiết bị HomeKit"
    elif has("_ipp._tcp", "_printer._tcp", "_pdl-datastream._tcp") or rx(r"printer|laserjet|officejet"):
        kind = "Máy in"
    elif 9100 in ports:
        kind, conf = "Máy in", "trung bình"
    elif has("_apple-mobdev2._tcp", "_companion-link._tcp") or 62078 in ports:
        kind, conf = "iPhone / iPad (Apple)", "cao" if svc else "trung bình"
    elif rx(r"mediarenderer|smart ?tv|bravia|webos|roku|androidtv|tizen"):
        kind = "TV / thiết bị phát media"
    elif rx(r"hikvision|dahua|ipcam|ip camera|\bdvr\b|\bnvr\b|ds-2cd|ds-7|onvif|camera") or has("_axis-video._tcp", "_onvif._tcp"):
        kind = "Đầu ghi hình (NVR/DVR)" if rx(r"\bdvr\b|\bnvr\b|ds-7|ds-9|recorder") else "Camera IP"
    elif 554 in ports and (80 in ports or 8000 in ports):
        kind, conf = "Camera IP / đầu ghi hình (có cổng RTSP)", "trung bình"
    elif rx(r"internetgatewaydevice|router|gateway|access point|ruijie|mikrotik|ubiquiti|unifi|openwrt|tp-link|d-link|netgear|tenda|zyxel"):
        kind = "Router / AP / thiết bị mạng"
    elif rx(r"synology|qnap|diskstation|\bnas\b|readynas|truenas") or (5000 in ports and 445 in ports):
        kind, conf = "NAS / ổ mạng", ("cao" if rx(r"synology|qnap|diskstation|\bnas\b|truenas") else "trung bình")
    elif 3389 in ports:
        kind, conf = "Máy tính Windows (Remote Desktop đang bật)", "trung bình"
    elif has("_smb._tcp", "_workstation._tcp", "_device-info._tcp") or (445 in ports and 139 in ports):
        kind, conf = "Máy tính / máy chia sẻ file", ("cao" if svc else "trung bình")
    elif 22 in ports:
        kind, conf = "Thiết bị Linux / SSH (Raspberry Pi, NAS, router…)", "trung bình"
    model = " ".join(x for x in [up.get("manufacturer"), up.get("modelName"), up.get("modelNumber")] if x) \
        or next((txt[k] for k in ("md", "model", "am", "ty", "product", "rpmd", "usb_mdl") if txt.get(k)), "")
    if not model and re.match(r"^[A-Za-z]{2,4}-\w[\w\-]{3,}$", ht.get("realm", "")):
        model = ht["realm"]  # camera Hikvision/Dahua hay ghi mã model vào realm đăng nhập
    fname = up.get("friendlyName") or txt.get("fn") or (m.get("inst") or [""])[0]
    evid = []
    if svc - {"_services._dns-sd._udp"}:
        evid.append("mDNS: " + ", ".join(sorted(svc - {"_services._dns-sd._udp"})[:4]))
    if up:
        evid.append("UPnP: " + (up.get("friendlyName") or up.get("modelName") or up.get("deviceType", "")))
    if ht:
        evid.append("Web: " + (ht.get("title") or ht.get("realm") or ht.get("server") or "có trang quản trị"))
    if ports:
        evid.append("Cổng mở: " + ", ".join(map(str, sorted(ports))))
    if not (kind or model or fname or evid):
        return None
    return {"kind": kind, "conf": conf if kind else "", "model": model[:90], "fname": fname[:60], "evidence": evid}


# ------------------------------------------------------------------ server
class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _guard(self):
        # Chặn trang web lạ gọi vào server localhost (CSRF / DNS rebinding)
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
        if host not in ("127.0.0.1", "localhost"):
            return False
        origin = self.headers.get("Origin")
        return not origin or urlparse(origin).hostname in ("127.0.0.1", "localhost")

    def _json(self, payload):
        self._send(200, json.dumps(payload).encode("utf-8"), "application/json")

    def do_POST(self):
        if not self._guard() or "application/json" not in (self.headers.get("Content-Type") or ""):
            return self._send(403, b"Forbidden", "text/plain")
        n = int(self.headers.get("Content-Length") or 0)
        if n > 4096:
            return self._send(413, b"Too large", "text/plain")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
            if self.path == "/api/connect":
                res = connect(str(body.get("ssid", "")), str(body.get("bssid", "")),
                              body.get("password") or None, str(body.get("security", "")))
                self._json({"ok": True, **res})
            elif self.path == "/api/ping/control":
                self._json(ping_control(bool(body.get("on")), str(body.get("custom") or ""), bool(body.get("reset"))))
            elif self.path == "/api/disconnect":
                disconnect()
                self._json({"ok": True})
            else:
                self._send(404, b"Not found", "text/plain")
        except Exception as e:
            self._json({"ok": False, "error": str(e)})

    def do_GET(self):
        if not self._guard():
            return self._send(403, b"Forbidden", "text/plain")
        if self.path == "/":
            from pathlib import Path
            ui = Path(__file__).with_name("wifi_ui.html")
            html = ui.read_text(encoding="utf-8") if ui.exists() else PAGE
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
        elif self.path.startswith("/api/scan"):
            try:
                payload = {"ok": True, "os": platform.system(),
                           "time": time.strftime("%H:%M:%S"), "networks": cached_scan()}
            except Exception as e:
                payload = {"ok": False, "error": str(e), "networks": []}
            self._send(200, json.dumps(payload).encode("utf-8"), "application/json")
        elif self.path.startswith("/api/ping"):
            self._json(ping_payload())
        elif self.path.startswith("/api/netinfo"):
            try:
                i = net_info()
                payload = {"ok": True, **i} if i else {"ok": False, "error": "Chưa có địa chỉ IP — hãy kết nối WiFi."}
            except Exception as e:
                payload = {"ok": False, "error": str(e)}
            self._json(payload)
        elif self.path.startswith("/api/devices"):
            try:
                payload = devices_payload(cached="cached=1" in self.path, deep="deep=1" in self.path)
            except Exception as e:
                payload = {"ok": False, "error": str(e), "devices": []}
            self._json(payload)
        else:
            self._send(404, b"Not found", "text/plain")

    def log_message(self, *args):
        pass


PAGE = r"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WiFi Scanner</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--text:#1a1d21;--muted:#6b7280;--line:#e5e7eb;--accent:#2563eb;
--good:#16a34a;--mid:#d97706;--bad:#dc2626}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#181b21;--text:#e8eaed;--muted:#9aa1ab;
--line:#2a2f38;--accent:#60a5fa;--good:#4ade80;--mid:#fbbf24;--bad:#f87171}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:20px 16px 40px}
h1{font-size:20px;margin:0 0 2px}
.sub{color:var(--muted);margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;margin-bottom:16px}
.bar{display:flex;flex-wrap:wrap;gap:10px;align-items:center}
input,select,button{font:inherit;color:inherit;background:var(--card);border:1px solid var(--line);
border-radius:8px;padding:6px 10px}
button{cursor:pointer;background:var(--accent);border-color:var(--accent);color:#fff}
button:disabled{opacity:.6;cursor:wait}
.grow{flex:1;min-width:160px}
.stats{display:flex;gap:20px;flex-wrap:wrap;color:var(--muted)}
.stats b{color:var(--text)}
.tw{overflow-x:auto}
table{width:100%;border-collapse:collapse;white-space:nowrap}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
th{cursor:pointer;user-select:none;color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase}
th.on{color:var(--accent)}
td.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}
.sig{display:flex;align-items:center;gap:8px}
.meter{width:70px;height:8px;background:var(--line);border-radius:4px;overflow:hidden}
.meter i{display:block;height:100%}
.chip{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;border:1px solid var(--line)}
.err{color:var(--bad)}
.ch{display:flex;align-items:center;gap:8px;margin:3px 0;font-size:13px}
.ch span:first-child{width:44px;color:var(--muted);text-align:right}
.ch .b{height:14px;background:var(--accent);border-radius:3px;min-width:3px}
.ch .n{color:var(--muted)}
h2{font-size:14px;margin:0 0 8px}
.empty{padding:24px;text-align:center;color:var(--muted)}
</style>
</head>
<body>
<div class="wrap">
  <h1>WiFi Scanner</h1>
  <div class="sub" id="sub">Đang khởi động…</div>

  <div class="card">
    <div class="bar">
      <button id="scanBtn">Quét ngay</button>
      <select id="auto">
        <option value="0">Tự động: tắt</option>
        <option value="3" selected>Tự động: 3 giây</option>
        <option value="5">Tự động: 5 giây</option>
        <option value="10">Tự động: 10 giây</option>
      </select>
      <input id="q" class="grow" placeholder="Tìm theo SSID / BSSID / bảo mật…">
      <select id="band">
        <option value="">Mọi băng tần</option>
        <option>2.4 GHz</option><option>5 GHz</option><option>6 GHz</option>
      </select>
      <button id="csvBtn" style="background:transparent;color:var(--text);border-color:var(--line)">Xuất CSV</button>
    </div>
    <div class="stats" style="margin-top:10px" id="stats"></div>
  </div>

  <div class="card">
    <div class="tw"><table>
      <thead><tr id="head"></tr></thead>
      <tbody id="body"></tbody>
    </table></div>
    <div class="empty" id="empty" hidden></div>
  </div>

  <div class="card">
    <h2>Mức sử dụng kênh</h2>
    <div id="channels"></div>
  </div>
</div>

<script>
const COLS=[
 ["ssid","SSID"],["bssid","BSSID"],["signal_pct","Tín hiệu"],["dbm","dBm"],
 ["channel","Kênh"],["band","Băng tần"],["security","Bảo mật"],["radio","Chuẩn"]
];
let data=[], sortKey="signal_pct", sortDir=-1, timer=null, busy=false;
const $=id=>document.getElementById(id);

function buildHead(){
  const tr=$("head"); tr.innerHTML="";
  COLS.forEach(([k,label])=>{
    const th=document.createElement("th");
    th.textContent=label+(k===sortKey?(sortDir<0?" ▼":" ▲"):"");
    if(k===sortKey) th.className="on";
    th.onclick=()=>{ if(sortKey===k) sortDir*=-1; else {sortKey=k; sortDir=(k==="ssid"||k==="bssid")?1:-1;} render(); };
    tr.appendChild(th);
  });
}
function colorFor(dbm){ return dbm>=-60?"var(--good)":dbm>=-75?"var(--mid)":"var(--bad)"; }
function cell(text,cls){ const td=document.createElement("td"); td.textContent=text??""; if(cls) td.className=cls; return td; }

function filtered(){
  const q=$("q").value.trim().toLowerCase(), band=$("band").value;
  return data.filter(n=>{
    if(band && n.band!==band) return false;
    if(!q) return true;
    return [n.ssid,n.bssid,n.security,n.radio].join(" ").toLowerCase().includes(q);
  }).sort((a,b)=>{
    const x=a[sortKey], y=b[sortKey];
    if(x===undefined) return 1; if(y===undefined) return -1;
    if(typeof x==="number" && typeof y==="number") return (x-y)*sortDir;
    return String(x).localeCompare(String(y),undefined,{numeric:true})*sortDir;
  });
}

function render(){
  buildHead();
  const rows=filtered(), body=$("body");
  body.innerHTML="";
  rows.forEach(n=>{
    const tr=document.createElement("tr");
    const ts=cell(n.ssid);
    if(n.connected){ const c=document.createElement("span"); c.className="chip";
      c.style.cssText="margin-left:8px;color:var(--good);border-color:var(--good)"; c.textContent="đang kết nối"; ts.appendChild(c); }
    tr.appendChild(ts);
    tr.appendChild(cell(n.bssid,"mono"));
    const tdS=document.createElement("td");
    const w=document.createElement("div"); w.className="sig";
    const m=document.createElement("div"); m.className="meter";
    const i=document.createElement("i"); i.style.width=(n.signal_pct||0)+"%"; i.style.background=colorFor(n.dbm);
    m.appendChild(i);
    const t=document.createElement("span"); t.textContent=(n.signal_pct??"")+"%";
    w.append(m,t); tdS.appendChild(w); tr.appendChild(tdS);
    tr.appendChild(cell(n.dbm));
    tr.appendChild(cell(n.channel));
    tr.appendChild(cell(n.band));
    tr.appendChild(cell(n.security));
    tr.appendChild(cell(n.radio));
    body.appendChild(tr);
  });
  const e=$("empty");
  e.hidden=rows.length>0;
  if(!rows.length) e.textContent=data.length?"Không có mạng nào khớp bộ lọc.":"Chưa có dữ liệu.";
  stats(rows); channels(rows);
}

function stats(rows){
  const ssids=new Set(rows.map(n=>n.ssid));
  const open=rows.filter(n=>/open|none/i.test(n.security||"")).length;
  $("stats").innerHTML="";
  const cur=data.find(n=>n.connected);
  [["Đang kết nối",cur?`${cur.ssid} · Kênh ${cur.channel} · ${cur.band||"?"}`:"—"],
   ["Access point",rows.length],["SSID khác nhau",ssids.size],["Mạng mở",open]].forEach(([l,v])=>{
    const s=document.createElement("span"); s.append(l+": ");
    const b=document.createElement("b"); b.textContent=v; s.appendChild(b); $("stats").appendChild(s);
  });
}

function channels(rows){
  const box=$("channels"); box.innerHTML="";
  const groups={};
  rows.forEach(n=>{ if(n.channel===undefined||n.channel==="") return;
    const g=n.band||"?"; (groups[g]=groups[g]||{}); (groups[g][n.channel]=groups[g][n.channel]||[]).push(n); });
  const names=Object.keys(groups).sort();
  if(!names.length){ box.textContent="—"; return; }
  names.forEach(g=>{
    const h=document.createElement("div"); h.style.cssText="margin:8px 0 4px;color:var(--muted);font-size:12px"; h.textContent=g; box.appendChild(h);
    const max=Math.max(...Object.values(groups[g]).map(l=>l.length));
    Object.keys(groups[g]).sort((a,b)=>a-b).forEach(ch=>{
      const r=document.createElement("div"); r.className="ch";
      const a=document.createElement("span"); a.textContent="Ch "+ch;
      const list=groups[g][ch];
      const b=document.createElement("span"); b.className="b"; b.style.width=(list.length/max*35)+"%";
      const n=document.createElement("span"); n.className="n";
      const names=[...new Set(list.map(x=>x.ssid))];
      n.textContent=list.length+" AP · "+names.join(", ");
      n.title=names.join(", ");
      if(list.some(x=>x.connected)){
        a.style.color="var(--good)"; a.style.fontWeight="700";
        b.style.background="var(--good)"; n.textContent+="  ← bạn đang ở đây";
      }
      r.append(a,b,n); box.appendChild(r);
    });
  });
}

async function scan(){
  if(busy) return; busy=true; $("scanBtn").disabled=true;
  try{
    const r=await fetch("/api/scan"); const j=await r.json();
    if(j.ok){ data=j.networks; $("sub").textContent="Cập nhật lúc "+j.time+" · "+j.os; $("sub").className="sub"; }
    else { $("sub").textContent="Lỗi: "+j.error; $("sub").className="sub err"; }
    render();
  }catch(e){ $("sub").textContent="Không kết nối được server: "+e; $("sub").className="sub err"; }
  busy=false; $("scanBtn").disabled=false;
}

function setAuto(){
  clearInterval(timer);
  const s=+$("auto").value; if(s>0) timer=setInterval(scan,s*1000);
}

function csv(){
  const keys=COLS.map(c=>c[0]);
  const esc=v=>'"'+String(v??"").replace(/"/g,'""')+'"';
  const lines=[keys.join(",")].concat(filtered().map(n=>keys.map(k=>esc(n[k])).join(",")));
  const a=document.createElement("a");
  a.href=URL.createObjectURL(new Blob(["\ufeff"+lines.join("\n")],{type:"text/csv"}));
  a.download="wifi_scan.csv"; a.click();
}

$("scanBtn").onclick=scan; $("auto").onchange=setAuto; $("csvBtn").onclick=csv;
$("q").oninput=render; $("band").onchange=render;
buildHead(); scan(); setAuto();
</script>
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser(description="WiFi scanner web UI")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--offline-oui", action="store_true",
                    help="Không tra hãng thiết bị qua mạng (chỉ dùng file oui.txt/manuf local)")
    args = ap.parse_args()
    global OUI
    OUI = Oui(online=not args.offline_oui)

    # Chỉ bind 127.0.0.1 để chỉ máy bạn truy cập được
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    url = f"http://127.0.0.1:{args.port}"
    print(f"Đang chạy tại {url}  (Ctrl+C để dừng)")
    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nĐã dừng.")


if __name__ == "__main__":
    main()
