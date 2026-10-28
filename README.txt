WiFi Analyzer (localhost)

Chay:  python wifi_web.py
Mo trinh duyet tai http://127.0.0.1:8000 (tu dong mo). Doi cong: --port 9000
Yeu cau: Python 3, Windows (netsh + PowerShell) hoac Linux (nmcli + ip). Khong can cai thu vien.
wifi_ui.html phai nam cung thu muc voi wifi_web.py.
Giao dien dung font/icon tu Google Fonts + unpkg (chi la trang tri): offline van dung duoc, chi mat icon/font dep.
Windows 11: bat Location services de quet duoc WiFi.

Cach dung:
- Bam "Chon mang manh nhat" hoac bam 1 dong trong bang -> hien o Ket noi / "Chi xem, khong ket noi".
- Mang da luu tren may: de trong mat khau. Mang moi: nhap mat khau (WPA/WPA2/WPA3-Personal hoac mang mo).
- Sau khi ket noi tool tu mo tab "Thiet bi trong mang": IP, MAC, hang, ten may.

Tab "Do tre (Ping)": ping that toi router + 1.1.1.1 + 8.8.8.8 (+ dich tuy chon) moi 2 giay, ve do thi, jitter, mat goi.
  Server tu dung do neu khong con trang nao xem trong 60 giay.
Tab "Thiet bi trong mang": "Quet nhanh" (ARP + hang) va "Quet sau" (them mDNS, UPnP/SSDP, cong mo, banner web de ra loai/model).
  Quet sau chi nen dung tren mang cua ban; mat them khoang 5-10 giay.

Tra hang theo MAC (3 byte dau):
- Tu dong dung file oui.txt / manuf (dat canh wifi_web.py) hoac file cua Wireshark/nmap/ieee-data neu co.
- Con lai tra online qua api.macvendors.com (chi gui 3 byte dau cua MAC, ket qua luu o oui_cache.json).
- Tat tra online: python wifi_web.py --offline-oui
- MAC "ngau nhien" (dien thoai bat Private Address) khong co hang that.

Gioi han:
- Khoang cach chi uoc luong duoc cho router/AP (tu dBm). Khong do duoc tung thiet bi khac.
- Mang doanh nghiep (802.1X) va mang an chua ho tro ket noi.
- Chi quet mang cua ban hoac mang ban duoc phep dung.
