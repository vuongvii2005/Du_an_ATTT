# Lightweight Web Vulnerability Scanner

Công cụ reconnaissance chủ động có giới hạn dành cho học tập: gửi một số HTTP
request cố định, phân tích response/header, nhận diện CMS và thử kết nối một
danh sách ngắn các cổng TCP. Công cụ còn kiểm tra một phiên TLS đã thương
lượng và trạng thái chứng chỉ của đúng mục tiêu đã được xác thực. Công cụ không gửi payload khai thác SQLi/XSS và
không thay thế một bài penetration test đầy đủ.

> Chỉ quét website hoặc hệ thống bạn sở hữu hay đã được cấp phép rõ ràng. Dò
> path và kết nối cổng là hoạt động chủ động, dù công cụ đã giới hạn cường độ.

## Chức năng

- Quét một website hoặc so sánh hai website độc lập.
- Kiểm tra HTTP security header và header rò rỉ công nghệ.
- Kiểm tra 13 path phổ biến, dùng baseline ngẫu nhiên để giảm soft-404.
- Chỉ đánh dấu file nhạy cảm mức cao khi nội dung khớp chữ ký; `security.txt`
  không bị coi là lỗ hổng.
- Phân tích `robots.txt`, dấu hiệu CMS và 13 cổng TCP phổ biến.
- Phân tích HTTPS/TLS: xác thực chứng chỉ và hostname, thời hạn, giao thức và
  cipher của phiên được thương lượng, cùng redirect HTTP sang HTTPS.
- Hiển thị trạng thái `success`, `error`, `skipped` và thời gian của từng module.
- Phân biệt phát hiện đã xác minh, nghi ngờ và lượt quét chưa hoàn chỉnh.
- Chặn SSRF, DNS rebinding, redirect không an toàn và response quá lớn.

## Cấu trúc

```text
web_vuln_scanner/
├── app.py                     # Flask UI, CSRF và xử lý lỗi
├── scanner.py                 # Điều phối, giới hạn thời gian/request/concurrency
├── target_guard.py            # Kiểm tra IP, redirect và pin DNS
├── report.py                  # Chuẩn hóa kết quả và chấm điểm
├── requirements.txt           # Dependency chạy ứng dụng
├── requirements-dev.txt       # Dependency kiểm thử
├── modules/
│   ├── header_checker.py
│   ├── dir_checker.py
│   ├── robots_checker.py
│   ├── cms_checker.py
│   ├── port_checker.py
│   └── tls_checker.py           # Chứng chỉ và phiên TLS được thương lượng
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── result.html
│   └── compare.html
├── static/style.css
└── tests/
```

## Cài đặt trên Windows PowerShell

Yêu cầu Python 3.9 trở lên.

```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Để phát triển và chạy test:

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Các test dùng mock HTTP/socket và không quét website ngoài Internet.

1. Chuẩn bị
Mở 3 cửa sổ PowerShell. Trong cả ba terminal, chuyển đến thư mục chứa app.py:
cd C:\Users\admin\Downloads\web_vuln_scanner\web_vuln_scanner
Kích hoạt môi trường ảo:
.\venv\Scripts\Activate.ps1
Nếu PowerShell chặn script:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
2. Terminal 1 — chạy Website A
python .\demo\site_a.py
Kết quả mong đợi:
Running on http://127.0.0.1:5001
Mở thử:
http://127.0.0.1:5001
Đây là website cố ý cấu hình yếu.
3. Terminal 2 — chạy Website B
python .\demo\site_b.py
Kết quả mong đợi:
Running on http://127.0.0.1:5002
Mở thử:
http://127.0.0.1:5002
Đây là phiên bản đã khắc phục Security Headers, Cookie và CORS.
4. Terminal 3 — bật Demo Mode
Thiết lập đúng ba biến bảo vệ mục tiêu:
$env:SCANNER_DEMO_MODE = "true"
$env:SCANNER_DEMO_CONFIRM = "I_UNDERSTAND_LOCAL_SCAN_RISK"
$env:SCANNER_DEMO_TARGETS = "localhost,127.0.0.1"
Thiết lập Flask scanner:
$env:SCANNER_HOST = "127.0.0.1"
$env:SCANNER_PORT = "5000"
$env:SCANNER_SECRET_KEY = "local-demo-only-change-before-sharing"
Chạy scanner:
python .\app.py
Mở giao diện:
http://127.0.0.1:5000
Luôn nhập 127.0.0.1 thay vì localhost để tránh Windows ưu tiên IPv6 ::1.

## Bảo vệ mục tiêu và SSRF

Mặc định scanner chỉ cho HTTP/HTTPS tới IP public/global. Công cụ từ chối:

- URL chứa username/password.
- Loopback, private, link-local, multicast, reserved, unspecified IP.
- Các địa chỉ cloud metadata phổ biến.
- Hostname có bất kỳ bản ghi IPv4/IPv6 nào không an toàn.
- Redirect sang mục tiêu bị cấm.
- Tập DNS thay đổi trong lượt quét.

HTTP connection được pin tới IP đã kiểm tra, đồng thời vẫn giữ Host header và
TLS SNI của domain. Requests không sử dụng proxy từ biến môi trường trong phiên
quét để tránh bỏ qua IP đã pin.

Có thể hạn chế thêm phạm vi bằng danh sách chính xác, wildcard domain hoặc CIDR
public:

```powershell
$env:SCANNER_ALLOWED_TARGETS = "example.com,*.example.org,93.184.216.34"
```

Khi biến này rỗng, các mục tiêu public hợp lệ vẫn được phép.

### Chế độ demo localhost/lab

Chế độ demo mặc định tắt. Để quét một hostname private trong lab, phải bật đủ
ba biến và liệt kê chính xác hostname/IP; scanner không tự mở toàn bộ private
network và không nhận wildcard/CIDR trong `SCANNER_DEMO_TARGETS`.

```powershell
$env:SCANNER_DEMO_MODE = "true"
$env:SCANNER_DEMO_CONFIRM = "I_UNDERSTAND_LOCAL_SCAN_RISK"
$env:SCANNER_DEMO_TARGETS = "localhost"
python app.py
```

Xóa các biến sau khi hoàn tất lab:

```powershell
Remove-Item Env:SCANNER_DEMO_MODE, Env:SCANNER_DEMO_CONFIRM, Env:SCANNER_DEMO_TARGETS
```

## Giới hạn tài nguyên

| Biến môi trường | Mặc định | Phạm vi trong code |
|---|---:|---:|
| `SCANNER_MAX_CONCURRENT` | 2 | 1–10 lượt |
| `SCANNER_TOTAL_TIMEOUT` | 45 giây | 10–180 giây |
| `SCANNER_REQUEST_BUDGET` | 20 | 5–50 request |
| `SCANNER_MAX_RESPONSE_BYTES` | 1 MiB | 64 KiB–5 MiB |
| `SCANNER_MAX_REDIRECTS` | 5 | 0–10 |

Directory checker dùng tối đa 14 HTTP request gồm một baseline soft-404. Port
checker dùng timeout 0,5 giây mỗi cổng và tôn trọng deadline chung. TLS checker
dùng tối đa một TLS connection tới IP đã pin và một HTTP request không theo
redirect để kiểm tra chuyển hướng; timeout TLS tối đa 4 giây và vẫn tôn trọng
deadline/request budget chung.

## TLS/SSL Security Analyzer

TLS checker chạy sau khi URL hiệu lực đã vượt qua `target_guard`. Kết nối TCP
được gửi thẳng tới `selected_ip` đã xác thực, còn TLS SNI và kiểm tra hostname
dùng hostname gốc. Module không tự phân giải lại DNS và không chuyển sang
hostname khác.

Kết quả gồm trạng thái hỗ trợ HTTPS, tính hợp lệ và thời hạn chứng chỉ, khớp
hostname, protocol/cipher của phiên hiện tại và redirect HTTP → HTTPS. Finding
TLS hiển thị mô tả, bằng chứng, nguyên nhân và khuyến nghị. Lỗi timeout hoặc
handshake được đánh dấu là lượt kiểm tra chưa hoàn thành, không được hiểu là
“không có lỗ hổng”.

## Cách chấm điểm

- High: 70 điểm; Medium: 35; Low: 10; Info: 0.
- Finding nghi ngờ nhận 50% trọng số.
- Finding trùng `module + title` chỉ được tính một lần.
- Mỗi module đóng góp tối đa 85 điểm để một nhóm kết quả lặp không lấn át báo cáo.
- Risk level không bao giờ thấp hơn finding đã xác minh nghiêm trọng nhất.
- Nếu không có finding nhưng có module lỗi/bị bỏ qua, kết quả là `Unknown`,
  không phải “an toàn”.

## Giới hạn còn lại

- CMS detection chỉ dùng fingerprint HTML và không xác định CVE/phiên bản chắc chắn.
- Port scanner xác nhận cổng mở nhưng tên dịch vụ chỉ được suy ra từ số cổng.
- TLS checker chỉ quan sát protocol/cipher được thương lượng bởi một kết nối
  mặc định; không liệt kê mọi phiên bản TLS hoặc cipher suite máy chủ hỗ trợ.
- Kiểm tra redirect HTTP bị bỏ qua với cổng HTTPS tùy chỉnh vì công cụ không tự
  suy đoán ánh xạ sang một cổng HTTP khác.
- Công cụ dựa vào kho CA và khả năng TLS của Python/OpenSSL trên máy đang chạy;
  chưa kiểm tra OCSP/CRL, certificate transparency, HSTS preload hay toàn bộ
  chuỗi cấu hình nâng cao.
- Không kiểm tra business logic, authenticated area, SQLi hoặc XSS thực tế.
- Một số CDN/load-balancer luân phiên tập IP có thể bị dừng bảo thủ như thay đổi
  DNS; có thể dùng allowlist và môi trường lab ổn định khi trình diễn.
