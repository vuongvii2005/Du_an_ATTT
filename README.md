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
│   ├── header_checker.py      # Security header, cookie, CORS, rò rỉ thông tin server
│   ├── dir_checker.py         # Path/file nhạy cảm (có baseline soft-404 + chữ ký nội dung)
│   ├── robots_checker.py      # Phân tích robots.txt
│   ├── cms_checker.py         # Phát hiện CMS (WordPress, Joomla, Drupal, Magento)
│   ├── port_checker.py        # Quét nhanh các cổng TCP phổ biến
│   └── tls_checker.py         # Chứng chỉ và phiên TLS được thương lượng
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── result.html
│   └── compare.html
├── static/style.css
├── demo/                      # Hai website demo: A (cấu hình yếu) và B (đã khắc phục)
├── test_target/               # Website giả lập một cổng 8080 + smoke test end-to-end
└── tests/                     # Unit test (mock HTTP/socket, không quét Internet)
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

## Chạy giao diện web

```powershell
$env:SCANNER_SECRET_KEY = "doi-gia-tri-nay-truoc-khi-chia-se"
python app.py
```

Mặc định server chạy tại **http://127.0.0.1:5000** (đổi bằng `SCANNER_HOST`,
`SCANNER_PORT`). Nhập một URL để quét riêng, hoặc hai URL để xem báo cáo cạnh
nhau. Khi bấm quét, form hiển thị trạng thái "Đang quét..." và khóa nút để tránh
gửi trùng. Nếu một website trong phần so sánh lỗi, website còn lại vẫn có báo cáo.

> `app.py` chạy với `debug=False`. Khi triển khai thật, hãy chạy bằng WSGI
> server (gunicorn, waitress...) và đặt `SCANNER_SECRET_KEY` cố định.

## Chạy scanner độc lập từ command line

`scanner.py` chạy trực tiếp được (không cần Flask) và in kết quả JSON, hữu ích
khi tích hợp vào script hoặc CI:

```powershell
python scanner.py https://example.com
```

## Các module quét

| Module | File | Chức năng |
|---|---|---|
| Header Check | `modules/header_checker.py` | Security header (HSTS, CSP, X-Frame-Options...), thuộc tính cookie, CORS, header rò rỉ thông tin (Server, X-Powered-By...) |
| TLS/SSL Check | `modules/tls_checker.py` | HTTPS, chứng chỉ/hostname/thời hạn, protocol và cipher của phiên, redirect HTTP → HTTPS |
| Directory Check | `modules/dir_checker.py` | 13 path nhạy cảm phổ biến; dùng baseline ngẫu nhiên chống soft-404 và đối chiếu chữ ký nội dung trước khi báo mức High |
| Robots.txt Check | `modules/robots_checker.py` | Lấy `/robots.txt`, gắn cờ các `Disallow` chứa từ khóa nhạy cảm |
| CMS Detection | `modules/cms_checker.py` | Nhận diện CMS qua `<meta name="generator">` và đường dẫn tài nguyên đặc trưng |
| Port Scan | `modules/port_checker.py` | `socket.connect_ex` tới 13 cổng TCP phổ biến (21, 22, 80, 443, 3306, 3389...) |

## Xử lý lỗi kết nối

Trước khi chạy module nào, `scanner.py` gọi `check_connectivity()` để xác nhận
website phản hồi. Lỗi được phân loại và hiển thị rõ trên UI: **timeout**,
**lỗi SSL/TLS**, **không kết nối được**, hoặc mục tiêu bị `target_guard` từ
chối. Nếu bước này thất bại, các module sẽ không chạy. Sau đó, module nào lỗi
hoặc bị bỏ qua được ghi ở mục "Trạng thái module" và báo cáo được đánh dấu là
chưa hoàn chỉnh, không bị hiểu nhầm là "an toàn".

## Demo hai website cục bộ (A yếu / B đã khắc phục)

Mở 3 cửa sổ PowerShell, cả ba cùng `cd` tới thư mục chứa `app.py` và kích hoạt
môi trường ảo (`.\venv\Scripts\Activate.ps1`; nếu PowerShell chặn script, chạy
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` trước).

**Terminal 1 — Website A** (cố ý cấu hình yếu: thiếu header, cookie thiếu thuộc
tính bảo vệ, CORS phản chiếu Origin):

```powershell
python .\demo\site_a.py          # http://127.0.0.1:5001
```

**Terminal 2 — Website B** (đã khắc phục header, cookie và CORS):

```powershell
python .\demo\site_b.py          # http://127.0.0.1:5002
```

**Terminal 3 — scanner ở Demo Mode** (bắt buộc đủ ba biến thì mới được quét
localhost):

```powershell
$env:SCANNER_DEMO_MODE = "true"
$env:SCANNER_DEMO_CONFIRM = "I_UNDERSTAND_LOCAL_SCAN_RISK"
$env:SCANNER_DEMO_TARGETS = "localhost,127.0.0.1"
$env:SCANNER_SECRET_KEY = "local-demo-only-change-before-sharing"
python .\app.py
```

Mở http://127.0.0.1:5000 và dùng ô **So sánh hai website** với
`http://127.0.0.1:5001` và `http://127.0.0.1:5002`. Nên nhập `127.0.0.1` thay vì
`localhost` để tránh Windows ưu tiên IPv6 `::1`.

## Website kiểm thử một cổng (`test_target/`)

Website giả lập chạy tại `127.0.0.1:8080` để thử toàn bộ module: thiếu security
header, `Server` header mặc định, robots.txt có dòng nhạy cảm, dấu hiệu
WordPress giả, và các path trả `200`/`403`/`302`. Mọi nội dung nhạy cảm đều là
dữ liệu giả; không đưa app này lên server công khai. Xem
[`test_target/README.md`](test_target/README.md).

Smoke test tự khởi động target, bật Demo Mode chỉ cho process của nó, quét và tự
tắt server:

```powershell
python test_target/smoke_test.py
```

## Bảo vệ mục tiêu và SSRF

> **Quét localhost:** mặc định đã bật khi app chỉ chạy trên máy này (`SCANNER_HOST` để trống hoặc là loopback). Chỉ `localhost`, `127.0.0.1`, `::1` được phép; mạng nội bộ vẫn bị chặn và website công khai không thể redirect scanner vào localhost. Tắt bằng `SCANNER_ALLOW_LOCAL=false`.


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
- Finding nghi ngờ nhận 25% trọng số và tổng phần nghi ngờ bị giới hạn 10 điểm.
- Finding trùng `module + title` chỉ được tính một lần.
- Các nhóm hiển thị thuộc cùng một module dùng chung mức trần 70 điểm.
- Mức `High` chỉ dành cho finding High đã xác minh; thiếu header, cổng mở và dấu hiệu
  chưa đủ bằng chứng chỉ là thông tin tham khảo.
- Nếu thiếu module, module lỗi hoặc bị bỏ qua, risk level là `Unknown`, không phải
  kết luận “an toàn” hay “nguy hiểm”.

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
