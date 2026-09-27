# Lightweight Web Vulnerability Scanner

Công cụ quét bảo mật web nhẹ, chỉ thực hiện **thu thập thông tin thụ động /
không xâm nhập** (passive recon): gửi HTTP request thông thường, phân tích
status code, header và response body. Không có module nào khai thác lỗ hổng
hay gửi payload tấn công.

> ⚠️ **Chỉ sử dụng công cụ này trên website/hệ thống bạn sở hữu, hoặc đã được
> cấp phép rõ ràng để kiểm tra** (ví dụ: môi trường staging của bạn, hoặc
> chương trình bug bounty/pentest được ủy quyền). Việc quét hệ thống của
> người khác mà không được phép có thể vi phạm pháp luật.

## Cấu trúc dự án

```
web_vuln_scanner/
├── app.py                     # Flask Web UI
├── scanner.py                 # Core Orchestrator - điều phối toàn bộ quy trình quét
├── report.py                  # Tổng hợp kết quả & tính điểm rủi ro
├── requirements.txt
├── modules/
│   ├── __init__.py
│   ├── header_checker.py      # Kiểm tra security header & rò rỉ thông tin server
│   ├── dir_checker.py         # Kiểm tra thư mục/file nhạy cảm
│   ├── robots_checker.py      # Phân tích robots.txt
│   ├── cms_checker.py         # Phát hiện CMS (WordPress, Joomla, Drupal, Magento)
│   └── port_checker.py        # Quét nhanh các cổng TCP phổ biến
├── templates/
│   ├── base.html
│   ├── index.html
│   └── result.html
└── static/
    └── style.css
```

## 1. Cài đặt

Yêu cầu: Python 3.9+

```bash
# Tạo virtual environment (khuyến nghị)
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# Cài thư viện từ requirements.txt
pip install -r requirements.txt
```

Nội dung `requirements.txt`:

```
Flask==3.0.3
requests==2.32.3
beautifulsoup4==4.12.3
urllib3==2.2.2
```

## 2. Khởi chạy ứng dụng Flask (Web UI)

```bash
python app.py
```

Mặc định server chạy tại: **http://127.0.0.1:5000**

Mở trình duyệt, nhập URL cần quét (ví dụ `example.com` hoặc
`https://example.com`) vào form và nhấn **"Bắt đầu quét"**. Kết quả sẽ hiển
thị dưới dạng báo cáo gồm: điểm rủi ro tổng quan, số lượng phát hiện theo mức
độ (High/Medium/Low/Info), danh sách chi tiết từng phát hiện, và thông tin bổ
sung (robots.txt, cổng mở, raw header).

> Lưu ý: `debug=True` trong `app.py` chỉ nên dùng khi phát triển. Khi deploy
> thực tế, hãy tắt debug mode và chạy bằng WSGI server (gunicorn, waitress...).

## 3. Chạy scanner độc lập từ command line (không cần Flask)

`scanner.py` cũng có thể chạy trực tiếp để lấy kết quả dạng JSON, hữu ích khi
muốn tích hợp vào script khác hoặc CI pipeline:

```bash
python scanner.py https://example.com
```

## 4. Các module quét

| Module | File | Chức năng |
|---|---|---|
| Header Check | `modules/header_checker.py` | So sánh header phản hồi với danh sách security header khuyến nghị (HSTS, CSP, X-Frame-Options...) và phát hiện header rò rỉ thông tin (Server, X-Powered-By...) |
| Directory Check | `modules/dir_checker.py` | Gửi GET request tới danh sách rút gọn các path nhạy cảm thường gặp (`.env`, `.git/config`, `backup.zip`...) và ghi nhận status code đáng chú ý |
| Robots.txt Check | `modules/robots_checker.py` | Lấy `/robots.txt`, phân tích các dòng `Disallow` và gắn cờ path chứa từ khoá nhạy cảm |
| CMS Detection | `modules/cms_checker.py` | Phân tích thẻ `<meta name="generator">` và các đường dẫn tài nguyên đặc trưng để nhận diện CMS |
| Port Scan | `modules/port_checker.py` | Dùng `socket.connect_ex` để kiểm tra nhanh một số cổng TCP phổ biến (21, 22, 80, 443, 3306, 3389...) |

## 5. Xử lý lỗi kết nối

Trước khi chạy bất kỳ module nào, `scanner.py` luôn gọi
`check_connectivity()` để xác nhận website còn hoạt động. Các lỗi được bắt
riêng biệt và hiển thị thông báo rõ ràng lên UI:

- **Timeout**: server không phản hồi trong thời gian cho phép.
- **SSL Error**: chứng chỉ TLS không hợp lệ / hết hạn.
- **Connection Failure**: domain không tồn tại hoặc server offline.

Nếu kiểm tra kết nối thất bại, các module quét sẽ **không được chạy**, tránh
lãng phí thời gian và request không cần thiết.

## 6. Giới hạn của công cụ

Đây là công cụ ở mức "lightweight", phù hợp để audit nhanh cấu hình cơ bản.
Nó **không** thay thế cho một bài kiểm tra thâm nhập (penetration test) đầy
đủ, và không phát hiện các lỗ hổng logic nghiệp vụ, lỗ hổng cần xác thực,
hoặc lỗ hổng ở tầng ứng dụng sâu (SQLi, XSS thực tế...). Nên kết hợp với các
công cụ chuyên sâu hơn (Burp Suite, OWASP ZAP, Nikto...) và đánh giá thủ công
khi cần độ chính xác cao hơn.
