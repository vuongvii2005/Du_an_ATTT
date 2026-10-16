# Local test target

Đây là một website giả lập chỉ chạy trên `127.0.0.1:8080` để kiểm thử
`scanner.py`. Các dữ liệu nhạy cảm đều là dữ liệu giả; không đưa app này lên
server công khai.

Scanner mặc định **từ chối** quét loopback/private IP (xem `target_guard.py`),
nên để quét target này phải bật Demo Mode với đủ ba biến môi trường. Smoke test
(Cách 3) tự bật giúp bạn, còn Cách 1 và 2 cần làm thủ công.

## Cách 1: chạy scanner CLI

Terminal 1, tại thư mục gốc project:

```powershell
python test_target/app.py
```

Terminal 2:

```powershell
$env:SCANNER_DEMO_MODE = "true"
$env:SCANNER_DEMO_CONFIRM = "I_UNDERSTAND_LOCAL_SCAN_RISK"
$env:SCANNER_DEMO_TARGETS = "127.0.0.1"
python scanner.py http://127.0.0.1:8080
```

Bạn sẽ thấy JSON có các finding từ header, TLS, directory, robots.txt, CMS và
port `8080`.

## Cách 2: chạy giao diện Flask

Giữ Terminal 1 đang chạy test target. Ở Terminal 2, đặt ba biến Demo Mode như
trên rồi chạy:

```powershell
python app.py
```

Truy cập `http://127.0.0.1:5000`, nhập `http://127.0.0.1:8080` để quét, hoặc
nhập cùng URL vào Website A và Website B rồi bấm **So sánh 2 website** để thử
route `/compare`.

## Cách 3: smoke test tự động

Script tự khởi động test target, bật Demo Mode chỉ cho process của nó (chỉ cho
`127.0.0.1`), gọi `scanner.run_scan()`, kiểm tra các module chính và tự tắt
server:

```powershell
python test_target/smoke_test.py
```

Kết quả mong đợi bắt đầu bằng:

```text
PASS: local target was scanned successfully
```

Xóa các biến Demo Mode sau khi dùng Cách 1 hoặc 2:

```powershell
Remove-Item Env:SCANNER_DEMO_MODE, Env:SCANNER_DEMO_CONFIRM, Env:SCANNER_DEMO_TARGETS
```

## Target cố ý tạo các tình huống

- Thiếu security headers và có `Server` header mặc định của Flask/Werkzeug.
- Có các dòng nhạy cảm trong `robots.txt`.
- Có dấu hiệu WordPress giả trong HTML.
- Trả `200` kèm nội dung giả khớp chữ ký cho `.env`, `.git/config`,
  `backup.zip`, `backup.sql`, `config.php.bak`, `phpinfo.php`, `web.config`
  (để Directory Check báo "đã xác minh").
- Trả `403` cho `server-status` và `302` cho `admin/`.
- Trả `404` thuần cho mọi path khác, giữ baseline soft-404 sạch.
- Lắng nghe trên port `8080`, là port có trong `modules/port_checker.py`.
