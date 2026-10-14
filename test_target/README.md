# Local test target

Đây là một website giả lập chỉ chạy trên `127.0.0.1:8080` để kiểm thử
`scanner.py`. Các dữ liệu nhạy cảm đều là dữ liệu giả; không đưa app này lên
server công khai.

## Cách 1: chạy scanner CLI

Mở Terminal 1 tại thư mục gốc project:

```powershell
python test_target/app.py
```

Mở Terminal 2:

```powershell
python scanner.py http://127.0.0.1:8080
```

Bạn sẽ thấy JSON có các finding từ header, directory, robots.txt, CMS và port
`8080`.

## Cách 2: chạy giao diện Flask

Giữ Terminal 1 đang chạy test target. Mở Terminal 2:

```powershell
python app.py
```

Truy cập `http://127.0.0.1:5000`, nhập:

```text
Website A: http://127.0.0.1:8080
Website B: http://127.0.0.1:8080
```

Sau đó bấm **So sánh 2 website** để kiểm thử route `/compare` và giao diện
`compare.html`.

## Cách 3: smoke test tự động

Script này tự khởi động test target, gọi `scanner.run_scan()`, kiểm tra các
module chính và tự tắt server:

```powershell
python test_target/smoke_test.py
```

Kết quả mong đợi bắt đầu bằng:

```text
PASS: local target was scanned successfully
```

Test target cố ý tạo các tình huống sau:

- Thiếu security headers.
- Có `Server` header mặc định của Flask/Werkzeug.
- Có các dòng nhạy cảm trong `robots.txt`.
- Có dấu hiệu WordPress giả trong HTML.
- Trả `200`, `403` và `302` cho một số path kiểm thử.
- Lắng nghe trên port `8080`, là port có trong `port_checker.py`.
