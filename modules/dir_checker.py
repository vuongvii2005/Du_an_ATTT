# -*- coding: utf-8 -*-
"""
Module: dir_checker
Chức năng: Kiểm tra sự tồn tại của một số thư mục/file nhạy cảm thường bị lộ công khai.
Cơ chế: Passive/Non-intrusive - chỉ gửi GET request thông thường tới danh sách path
cố định và đọc status code trả về, KHÔNG brute-force sâu, KHÔNG khai thác lỗ hổng.

Lưu ý: Danh sách path chỉ mang tính tham khảo/rút gọn cho mục đích audit nhanh.
Chỉ sử dụng trên hệ thống bạn sở hữu hoặc được cấp phép kiểm tra.
"""

import requests

# Danh sách rút gọn các path nhạy cảm phổ biến
COMMON_SENSITIVE_PATHS = [
    ".env",
    ".git/config",
    ".htaccess",
    "backup.zip",
    "backup.sql",
    "config.php.bak",
    "phpinfo.php",
    "server-status",
    "admin/",
    "administrator/",
    "wp-admin/",
    ".well-known/security.txt",
    "web.config",
]

TIMEOUT = 5


def run(base_url, session=None):
    """
    Kiểm tra từng path trong danh sách, ghi lại các path trả về status "đáng chú ý".
    base_url: URL gốc đã chuẩn hoá (có scheme, không có dấu / cuối)
    session: requests.Session dùng chung (tái sử dụng connection, tùy chọn)
    """
    sess = session or requests.Session()
    result = {
        "module": "dir_checker",
        "findings": [],
    }

    for path in COMMON_SENSITIVE_PATHS:
        url = f"{base_url}/{path}"
        try:
            resp = sess.get(url, timeout=TIMEOUT, allow_redirects=False)
            status = resp.status_code

            if status == 200:
                result["findings"].append(
                    {
                        "path": path,
                        "url": url,
                        "status_code": status,
                        "severity": "High",
                        "description": "Path phản hồi 200 OK - có thể đang bị public truy cập ngoài ý muốn.",
                    }
                )
            elif status in (401, 403):
                result["findings"].append(
                    {
                        "path": path,
                        "url": url,
                        "status_code": status,
                        "severity": "Info",
                        "description": "Path tồn tại nhưng bị chặn truy cập (cơ chế bảo mật đang hoạt động).",
                    }
                )
            elif status in (301, 302, 307, 308):
                result["findings"].append(
                    {
                        "path": path,
                        "url": url,
                        "status_code": status,
                        "severity": "Low",
                        "description": "Path bị redirect - nên kiểm tra thêm đích redirect trỏ tới đâu.",
                    }
                )
            # Các status khác (404, 500...) được bỏ qua để tránh gây nhiễu báo cáo

        except requests.exceptions.Timeout:
            continue
        except requests.exceptions.SSLError:
            continue
        except requests.exceptions.RequestException:
            continue

    return result
