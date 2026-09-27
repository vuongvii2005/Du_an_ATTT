# -*- coding: utf-8 -*-
"""
Module: header_checker
Chức năng: Kiểm tra các HTTP Security Header và phát hiện rò rỉ thông tin server.
Cơ chế: Passive - chỉ đọc header từ response GET đã có sẵn (do scanner.py truyền vào),
không gửi thêm request nào khác.
"""

# Danh sách các security header quan trọng cần có trên 1 website an toàn
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "Medium",
        "description": "Thiếu HSTS - trình duyệt có thể bị hạ cấp từ HTTPS về HTTP (downgrade attack).",
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "description": "Thiếu X-Content-Type-Options - trình duyệt có thể bị lợi dụng MIME-sniffing.",
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "description": "Thiếu X-Frame-Options - website có thể bị nhúng vào iframe (Clickjacking).",
    },
    "Content-Security-Policy": {
        "severity": "High",
        "description": "Thiếu Content-Security-Policy - tăng nguy cơ bị khai thác XSS và Data Injection.",
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": "Thiếu Referrer-Policy - URL hiện tại có thể bị rò rỉ qua header Referer khi chuyển trang.",
    },
    "Permissions-Policy": {
        "severity": "Low",
        "description": "Thiếu Permissions-Policy - không kiểm soát quyền truy cập API trình duyệt (camera, mic, vị trí...).",
    },
}

# Các header có thể làm rò rỉ thông tin công nghệ / phiên bản server đang chạy
INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


def run(response):
    """
    Phân tích header từ 1 response object (requests.Response) của trang chủ.
    Trả về dict kết quả gồm: missing_headers, info_leak, raw_headers.
    """
    result = {
        "module": "header_checker",
        "missing_headers": [],
        "info_leak": [],
        "raw_headers": dict(response.headers),
    }

    headers = response.headers  # requests dùng CaseInsensitiveDict -> tra cứu không phân biệt hoa/thường

    # 1. Kiểm tra các security header đang bị thiếu
    for header_name, meta in SECURITY_HEADERS.items():
        if header_name not in headers:
            result["missing_headers"].append(
                {
                    "header": header_name,
                    "severity": meta["severity"],
                    "description": meta["description"],
                }
            )

    # 2. Kiểm tra rò rỉ thông tin qua các header đặc trưng
    for header_name in INFO_LEAK_HEADERS:
        if header_name in headers:
            result["info_leak"].append(
                {
                    "header": header_name,
                    "value": headers[header_name],
                    "severity": "Info",
                    "description": f"Server đang tiết lộ thông tin công nghệ/phiên bản qua header '{header_name}'.",
                }
            )

    return result
