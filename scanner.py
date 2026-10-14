# -*- coding: utf-8 -*-
"""
scanner.py
File điều phối chính (Core Orchestrator) của Lightweight Web Vulnerability Scanner.

Luồng xử lý:
1. Chuẩn hoá URL đầu vào (thêm scheme nếu thiếu, validate).
2. Kiểm tra kết nối (connectivity check) trước khi chạy các module con.
3. Chạy tuần tự từng module thu thập thông tin thụ động (header, dir, robots, cms, port).
4. Gửi toàn bộ kết quả cho report.py để tổng hợp & tính điểm rủi ro.

Lưu ý đạo đức & pháp lý:
Tool này CHỈ thực hiện các hành vi passive/non-intrusive (gửi HTTP request thông
thường, đọc header/response, TCP handshake cơ bản). Không có bước nào khai thác
lỗ hổng hay gửi payload tấn công. CHỈ sử dụng trên hệ thống bạn sở hữu hoặc đã
được cấp phép rõ ràng để kiểm tra (authorized penetration testing / bug bounty
trong phạm vi cho phép).
"""

import time
from urllib.parse import urlparse

import requests
import urllib3

from modules import header_checker, dir_checker, robots_checker, cms_checker, port_checker
import report as report_module

# Tắt cảnh báo urllib3 phòng trường hợp mở rộng thêm verify=False trong tương lai
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REQUEST_TIMEOUT = 6
USER_AGENT = "LightweightWebVulnScanner/1.0 (+passive-recon)"


class ScannerError(Exception):
    """Lỗi tổng quát của quá trình scan, chứa message thân thiện để hiển thị lên UI."""

    pass


def normalize_url(raw_url):
    """
    Chuẩn hoá URL đầu vào: tự thêm scheme http:// nếu thiếu, loại bỏ dấu / ở cuối.
    Trả về tuple (base_url, hostname).
    """
    raw_url = (raw_url or "").strip()
    if not raw_url:
        raise ScannerError("URL không được để trống.")

    parsed = urlparse(raw_url)
    if not parsed.scheme:
        raw_url = "http://" + raw_url
        parsed = urlparse(raw_url)

    if parsed.scheme not in ("http", "https"):
        raise ScannerError("URL phải bắt đầu bằng http:// hoặc https://")

    if not parsed.netloc:
        raise ScannerError("URL không hợp lệ, thiếu tên domain.")

    normalized = f"{parsed.scheme}://{parsed.netloc}"
    return normalized, parsed.hostname


def check_connectivity(base_url, session):
    """
    Kiểm tra website có hoạt động hay không TRƯỚC KHI chạy các module quét.
    Bắt lỗi chặt chẽ: Timeout, SSL Error, Connection Failure.
    Trả về response nếu thành công, raise ScannerError nếu thất bại.
    """
    try:
        response = session.get(
            base_url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
        )
        return response

    except requests.exceptions.SSLError as e:
        raise ScannerError(
            f"Lỗi SSL/TLS khi kết nối tới {base_url}. Chứng chỉ có thể không hợp lệ hoặc hết hạn. "
            f"Chi tiết: {str(e)}"
        )
    except requests.exceptions.Timeout:
        raise ScannerError(
            f"Kết nối tới {base_url} bị timeout sau {REQUEST_TIMEOUT}s. Website có thể đang chậm hoặc chặn request."
        )
    except requests.exceptions.ConnectionError as e:
        raise ScannerError(
            f"Không thể kết nối tới {base_url}. Website có thể đang offline hoặc domain không tồn tại. "
            f"Chi tiết: {str(e)}"
        )
    except requests.exceptions.RequestException as e:
        raise ScannerError(f"Lỗi không xác định khi kết nối tới {base_url}: {str(e)}")


def run_scan(raw_url):
    """
    Hàm chính để chạy toàn bộ quy trình scan cho 1 URL.
    Trả về report dict (xem report.py) hoặc raise ScannerError nếu không thể tiếp tục.
    """
    start_time = time.time()

    base_url, hostname = normalize_url(raw_url)

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    # 1. Kiểm tra kết nối trước khi chạy bất kỳ module nào
    homepage_response = check_connectivity(base_url, session)

    module_results = {}

    # 2. Header checker - dùng lại response trang chủ đã có, không gửi request thừa
    try:
        module_results["header_checker"] = header_checker.run(homepage_response)
    except Exception as e:
        module_results["header_checker"] = {"module": "header_checker", "error": str(e)}

    # 3. Directory checker
    try:
        module_results["dir_checker"] = dir_checker.run(base_url, session)
    except Exception as e:
        module_results["dir_checker"] = {"module": "dir_checker", "error": str(e)}

    # 4. Robots.txt checker
    try:
        module_results["robots_checker"] = robots_checker.run(base_url, session)
    except Exception as e:
        module_results["robots_checker"] = {"module": "robots_checker", "error": str(e)}

    # 5. CMS checker - phân tích lại response trang chủ, không gửi thêm request
    try:
        module_results["cms_checker"] = cms_checker.run(homepage_response)
    except Exception as e:
        module_results["cms_checker"] = {"module": "cms_checker", "error": str(e)}

    # 6. Port checker - dùng hostname thuần (không có scheme)
    try:
        module_results["port_checker"] = port_checker.run(hostname)
    except Exception as e:
        module_results["port_checker"] = {"module": "port_checker", "error": str(e)}

    duration = round(time.time() - start_time, 2)

    final_report = report_module.generate_report(base_url, module_results, scan_duration=duration)
    return final_report


if __name__ == "__main__":
    # Cho phép chạy scanner độc lập từ command line để test nhanh, không cần Flask.
    # Cách dùng: python scanner.py https://example.com
    import sys
    import json

    if len(sys.argv) < 2:
        print("Cách dùng: python scanner.py <url>")
        sys.exit(1)

    target = sys.argv[1]
    try:
        result = run_scan(target)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except ScannerError as e:
        print(f"[LỖI] {str(e)}")
        sys.exit(1)
