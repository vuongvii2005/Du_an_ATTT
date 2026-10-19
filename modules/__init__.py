"""
Package: modules
Chứa các module quét độc lập của Lightweight Web Vulnerability Scanner.
Mỗi module nhận dữ liệu đầu vào (response/URL/hostname) và trả về một dict
kết quả có cấu trúc thống nhất để report.py có thể tổng hợp.
"""

from . import header_checker
from . import dir_checker
from . import robots_checker
from . import cms_checker
from . import port_checker
from . import tls_checker

__all__ = [
    "header_checker",
    "dir_checker",
    "robots_checker",
    "cms_checker",
    "port_checker",
    "tls_checker",
]
