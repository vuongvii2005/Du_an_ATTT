import socket

import report


PUBLIC_IP = "93.184.216.34"


def resolver_for(*addresses):
    def resolve(_hostname, port, _family, _socktype):
        answers = []
        for address in addresses:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            sockaddr = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
            answers.append((family, socket.SOCK_STREAM, 6, "", sockaddr))
        return answers

    return resolve


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None, url="https://example.com/"):
        self.status_code = status_code
        self.headers = headers or {}
        self.url = url
        self.encoding = "utf-8"
        self._content = text.encode("utf-8")
        self._content_consumed = True
        self.history = []
        self.closed = False

    @property
    def content(self):
        return self._content

    @property
    def text(self):
        return self._content.decode(self.encoding)

    def iter_content(self, chunk_size=65536):
        for offset in range(0, len(self._content), chunk_size):
            yield self._content[offset : offset + chunk_size]

    def close(self):
        self.closed = True


def complete_report(target="https://example.com"):
    modules = {
        name: {"module": name, "status": "success", "error": None, "duration_sec": 0}
        for name in (
            "header_checker",
            "dir_checker",
            "robots_checker",
            "cms_checker",
            "port_checker",
            "tls_checker",
        )
    }
    modules["header_checker"]["raw_headers"] = {}
    modules["robots_checker"].update(exists=False, disallowed_paths=[])
    modules["port_checker"].update(resolved_ip=PUBLIC_IP, open_ports=[])
    modules["tls_checker"].update(
        https_supported=True,
        certificate={"valid": True, "hostname_matches": True},
        protocol="TLSv1.3",
        cipher={"name": "TLS_AES_256_GCM_SHA384", "bits": 256},
        http_redirect={"status": "success", "redirects_to_https": True},
        findings=[],
    )
    return report.generate_report(target, modules, scan_duration=0.01)


def sample_module_results(extra_findings=None, failed_modules=()):
    """Kết quả module giả có nhiều loại finding, dùng cho test báo cáo/giao diện."""
    modules = {
        name: {"module": name, "status": "success", "error": None, "duration_sec": 0}
        for name in (
            "header_checker",
            "dir_checker",
            "robots_checker",
            "cms_checker",
            "port_checker",
            "tls_checker",
        )
    }
    modules["header_checker"].update(
        raw_headers={},
        missing_headers=[
            {"header": "Content-Security-Policy", "severity": "High", "verification": "verified",
             "confidence": "high", "description": "Thiếu CSP"},
            {"header": "Strict-Transport-Security", "severity": "Medium", "verification": "verified",
             "confidence": "high", "description": "Thiếu HSTS"},
            {"header": "X-Frame-Options", "severity": "Medium", "verification": "verified",
             "confidence": "high", "description": "Thiếu XFO"},
            {"header": "Referrer-Policy", "severity": "Low", "verification": "verified",
             "confidence": "high", "description": "Thiếu Referrer-Policy"},
        ],
        info_leak=[
            {"header": "Server", "value": "nginx/1.18", "severity": "Info", "verification": "verified",
             "confidence": "high", "description": "Lộ server"},
        ],
        findings=list(extra_findings or []),
    )
    modules["dir_checker"]["findings"] = [
        {"path": ".env", "url": "https://example.com/.env", "status_code": 200, "severity": "High",
         "verification": "verified", "confidence": "high", "description": "Lộ .env"},
        {"path": "admin/", "url": "https://example.com/admin/", "status_code": 200, "severity": "Info",
         "verification": "suspected", "confidence": "medium", "description": "Có trang admin"},
    ]
    modules["robots_checker"].update(exists=False, disallowed_paths=[])
    modules["port_checker"].update(
        resolved_ip=PUBLIC_IP,
        open_ports=[{"port": 3306, "service": "MySQL", "severity": "High", "verification": "verified",
                     "confidence": "high", "description": "MySQL mở"}],
    )
    modules["tls_checker"].update(
        https_supported=True,
        certificate={"valid": True, "hostname_matches": True},
        protocol="TLSv1.3",
        cipher={"name": "TLS_AES_256_GCM_SHA384", "bits": 256},
        http_redirect={"status": "success", "redirects_to_https": True},
        findings=[],
    )
    for name in failed_modules:
        modules[name].update(status="error", error="lỗi giả lập")
    return modules


def sample_report(target="https://example.com", **kwargs):
    return report.generate_report(target, sample_module_results(**kwargs), scan_duration=0.01)
