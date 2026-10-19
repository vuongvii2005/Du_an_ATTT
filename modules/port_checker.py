# -*- coding: utf-8 -*-
"""
Module: port_checker
Chức năng: Quét nhanh một số cổng (port) TCP phổ biến để xác định dịch vụ đang mở.
Cơ chế: Dùng socket.connect_ex - chỉ thực hiện TCP handshake cơ bản (SYN/ACK),
KHÔNG gửi payload khai thác, KHÔNG xâm nhập dịch vụ đang chạy trên cổng đó.

CẢNH BÁO ĐẠO ĐỨC & PHÁP LÝ:
Chỉ sử dụng module này trên hệ thống bạn sở hữu hoặc đã được cấp phép rõ ràng
để kiểm tra (authorized penetration testing / bug bounty trong phạm vi cho phép).
Quét cổng trên hệ thống của người khác mà không được phép có thể vi phạm pháp luật.
"""

import ipaddress
import socket
import time

# Danh sách cổng phổ biến cần kiểm tra (rút gọn, KHÔNG quét toàn bộ 65535 cổng)
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

SOCKET_TIMEOUT = 0.5


def run(hostname, resolved_ip=None, deadline=None):
    """
    hostname: tên domain hoặc địa chỉ IP (KHÔNG kèm scheme http/https)
    """
    started = time.monotonic()
    result = {
        "module": "port_checker",
        "status": "success",
        "resolved_ip": None,
        "open_ports": [],
        "error": None,
        "duration_sec": 0,
    }

    if resolved_ip is None:
        try:
            resolved_ip = socket.gethostbyname(hostname)
        except socket.gaierror:
            result.update(status="error", error=f"Không thể phân giải hostname: {hostname}")
            return result
    result["resolved_ip"] = resolved_ip
    ip_version = ipaddress.ip_address(resolved_ip).version
    family = socket.AF_INET6 if ip_version == 6 else socket.AF_INET

    for port, service in COMMON_PORTS.items():
        if deadline is not None and time.monotonic() >= deadline:
            result.update(status="error", error="Quét cổng dừng sớm vì hết tổng thời gian quét.")
            break
        sock = socket.socket(family, socket.SOCK_STREAM)
        timeout = SOCKET_TIMEOUT
        if deadline is not None:
            timeout = min(timeout, max(0.05, deadline - time.monotonic()))
        sock.settimeout(timeout)
        try:
            destination = (resolved_ip, port, 0, 0) if family == socket.AF_INET6 else (resolved_ip, port)
            code = sock.connect_ex(destination)
            if code == 0:
                # A TCP handshake identifies exposure, not an exploitable service.
                result["open_ports"].append(
                    {
                        "port": port,
                        "service": service,
                        "severity": "Info",
                        "verification": "suspected",
                        "confidence": "low",
                        "description": f"Cổng {port} ({service}) đang mở và có thể kết nối được.",
                    }
                )
        except socket.timeout:
            pass
        except socket.error:
            pass
        finally:
            sock.close()

    result["duration_sec"] = round(time.monotonic() - started, 3)
    return result
