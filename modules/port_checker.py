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

import socket

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

SOCKET_TIMEOUT = 1.5  # giây - giữ ngắn để tránh việc quét bị treo quá lâu


def run(hostname):
    """
    hostname: tên domain hoặc địa chỉ IP (KHÔNG kèm scheme http/https)
    """
    result = {
        "module": "port_checker",
        "resolved_ip": None,
        "open_ports": [],
        "error": None,
    }

    try:
        ip = socket.gethostbyname(hostname)
        result["resolved_ip"] = ip
    except socket.gaierror:
        result["error"] = f"Không thể phân giải hostname: {hostname}"
        return result

    for port, service in COMMON_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)
        try:
            code = sock.connect_ex((ip, port))
            if code == 0:
                # Các dịch vụ quản trị/nhạy cảm nếu mở public thì mức rủi ro cao hơn
                severity = "Medium" if port in (21, 23, 3306, 3389) else "Info"
                result["open_ports"].append(
                    {
                        "port": port,
                        "service": service,
                        "severity": severity,
                        "description": f"Cổng {port} ({service}) đang mở và có thể kết nối được.",
                    }
                )
        except socket.timeout:
            pass
        except socket.error:
            pass
        finally:
            sock.close()

    return result
