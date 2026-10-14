"""Bounded TLS/SSL checks for an already validated scan target."""

from datetime import datetime, timezone
import socket
import ssl
import time
from urllib.parse import urljoin, urlsplit

import requests

from target_guard import TargetGuardError


TLS_TIMEOUT_SECONDS = 4.0
REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5")


def _base_result():
    return {
        "module": "tls_checker",
        "status": "success",
        "error": None,
        "duration_sec": 0.0,
        "https_supported": None,
        "tls_port": None,
        "certificate": {},
        "protocol": None,
        "cipher": {},
        "http_redirect": {
            "status": "skipped",
            "redirects_to_https": None,
            "status_code": None,
            "location": None,
            "reason": "Không đủ dữ liệu để kiểm tra.",
        },
        "findings": [],
    }


def _finding(title, severity, description, evidence, cause, recommendation,
             verification="verified", confidence="high"):
    return {
        "title": title,
        "severity": severity,
        "verification": verification,
        "confidence": confidence,
        "description": description,
        "evidence": evidence,
        "cause": cause,
        "recommendation": recommendation,
    }


def _remaining_timeout(deadline):
    if deadline is None:
        return TLS_TIMEOUT_SECONDS
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Đã hết tổng thời gian quét trước khi kiểm tra TLS.")
    return min(TLS_TIMEOUT_SECONDS, remaining)


def _format_distinguished_name(value):
    parts = []
    for rdn in value or ():
        for key, item in rdn:
            parts.append("{}={}".format(key, item))
    return ", ".join(parts) or None


def _certificate_time(value):
    if not value:
        return None
    try:
        timestamp = ssl.cert_time_to_seconds(value)
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except (OverflowError, ValueError):
        return None


def _certificate_details(cert, now):
    not_before = _certificate_time(cert.get("notBefore"))
    not_after = _certificate_time(cert.get("notAfter"))
    days_remaining = None
    if not_after is not None:
        days_remaining = int((not_after - now).total_seconds() // 86400)

    return {
        "valid": True,
        "hostname_matches": True,
        "subject": _format_distinguished_name(cert.get("subject")),
        "issuer": _format_distinguished_name(cert.get("issuer")),
        "serial_number": cert.get("serialNumber"),
        "not_before": not_before.isoformat() if not_before else None,
        "not_after": not_after.isoformat() if not_after else None,
        "days_remaining": days_remaining,
    }


def _add_certificate_findings(result):
    certificate = result["certificate"]
    days_remaining = certificate.get("days_remaining")
    expires_at = certificate.get("not_after") or "không xác định"

    if days_remaining is None:
        result["findings"].append(_finding(
            "Không đủ dữ liệu về thời hạn chứng chỉ",
            "Info",
            "Kết nối TLS thành công nhưng chứng chỉ không cung cấp ngày hết hạn có thể phân tích.",
            "notAfter không có hoặc không đọc được.",
            "Máy chủ hoặc thư viện TLS không cung cấp đầy đủ trường chứng chỉ.",
            "Kiểm tra lại chuỗi chứng chỉ bằng công cụ quản trị TLS của máy chủ.",
            verification="suspected",
            confidence="low",
        ))
    elif days_remaining < 0:
        result["findings"].append(_finding(
            "Chứng chỉ TLS đã hết hạn",
            "High",
            "Chứng chỉ đã qua ngày hết hạn và không còn bảo đảm xác thực máy chủ.",
            "Hết hạn lúc {}; quá hạn {} ngày.".format(expires_at, abs(days_remaining)),
            "Chứng chỉ chưa được gia hạn hoặc triển khai chứng chỉ mới không thành công.",
            "Gia hạn chứng chỉ, cài đặt đầy đủ chuỗi chứng chỉ và tự động hóa cảnh báo gia hạn.",
        ))
    elif days_remaining <= 30:
        result["findings"].append(_finding(
            "Chứng chỉ TLS sắp hết hạn",
            "Medium",
            "Chứng chỉ sẽ hết hạn trong vòng 30 ngày.",
            "Hết hạn lúc {}; còn khoảng {} ngày.".format(expires_at, days_remaining),
            "Thời hạn chứng chỉ còn ngắn và có nguy cơ gián đoạn nếu không gia hạn kịp thời.",
            "Gia hạn và triển khai chứng chỉ mới trước ngày hết hạn; cấu hình cảnh báo tự động.",
        ))
    elif days_remaining <= 90:
        result["findings"].append(_finding(
            "Chứng chỉ TLS gần đến kỳ gia hạn",
            "Low",
            "Chứng chỉ còn không quá 90 ngày trước khi hết hạn.",
            "Hết hạn lúc {}; còn khoảng {} ngày.".format(expires_at, days_remaining),
            "Chứng chỉ đang tiến gần chu kỳ gia hạn.",
            "Theo dõi lịch gia hạn và kiểm thử quy trình triển khai chứng chỉ mới.",
        ))


def _add_negotiation_findings(result):
    protocol = result.get("protocol")
    cipher = result.get("cipher") or {}
    cipher_name = cipher.get("name") or ""
    cipher_bits = cipher.get("bits")

    if protocol in WEAK_PROTOCOLS:
        result["findings"].append(_finding(
            "Phiên TLS thương lượng giao thức yếu",
            "High",
            "Kết nối kiểm tra đã thương lượng một phiên bản SSL/TLS lỗi thời.",
            "Giao thức được thương lượng: {}.".format(protocol),
            "Máy chủ vẫn cho phép hoặc ưu tiên phiên bản giao thức cũ.",
            "Tắt SSLv2, SSLv3, TLS 1.0 và TLS 1.1; ưu tiên TLS 1.2 hoặc TLS 1.3.",
        ))

    weak_marker = next(
        (marker for marker in WEAK_CIPHER_MARKERS if marker in cipher_name.upper()),
        None,
    )
    weak_bits = isinstance(cipher_bits, int) and cipher_bits < 128
    if weak_marker or weak_bits:
        result["findings"].append(_finding(
            "Phiên TLS thương lượng cipher yếu",
            "High",
            "Cipher suite của phiên kiểm tra sử dụng thuật toán hoặc độ dài khóa yếu.",
            "Cipher: {}; số bit: {}.".format(cipher_name or "không xác định", cipher_bits),
            "Cấu hình TLS còn cho phép cipher suite lỗi thời hoặc có mức bảo vệ thấp.",
            "Loại bỏ RC4, 3DES, DES, NULL, EXPORT, MD5 và cipher dưới 128 bit; ưu tiên AEAD hiện đại.",
        ))


def _redirect_result(status="skipped", redirects_to_https=None, status_code=None,
                     location=None, reason=None):
    return {
        "status": status,
        "redirects_to_https": redirects_to_https,
        "status_code": status_code,
        "location": location,
        "reason": reason,
    }


def _check_http_redirect(target, session, homepage_response, deadline):
    if target.scheme == "http":
        if homepage_response is None:
            return _redirect_result(reason="Không có response HTTP ban đầu để đối chiếu.")
        return _redirect_result(
            status="success",
            redirects_to_https=False,
            status_code=getattr(homepage_response, "status_code", None),
            location=getattr(homepage_response, "url", None),
            reason="URL hiệu lực sau redirect vẫn sử dụng HTTP.",
        )

    if target.port != 443:
        return _redirect_result(
            reason="Bỏ qua vì không suy đoán ánh xạ HTTP cho cổng TLS tùy chỉnh.",
        )
    if session is None:
        return _redirect_result(reason="Không có HTTP session đã được bảo vệ để kiểm tra.")

    http_url = "http://{}".format(target.host_header)
    response = session.get(
        http_url,
        timeout=_remaining_timeout(deadline),
        allow_redirects=False,
    )
    location = response.headers.get("Location")
    redirects_to_https = False
    reason = "HTTP không trả về redirect sang HTTPS cùng mục tiêu."

    if response.status_code in REDIRECT_STATUS_CODES and location:
        redirect_url = urljoin(http_url, location)
        parsed = urlsplit(redirect_url)
        redirect_port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        redirects_to_https = (
            parsed.scheme.lower() == "https"
            and (parsed.hostname or "").lower() == target.hostname.lower()
            and redirect_port == target.port
        )
        if redirects_to_https:
            reason = "HTTP redirect sang HTTPS cùng hostname và cổng TLS đã xác thực."
        else:
            reason = "Redirect không trỏ tới HTTPS cùng mục tiêu; không tự động theo redirect này."

    return _redirect_result(
        status="success",
        redirects_to_https=redirects_to_https,
        status_code=response.status_code,
        location=location,
        reason=reason,
    )


def _add_redirect_finding(result):
    redirect = result["http_redirect"]
    if result.get("https_supported") is not True:
        return
    if redirect.get("status") != "success" or redirect.get("redirects_to_https") is not False:
        return

    result["findings"].append(_finding(
        "HTTP không chuyển hướng an toàn sang HTTPS",
        "Medium",
        "Máy chủ hỗ trợ HTTPS nhưng yêu cầu HTTP kiểm tra không được chuyển hướng sang HTTPS cùng mục tiêu.",
        "HTTP status: {}; Location: {}.".format(
            redirect.get("status_code"), redirect.get("location") or "không có"
        ),
        "Cấu hình máy chủ chưa buộc người dùng HTTP chuyển sang kênh HTTPS.",
        "Cấu hình redirect vĩnh viễn từ HTTP sang HTTPS trên cùng hostname; cân nhắc HSTS sau khi xác minh.",
    ))


def _verification_finding(exc):
    verify_code = getattr(exc, "verify_code", None)
    message = str(exc)
    lowered = message.lower()

    if verify_code == 10 or "expired" in lowered or "hết hạn" in lowered:
        title = "Chứng chỉ TLS đã hết hạn"
        description = "TLS handshake xác định chứng chỉ của máy chủ đã hết hạn."
        cause = "Chứng chỉ chưa được gia hạn hoặc máy chủ vẫn phục vụ chứng chỉ cũ."
        recommendation = "Gia hạn chứng chỉ và triển khai đầy đủ chuỗi chứng chỉ mới."
    elif verify_code == 62 or "hostname" in lowered or "not valid for" in lowered:
        title = "Hostname không khớp chứng chỉ TLS"
        description = "Chứng chỉ máy chủ không hợp lệ cho hostname đang được quét."
        cause = "SAN/CN của chứng chỉ không chứa hostname mục tiêu hoặc cấu hình virtual host sai."
        recommendation = "Cấp và cấu hình chứng chỉ có SAN phù hợp chính xác với hostname mục tiêu."
    else:
        title = "Chứng chỉ TLS không hợp lệ"
        description = "Không thể xác thực chứng chỉ TLS bằng kho tin cậy của hệ thống."
        cause = "Chuỗi chứng chỉ có thể không đầy đủ, tự ký, bị thu hồi hoặc do CA không được tin cậy."
        recommendation = "Cài chứng chỉ từ CA tin cậy và phục vụ đầy đủ intermediate certificate."

    return _finding(
        title,
        "High",
        description,
        "Mã xác thực: {}; lỗi: {}.".format(verify_code, message[:240]),
        cause,
        recommendation,
    )


def run(target, session=None, homepage_response=None, deadline=None, now=None):
    """Inspect one negotiated TLS session without enumerating protocols or ciphers."""
    started = time.monotonic()
    result = _base_result()
    result["tls_port"] = target.port if target.scheme == "https" else 443
    check_time = now or datetime.now(timezone.utc)

    try:
        timeout = _remaining_timeout(deadline)
        context = ssl.create_default_context()
        with socket.create_connection(
            (target.selected_ip, result["tls_port"]), timeout=timeout
        ) as raw_socket:
            with context.wrap_socket(
                raw_socket, server_hostname=target.hostname
            ) as tls_socket:
                certificate = tls_socket.getpeercert()
                cipher = tls_socket.cipher() or (None, None, None)
                result["https_supported"] = True
                result["certificate"] = _certificate_details(certificate, check_time)
                result["protocol"] = tls_socket.version()
                result["cipher"] = {
                    "name": cipher[0],
                    "protocol": cipher[1],
                    "bits": cipher[2],
                }
                _add_certificate_findings(result)
                _add_negotiation_findings(result)
    except ssl.SSLCertVerificationError as exc:
        result["https_supported"] = True
        result["certificate"] = {
            "valid": False,
            "hostname_matches": False if (
                getattr(exc, "verify_code", None) == 62
                or "hostname" in str(exc).lower()
                or "not valid for" in str(exc).lower()
            ) else None,
            "validation_error": str(exc)[:240],
        }
        result["findings"].append(_verification_finding(exc))
    except ConnectionRefusedError:
        result["https_supported"] = False
        result["findings"].append(_finding(
            "Website không hỗ trợ HTTPS trên cổng kiểm tra",
            "High",
            "Kết nối TCP tới cổng HTTPS bị từ chối.",
            "{}:{} từ chối kết nối.".format(target.selected_ip, result["tls_port"]),
            "Dịch vụ HTTPS chưa chạy, không lắng nghe trên cổng này hoặc bị chặn chủ động.",
            "Bật HTTPS với chứng chỉ hợp lệ và cấu hình chuyển hướng HTTP sang HTTPS.",
        ))
    except (socket.timeout, TimeoutError) as exc:
        result["status"] = "error"
        result["error"] = "Kiểm tra TLS hết thời gian: {}".format(str(exc) or "timeout")
    except ssl.SSLError as exc:
        result["status"] = "error"
        result["error"] = "TLS handshake thất bại: {}".format(str(exc)[:240])
        result["findings"].append(_finding(
            "TLS handshake thất bại",
            "Medium",
            "Không thể hoàn tất TLS handshake nên chưa thể xác nhận chứng chỉ và cấu hình phiên.",
            str(exc)[:240] or "Không có chi tiết từ thư viện TLS.",
            "Máy chủ có thể dùng cấu hình TLS không tương thích hoặc đóng kết nối trong handshake.",
            "Kiểm tra log máy chủ, chuỗi chứng chỉ, giao thức và cipher; quét lại sau khi khắc phục.",
            verification="suspected",
            confidence="medium",
        ))
    except OSError as exc:
        result["status"] = "error"
        result["error"] = "Không thể kết nối dịch vụ TLS: {}".format(str(exc)[:240])

    try:
        result["http_redirect"] = _check_http_redirect(
            target, session, homepage_response, deadline
        )
        _add_redirect_finding(result)
    except (requests.RequestException, TargetGuardError, TimeoutError, ValueError) as exc:
        result["http_redirect"] = _redirect_result(
            status="error",
            reason="Không thể kiểm tra redirect HTTP: {}".format(str(exc)[:240]),
        )
        if result["status"] == "success":
            result["status"] = "error"
            result["error"] = result["http_redirect"]["reason"]

    result["duration_sec"] = round(time.monotonic() - started, 3)
    return result
