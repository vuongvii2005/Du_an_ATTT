# -*- coding: utf-8 -*-
"""
Module: header_checker
Chức năng: Phân tích security header, cookie, CORS và rò rỉ thông tin server.
Cơ chế: Tận dụng response có sẵn; chỉ gửi một CORS probe khi response có dấu hiệu CORS.
"""

from http.cookies import CookieError, SimpleCookie
import re
import time
from urllib.parse import urlsplit

import requests


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
PROBE_ORIGIN = "https://cors-probe.invalid"


def _finding(category, title, severity, description, evidence, cause, recommendation,
             verification="verified", confidence="high"):
    return {
        "category": category,
        "title": title,
        "severity": severity,
        "verification": verification,
        "confidence": confidence,
        "description": description,
        "evidence": evidence,
        "cause": cause,
        "recommendation": recommendation,
    }


def _csp_directives(value):
    directives = {}
    for raw_directive in value.split(";"):
        parts = raw_directive.strip().lower().split()
        if parts:
            directives.setdefault(parts[0], parts[1:])
    return directives


def _csp_protects_frames(value):
    sources = _csp_directives(value).get("frame-ancestors")
    return bool(sources) and "*" not in sources


def _analyze_security_header_values(headers, response_url):
    findings = []
    csp = headers.get("Content-Security-Policy")
    if csp is not None:
        directives = _csp_directives(csp)
        script_sources = directives.get("script-src", directives.get("default-src"))
        if not csp.strip() or script_sources is None:
            findings.append(_finding(
                "Security Header", "CSP không bảo vệ nguồn script", "High",
                "CSP tồn tại nhưng không có chính sách hiệu lực để giới hạn nguồn JavaScript.",
                "Content-Security-Policy: {}".format(csp or "<rỗng>"),
                "Header CSP rỗng hoặc thiếu cả script-src và default-src.",
                "Khai báo default-src và script-src theo allowlist tối thiểu cần thiết.",
            ))
        else:
            has_nonce_or_hash = any(
                source.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
                for source in script_sources
            )
            if "'unsafe-inline'" in script_sources and not has_nonce_or_hash:
                findings.append(_finding(
                    "Security Header", "CSP cho phép inline script không an toàn", "Medium",
                    "Nguồn script cho phép 'unsafe-inline' mà không có nonce/hash giảm nhẹ.",
                    "Nguồn script hiệu lực: {}".format(" ".join(script_sources)),
                    "Chính sách CSP vẫn cho phép thực thi JavaScript inline.",
                    "Loại bỏ 'unsafe-inline' và dùng nonce hoặc hash cho script cần thiết.",
                ))
            if "'unsafe-eval'" in script_sources:
                findings.append(_finding(
                    "Security Header", "CSP cho phép unsafe-eval", "Medium",
                    "CSP cho phép các API biên dịch chuỗi thành JavaScript.",
                    "Nguồn script hiệu lực: {}".format(" ".join(script_sources)),
                    "script-src/default-src chứa 'unsafe-eval'.",
                    "Loại bỏ 'unsafe-eval' và thay thế các thư viện phụ thuộc vào eval.",
                ))
            if "*" in script_sources:
                findings.append(_finding(
                    "Security Header", "CSP cho phép script từ mọi nguồn", "High",
                    "Allowlist script chứa wildcard nên không giới hạn nguồn tải mã.",
                    "Nguồn script hiệu lực: {}".format(" ".join(script_sources)),
                    "script-src/default-src sử dụng wildcard '*'.",
                    "Thay wildcard bằng danh sách origin tin cậy và ưu tiên nonce/hash.",
                ))

    hsts = headers.get("Strict-Transport-Security")
    if hsts is not None and response_url.lower().startswith("https://"):
        match = re.search(
            r'(?:^|;)\s*max-age\s*=\s*(?:"(\d+)"|(\d+))\s*(?:;|$)', hsts, re.I
        )
        if not match:
            findings.append(_finding(
                "Security Header", "HSTS có max-age không hợp lệ", "High",
                "Trình duyệt không thể áp dụng HSTS nếu thiếu max-age hợp lệ.",
                "Strict-Transport-Security: {}".format(hsts or "<rỗng>"),
                "Directive max-age bị thiếu, âm hoặc không phải số nguyên.",
                "Đặt max-age hợp lệ; khuyến nghị tối thiểu 15552000 giây.",
            ))
        else:
            max_age = int(match.group(1) or match.group(2))
            if max_age == 0:
                findings.append(_finding(
                    "Security Header", "HSTS đang bị vô hiệu hóa", "High",
                    "max-age=0 yêu cầu trình duyệt xóa chính sách HSTS đã lưu.",
                    "Strict-Transport-Security: {}".format(hsts),
                    "Cấu hình HSTS đặt thời gian hiệu lực bằng 0.",
                    "Đặt max-age tối thiểu 15552000 và kiểm thử HTTPS trước khi tăng thời hạn.",
                ))
            elif max_age < 15552000:
                findings.append(_finding(
                    "Security Header", "Thời hạn HSTS quá ngắn", "Medium",
                    "HSTS có hiệu lực dưới 180 ngày nên bảo vệ downgrade bị giới hạn.",
                    "max-age={}.".format(max_age),
                    "Máy chủ cấu hình thời hạn HSTS thấp hơn mức khuyến nghị.",
                    "Tăng max-age lên ít nhất 15552000 giây sau khi xác minh toàn bộ HTTPS.",
                ))
            if max_age > 0 and not re.search(
                r"(?:^|;)\s*includesubdomains\s*(?:;|$)", hsts, re.I
            ):
                findings.append(_finding(
                    "Security Header", "HSTS chưa bao phủ subdomain", "Low",
                    "HSTS chỉ bảo vệ hostname hiện tại, không tự áp dụng cho subdomain.",
                    "Strict-Transport-Security không có includeSubDomains.",
                    "Directive includeSubDomains chưa được bật.",
                    "Bổ sung includeSubDomains sau khi xác minh mọi subdomain đều hỗ trợ HTTPS.",
                    verification="suspected", confidence="medium",
                ))

    xfo = headers.get("X-Frame-Options")
    if xfo is not None and xfo.strip().upper() not in {"DENY", "SAMEORIGIN"}:
        findings.append(_finding(
            "Security Header", "X-Frame-Options không hợp lệ", "Medium",
            "Giá trị này không tạo bảo vệ clickjacking đáng tin cậy trên trình duyệt hiện đại.",
            "X-Frame-Options: {}".format(xfo or "<rỗng>"),
            "Header dùng giá trị không chuẩn hoặc ALLOW-FROM đã lỗi thời.",
            "Dùng DENY/SAMEORIGIN hoặc CSP frame-ancestors phù hợp.",
        ))

    xcto = headers.get("X-Content-Type-Options")
    if xcto is not None and xcto.strip().lower() != "nosniff":
        findings.append(_finding(
            "Security Header", "X-Content-Type-Options không hiệu lực", "Low",
            "Chỉ giá trị nosniff mới ngăn trình duyệt suy đoán MIME type.",
            "X-Content-Type-Options: {}".format(xcto or "<rỗng>"),
            "Header được đặt với giá trị không được trình duyệt hỗ trợ.",
            "Đặt chính xác X-Content-Type-Options: nosniff.",
        ))

    referrer = headers.get("Referrer-Policy")
    if referrer is not None:
        recognized = {
            "no-referrer", "no-referrer-when-downgrade", "origin",
            "origin-when-cross-origin", "same-origin", "strict-origin",
            "strict-origin-when-cross-origin", "unsafe-url",
        }
        policies = [item.strip().lower() for item in referrer.split(",")]
        effective = next((item for item in reversed(policies) if item in recognized), None)
        if effective is None:
            findings.append(_finding(
                "Security Header", "Referrer-Policy không hợp lệ", "Low",
                "Không có policy được trình duyệt nhận diện trong header.",
                "Referrer-Policy: {}".format(referrer or "<rỗng>"),
                "Header chứa giá trị sai cú pháp hoặc không được hỗ trợ.",
                "Dùng strict-origin-when-cross-origin hoặc no-referrer.",
            ))
        elif effective == "unsafe-url":
            findings.append(_finding(
                "Security Header", "Referrer-Policy làm lộ toàn bộ URL", "Medium",
                "unsafe-url có thể gửi cả path và query sang website khác.",
                "Referrer-Policy hiệu lực: unsafe-url.",
                "Policy cho phép gửi referrer đầy đủ cả khi khác origin.",
                "Dùng strict-origin-when-cross-origin hoặc policy chặt hơn.",
            ))
        elif effective == "no-referrer-when-downgrade":
            findings.append(_finding(
                "Security Header", "Referrer-Policy còn rộng", "Low",
                "Policy có thể gửi URL đầy đủ giữa các origin HTTPS.",
                "Referrer-Policy hiệu lực: no-referrer-when-downgrade.",
                "Policy tương thích cũ không giới hạn referrer giữa các origin cùng mức bảo mật.",
                "Ưu tiên strict-origin-when-cross-origin hoặc no-referrer.",
            ))

    permissions = headers.get("Permissions-Policy")
    if permissions is not None:
        if not permissions.strip():
            findings.append(_finding(
                "Security Header", "Permissions-Policy rỗng", "Low",
                "Header rỗng không giới hạn quyền truy cập API trình duyệt.",
                "Permissions-Policy: <rỗng>.",
                "Máy chủ gửi header nhưng không khai báo directive.",
                "Khai báo allowlist tối thiểu cho camera, microphone, geolocation và API cần dùng.",
            ))
        elif re.search(r"(?:^|,)\s*[a-z0-9-]+\s*=\s*\*", permissions, re.I):
            findings.append(_finding(
                "Security Header", "Permissions-Policy cấp quyền cho mọi origin", "Medium",
                "Ít nhất một tính năng trình duyệt được cấp cho wildcard origin.",
                "Permissions-Policy: {}".format(permissions),
                "Allowlist của directive sử dụng '*'.",
                "Giới hạn tính năng về self, origin tin cậy hoặc vô hiệu hóa bằng ().",
            ))

    return findings


def _set_cookie_lines(response):
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    for method_name in ("getlist", "get_all"):
        method = getattr(raw_headers, method_name, None)
        if callable(method):
            values = method("Set-Cookie")
            if values:
                return list(values) if not isinstance(values, str) else [values]
    value = response.headers.get("Set-Cookie")
    return [value] if value else []


def _analyze_cookies(response):
    cookies = []
    findings = []
    hostname = (urlsplit(getattr(response, "url", "")).hostname or "").lower()
    is_https = getattr(response, "url", "").lower().startswith("https://")

    for header_value in _set_cookie_lines(response):
        parsed = SimpleCookie()
        try:
            parsed.load(header_value)
        except CookieError:
            parsed = SimpleCookie()
        if not parsed:
            findings.append(_finding(
                "Cookie Check", "Set-Cookie không thể phân tích", "Low",
                "Một Set-Cookie có cú pháp không hợp lệ nên trình duyệt có thể xử lý không nhất quán.",
                "Giá trị cookie đã được ẩn; parser không nhận diện được cookie.",
                "Set-Cookie sai cú pháp hoặc nhiều cookie bị gộp không đúng.",
                "Gửi từng Set-Cookie riêng và tuân thủ cú pháp RFC hiện hành.",
            ))
            continue

        for name, morsel in parsed.items():
            secure = bool(morsel["secure"])
            http_only = bool(morsel["httponly"])
            same_site = morsel["samesite"].strip()
            domain = morsel["domain"].strip()
            path = morsel["path"].strip()
            sensitive = any(token in name.lower() for token in ("session", "auth", "token", "jwt", "sid"))
            cookies.append({
                "name": name,
                "secure": secure,
                "http_only": http_only,
                "same_site": same_site or None,
                "domain": domain or None,
                "path": path or None,
            })

            if not secure:
                same_site_none = same_site.lower() == "none"
                findings.append(_finding(
                    "Cookie Check",
                    (
                        "Cookie '{}' dùng SameSite=None nhưng thiếu Secure".format(name)
                        if same_site_none
                        else "Cookie '{}' thiếu Secure".format(name)
                    ),
                    "Medium" if sensitive else "Low",
                    (
                        "SameSite=None yêu cầu Secure; trình duyệt hiện đại có thể từ chối cookie này."
                        if same_site_none
                        else "Cookie có thể bị gửi qua kết nối HTTP nếu trình duyệt truy cập URL không mã hóa."
                    ),
                    "Cookie '{}': không có Secure; response dùng {}; giá trị đã được ẩn.".format(
                        name, "HTTPS" if is_https else "HTTP"
                    ),
                    "Thuộc tính Secure chưa được cấu hình{}.".format(
                        " cùng SameSite=None" if same_site_none else ""
                    ),
                    "Thêm Secure và chỉ phát hành cookie qua HTTPS.",
                    verification="suspected", confidence="medium",
                ))
            if not http_only:
                findings.append(_finding(
                    "Cookie Check", "Cookie '{}' thiếu HttpOnly".format(name),
                    "Medium" if sensitive else "Low",
                    "JavaScript phía client có thể đọc cookie nếu xảy ra XSS.",
                    "Cookie '{}': không có HttpOnly; giá trị cookie đã được ẩn.".format(name),
                    "Thuộc tính HttpOnly chưa được cấu hình.",
                    "Thêm HttpOnly cho cookie không cần JavaScript truy cập.",
                    verification="suspected", confidence="medium",
                ))
            if not same_site:
                findings.append(_finding(
                    "Cookie Check", "Cookie '{}' thiếu SameSite".format(name), "Low",
                    "Cookie không khai báo rõ hành vi gửi trong request cross-site.",
                    "Cookie '{}': không có SameSite; giá trị cookie đã được ẩn.".format(name),
                    "Thuộc tính SameSite chưa được cấu hình.",
                    "Đặt SameSite=Lax hoặc Strict; chỉ dùng None khi thực sự cần và kèm Secure.",
                    verification="suspected", confidence="medium",
                ))
            elif same_site.lower() not in {"strict", "lax", "none"}:
                findings.append(_finding(
                    "Cookie Check", "Cookie '{}' có SameSite không hợp lệ".format(name), "Low",
                    "Trình duyệt có thể bỏ qua giá trị SameSite không chuẩn.",
                    "SameSite={}; giá trị cookie đã được ẩn.".format(same_site),
                    "Thuộc tính SameSite dùng giá trị ngoài Strict, Lax hoặc None.",
                    "Đặt SameSite=Strict, Lax hoặc None theo nhu cầu.",
                ))
            if domain:
                normalized_domain = domain.lstrip(".").lower()
                if not hostname or not (
                    hostname == normalized_domain or hostname.endswith("." + normalized_domain)
                ):
                    findings.append(_finding(
                        "Cookie Check", "Cookie '{}' có Domain không phù hợp".format(name), "Low",
                        "Domain của cookie không khớp hostname response và có thể bị trình duyệt từ chối.",
                        "Domain={}; hostname={}.".format(domain, hostname or "không xác định"),
                        "Ứng dụng cấu hình sai phạm vi Domain của cookie.",
                        "Bỏ Domain để dùng host-only cookie hoặc đặt domain cha hợp lệ.",
                    ))
                else:
                    findings.append(_finding(
                        "Cookie Check", "Cookie '{}' mở rộng phạm vi Domain".format(name), "Low",
                        "Cookie có Domain attribute nên có thể được chia sẻ cho các subdomain phù hợp.",
                        "Domain={}; hostname={}.".format(domain, hostname),
                        "Cookie không được giới hạn ở host phát hành.",
                        "Bỏ Domain nếu cookie chỉ cần dùng trên hostname hiện tại.",
                        verification="suspected", confidence="medium",
                    ))
            if path and not path.startswith("/"):
                findings.append(_finding(
                    "Cookie Check", "Cookie '{}' có Path không hợp lệ".format(name), "Low",
                    "Path không bắt đầu bằng '/' có thể bị trình duyệt thay bằng path mặc định.",
                    "Path={}; giá trị cookie đã được ẩn.".format(path),
                    "Thuộc tính Path không đúng cú pháp.",
                    "Đặt Path bắt đầu bằng '/', thường là '/' hoặc phạm vi ứng dụng cần thiết.",
                ))

    return cookies, findings


def _probe_timeout(deadline):
    if deadline is None:
        return 5
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Đã hết tổng thời gian quét trước khi kiểm tra CORS.")
    return min(5, remaining)


def _analyze_cors(response, session=None, target_url=None, deadline=None):
    headers = response.headers
    allow_origin = headers.get("Access-Control-Allow-Origin", "").strip()
    allow_credentials = headers.get("Access-Control-Allow-Credentials", "").strip()
    vary = headers.get("Vary", "")
    cors = {
        "allow_origin": allow_origin or None,
        "allow_credentials": allow_credentials or None,
        "probe_status": "skipped",
        "origin_reflected": None,
    }
    findings = []

    if allow_origin == "*":
        severity = "Medium" if allow_credentials == "true" else "Low"
        findings.append(_finding(
            "CORS Check", "CORS cho phép mọi origin", severity,
            "Access-Control-Allow-Origin dùng wildcard; mức ảnh hưởng phụ thuộc dữ liệu endpoint.",
            "Allow-Origin=*; Allow-Credentials={}.".format(allow_credentials or "không có"),
            "CORS được cấu hình với wildcard origin.",
            "Dùng allowlist origin cụ thể cho endpoint chứa dữ liệu không công khai.",
            verification="suspected", confidence="medium",
        ))
    elif allow_origin.lower() == "null":
        findings.append(_finding(
            "CORS Check", "CORS tin cậy origin null", "Medium",
            "Origin null có thể xuất hiện từ sandboxed iframe hoặc tài liệu cục bộ.",
            "Access-Control-Allow-Origin: null.",
            "Máy chủ cho phép origin đặc biệt null.",
            "Không allowlist null; kiểm tra origin theo danh sách chính xác.",
            verification="suspected", confidence="medium",
        ))
    elif "," in allow_origin:
        findings.append(_finding(
            "CORS Check", "Access-Control-Allow-Origin không hợp lệ", "Low",
            "Header này không hỗ trợ danh sách origin phân cách bằng dấu phẩy.",
            "Access-Control-Allow-Origin: {}".format(allow_origin),
            "Nhiều origin được ghép vào một giá trị header.",
            "Trả về tối đa một origin đã xác thực cho mỗi request và thêm Vary: Origin.",
        ))

    if allow_credentials and allow_credentials != "true":
        findings.append(_finding(
            "CORS Check", "Access-Control-Allow-Credentials không hợp lệ", "Low",
            "Trình duyệt chỉ nhận giá trị phân biệt hoa thường 'true'.",
            "Access-Control-Allow-Credentials: {}".format(allow_credentials),
            "Header dùng giá trị không được CORS hỗ trợ.",
            "Chỉ gửi chính xác 'true' khi endpoint cần credential cross-origin; nếu không hãy bỏ header.",
        ))

    vary_origin = "origin" in {item.strip().lower() for item in vary.split(",")}
    should_probe = bool(allow_origin and allow_origin != "*") or vary_origin
    if not should_probe or session is None or not target_url:
        return cors, findings, None

    try:
        probe = session.get(
            target_url,
            headers={"Origin": PROBE_ORIGIN},
            timeout=_probe_timeout(deadline),
            allow_redirects=False,
        )
        probe_origin = probe.headers.get("Access-Control-Allow-Origin", "").strip()
        probe_credentials = probe.headers.get("Access-Control-Allow-Credentials", "").strip()
        cors.update({
            "probe_status": "success",
            "origin_reflected": False,
            "probe_status_code": getattr(probe, "status_code", None),
        })
        if 200 <= getattr(probe, "status_code", 0) < 300 and probe_origin == PROBE_ORIGIN:
            cors["origin_reflected"] = True
            credentialed = probe_credentials == "true"
            findings.append(_finding(
                "CORS Check", "CORS phản chiếu origin không tin cậy",
                "High" if credentialed else "Medium",
                "Server phản chiếu Origin do scanner cung cấp{}.".format(
                    " và cho phép credentials" if credentialed else ""
                ),
                "Origin gửi: {}; Allow-Origin trả về: {}; Allow-Credentials: {}.".format(
                    PROBE_ORIGIN, probe_origin, probe_credentials or "không có"
                ),
                "Server trả lại Origin mà không đối chiếu allowlist chặt chẽ.",
                "Dùng allowlist origin chính xác, thêm Vary: Origin và chỉ bật credentials khi cần.",
            ))
        return cors, findings, None
    except (requests.RequestException, TimeoutError) as exc:
        cors["probe_status"] = "error"
        return cors, findings, "Không thể hoàn tất CORS probe: {}".format(str(exc)[:240])


def run(response, session=None, target_url=None, deadline=None):
    """
    Phân tích header từ 1 response object (requests.Response) của trang chủ.
    Trả về kết quả security header, cookie, CORS và raw header đã che cookie.
    """
    started = time.monotonic()
    result = {
        "module": "header_checker",
        "status": "success",
        "error": None,
        "duration_sec": 0,
        "missing_headers": [],
        "info_leak": [],
        "findings": [],
        "cookies": [],
        "cors": {},
        "raw_headers": dict(response.headers),
    }

    for key in list(result["raw_headers"]):
        if key.lower() == "set-cookie":
            result["raw_headers"][key] = "[đã ẩn giá trị; thuộc tính cookie được phân tích riêng]"

    headers = response.headers  # requests dùng CaseInsensitiveDict -> tra cứu không phân biệt hoa/thường

    # 1. Kiểm tra các security header đang bị thiếu
    for header_name, meta in SECURITY_HEADERS.items():
        if header_name == "Strict-Transport-Security" and not getattr(
            response, "url", ""
        ).lower().startswith("https://"):
            continue
        if header_name == "X-Frame-Options" and _csp_protects_frames(
            headers.get("Content-Security-Policy", "")
        ):
            continue
        if header_name not in headers:
            result["missing_headers"].append(
                {
                    "header": header_name,
                    "severity": meta["severity"],
                    "verification": "verified",
                    "confidence": "high",
                    "description": meta["description"],
                }
            )

    result["findings"].extend(
        _analyze_security_header_values(headers, getattr(response, "url", ""))
    )
    result["cookies"], cookie_findings = _analyze_cookies(response)
    result["findings"].extend(cookie_findings)
    result["cors"], cors_findings, cors_error = _analyze_cors(
        response, session=session, target_url=target_url, deadline=deadline
    )
    result["findings"].extend(cors_findings)
    if cors_error:
        result["status"] = "error"
        result["error"] = cors_error

    # 2. Kiểm tra rò rỉ thông tin qua các header đặc trưng
    for header_name in INFO_LEAK_HEADERS:
        if header_name in headers:
            result["info_leak"].append(
                {
                    "header": header_name,
                    "value": headers[header_name],
                    "severity": "Info",
                    "verification": "verified",
                    "confidence": "high",
                    "description": f"Server đang tiết lộ thông tin công nghệ/phiên bản qua header '{header_name}'.",
                }
            )

    result["duration_sec"] = round(time.monotonic() - started, 3)
    return result
