# -*- coding: utf-8 -*-
"""Từ điển ngắn gọn cho 16 tiêu chí chính và các quan sát tham khảo.

Một tiêu chí có thể nhận nhiều biến thể finding (ví dụ CSP thiếu, CSP dùng
wildcard hoặc unsafe-eval). ``lookup_key`` gom các biến thể đó về cùng một khóa
để báo cáo không giải thích và tính điểm lặp lại.
"""

import re


MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
OWASP_HEADERS = (
    "OWASP Secure Headers Project",
    "https://owasp.org/www-project-secure-headers/",
)
OWASP_TLS = (
    "OWASP: Transport Layer Security",
    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
)


def _entry(title, severity, what, why, fix, learn_more=()):
    return {
        "title": title,
        "severity": severity,
        "what": what,
        "why": why,
        "fix": fix,
        "learn_more": [{"label": label, "url": url} for label, url in learn_more],
    }


FALLBACK = _entry(
    "Phát hiện chưa có hướng dẫn riêng",
    "Info",
    "Công cụ ghi nhận một điểm đáng chú ý nhưng chưa có hướng dẫn riêng cho loại này.",
    "Ảnh hưởng phụ thuộc vào bằng chứng và ngữ cảnh của website; đây chưa tự động là một lỗ hổng.",
    "Đọc bằng chứng và khuyến nghị kỹ thuật trong finding, xác minh thủ công rồi quét lại sau khi sửa.",
)


# 16 tiêu chí chính, theo đúng thứ tự dùng trên trang từ điển.
MAIN_ENTRIES = {
    # A. HTTP Security Headers
    "csp_missing": _entry(
        "Content-Security-Policy (CSP) thiếu hoặc yếu",
        "Low",
        "CSP giới hạn nguồn script và tài nguyên mà trình duyệt được phép tải. Tiêu chí này gồm cả CSP bị thiếu và CSP có cấu hình quá rộng.",
        "CSP yếu không tự tạo ra XSS, nhưng làm mất một lớp giảm thiểu quan trọng nếu nội dung độc hại bị chèn vào trang.",
        "Bắt đầu với Content-Security-Policy-Report-Only, sau đó dùng allowlist tối thiểu; tránh '*' và 'unsafe-eval', dùng nonce/hash thay cho inline script khi có thể.",
        [("MDN: Content-Security-Policy", MDN + "Content-Security-Policy"), OWASP_HEADERS],
    ),
    "xfo_missing": _entry(
        "Thiếu bảo vệ chống clickjacking",
        "Low",
        "X-Frame-Options hoặc directive CSP frame-ancestors kiểm soát website nào được nhúng trang vào iframe.",
        "Nếu trang có thao tác nhạy cảm và bị website lạ nhúng, người dùng có thể bị đánh lừa bấm vào giao diện thật mà không nhận ra.",
        "Đặt X-Frame-Options: DENY/SAMEORIGIN hoặc CSP frame-ancestors phù hợp. Chỉ cần một cơ chế đúng và tương thích với nhu cầu nhúng trang.",
        [("MDN: X-Frame-Options", MDN + "X-Frame-Options"), OWASP_HEADERS],
    ),
    "xcto_missing": _entry(
        "X-Content-Type-Options thiếu hoặc sai",
        "Low",
        "Giá trị nosniff yêu cầu trình duyệt tôn trọng MIME type do máy chủ khai báo thay vì tự suy đoán.",
        "Trong một số ngữ cảnh, suy đoán MIME type có thể khiến nội dung tải lên bị xử lý như script hoặc stylesheet.",
        "Gửi chính xác header X-Content-Type-Options: nosniff và khai báo Content-Type đúng cho mọi tài nguyên.",
        [("MDN: X-Content-Type-Options", MDN + "X-Content-Type-Options")],
    ),
    "hsts_missing": _entry(
        "HSTS thiếu hoặc cấu hình yếu",
        "Low",
        "HSTS yêu cầu trình duyệt chỉ dùng HTTPS trong một khoảng thời gian. Công cụ chỉ đánh giá header này khi response thực sự dùng HTTPS.",
        "Thiếu hoặc vô hiệu hóa HSTS có thể để lại cơ hội hạ cấp kết nối ở lần truy cập đầu, nhưng không đồng nghĩa website đã bị khai thác.",
        "Sau khi toàn bộ website chạy ổn định trên HTTPS, đặt Strict-Transport-Security với max-age ít nhất 15552000; thêm includeSubDomains chỉ khi mọi subdomain đều hỗ trợ HTTPS.",
        [("MDN: Strict-Transport-Security", MDN + "Strict-Transport-Security"), OWASP_HEADERS],
    ),
    # B. Cookie Security
    "cookie_secure": _entry(
        "Cookie thiếu thuộc tính Secure",
        "Medium",
        "Secure buộc trình duyệt chỉ gửi cookie qua HTTPS. Mức ảnh hưởng cao hơn với cookie phiên, xác thực hoặc SameSite=None.",
        "Cookie có thể đi qua kết nối HTTP không mã hóa và bị lộ cho người có khả năng quan sát đường truyền.",
        "Chỉ phát hành cookie nhạy cảm qua HTTPS và bật Secure, ví dụ Flask: response.set_cookie(..., secure=True).",
        [("MDN: Set-Cookie", MDN + "Set-Cookie")],
    ),
    "cookie_httponly": _entry(
        "Cookie thiếu thuộc tính HttpOnly",
        "Medium",
        "HttpOnly ngăn JavaScript phía trình duyệt đọc cookie. Thuộc tính này phù hợp với cookie phiên không cần client script truy cập.",
        "Nếu trang có XSS, cookie không có HttpOnly dễ bị script độc hại đọc và gửi ra ngoài hơn.",
        "Bật HttpOnly cho cookie phiên/xác thực, ví dụ Flask: response.set_cookie(..., httponly=True).",
        [("MDN: Set-Cookie", MDN + "Set-Cookie")],
    ),
    "cookie_samesite": _entry(
        "Cookie thiếu hoặc sai SameSite",
        "Low",
        "SameSite kiểm soát việc gửi cookie trong request xuất phát từ website khác.",
        "Cấu hình không phù hợp có thể làm yếu lớp giảm thiểu CSRF hoặc khiến trình duyệt từ chối cookie SameSite=None không kèm Secure.",
        "Dùng SameSite=Lax hoặc Strict theo luồng đăng nhập; chỉ dùng None khi thật sự cần cross-site và luôn kèm Secure.",
        [("MDN: Set-Cookie (SameSite)", MDN + "Set-Cookie#samesitesamesite-value")],
    ),
    # C. CORS Security
    "cors_reflect": _entry(
        "CORS phản chiếu Origin không tin cậy",
        "Medium",
        "Máy chủ trả lại Origin do bên gửi cung cấp mà không đối chiếu allowlist. Scanner chỉ xác nhận khi probe origin riêng được phản chiếu.",
        "Một website độc hại có thể đọc response cross-origin; hậu quả nghiêm trọng hơn khi endpoint trả dữ liệu riêng và cho phép credentials.",
        "So khớp Origin chính xác với allowlist, trả tối đa một origin, thêm Vary: Origin và chỉ bật credentials khi cần.",
        [("OWASP: CORS", "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny")],
    ),
    "cors_open": _entry(
        "CORS cấu hình quá rộng",
        "Low",
        "CORS cho phép wildcard hoặc origin đặc biệt quá rộng. Wildcard có thể hợp lệ cho dữ liệu công khai nên mức độ phụ thuộc endpoint.",
        "Dữ liệu không công khai có thể bị website khác đọc; cấu hình rộng đi cùng credentials làm tăng rủi ro.",
        "Chỉ dùng '*' cho tài nguyên thực sự công khai. Với dữ liệu riêng, dùng allowlist origin chính xác và không kết hợp wildcard với credentials.",
        [("MDN: CORS", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS")],
    ),
    # D. HTTPS/TLS
    "tls_no_https": _entry(
        "HTTPS không được dùng hoặc HTTP không chuyển hướng",
        "High",
        "Tiêu chí này kiểm tra website có hỗ trợ HTTPS và bản HTTP có chuyển sang đúng HTTPS cùng mục tiêu hay không.",
        "Nếu người dùng ở lại HTTP, dữ liệu có thể bị đọc hoặc sửa trên đường truyền. Thiếu redirect có mức ảnh hưởng thấp hơn việc không có HTTPS.",
        "Cài chứng chỉ hợp lệ, bật HTTPS và cấu hình redirect 301/308 từ HTTP sang HTTPS cùng hostname; sau đó mới bật HSTS.",
        [OWASP_TLS, ("Let's Encrypt", "https://letsencrypt.org/getting-started/")],
    ),
    "tls_invalid": _entry(
        "Chứng chỉ TLS không hợp lệ hoặc đã hết hạn",
        "High",
        "Chứng chỉ không còn hạn hoặc không thể được xác thực bằng kho tin cậy của hệ thống.",
        "Trình duyệt sẽ cảnh báo hoặc chặn kết nối, và người dùng không có bảo đảm đáng tin cậy về máy chủ đang kết nối.",
        "Gia hạn/cấp lại chứng chỉ từ CA tin cậy, cài đầy đủ chuỗi intermediate và tự động hóa gia hạn cùng cảnh báo hết hạn.",
        [OWASP_TLS, ("Let's Encrypt", "https://letsencrypt.org/getting-started/")],
    ),
    "tls_hostname": _entry(
        "Chứng chỉ TLS không khớp hostname",
        "High",
        "Tên miền đang quét không nằm trong SAN/CN hợp lệ của chứng chỉ được máy chủ cung cấp.",
        "Trình duyệt cảnh báo kết nối không riêng tư vì chứng chỉ không chứng minh đúng danh tính hostname này.",
        "Cấp chứng chỉ có SAN chứa mọi hostname phục vụ và kiểm tra cấu hình virtual host/SNI đang chọn đúng chứng chỉ.",
        [OWASP_TLS],
    ),
    "tls_weak_protocol": _entry(
        "Phiên TLS dùng giao thức hoặc cipher yếu",
        "High",
        "Phiên kiểm tra đã thương lượng phiên bản TLS lỗi thời hoặc cipher có thuật toán/độ dài khóa yếu.",
        "Cấu hình cũ có thể làm giảm tính bí mật và toàn vẹn của kết nối. Kết quả chỉ phản ánh phiên thực sự thương lượng, không phải quét toàn bộ cipher suite.",
        "Chỉ bật TLS 1.2/1.3; loại bỏ RC4, 3DES, DES, NULL, EXPORT, MD5 và cipher dưới 128 bit; dùng cấu hình TLS hiện đại đã được kiểm thử.",
        [OWASP_TLS, ("Mozilla SSL Config", "https://ssl-config.mozilla.org/")],
    ),
    # E. Sensitive Files
    "path_env": _entry(
        "Tệp .env bị công khai",
        "High",
        "Scanner chỉ kết luận khi response 200 có nội dung giống biến môi trường hoặc bí mật cấu hình, không chỉ dựa vào status code.",
        "Tệp có thể chứa mật khẩu cơ sở dữ liệu, API key hoặc khóa ứng dụng, cho phép truy cập trái phép vào hệ thống khác.",
        "Chặn dotfile ở web server, đặt .env ngoài document root và lập tức xoay vòng mọi bí mật đã có khả năng bị lộ.",
        [("OWASP: Cryptographic Failures", "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/")],
    ),
    "path_git": _entry(
        "Dữ liệu .git bị công khai",
        "High",
        "Scanner xác nhận khi /.git/config truy cập được và nội dung khớp cấu hình Git.",
        "Lịch sử Git có thể làm lộ mã nguồn, bí mật đã commit và thông tin giúp tìm điểm yếu của ứng dụng.",
        "Chặn /.git ở web server, chỉ triển khai artifact cần chạy và xoay vòng bí mật từng xuất hiện trong repository.",
        [("OWASP: Information Leakage", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/01_Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage")],
    ),
    "path_backup": _entry(
        "Tệp sao lưu/cấu hình nhạy cảm bị công khai",
        "High",
        "Scanner đối chiếu chữ ký nội dung trước khi báo tệp ZIP, SQL dump, bản sao PHP hoặc tệp cấu hình máy chủ bị lộ.",
        "Bản sao lưu thường chứa mã nguồn, dữ liệu người dùng hoặc thông tin kết nối và có thể bị tải về trực tiếp.",
        "Xóa tệp khỏi document root, chặn phần mở rộng backup ở web server, lưu backup trong kho riêng có kiểm soát truy cập và xoay vòng bí mật bị lộ.",
        [("OWASP: Sensitive Data Exposure", "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/")],
    ),
}


# Các mục này vẫn giải thích dữ liệu module cũ nhưng không phải tiêu chí đánh giá chính.
REFERENCE_ENTRIES = {
    "technical_header": _entry(
        "Header kỹ thuật/tùy chọn",
        "Info",
        "Referrer-Policy, Permissions-Policy và thông tin Server/X-Powered-By giúp đánh giá cấu hình nhưng không tự chứng minh một lỗ hổng.",
        "Ảnh hưởng phụ thuộc dữ liệu trong URL, tính năng trình duyệt được dùng và việc phần mềm có được cập nhật hay không.",
        "Chỉ siết các header phù hợp với ứng dụng; ưu tiên cập nhật phần mềm và xử lý 16 tiêu chí chính trước.",
    ),
    "cookie_other": _entry(
        "Quan sát khác về cookie",
        "Info",
        "Cú pháp, Domain hoặc Path của cookie có điểm cần xem lại nhưng không thuộc ba thuộc tính bảo mật chính.",
        "Có thể làm cookie hoạt động sai hoặc rộng hơn dự kiến; chưa đủ bằng chứng về tác động bảo mật cụ thể.",
        "Dùng cookie host-only khi có thể, Path bắt đầu bằng '/' và gửi từng Set-Cookie đúng cú pháp.",
    ),
    "cors_other": _entry(
        "Quan sát khác về CORS",
        "Info",
        "Một header CORS có cú pháp hoặc giá trị chưa chuẩn nhưng chưa có bằng chứng origin không tin cậy đọc được dữ liệu.",
        "Trình duyệt có thể bỏ qua cấu hình hoặc ứng dụng hoạt động không như dự kiến.",
        "Trả một origin hợp lệ cho mỗi response, dùng đúng chữ thường 'true' cho credentials và thêm Vary: Origin khi phản hồi động.",
    ),
    "path_other": _entry(
        "Đường dẫn kỹ thuật cần xem lại",
        "Info",
        "Một đường dẫn cấu hình, trạng thái hoặc quản trị có phản hồi nhưng không thuộc ba nhóm tệp nhạy cảm chính.",
        "Nội dung có thể chỉ là thông tin kỹ thuật hoặc trang đăng nhập; cần đánh giá thủ công trước khi coi là lỗ hổng.",
        "Xác nhận nội dung có chủ ý công khai hay không; nếu không cần, trả 404/403 và giới hạn truy cập phù hợp.",
    ),
    "robots_sensitive": _entry(
        "Robots.txt chứa đường dẫn đáng chú ý",
        "Info",
        "robots.txt công khai các đường dẫn không muốn công cụ tìm kiếm lập chỉ mục; đây không phải cơ chế kiểm soát truy cập.",
        "Đường dẫn có thể gợi ý khu vực cần kiểm tra nhưng không chứng minh dữ liệu bên trong truy cập được.",
        "Bảo vệ tài nguyên bằng xác thực/ủy quyền và không dựa vào robots.txt để giấu nội dung.",
    ),
    "cms": _entry(
        "Dấu hiệu CMS",
        "Info",
        "Công cụ nhận diện dấu hiệu WordPress, Joomla, Drupal hoặc Magento từ HTML/tài nguyên công khai.",
        "Việc dùng CMS không phải lỗ hổng; rủi ro chỉ xuất hiện khi core, plugin hoặc giao diện có lỗi/chưa cập nhật.",
        "Cập nhật CMS và extension, gỡ thành phần không dùng và bảo vệ tài khoản quản trị.",
    ),
    "port_other": _entry(
        "Cổng TCP đang mở",
        "Info",
        "Scanner hoàn tất TCP handshake với một cổng phổ biến. Điều này chỉ xác nhận khả năng kết nối, không xác nhận dịch vụ hay lỗ hổng.",
        "Dịch vụ không cần thiết làm tăng bề mặt tấn công, nhưng một cổng mở có thể hoàn toàn hợp lệ.",
        "Đối chiếu với kiến trúc hệ thống; đóng hoặc giới hạn IP cho dịch vụ không cần công khai.",
    ),
    "tls_reference": _entry(
        "Thông tin TLS chưa đủ để kết luận",
        "Info",
        "Chứng chỉ sắp gia hạn, thiếu metadata hoặc handshake không hoàn tất là trạng thái vận hành/chưa xác định.",
        "Có thể dẫn tới gián đoạn hoặc che khuất vấn đề, nhưng scanner chưa có đủ bằng chứng để kết luận một lỗ hổng cụ thể.",
        "Kiểm tra bằng trình duyệt hoặc công cụ TLS quản trị, xem log máy chủ và quét lại khi kết nối ổn định.",
    ),
}


# Giữ API cũ cho caller đang dùng knowledge.ENTRIES.
ENTRIES = {**MAIN_ENTRIES, **REFERENCE_ENTRIES}


_HEADER_KEYS = {
    "strict-transport-security": "hsts_missing",
    "hsts": "hsts_missing",
    "content-security-policy": "csp_missing",
    "csp": "csp_missing",
    "x-frame-options": "xfo_missing",
    "x-content-type-options": "xcto_missing",
    "referrer-policy": "technical_header",
    "permissions-policy": "technical_header",
}


def _header_key(text):
    lowered = text.lower()
    for marker, key in _HEADER_KEYS.items():
        if marker in lowered:
            return key
    return None


def lookup_key(finding):
    """Trả về khóa tiêu chí chuẩn cho một finding, hoặc ``None`` nếu chưa biết."""
    criterion_key = finding.get("criterion_key")
    if criterion_key in ENTRIES:
        return criterion_key
    module = finding.get("module") or ""
    title = finding.get("title") or ""
    lowered = title.lower()

    if module in {"Header Check", "Security Header"}:
        if lowered.startswith("rò rỉ thông tin"):
            return "technical_header"
        return _header_key(title)

    if module == "Cookie Check":
        if "thiếu secure" in lowered:
            return "cookie_secure"
        if "httponly" in lowered:
            return "cookie_httponly"
        if "samesite" in lowered:
            return "cookie_samesite"
        if any(marker in lowered for marker in ("set-cookie", "domain", "path")):
            return "cookie_other"
        return None

    if module == "CORS Check":
        if "phản chiếu" in lowered:
            return "cors_reflect"
        if "cho phép mọi origin" in lowered or "origin null" in lowered:
            return "cors_open"
        if "access-control-allow" in lowered:
            return "cors_other"
        return None

    if module == "Directory Check":
        match = re.match(r"path:\s*/(\S+)", lowered)
        if not match:
            return None
        path = match.group(1)
        if finding.get("severity") == "Info":
            return "path_other"
        if path == ".env":
            return "path_env"
        if path == ".git/config":
            return "path_git"
        if path in {".htaccess", "backup.zip", "backup.sql", "config.php.bak", "web.config"}:
            return "path_backup"
        return "path_other"

    if module == "Robots.txt Check":
        return "robots_sensitive"
    if module == "CMS Detection":
        return "cms"
    if module == "Port Scan":
        return "port_other" if re.search(r"\d+", title) else None

    if module == "TLS/SSL Check":
        if "hostname không khớp" in lowered:
            return "tls_hostname"
        if "không hỗ trợ https" in lowered or "không chuyển hướng" in lowered:
            return "tls_no_https"
        if "đã hết hạn" in lowered or "không hợp lệ" in lowered:
            return "tls_invalid"
        if "giao thức yếu" in lowered or "cipher yếu" in lowered:
            return "tls_weak_protocol"
        if any(marker in lowered for marker in (
            "sắp hết hạn", "gần đến kỳ gia hạn", "không đủ dữ liệu", "handshake"
        )):
            return "tls_reference"
        return None

    return None


def is_reference(finding):
    """True khi finding chỉ nên xuất hiện trong thông tin kỹ thuật tham khảo."""
    key = lookup_key(finding or {})
    return key in REFERENCE_ENTRIES or (key is None and finding.get("severity") == "Info")


def explain(finding):
    """Luôn trả về một dict giải thích hợp lệ và không ném lỗi."""
    try:
        key = lookup_key(finding or {})
    except Exception:
        key = None
    entry = ENTRIES.get(key) if key else None
    if entry is None:
        entry, key, generic = FALLBACK, "generic", True
    else:
        generic = False
    return {
        "key": key,
        "title": entry["title"],
        "severity": entry["severity"],
        "what": entry["what"],
        "why": entry["why"],
        "fix": entry["fix"],
        "learn_more": list(entry["learn_more"]),
        "generic": generic,
    }
