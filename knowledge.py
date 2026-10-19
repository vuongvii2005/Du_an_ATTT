# -*- coding: utf-8 -*-
"""Từ điển giải thích finding cho người mới (không cần biết thuật ngữ bảo mật).

Mỗi mục có:
  title      tên gọi dễ hiểu (dùng làm tiêu đề ở trang /glossary)
  what       "Đây là gì?"
  why        "Vì sao nguy hiểm?"
  fix        "Cách khắc phục" (các bước cụ thể, kèm ví dụ cấu hình)
  learn_more danh sách (nhãn, liên kết) tới OWASP/MDN, có thể rỗng

`explain(finding)` luôn trả về một dict hợp lệ: nếu finding không có trong từ điển
thì dùng nội dung dự phòng chung (FALLBACK) và đặt `generic = True`.
"""

import re

MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
OWASP_HEADERS = ("OWASP Secure Headers Project", "https://owasp.org/www-project-secure-headers/")
OWASP_TLS = ("OWASP: Transport Layer Security", "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html")


def _entry(title, what, why, fix, learn_more=()):
    return {
        "title": title,
        "what": what,
        "why": why,
        "fix": fix,
        "learn_more": [{"label": label, "url": url} for label, url in learn_more],
    }


FALLBACK = _entry(
    "Phát hiện chưa có hướng dẫn riêng",
    "Công cụ ghi nhận một điểm đáng chú ý ở website này nhưng chưa có lời giải thích riêng cho loại phát hiện này.",
    "Mức độ ảnh hưởng phụ thuộc vào website của bạn. Hãy đọc phần chi tiết kỹ thuật (bằng chứng, nguyên nhân) bên dưới để biết cụ thể.",
    "Làm theo phần \"Khuyến nghị\" trong chi tiết kỹ thuật nếu có, hoặc nhờ người quản trị website xem giúp. "
    "Sau khi sửa, hãy quét lại để kiểm tra.",
)

ENTRIES = {
    # ---------------------------------------------------------------- Header thiếu
    "hsts_missing": _entry(
        "Thiếu HSTS (Strict-Transport-Security)",
        "HSTS là một dòng nhắn mà website gửi cho trình duyệt: \"từ nay chỉ được vào tôi bằng HTTPS (kết nối có mã hóa)\". "
        "Website này chưa gửi dòng nhắn đó.",
        "Nếu ai đó ngồi chung mạng Wi-Fi với bạn (quán cà phê, sân bay), họ có thể ép trình duyệt dùng bản HTTP không mã hóa "
        "rồi đọc hoặc sửa dữ liệu như mật khẩu, cookie đăng nhập.",
        "Chỉ bật sau khi chắc chắn toàn bộ website chạy được bằng HTTPS.\n"
        "Nginx:  add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
        "Apache: Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"\n"
        "Flask:  trong hàm @app.after_request đặt r.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'",
        [("MDN: Strict-Transport-Security", MDN + "Strict-Transport-Security"), OWASP_HEADERS],
    ),
    "csp_missing": _entry(
        "Thiếu CSP (Content-Security-Policy)",
        "CSP là danh sách \"nguồn được tin cậy\" mà website đưa cho trình duyệt: script, ảnh, font được phép tải từ đâu. "
        "Website này chưa có danh sách đó nên trình duyệt chạy mọi script nó gặp.",
        "Nếu kẻ xấu chèn được một đoạn script vào trang (lỗi XSS), trình duyệt sẽ chạy nó và có thể đánh cắp phiên đăng nhập "
        "hoặc thông tin người dùng. CSP là lớp chặn thứ hai khi lỗi đó xảy ra.",
        "Bắt đầu với chính sách đơn giản rồi siết dần:\n"
        "Nginx:  add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self'\" always;\n"
        "Apache: Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'\"\n"
        "Flask:  r.headers['Content-Security-Policy'] = \"default-src 'self'; script-src 'self'; object-src 'none'\"\n"
        "Mẹo: thử bằng header Content-Security-Policy-Report-Only trước để không làm hỏng trang.",
        [("MDN: Content-Security-Policy", MDN + "Content-Security-Policy"), OWASP_HEADERS],
    ),
    "xfo_missing": _entry(
        "Thiếu X-Frame-Options",
        "Header này cho trình duyệt biết trang của bạn có được phép nằm trong khung (iframe) của website khác hay không. "
        "Website chưa nói rõ nên có thể bị nhúng vào trang lạ.",
        "Kẻ xấu có thể dựng một trang giả, nhúng website của bạn vào dạng vô hình rồi lừa người dùng bấm vào nút thật mà không biết "
        "(gọi là clickjacking), ví dụ bấm \"Xóa tài khoản\" hay \"Chuyển tiền\".",
        "Nginx:  add_header X-Frame-Options \"SAMEORIGIN\" always;\n"
        "Apache: Header always set X-Frame-Options \"SAMEORIGIN\"\n"
        "Flask:  r.headers['X-Frame-Options'] = 'SAMEORIGIN'\n"
        "Hoặc dùng CSP: frame-ancestors 'self'.",
        [("MDN: X-Frame-Options", MDN + "X-Frame-Options"), OWASP_HEADERS],
    ),
    "xcto_missing": _entry(
        "Thiếu X-Content-Type-Options",
        "Header này bảo trình duyệt \"cứ tin loại tệp mà tôi khai báo, đừng tự đoán\". Thiếu nó, trình duyệt có thể tự đoán loại tệp.",
        "Một tệp người dùng tải lên (ví dụ ảnh) có thể bị trình duyệt đoán thành script và chạy, tạo đường cho kẻ xấu chèn mã.",
        "Nginx:  add_header X-Content-Type-Options \"nosniff\" always;\n"
        "Apache: Header always set X-Content-Type-Options \"nosniff\"\n"
        "Flask:  r.headers['X-Content-Type-Options'] = 'nosniff'",
        [("MDN: X-Content-Type-Options", MDN + "X-Content-Type-Options")],
    ),
    "referrer_missing": _entry(
        "Thiếu Referrer-Policy",
        "Khi người dùng bấm một liên kết rời website, trình duyệt thường báo cho nơi đến biết họ đến từ địa chỉ nào. "
        "Referrer-Policy là quy tắc quyết định báo bao nhiêu chi tiết.",
        "Địa chỉ trang có thể chứa thông tin riêng (mã đơn hàng, token đặt lại mật khẩu...). Thiếu quy tắc, các thông tin này có thể bị gửi sang website khác.",
        "Nginx:  add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
        "Apache: Header always set Referrer-Policy \"strict-origin-when-cross-origin\"\n"
        "Flask:  r.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'",
        [("MDN: Referrer-Policy", MDN + "Referrer-Policy")],
    ),
    "permissions_missing": _entry(
        "Thiếu Permissions-Policy",
        "Header này khai báo website (và các khung nhúng trong nó) được phép dùng tính năng nào của thiết bị: camera, micro, vị trí...",
        "Nếu có mã lạ chạy trong trang hoặc một quảng cáo nhúng, nó có thể xin quyền dùng camera, micro hay vị trí của người truy cập.",
        "Nginx:  add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;\n"
        "Apache: Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=()\"\n"
        "Flask:  r.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'",
        [("MDN: Permissions-Policy", MDN + "Permissions-Policy")],
    ),
    # ---------------------------------------------------------------- Header cấu hình yếu
    "hsts_weak": _entry(
        "HSTS cấu hình chưa tốt",
        "Website có gửi HSTS nhưng giá trị chưa hợp lệ, quá ngắn hoặc bị tắt nên trình duyệt không bảo vệ như mong muốn.",
        "Bảo vệ \"luôn dùng HTTPS\" chỉ kéo dài ngắn hoặc không có, kẻ xấu trên cùng mạng vẫn có cơ hội ép dùng HTTP.",
        "Đặt thời hạn ít nhất 6 tháng (khuyến nghị 1 năm) và thêm includeSubDomains nếu mọi subdomain đều dùng HTTPS:\n"
        "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        [("MDN: Strict-Transport-Security", MDN + "Strict-Transport-Security")],
    ),
    "csp_weak": _entry(
        "CSP cấu hình chưa chặt",
        "Website có Content-Security-Policy nhưng cho phép quá rộng (ví dụ cho script từ mọi nguồn, hoặc cho chạy script ngay trong trang).",
        "Chính sách quá lỏng gần như không còn tác dụng ngăn script lạ, nên lớp bảo vệ này chỉ có trên danh nghĩa.",
        "Bỏ 'unsafe-inline', 'unsafe-eval' và dấu * trong script-src. Chuyển script nhúng trực tiếp ra tệp .js riêng, "
        "hoặc dùng nonce:\nContent-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
        [("MDN: Content-Security-Policy", MDN + "Content-Security-Policy")],
    ),
    "xfo_weak": _entry(
        "X-Frame-Options có giá trị không hợp lệ",
        "Header có mặt nhưng giá trị không phải DENY hoặc SAMEORIGIN nên trình duyệt hiện đại bỏ qua nó.",
        "Website coi như chưa được bảo vệ khỏi việc bị nhúng vào trang lạ để lừa người dùng bấm nhầm (clickjacking).",
        "Đổi giá trị thành SAMEORIGIN (cho phép chính website mình nhúng) hoặc DENY (không cho ai nhúng):\n"
        "X-Frame-Options: SAMEORIGIN",
        [("MDN: X-Frame-Options", MDN + "X-Frame-Options")],
    ),
    "xcto_weak": _entry(
        "X-Content-Type-Options có giá trị sai",
        "Header có mặt nhưng chỉ giá trị \"nosniff\" mới có tác dụng.",
        "Trình duyệt vẫn có thể tự đoán loại tệp và chạy nhầm tệp không phải script như script.",
        "Đổi thành đúng giá trị: X-Content-Type-Options: nosniff",
        [("MDN: X-Content-Type-Options", MDN + "X-Content-Type-Options")],
    ),
    "referrer_weak": _entry(
        "Referrer-Policy chưa an toàn",
        "Quy tắc báo \"bạn đến từ đâu\" của website đang để quá rộng hoặc không hợp lệ, có thể gửi cả địa chỉ đầy đủ sang website khác.",
        "Phần sau dấu ? trong địa chỉ có thể chứa mã tạm hay thông tin riêng và bị lộ cho bên thứ ba.",
        "Dùng giá trị cân bằng giữa riêng tư và tiện dụng: Referrer-Policy: strict-origin-when-cross-origin",
        [("MDN: Referrer-Policy", MDN + "Referrer-Policy")],
    ),
    "permissions_weak": _entry(
        "Permissions-Policy chưa chặt",
        "Header có mặt nhưng để trống hoặc cấp tính năng thiết bị (camera, micro...) cho mọi nguồn.",
        "Mã hoặc khung nhúng từ nơi khác vẫn có thể xin dùng các tính năng nhạy cảm của người truy cập.",
        "Chỉ cấp những tính năng thật sự cần, ví dụ: Permissions-Policy: camera=(), microphone=(), geolocation=(self)",
        [("MDN: Permissions-Policy", MDN + "Permissions-Policy")],
    ),
    # ---------------------------------------------------------------- Rò rỉ thông tin
    "info_leak": _entry(
        "Máy chủ tiết lộ công nghệ đang dùng",
        "Mỗi lần trả lời, máy chủ kèm theo tên phần mềm và đôi khi cả số phiên bản (ví dụ \"nginx/1.18\", \"PHP/7.4\").",
        "Thông tin này không phải lỗ hổng, nhưng giúp kẻ xấu tìm nhanh các lỗi đã biết của đúng phiên bản bạn đang dùng.",
        "Nginx:  server_tokens off;  (và proxy_hide_header X-Powered-By;)\n"
        "Apache: ServerTokens Prod  và  ServerSignature Off  (Header unset X-Powered-By)\n"
        "PHP:    expose_php = Off trong php.ini\n"
        "Flask (gunicorn): đặt sau Nginx rồi ẩn như trên. Quan trọng hơn: luôn cập nhật phần mềm lên bản mới.",
        [("OWASP: Fingerprint Web Server", "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server")],
    ),
    # ---------------------------------------------------------------- Cookie
    "cookie_secure": _entry(
        "Cookie thiếu thuộc tính Secure",
        "Cookie là mẩu thông tin website lưu trong trình duyệt (ví dụ để nhớ bạn đã đăng nhập). "
        "Thuộc tính Secure bảo trình duyệt chỉ gửi cookie qua kết nối HTTPS có mã hóa.",
        "Thiếu Secure, cookie có thể bị gửi qua HTTP không mã hóa và bị kẻ nghe lén cùng mạng đọc được, từ đó chiếm phiên đăng nhập.",
        "Flask:  app.config['SESSION_COOKIE_SECURE'] = True  (hoặc response.set_cookie(..., secure=True))\n"
        "Nginx (proxy):  proxy_cookie_path / \"/; Secure\";\n"
        "PHP:    session.cookie_secure = 1",
        [("MDN: Set-Cookie", MDN + "Set-Cookie"), ("OWASP: Session Management", "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html")],
    ),
    "cookie_httponly": _entry(
        "Cookie thiếu thuộc tính HttpOnly",
        "HttpOnly cấm mã JavaScript trên trang đọc cookie. Cookie này chưa có thuộc tính đó.",
        "Nếu trang bị chèn script lạ (XSS), script đó đọc được cookie đăng nhập và gửi cho kẻ xấu để chiếm tài khoản.",
        "Flask:  app.config['SESSION_COOKIE_HTTPONLY'] = True  (hoặc set_cookie(..., httponly=True))\n"
        "Nginx (proxy):  proxy_cookie_path / \"/; HttpOnly\";\n"
        "PHP:    session.cookie_httponly = 1",
        [("MDN: Set-Cookie", MDN + "Set-Cookie")],
    ),
    "cookie_samesite": _entry(
        "Cookie thiếu hoặc sai SameSite",
        "SameSite quyết định cookie có được gửi kèm khi người dùng đến từ website khác hay không.",
        "Không có quy tắc rõ ràng, một trang độc hại có thể khiến trình duyệt của nạn nhân gửi yêu cầu kèm cookie đăng nhập "
        "(tấn công CSRF), ví dụ để đổi mật khẩu mà người dùng không hay.",
        "Flask:  app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  (dùng 'Strict' nếu website không cần liên kết từ nơi khác vào khi đã đăng nhập)\n"
        "PHP:    session.cookie_samesite = Lax\n"
        "Chỉ dùng SameSite=None khi thật sự cần, và phải kèm Secure.",
        [("MDN: Set-Cookie (SameSite)", MDN + "Set-Cookie#samesitesamesite-value")],
    ),
    "cookie_other": _entry(
        "Cookie cấu hình chưa gọn",
        "Một thuộc tính khác của cookie (Domain, Path hoặc cú pháp) chưa chuẩn hoặc rộng hơn cần thiết.",
        "Cookie có thể bị trình duyệt xử lý không như dự định, hoặc được chia sẻ cho cả các subdomain không cần thiết.",
        "Chỉ đặt Domain khi cần chia sẻ giữa các subdomain, đặt Path bắt đầu bằng \"/\", và kiểm tra lại cú pháp Set-Cookie.",
        [("MDN: Set-Cookie", MDN + "Set-Cookie")],
    ),
    # ---------------------------------------------------------------- CORS
    "cors_open": _entry(
        "CORS cho phép mọi website",
        "CORS là quy tắc cho biết website nào khác được phép đọc dữ liệu từ website của bạn qua trình duyệt. "
        "Giá trị * nghĩa là bất kỳ website nào cũng được.",
        "Nếu các địa chỉ này trả dữ liệu riêng của người dùng, một trang lạ có thể đọc chúng khi người dùng ghé thăm. "
        "Nếu chỉ là dữ liệu công khai thì rủi ro thấp.",
        "Chỉ liệt kê website tin cậy:\n"
        "Nginx:  add_header Access-Control-Allow-Origin \"https://app.vidu.com\" always;\n"
        "Flask:  dùng flask-cors với origins=['https://app.vidu.com']\n"
        "Không bao giờ kết hợp * với Allow-Credentials: true.",
        [("MDN: CORS", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS")],
    ),
    "cors_reflect": _entry(
        "CORS tin mọi website xin vào",
        "Máy chủ chép nguyên nguồn gốc (Origin) mà bên gửi yêu cầu khai báo rồi trả về kiểu \"được phép\". "
        "Tức là website nào cũng được tin.",
        "Một trang độc hại có thể đọc dữ liệu riêng của người đang đăng nhập (nhất là khi kèm credentials) và gửi đi.",
        "Tạo danh sách trắng các website được tin và chỉ trả Allow-Origin khi Origin nằm trong danh sách:\n"
        "ALLOWED = {'https://app.vidu.com'}\n"
        "if origin in ALLOWED: r.headers['Access-Control-Allow-Origin'] = origin; r.headers['Vary'] = 'Origin'",
        [("MDN: CORS", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"), ("OWASP: CORS", "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny")],
    ),
    "cors_other": _entry(
        "CORS cấu hình sai cú pháp hoặc quá rộng",
        "Header CORS có giá trị không đúng chuẩn (ví dụ liệt kê nhiều website bằng dấu phẩy, hoặc tin origin \"null\").",
        "Trình duyệt có thể bỏ qua cấu hình, hoặc origin \"null\" (từ tệp cục bộ, iframe sandbox) bị lợi dụng để đọc dữ liệu.",
        "Mỗi phản hồi chỉ trả về MỘT origin cụ thể nằm trong danh sách trắng; không tin origin \"null\"; "
        "Allow-Credentials chỉ nhận giá trị đúng là true.",
        [("MDN: CORS", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS")],
    ),
    # ---------------------------------------------------------------- Đường dẫn nhạy cảm
    "path_env": _entry(
        "Tệp .env bị công khai",
        "Tệp .env chứa các \"chìa khóa\" của ứng dụng: mật khẩu cơ sở dữ liệu, khóa API, khóa bí mật. Ai cũng tải được tệp này từ internet.",
        "Kẻ xấu lấy được tệp này là vào thẳng cơ sở dữ liệu hoặc dịch vụ bên thứ ba bằng chính chìa khóa của bạn. Đây là mức nguy hiểm cao nhất.",
        "1) Chặn truy cập ngay. Nginx: location ~ /\\.(?!well-known) { deny all; }  Apache: <FilesMatch \"^\\.\"> Require all denied </FilesMatch>\n"
        "2) Đổi TẤT CẢ mật khẩu và khóa trong tệp (coi như đã lộ).\n"
        "3) Đặt .env ngoài thư mục web (document root), đừng đưa lên Git.",
        [("OWASP: Sensitive Data Exposure", "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/")],
    ),
    "path_git": _entry(
        "Thư mục .git bị công khai",
        "Thư mục .git chứa toàn bộ lịch sử mã nguồn của website. Nó đang truy cập được từ internet.",
        "Kẻ xấu có thể tải về toàn bộ mã nguồn, trong đó thường có mật khẩu hay khóa bị lỡ commit, và tìm lỗi bảo mật dễ dàng hơn.",
        "1) Chặn: Nginx: location ~ /\\.git { deny all; }  Apache: RedirectMatch 404 /\\.git\n"
        "2) Đừng deploy bằng cách chép cả thư mục dự án; chỉ đưa các tệp cần chạy lên máy chủ.\n"
        "3) Đổi mọi mật khẩu/khóa từng nằm trong mã nguồn.",
        [("OWASP: Information Exposure", "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url")],
    ),
    "path_htaccess": _entry(
        "Tệp .htaccess đọc được từ bên ngoài",
        ".htaccess là tệp cấu hình của máy chủ Apache. Nội dung của nó đang hiển thị công khai.",
        "Kẻ xấu biết được quy tắc chuyển hướng, vùng bị chặn và cách xác thực, giúp họ tìm cách vượt qua.",
        "Apache chuẩn đã chặn sẵn tệp này; nếu đang lộ, kiểm tra lại cấu hình:\n"
        "<Files \".ht*\"> Require all denied </Files>\n"
        "Nginx không dùng .htaccess: thêm location ~ /\\.ht { deny all; }",
        [],
    ),
    "path_backup_zip": _entry(
        "Tệp sao lưu .zip bị công khai",
        "Một bản nén (backup.zip) nằm trên website và ai cũng tải được.",
        "Bản sao lưu thường chứa mã nguồn, cấu hình và dữ liệu. Kẻ xấu chỉ cần đoán đúng tên tệp là tải về.",
        "Xóa tệp khỏi thư mục web ngay, lưu sao lưu ở nơi không công khai (ngoài document root hoặc kho lưu trữ riêng). "
        "Nếu bên trong có mật khẩu hoặc khóa, hãy đổi chúng.",
        [],
    ),
    "path_backup_sql": _entry(
        "Tệp sao lưu cơ sở dữ liệu (.sql) bị công khai",
        "Bản xuất cơ sở dữ liệu (backup.sql) nằm trên website và ai cũng tải được.",
        "Trong đó có thể có toàn bộ dữ liệu người dùng: tên, email, mật khẩu băm... Lộ tệp này là lộ dữ liệu khách hàng.",
        "1) Xóa tệp khỏi thư mục web ngay, lưu sao lưu ở nơi riêng tư.\n"
        "2) Nếu dữ liệu người dùng bị lộ, đổi mật khẩu hệ thống và cân nhắc thông báo cho người dùng bị ảnh hưởng.",
        [],
    ),
    "path_config_bak": _entry(
        "Tệp cấu hình sao lưu (.bak) lộ mã nguồn",
        "Bản sao lưu của tệp cấu hình PHP (config.php.bak) mở được trực tiếp. Máy chủ không chạy nó mà trả nguyên văn mã.",
        "Người ngoài đọc được mật khẩu cơ sở dữ liệu và các thiết lập bí mật ghi trong tệp.",
        "Xóa tệp .bak, .old, .orig khỏi thư mục web; đổi mật khẩu đã nằm trong tệp. "
        "Nginx có thể chặn: location ~* \\.(bak|old|orig|sql|zip)$ { deny all; }",
        [],
    ),
    "path_phpinfo": _entry(
        "Trang phpinfo.php đang mở",
        "phpinfo.php là trang liệt kê chi tiết cấu hình PHP của máy chủ, vốn chỉ để lập trình viên dùng khi kiểm tra.",
        "Trang này tiết lộ phiên bản, đường dẫn thư mục, module, biến môi trường... giúp kẻ xấu lên kế hoạch tấn công chính xác hơn.",
        "Xóa tệp phpinfo.php (hoặc mọi tệp có gọi hàm phpinfo()) khỏi máy chủ thật.",
        [],
    ),
    "path_server_status": _entry(
        "Trang trạng thái máy chủ Apache đang mở",
        "/server-status là trang theo dõi nội bộ của Apache (đang có ai truy cập, yêu cầu nào đang chạy).",
        "Lộ địa chỉ IP người dùng, đường dẫn đang được gọi, đôi khi cả thông tin nhạy cảm trong địa chỉ.",
        "Chỉ cho phép địa chỉ nội bộ:\n"
        "<Location \"/server-status\"> SetHandler server-status  Require local </Location>\n"
        "Hoặc tắt hẳn module status.",
        [],
    ),
    "path_web_config": _entry(
        "Tệp web.config đọc được từ bên ngoài",
        "web.config là tệp cấu hình của máy chủ IIS/.NET, có thể chứa chuỗi kết nối cơ sở dữ liệu.",
        "Người ngoài đọc được cấu hình và có thể thấy mật khẩu cơ sở dữ liệu.",
        "Kiểm tra IIS đã bật request filtering (mặc định chặn web.config), không phục vụ tệp này như tệp tĩnh; "
        "đồng thời mã hóa phần connectionStrings hoặc chuyển bí mật sang biến môi trường.",
        [],
    ),
    "path_admin": _entry(
        "Trang quản trị truy cập được từ internet",
        "Trang đăng nhập quản trị (admin, administrator, wp-admin) mở cho mọi người. Phát hiện này chỉ ghi nhận trang tồn tại, "
        "chưa có dấu hiệu dữ liệu bị lộ.",
        "Kẻ xấu có thể thử đoán mật khẩu hàng loạt vào đúng trang này. Trang càng dễ đoán địa chỉ, càng bị dò nhiều.",
        "Dùng mật khẩu mạnh + xác thực hai lớp; giới hạn số lần đăng nhập sai; nếu được, chỉ cho phép địa chỉ IP của bạn:\n"
        "Nginx:  location /admin/ { allow 203.0.113.10; deny all; }\n"
        "Apache: <Location /admin/> Require ip 203.0.113.10 </Location>",
        [("OWASP: Authentication", "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html")],
    ),
    "path_info": _entry(
        "Đường dẫn thường bị dò có phản hồi",
        "Công cụ thử một số địa chỉ thường gặp. Địa chỉ này có phản hồi (hiện trang, chuyển hướng hoặc yêu cầu đăng nhập) "
        "nhưng nội dung không giống tệp nhạy cảm.",
        "Thường không nguy hiểm. Đây chỉ là gợi ý để bạn xem lại xem địa chỉ đó có nên công khai hay không.",
        "Mở địa chỉ đó xem có đúng ý định không. Nếu không cần công khai, hãy xóa hoặc chặn bằng cách trả về 404/403.",
        [],
    ),
    "robots_sensitive": _entry(
        "robots.txt nhắc tới khu vực nhạy cảm",
        "robots.txt là tệp nhắn các công cụ tìm kiếm \"đừng lập chỉ mục chỗ này\". Nó cũng công khai cho mọi người đọc.",
        "Liệt kê đường dẫn như /admin hay /backup vô tình chỉ cho kẻ xấu nơi cần thử. robots.txt KHÔNG phải là cách bảo vệ.",
        "Đừng dựa vào robots.txt để giấu. Bảo vệ khu vực đó bằng đăng nhập hoặc giới hạn IP, và nếu có thể hãy bỏ dòng Disallow tiết lộ tên khu vực. "
        "Để không bị lập chỉ mục, dùng header X-Robots-Tag: noindex.",
        [("MDN: robots.txt", "https://developer.mozilla.org/en-US/docs/Glossary/Robots.txt")],
    ),
    "cms": _entry(
        "Website dùng một hệ quản trị nội dung (CMS)",
        "CMS (WordPress, Joomla, Drupal, Magento...) là phần mềm dựng sẵn để làm website. Công cụ nhận ra nhờ dấu hiệu công khai trong trang.",
        "Dùng CMS không có gì sai, nhưng vì phổ biến nên bị dò tìm lỗi rất nhiều. Phiên bản cũ hoặc plugin không cập nhật là nguồn rủi ro lớn nhất.",
        "1) Luôn cập nhật CMS, giao diện và plugin lên bản mới.\n"
        "2) Gỡ plugin/giao diện không dùng.\n"
        "3) Dùng mật khẩu mạnh cho quản trị và bật xác thực hai lớp.\n"
        "4) Ẩn dấu hiệu phiên bản nếu có thể (ví dụ WordPress: remove_action('wp_head', 'wp_generator');).",
        [("OWASP: Vulnerable and Outdated Components", "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/")],
    ),
    # ---------------------------------------------------------------- Cổng mạng
    "port_ftp": _entry(
        "Cổng 21 (FTP) đang mở",
        "FTP là cách cũ để tải tệp lên máy chủ. Dữ liệu và mật khẩu đi qua mạng không được mã hóa.",
        "Mật khẩu có thể bị nghe lén; FTP cũng thường là mục tiêu dò mật khẩu hàng loạt.",
        "Chuyển sang SFTP (qua cổng 22) hoặc FTPS rồi đóng cổng 21:\n"
        "ufw deny 21/tcp   (hoặc chặn trong tường lửa của nhà cung cấp hosting)",
        [],
    ),
    "port_ssh": _entry(
        "Cổng 22 (SSH) đang mở",
        "SSH là cách quản trị máy chủ từ xa có mã hóa. Cổng mở là bình thường nếu bạn cần quản trị từ xa.",
        "Cổng này bị dò mật khẩu liên tục từ khắp internet. Nếu dùng mật khẩu yếu, máy chủ có nguy cơ bị chiếm.",
        "Tắt đăng nhập bằng mật khẩu, chỉ dùng khóa SSH; không cho root đăng nhập; cài fail2ban; giới hạn IP nếu có thể:\n"
        "/etc/ssh/sshd_config:  PasswordAuthentication no  và  PermitRootLogin no\n"
        "ufw allow from 203.0.113.10 to any port 22",
        [],
    ),
    "port_telnet": _entry(
        "Cổng 23 (Telnet) đang mở",
        "Telnet là cách điều khiển máy từ xa rất cũ, không có mã hóa.",
        "Mọi thứ gõ vào, kể cả mật khẩu, đi qua mạng dạng chữ thường. Đây là cổng rất hay bị tấn công.",
        "Tắt dịch vụ Telnet và đóng cổng 23; dùng SSH thay thế:\n"
        "systemctl disable --now telnet.socket   ;   ufw deny 23/tcp",
        [],
    ),
    "port_mail": _entry(
        "Cổng thư điện tử (25/110/143) đang mở",
        "Các cổng này dành cho dịch vụ gửi và nhận thư (SMTP, POP3, IMAP).",
        "Máy chủ thư cấu hình sai có thể bị lợi dụng gửi thư rác, hoặc thư và mật khẩu đi qua mạng không mã hóa.",
        "Nếu không chạy máy chủ thư, đóng các cổng này. Nếu có, bật mã hóa (SMTPS 465/587, IMAPS 993, POP3S 995), "
        "bắt buộc đăng nhập và đóng các cổng không mã hóa.",
        [],
    ),
    "port_dns": _entry(
        "Cổng 53 (DNS) đang mở",
        "DNS là dịch vụ \"danh bạ\" đổi tên miền thành địa chỉ IP.",
        "DNS mở cho mọi người có thể bị lợi dụng để khuếch đại tấn công làm sập dịch vụ khác, hoặc bị dò thông tin vùng tên miền.",
        "Nếu máy chủ này không phải máy chủ DNS, đóng cổng 53. Nếu có, tắt chế độ trả lời đệ quy cho người ngoài và chặn chuyển vùng (zone transfer).",
        [],
    ),
    "port_web": _entry(
        "Cổng web (80/443/8080/8443) đang mở",
        "Đây là các cổng của website (HTTP/HTTPS). Mở là điều bình thường với một website.",
        "Bản thân việc mở cổng không nguy hiểm. Cổng phụ như 8080/8443 đôi khi là trang quản trị hay môi trường thử nghiệm bị quên.",
        "Với cổng 8080/8443, kiểm tra xem đó có phải dịch vụ cần công khai không; nếu không thì đóng hoặc chặn bằng tường lửa. "
        "Cổng 80 nên chỉ dùng để chuyển hướng sang HTTPS.",
        [],
    ),
    "port_mysql": _entry(
        "Cổng 3306 (cơ sở dữ liệu MySQL) mở ra internet",
        "MySQL là phần mềm lưu dữ liệu của website. Cổng của nó đang mở cho cả internet.",
        "Cơ sở dữ liệu chỉ nên được chính website kết nối. Mở ra ngoài khiến kẻ xấu dò mật khẩu trực tiếp vào nơi chứa toàn bộ dữ liệu.",
        "Chỉ cho MySQL nghe trên địa chỉ nội bộ: my.cnf  bind-address = 127.0.0.1\n"
        "Và chặn cổng bằng tường lửa: ufw deny 3306/tcp",
        [],
    ),
    "port_rdp": _entry(
        "Cổng 3389 (Remote Desktop) đang mở",
        "RDP là cách điều khiển máy Windows từ xa bằng giao diện đồ họa.",
        "Đây là một trong những đường chính bị tấn công mã hóa tống tiền (ransomware) vì bị dò mật khẩu liên tục.",
        "Đóng cổng 3389 với internet; truy cập qua VPN hoặc cổng bảo vệ (RD Gateway), bật xác thực hai lớp và yêu cầu Network Level Authentication.",
        [],
    ),
    "port_other": _entry(
        "Có một cổng mạng đang mở",
        "Cổng là \"cửa\" để một dịch vụ trên máy chủ nhận kết nối từ ngoài.",
        "Mỗi cổng mở là một nơi có thể bị dò tìm lỗi. Dịch vụ không cần dùng nên được đóng lại.",
        "Xác định dịch vụ nào đang dùng cổng; nếu không cần công khai thì tắt dịch vụ hoặc chặn bằng tường lửa (ví dụ ufw deny <số cổng>/tcp).",
        [],
    ),
    # ---------------------------------------------------------------- TLS / HTTPS
    "tls_no_https": _entry(
        "Website không hỗ trợ HTTPS",
        "HTTPS là phiên bản có mã hóa của HTTP (biểu tượng ổ khóa trên trình duyệt). Website này không trả lời trên cổng HTTPS.",
        "Mọi dữ liệu giữa người dùng và website (mật khẩu, thông tin cá nhân) đi dạng chữ thường, ai trên đường truyền cũng đọc và sửa được. Trình duyệt cũng sẽ cảnh báo \"Không an toàn\".",
        "Cài chứng chỉ miễn phí của Let's Encrypt rồi bật HTTPS:\n"
        "sudo certbot --nginx -d vidu.com -d www.vidu.com   (hoặc --apache)\n"
        "Sau đó chuyển hướng HTTP sang HTTPS.",
        [OWASP_TLS, ("Let's Encrypt", "https://letsencrypt.org/getting-started/")],
    ),
    "tls_no_redirect": _entry(
        "HTTP không tự chuyển sang HTTPS",
        "Website có HTTPS nhưng ai gõ địa chỉ dạng http:// vẫn vào được bản không mã hóa.",
        "Người dùng có thể vô tình dùng bản không mã hóa và bị nghe lén hoặc chỉnh sửa nội dung.",
        "Nginx:  server { listen 80; server_name vidu.com; return 301 https://$host$request_uri; }\n"
        "Apache: RewriteEngine On  RewriteCond %{HTTPS} off  RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n"
        "Flask:  dùng flask-talisman hoặc cấu hình ở Nginx phía trước.",
        [OWASP_TLS],
    ),
    "tls_expired": _entry(
        "Chứng chỉ HTTPS đã hết hạn",
        "Chứng chỉ là \"giấy chứng nhận\" chứng minh website đúng là của bạn. Giấy này đã quá hạn.",
        "Trình duyệt hiện cảnh báo đỏ chặn người dùng vào, và không còn bảo đảm họ đang nói chuyện với đúng website.",
        "Gia hạn ngay: sudo certbot renew  (rồi nạp lại máy chủ: sudo systemctl reload nginx).\n"
        "Bật gia hạn tự động và nhắc nhở trước ngày hết hạn.",
        [OWASP_TLS, ("Let's Encrypt", "https://letsencrypt.org/getting-started/")],
    ),
    "tls_expiring": _entry(
        "Chứng chỉ HTTPS sắp đến hạn",
        "Chứng chỉ HTTPS của website còn hạn nhưng sắp hết.",
        "Nếu quên gia hạn, người dùng sẽ gặp cảnh báo đỏ và không vào được website.",
        "Gia hạn sớm và bật tự động: sudo certbot renew --dry-run để thử; kiểm tra cron/systemd timer của certbot đang chạy.",
        [("Let's Encrypt", "https://letsencrypt.org/getting-started/")],
    ),
    "tls_hostname": _entry(
        "Chứng chỉ HTTPS không khớp tên miền",
        "Chứng chỉ được cấp cho một tên miền khác với tên miền đang được truy cập.",
        "Trình duyệt hiện cảnh báo \"kết nối không riêng tư\". Người dùng quen bấm bỏ qua cảnh báo sẽ dễ mắc bẫy trang giả mạo.",
        "Cấp lại chứng chỉ có đủ các tên miền bạn dùng (cả có www và không www):\n"
        "sudo certbot --nginx -d vidu.com -d www.vidu.com",
        [OWASP_TLS],
    ),
    "tls_invalid": _entry(
        "Chứng chỉ HTTPS không đáng tin cậy",
        "Trình duyệt không xác minh được chứng chỉ: có thể do tự tạo (tự ký), thiếu chứng chỉ trung gian hoặc nơi cấp không được tin cậy.",
        "Người dùng thấy cảnh báo đỏ, và không có gì đảm bảo họ đang kết nối đúng website thật.",
        "Dùng chứng chỉ từ nơi cấp được tin cậy (ví dụ Let's Encrypt) và cài đủ chuỗi chứng chỉ (fullchain.pem):\n"
        "Nginx: ssl_certificate /etc/letsencrypt/live/vidu.com/fullchain.pem;",
        [OWASP_TLS],
    ),
    "tls_nodata": _entry(
        "Không đọc được thời hạn chứng chỉ",
        "Kết nối HTTPS thành công nhưng công cụ không đọc được ngày hết hạn của chứng chỉ.",
        "Chưa đủ thông tin để kết luận chứng chỉ còn hạn hay không.",
        "Mở website bằng trình duyệt, bấm vào ổ khóa để xem ngày hết hạn, hoặc dùng công cụ như SSL Labs để kiểm tra lại.",
        [("SSL Labs", "https://www.ssllabs.com/ssltest/")],
    ),
    "tls_handshake": _entry(
        "Không thiết lập được kết nối HTTPS",
        "Công cụ thử bắt tay (handshake) HTTPS với website nhưng bị từ chối hoặc không tương thích, nên chưa kiểm tra được chứng chỉ.",
        "Nếu người dùng thật cũng gặp lỗi này thì họ không vào được website bằng HTTPS, hoặc trình duyệt sẽ báo lỗi bảo mật.",
        "Mở website bằng trình duyệt xem có lỗi không; kiểm tra chứng chỉ có đủ chuỗi (fullchain), giao thức TLS 1.2/1.3 đã bật, "
        "và nhật ký lỗi của máy chủ web. Sau khi sửa, hãy quét lại.",
        [("SSL Labs", "https://www.ssllabs.com/ssltest/"), OWASP_TLS],
    ),
    "tls_weak_protocol": _entry(
        "Máy chủ còn dùng giao thức mã hóa cũ",
        "Máy chủ vẫn chấp nhận phiên bản SSL/TLS đã lỗi thời (SSLv3, TLS 1.0, TLS 1.1) có điểm yếu đã được công bố.",
        "Kẻ xấu có thể bẻ lớp mã hóa yếu để đọc dữ liệu giữa người dùng và website.",
        "Chỉ bật TLS 1.2 và 1.3.\n"
        "Nginx:  ssl_protocols TLSv1.2 TLSv1.3;\n"
        "Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3",
        [OWASP_TLS, ("Mozilla SSL Config", "https://ssl-config.mozilla.org/")],
    ),
    "tls_weak_cipher": _entry(
        "Máy chủ còn dùng thuật toán mã hóa yếu",
        "Thuật toán (cipher) dùng để mã hóa kết nối là loại cũ hoặc khóa quá ngắn.",
        "Mã hóa yếu có thể bị bẻ, khiến lớp bảo vệ HTTPS mất tác dụng.",
        "Dùng cấu hình khuyến nghị của Mozilla (loại bỏ RC4, 3DES, DES, EXPORT, NULL):\n"
        "https://ssl-config.mozilla.org/  (chọn Nginx/Apache và mức \"Intermediate\")",
        [OWASP_TLS, ("Mozilla SSL Config", "https://ssl-config.mozilla.org/")],
    ),
}

_HEADER_FAMILIES = (
    ("strict-transport-security|hsts", "hsts"),
    ("content-security-policy|csp", "csp"),
    ("x-frame-options", "xfo"),
    ("x-content-type-options", "xcto"),
    ("referrer-policy", "referrer"),
    ("permissions-policy", "permissions"),
)

_PORT_KEYS = {
    21: "port_ftp", 22: "port_ssh", 23: "port_telnet",
    25: "port_mail", 110: "port_mail", 143: "port_mail",
    53: "port_dns",
    80: "port_web", 443: "port_web", 8080: "port_web", 8443: "port_web",
    3306: "port_mysql", 3389: "port_rdp",
}

_PATH_KEYS = {
    ".env": "path_env",
    ".git/config": "path_git",
    ".htaccess": "path_htaccess",
    "backup.zip": "path_backup_zip",
    "backup.sql": "path_backup_sql",
    "config.php.bak": "path_config_bak",
    "phpinfo.php": "path_phpinfo",
    "server-status": "path_server_status",
    "web.config": "path_web_config",
    "admin/": "path_admin",
    "administrator/": "path_admin",
    "wp-admin/": "path_admin",
}


def _header_family(text):
    lowered = text.lower()
    for pattern, family in _HEADER_FAMILIES:
        if re.search(pattern, lowered):
            return family
    return None


def lookup_key(finding):
    """Trả về khóa từ điển cho finding, hoặc None nếu không nhận ra."""
    module = (finding.get("module") or "")
    title = (finding.get("title") or "")
    lowered = title.lower()

    if module == "Header Check":
        if lowered.startswith("thiếu header:"):
            family = _header_family(title)
            return f"{family}_missing" if family else None
        if lowered.startswith("rò rỉ thông tin"):
            return "info_leak"
        return None

    if module == "Security Header":
        family = _header_family(title)
        return f"{family}_weak" if family else None

    if module == "Cookie Check":
        if "thiếu secure" in lowered:
            return "cookie_secure"
        if "httponly" in lowered:
            return "cookie_httponly"
        if "samesite" in lowered:
            return "cookie_samesite"
        return "cookie_other"

    if module == "CORS Check":
        if "cho phép mọi origin" in lowered:
            return "cors_open"
        if "phản chiếu" in lowered:
            return "cors_reflect"
        return "cors_other"

    if module == "Directory Check":
        match = re.match(r"path:\s*/(\S+)", lowered)
        path = match.group(1) if match else ""
        key = _PATH_KEYS.get(path)
        if key == "path_admin":
            return key
        if key and finding.get("severity") != "Info":
            return key
        return "path_info" if match else None

    if module == "Robots.txt Check":
        return "robots_sensitive"

    if module == "CMS Detection":
        return "cms"

    if module == "Port Scan":
        match = re.search(r"(\d+)", title)
        if not match:
            return None
        return _PORT_KEYS.get(int(match.group(1)), "port_other")

    if module == "TLS/SSL Check":
        if "không hỗ trợ https" in lowered:
            return "tls_no_https"
        if "không chuyển hướng" in lowered:
            return "tls_no_redirect"
        if "đã hết hạn" in lowered:
            return "tls_expired"
        if "sắp hết hạn" in lowered or "gần đến kỳ gia hạn" in lowered:
            return "tls_expiring"
        if "hostname không khớp" in lowered:
            return "tls_hostname"
        if "không hợp lệ" in lowered:
            return "tls_invalid"
        if "handshake" in lowered:
            return "tls_handshake"
        if "không đủ dữ liệu" in lowered:
            return "tls_nodata"
        if "giao thức yếu" in lowered:
            return "tls_weak_protocol"
        if "cipher yếu" in lowered:
            return "tls_weak_cipher"
        return None

    return None


def explain(finding):
    """Luôn trả về dict giải thích hợp lệ cho một finding (không bao giờ ném lỗi)."""
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
        "what": entry["what"],
        "why": entry["why"],
        "fix": entry["fix"],
        "learn_more": list(entry["learn_more"]),
        "generic": generic,
    }
