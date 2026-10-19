from requests.structures import CaseInsensitiveDict

from modules import header_checker


def _secure_headers(**extra):
    headers = {
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    }
    headers.update(extra)
    return headers


class RawHeaders:
    def __init__(self, cookies):
        self.cookies = cookies

    def getlist(self, name):
        return self.cookies if name.lower() == "set-cookie" else []


class Response:
    def __init__(self, headers=None, url="https://app.example.com/", status_code=200,
                 cookies=None):
        self.headers = CaseInsensitiveDict(headers or {})
        self.url = url
        self.status_code = status_code
        self.raw = type("Raw", (), {"headers": RawHeaders(cookies or [])})()


def test_secure_headers_and_cookie_do_not_raise_findings():
    response = Response(
        _secure_headers(**{"Set-Cookie": "session=hidden; Secure; HttpOnly; SameSite=Lax; Path=/"}),
        cookies=["session=hidden; Secure; HttpOnly; SameSite=Lax; Path=/"],
    )

    result = header_checker.run(response)

    assert result["status"] == "success"
    assert result["missing_headers"] == []
    assert result["findings"] == []
    assert result["cookies"][0] == {
        "name": "session",
        "secure": True,
        "http_only": True,
        "same_site": "Lax",
        "domain": None,
        "path": "/",
    }


def test_weak_security_header_values_are_reported():
    response = Response(_secure_headers(**{
        "Content-Security-Policy": "default-src *; script-src * 'unsafe-inline' 'unsafe-eval'",
        "Strict-Transport-Security": "max-age=0",
        "X-Frame-Options": "ALLOW-FROM https://example.com",
        "X-Content-Type-Options": "sniff",
        "Referrer-Policy": "unsafe-url",
        "Permissions-Policy": "camera=*, geolocation=()",
    }))

    result = header_checker.run(response)
    titles = {item["title"] for item in result["findings"]}

    assert {
        "CSP cho phép inline script không an toàn",
        "CSP cho phép unsafe-eval",
        "CSP cho phép script từ mọi nguồn",
        "HSTS đang bị vô hiệu hóa",
        "X-Frame-Options không hợp lệ",
        "X-Content-Type-Options không hiệu lực",
        "Referrer-Policy làm lộ toàn bộ URL",
        "Permissions-Policy cấp quyền cho mọi origin",
    } <= titles


def test_cookie_attributes_are_analyzed_without_exposing_values():
    cookie_lines = [
        "session_token=top-secret; Path=/",
        "preferences=private-value; Secure; HttpOnly; SameSite=None; Domain=.example.com; Path=/",
        "cross_session=cross-secret; HttpOnly; SameSite=None; Path=/",
    ]
    response = Response(
        _secure_headers(**{"Set-Cookie": cookie_lines[0]}),
        cookies=cookie_lines,
    )

    result = header_checker.run(response)
    titles = {item["title"] for item in result["findings"]}

    assert "Cookie 'session_token' thiếu Secure" in titles
    assert "Cookie 'session_token' thiếu HttpOnly" in titles
    assert "Cookie 'session_token' thiếu SameSite" in titles
    assert "Cookie 'preferences' mở rộng phạm vi Domain" in titles
    assert "Cookie 'cross_session' dùng SameSite=None nhưng thiếu Secure" in titles
    assert "top-secret" not in str(result)
    assert "private-value" not in str(result)
    assert "cross-secret" not in str(result)
    assert result["raw_headers"]["Set-Cookie"].startswith("[đã ẩn")


def test_cors_reflection_uses_one_guarded_non_redirecting_probe():
    initial = Response(_secure_headers(Vary="Origin"))

    class Session:
        def __init__(self):
            self.calls = []

        def get(self, url, **kwargs):
            self.calls.append((url, kwargs))
            return Response({
                "Access-Control-Allow-Origin": header_checker.PROBE_ORIGIN,
                "Access-Control-Allow-Credentials": "true",
            })

    session = Session()
    result = header_checker.run(
        initial,
        session=session,
        target_url=initial.url,
    )

    assert len(session.calls) == 1
    assert session.calls[0][1]["headers"]["Origin"] == header_checker.PROBE_ORIGIN
    assert session.calls[0][1]["allow_redirects"] is False
    assert result["cors"]["origin_reflected"] is True
    finding = next(item for item in result["findings"] if "phản chiếu" in item["title"])
    assert finding["severity"] == "Medium"


def test_cors_wildcard_is_reported_without_extra_probe():
    response = Response(_secure_headers(**{
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    }))

    class Session:
        def get(self, *_args, **_kwargs):
            raise AssertionError("wildcard CORS must not trigger a redundant probe")

    result = header_checker.run(response, session=Session(), target_url=response.url)

    finding = next(item for item in result["findings"] if item["title"] == "CORS cho phép mọi origin")
    assert finding["severity"] == "Medium"
    assert result["cors"]["probe_status"] == "skipped"


def test_cors_credentials_value_is_case_sensitive():
    response = Response(_secure_headers(**{
        "Access-Control-Allow-Origin": "https://client.example",
        "Access-Control-Allow-Credentials": "TRUE",
    }))

    result = header_checker.run(response)

    assert any(
        item["title"] == "Access-Control-Allow-Credentials không hợp lệ"
        for item in result["findings"]
    )
