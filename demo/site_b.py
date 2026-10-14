"""Hardened HTTP counterpart for the authorized local scanner demo."""

from flask import Flask, make_response, render_template_string, request


app = Flask(__name__)
TRUSTED_ORIGIN = "https://trusted.example"

PAGE = """<!doctype html>
<html lang="vi">
<head><meta charset="utf-8"><title>Demo Website B</title></head>
<body>
  <main>
    <h1>Website B — đã khắc phục</h1>
    <p>Giao diện tương đương Website A sau khi tăng cường cấu hình bảo mật.</p>
    <ul>
      <li>Security headers có giá trị an toàn</li>
      <li>Cookie có Secure, HttpOnly và SameSite</li>
      <li>CORS chỉ cho phép origin tin cậy</li>
    </ul>
  </main>
</body>
</html>
"""


@app.get("/")
def index():
    response = make_response(render_template_string(PAGE))
    response.set_cookie(
        "demo_session",
        "site-b-demo",
        secure=True,
        httponly=True,
        samesite="Lax",
        path="/",
    )
    return response


@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Vary"] = "Origin"

    if request.headers.get("Origin") == TRUSTED_ORIGIN:
        response.headers["Access-Control-Allow-Origin"] = TRUSTED_ORIGIN
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=False, use_reloader=False)
