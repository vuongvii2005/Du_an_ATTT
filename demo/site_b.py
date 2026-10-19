"""Hardened local fixture used as the scanner demo counterpart."""

from flask import Flask, Response, make_response, render_template_string, request


app = Flask(__name__)
TRUSTED_ORIGIN = "https://trusted.example"

PAGE = """<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <title>Demo Website B</title>
</head>
<body>
  <main>
    <h1>Website B — đã khắc phục</h1>
    <p>Fixture cục bộ với cấu hình an toàn hơn để đối chiếu với Website A.</p>
    <ul>
      <li>Security headers có giá trị chặt chẽ</li>
      <li>Cookie có Secure, HttpOnly và SameSite</li>
      <li>CORS chỉ cho phép origin tin cậy</li>
      <li>Các path nhạy cảm không trả dữ liệu fixture</li>
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


@app.get("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /\n", mimetype="text/plain")


@app.get("/admin/")
def admin():
    return Response("Authentication required\n", status=403, mimetype="text/plain")


@app.get("/server-status")
def server_status():
    return Response("Forbidden\n", status=403, mimetype="text/plain")


@app.route("/<path:requested_path>")
def not_found(requested_path):
    # Keep every unexposed fixture as a bounded, harmless 404 response.
    return Response("Not found\n", status=404, mimetype="text/plain")


@app.after_request
def add_security_headers(response):
    response.headers.update({
        "Content-Security-Policy": (
            "default-src 'self'; script-src 'self'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'"
        ),
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Vary": "Origin",
    })

    if request.headers.get("Origin") == TRUSTED_ORIGIN:
        response.headers["Access-Control-Allow-Origin"] = TRUSTED_ORIGIN
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=False, use_reloader=False)
