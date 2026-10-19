"""Intentionally weak local fixture for the authorized scanner demo."""

from flask import Flask, Response, make_response, redirect, render_template_string, request


app = Flask(__name__)

PAGE = """<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <meta name="generator" content="WordPress 6.0-test">
  <link rel="stylesheet" href="/wp-content/themes/demo/style.css">
  <title>Demo Website A</title>
</head>
<body>
  <main>
    <h1>Website A — cấu hình yếu</h1>
    <p>Fixture cục bộ dùng để minh họa các phát hiện bảo mật của scanner.</p>
    <ul>
      <li>Thiếu security headers</li>
      <li>Cookie thiếu thuộc tính bảo vệ</li>
      <li>CORS phản chiếu Origin</li>
      <li>Có path giả lập dữ liệu nhạy cảm</li>
    </ul>
  </main>
</body>
</html>
"""

# Nội dung chỉ là dữ liệu giả; các chữ ký này giúp directory checker tạo finding
# đã xác minh mà không đụng tới file bí mật thật trên máy.
EXPOSED_FIXTURES = {
    ".env": "APP_KEY=dummy-site-a-key\nDB_PASSWORD=not-a-real-password\nTEST_FIXTURE_ONLY=1\n",
    ".git/config": "[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
    ".htaccess": "RewriteEngine On\nRequire all granted\n",
    "backup.zip": b"PK\x03\x04dummy site-a backup fixture\n",
    "backup.sql": "-- MySQL dump (dummy fixture)\nCREATE TABLE demo (id INT);\nINSERT INTO demo VALUES (1);\n",
    "config.php.bak": "<?php // dummy fixture\n$db_password = 'not-a-real-password';\n?>\n",
    "phpinfo.php": "<html><body>phpinfo() dummy fixture - PHP Version 0.0-test</body></html>\n",
    "web.config": "<configuration><system.web></system.web></configuration>\n",
    "administrator/": "Dummy administrator fixture\n",
    "wp-admin/": "Dummy WordPress admin fixture\n",
    ".well-known/security.txt": "Contact: security@example.test\n",
}


@app.get("/")
def index():
    response = make_response(render_template_string(PAGE))
    response.set_cookie("demo_session", "site-a-demo", path="/")
    return response


@app.get("/robots.txt")
def robots():
    return Response(
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /backup.sql\n"
        "Disallow: /private/\n",
        mimetype="text/plain",
    )


@app.get("/admin/")
def admin_redirect():
    return redirect("/login", code=302)


@app.get("/server-status")
def server_status():
    return Response("Forbidden test fixture\n", status=403, mimetype="text/plain")


@app.get("/login")
def login():
    return Response("Dummy login page\n", mimetype="text/plain")


@app.route("/<path:requested_path>")
def fixture_path(requested_path):
    content = EXPOSED_FIXTURES.get(requested_path)
    if content is None:
        return Response("Not found\n", status=404, mimetype="text/plain")
    return Response(content, mimetype="text/plain")


@app.after_request
def add_unsafe_headers(response):
    # Deliberately reflect arbitrary Origin and expose a technology hint.
    response.headers["Access-Control-Allow-Origin"] = request.headers.get(
        "Origin", "https://untrusted.example"
    )
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["X-Powered-By"] = "DemoSiteA/0.1"
    response.headers["Vary"] = "Origin"
    return response


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False, use_reloader=False)
