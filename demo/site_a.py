"""Intentionally weak HTTP site for an authorized local scanner demo."""

from flask import Flask, make_response, render_template_string, request


app = Flask(__name__)

PAGE = """<!doctype html>
<html lang="vi">
<head><meta charset="utf-8"><title>Demo Website A</title></head>
<body>
  <main>
    <h1>Website A — cấu hình yếu</h1>
    <p>Ứng dụng Flask cục bộ dùng để minh họa finding trước khi khắc phục.</p>
    <ul>
      <li>Thiếu security headers</li>
      <li>Cookie thiếu thuộc tính bảo vệ</li>
      <li>CORS phản chiếu Origin</li>
    </ul>
  </main>
</body>
</html>
"""


@app.get("/")
def index():
    response = make_response(render_template_string(PAGE))
    response.set_cookie("demo_session", "site-a-demo", path="/")
    return response


@app.after_request
def add_unsafe_cors(response):
    response.headers["Access-Control-Allow-Origin"] = request.headers.get(
        "Origin", "https://untrusted.example"
    )
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Vary"] = "Origin"
    return response


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False, use_reloader=False)
