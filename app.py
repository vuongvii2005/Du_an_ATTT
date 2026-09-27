# -*- coding: utf-8 -*-
"""
app.py
Flask Web UI cho Lightweight Web Vulnerability Scanner.

Chức năng:
- GET  /       : hiển thị form nhập URL cần quét.
- POST /scan   : chạy scanner.py và hiển thị kết quả dưới dạng báo cáo trực quan.
- POST /compare: chạy hai URL và hiển thị báo cáo cạnh nhau.

Lưu ý: Đây là công cụ thu thập thông tin thụ động (passive recon). Chỉ nên sử
dụng trên hệ thống bạn sở hữu hoặc đã được cấp phép rõ ràng để kiểm tra.
"""

from flask import Flask, render_template, request

import scanner

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    target_url = request.form.get("url", "").strip()

    if not target_url:
        return render_template("index.html", error="Vui lòng nhập URL cần quét.")

    try:
        report = scanner.run_scan(target_url)
        return render_template("result.html", report=report)

    except scanner.ScannerError as e:
        # Lỗi đã được xử lý rõ ràng: Timeout, SSL Error, Connection Failure, URL không hợp lệ...
        return render_template("index.html", error=str(e), previous_url=target_url)

    except Exception as e:
        # Lỗi phát sinh ngoài dự kiến - vẫn hiển thị thân thiện, không để app crash
        return render_template(
            "index.html",
            error=f"Đã xảy ra lỗi không xác định trong quá trình quét: {str(e)}",
            previous_url=target_url,
        )


@app.route("/compare", methods=["POST"])
def compare():
    first_url = request.form.get("url_a", "").strip()
    second_url = request.form.get("url_b", "").strip()

    if not first_url or not second_url:
        return render_template(
            "index.html",
            error="Vui lòng nhập đủ 2 URL để so sánh.",
            previous_url_a=first_url,
            previous_url_b=second_url,
        )

    try:
        reports = [
            scanner.run_scan(first_url),
            scanner.run_scan(second_url),
        ]
        return render_template("compare.html", reports=reports)

    except scanner.ScannerError as e:
        return render_template(
            "index.html",
            error=str(e),
            previous_url_a=first_url,
            previous_url_b=second_url,
        )

    except Exception as e:
        return render_template(
            "index.html",
            error=f"Đã xảy ra lỗi không xác định trong quá trình quét: {str(e)}",
            previous_url_a=first_url,
            previous_url_b=second_url,
        )


if __name__ == "__main__":
    # debug=True chỉ nên dùng trong môi trường phát triển (development)
    app.run(host="0.0.0.0", port=5000, debug=True)
