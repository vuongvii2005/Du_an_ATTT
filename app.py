# -*- coding: utf-8 -*-
"""Flask UI for the bounded web reconnaissance scanner."""

import hmac
import os
import secrets

from flask import Flask, abort, render_template, request, session

import knowledge
import scanner


def _env_port():
    try:
        port = int(os.getenv("SCANNER_PORT", "5000"))
    except ValueError:
        return 5000
    return port if 1 <= port <= 65535 else 5000


def create_app(test_config=None):
    app = Flask(__name__)
    secret_key = os.getenv("SCANNER_SECRET_KEY") or secrets.token_hex(32)
    app.config.update(
        SECRET_KEY=secret_key,
        CSRF_ENABLED=True,
        MAX_CONTENT_LENGTH=16 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("SCANNER_COOKIE_SECURE", "").lower()
        in {"1", "true", "yes"},
    )
    if test_config:
        app.config.update(test_config)
    if not os.getenv("SCANNER_SECRET_KEY") and not app.config.get("TESTING"):
        app.logger.warning(
            "SCANNER_SECRET_KEY chưa được đặt; đang dùng khóa ngẫu nhiên chỉ phù hợp chạy cục bộ."
        )

    def csrf_token():
        token = session.get("_csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["_csrf_token"] = token
        return token

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def validate_csrf():
        if request.method == "POST" and app.config.get("CSRF_ENABLED", True):
            expected = session.get("_csrf_token", "")
            supplied = request.form.get("_csrf_token", "")
            if not expected or not supplied or not hmac.compare_digest(expected, supplied):
                abort(400, description="Phiên biểu mẫu không hợp lệ hoặc đã hết hạn.")

    @app.route("/", methods=["GET"])
    def index():
        return render_template("index.html")

    @app.route("/glossary", methods=["GET"])
    def glossary():
        return render_template("glossary.html", entries=knowledge.ENTRIES, fallback=knowledge.FALLBACK)

    @app.route("/scan", methods=["POST"])
    def scan():
        target_url = request.form.get("url", "").strip()
        if not target_url:
            return render_template("index.html", error="Vui lòng nhập URL cần quét."), 400
        try:
            report = scanner.run_scan(target_url)
            return render_template("result.html", report=report)
        except scanner.ScannerError as exc:
            return render_template(
                "index.html", error=str(exc), previous_url=target_url
            ), 400
        except Exception:
            app.logger.exception("Lỗi không mong đợi khi quét một URL")
            return render_template(
                "index.html",
                error="Đã xảy ra lỗi nội bộ. Không có request quét nào được tiếp tục.",
                previous_url=target_url,
            ), 500

    @app.route("/compare", methods=["POST"])
    def compare():
        urls = [
            ("A", request.form.get("url_a", "").strip()),
            ("B", request.form.get("url_b", "").strip()),
        ]
        if any(not url for _, url in urls):
            return render_template(
                "index.html",
                error="Vui lòng nhập đủ 2 URL để so sánh.",
                previous_url_a=urls[0][1],
                previous_url_b=urls[1][1],
            ), 400

        comparison_results = []
        for label, target_url in urls:
            try:
                comparison_results.append(
                    {"label": label, "url": target_url, "report": scanner.run_scan(target_url), "error": None}
                )
            except scanner.ScannerError as exc:
                comparison_results.append(
                    {"label": label, "url": target_url, "report": None, "error": str(exc)}
                )
            except Exception:
                app.logger.exception("Lỗi không mong đợi khi quét website %s", label)
                comparison_results.append(
                    {
                        "label": label,
                        "url": target_url,
                        "report": None,
                        "error": "Đã xảy ra lỗi nội bộ khi quét website này.",
                    }
                )
        return render_template("compare.html", comparison_results=comparison_results)

    @app.errorhandler(400)
    def bad_request(error):
        return render_template(
            "index.html", error=getattr(error, "description", "Yêu cầu không hợp lệ.")
        ), 400

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("index.html", error="Không tìm thấy trang được yêu cầu."), 404

    @app.errorhandler(500)
    def internal_error(_error):
        return render_template("index.html", error="Đã xảy ra lỗi nội bộ."), 500

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host=os.getenv("SCANNER_HOST", "127.0.0.1"), port=_env_port(), debug=False)
