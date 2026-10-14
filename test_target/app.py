# -*- coding: utf-8 -*-
"""
Local fixture used to test the scanner safely.

This is intentionally insecure-looking, but it only returns dummy text and
listens on 127.0.0.1. Do not expose it to a network interface.
"""

from flask import Flask, Response, redirect


app = Flask(__name__)


EXPOSED_FIXTURES = {
    ".env": "TEST_FIXTURE_ONLY=1\nFAKE_SECRET=not-a-real-secret\n",
    ".git/config": "[test-fixture]\nrepository = dummy\n",
    "backup.zip": "dummy backup fixture\n",
    "backup.sql": "-- dummy SQL backup fixture\n",
    "config.php.bak": "<?php // dummy config fixture ?>\n",
    "phpinfo.php": "Test fixture pretending to be phpinfo\n",
    "administrator/": "Dummy administrator fixture\n",
    "wp-admin/": "Dummy WordPress admin fixture\n",
    ".well-known/security.txt": "Contact: security@example.test\n",
    "web.config": "<!-- dummy web.config fixture -->\n",
}


@app.get("/")
def home():
    # Deliberately omits security headers so header_checker has findings.
    return Response(
        """<!doctype html>
<html lang="en">
  <head>
    <meta name="generator" content="WordPress 6.0-test">
    <link rel="stylesheet" href="/wp-content/themes/test/style.css">
  </head>
  <body><h1>Local scanner test target</h1></body>
</html>
""",
        mimetype="text/html",
    )


@app.get("/robots.txt")
def robots():
    return Response(
        """User-agent: *
Disallow: /admin-panel/
Disallow: /backup.sql
Disallow: /private/
""",
        mimetype="text/plain",
    )


@app.get("/admin/")
def admin_redirect():
    # Exercises the directory checker's redirect branch.
    return redirect("/login", code=302)


@app.get("/server-status")
def server_status():
    # Exercises the directory checker's 403 branch.
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


if __name__ == "__main__":
    # 8080 is one of the ports checked by modules/port_checker.py.
    app.run(host="127.0.0.1", port=8080, debug=False)
