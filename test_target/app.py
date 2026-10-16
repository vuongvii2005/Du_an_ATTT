# -*- coding: utf-8 -*-
"""
Local fixture used to test the scanner safely.

This is intentionally insecure-looking, but it only returns dummy text and
listens on 127.0.0.1. Do not expose it to a network interface.
"""

from flask import Flask, Response, redirect


app = Flask(__name__)


# Dummy content only. Each fixture is shaped so that the directory checker's
# content signatures (dir_checker._sensitive_evidence) recognise it, which lets
# the scanner demonstrate "verified" High findings without any real secret.
EXPOSED_FIXTURES = {
    ".env": "APP_KEY=dummy-fixture-value\nDB_PASSWORD=not-a-real-password\nTEST_FIXTURE_ONLY=1\n",
    ".git/config": "[core]\n\trepositoryformatversion = 0\n\tbare = false\n[test-fixture]\n\trepository = dummy\n",
    "backup.zip": b"PK\x03\x04dummy backup fixture (not a real archive)\n",
    "backup.sql": "-- MySQL dump (dummy fixture)\nCREATE TABLE fixture (id INT);\nINSERT INTO fixture VALUES (1);\n",
    "config.php.bak": "<?php // dummy fixture\n$db_password = 'not-a-real-password';\n?>\n",
    "phpinfo.php": "<html><body>phpinfo() dummy fixture - PHP Version 0.0-test</body></html>\n",
    "administrator/": "Dummy administrator fixture\n",
    "wp-admin/": "Dummy WordPress admin fixture\n",
    ".well-known/security.txt": "Contact: security@example.test\n",
    "web.config": "<configuration><system.web></system.web></configuration>\n",
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
