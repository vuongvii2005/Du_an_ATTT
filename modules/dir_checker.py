# -*- coding: utf-8 -*-
"""Bounded checks for a small, fixed list of commonly exposed paths."""

from difflib import SequenceMatcher
import re
import secrets
import time

import requests


COMMON_SENSITIVE_PATHS = [
    ".env",
    ".git/config",
    ".htaccess",
    "backup.zip",
    "backup.sql",
    "config.php.bak",
    "phpinfo.php",
    "server-status",
    "admin/",
    "administrator/",
    "wp-admin/",
    ".well-known/security.txt",
    "web.config",
]
PUBLIC_INFORMATION_PATHS = {".well-known/security.txt"}
LOGIN_PATHS = {"admin/", "administrator/", "wp-admin/"}
TIMEOUT = 3
SOFT_404_SIMILARITY = 0.90
MAX_BODY_SAMPLE = 65536


def _normalized_body(response):
    text = (getattr(response, "text", "") or "")[:MAX_BODY_SAMPLE].lower()
    text = re.sub(r"[a-f0-9]{12,}", "<token>", text)
    return re.sub(r"\s+", " ", text).strip()


def _looks_like_soft_404(response, baseline):
    if response.status_code != baseline.status_code:
        return False
    if response.status_code in {301, 302, 307, 308, 401, 403, 404}:
        return True
    if response.status_code != 200:
        return False
    candidate = _normalized_body(response)
    reference = _normalized_body(baseline)
    if not candidate or not reference:
        return candidate == reference
    return SequenceMatcher(None, candidate, reference).ratio() >= SOFT_404_SIMILARITY


def _content_type(response):
    return response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()


def _sensitive_evidence(path, response):
    content = bytes(getattr(response, "content", b"") or b"")[:MAX_BODY_SAMPLE]
    text = content.decode(getattr(response, "encoding", None) or "utf-8", errors="ignore").lower()
    content_type = _content_type(response)

    if path == ".env":
        assignments = re.findall(r"(?m)^[a-z_][a-z0-9_]*\s*=\s*.+$", text)
        secrets_found = re.search(
            r"(?m)^(app_key|secret_key|db_password|database_url|aws_access_key_id)\s*=", text
        )
        return bool(secrets_found or len(assignments) >= 3), "biến môi trường/cấu hình bí mật"
    if path == ".git/config":
        return "[core]" in text and "repositoryformatversion" in text, "cấu hình Git"
    if path == ".htaccess":
        return any(item in text for item in ("rewriteengine", "authtype", "require all", "deny from")), "directive Apache"
    if path == "backup.zip":
        return content.startswith(b"PK\x03\x04") or content_type in {
            "application/zip",
            "application/x-zip-compressed",
        }, "tệp ZIP"
    if path == "backup.sql":
        markers = sum(item in text for item in ("-- mysql dump", "create table", "insert into", "postgresql database dump"))
        return markers >= 2, "nội dung SQL dump"
    if path == "config.php.bak":
        return "<?php" in text and any(item in text for item in ("db_password", "database_password", "mysqli_connect")), "mã nguồn cấu hình PHP"
    if path == "phpinfo.php":
        return "phpinfo()" in text or "php version" in text, "trang PHPInfo"
    if path == "server-status":
        return "apache server status" in text or "server uptime" in text, "trạng thái Apache"
    if path == "web.config":
        return "<configuration" in text and ("<system.web" in text or "connectionstrings" in text), "cấu hình IIS/.NET"
    return False, ""


def _finding(path, url, response, severity, verification, confidence, description):
    return {
        "path": path,
        "url": url,
        "status_code": response.status_code,
        "content_type": _content_type(response),
        "severity": severity,
        "verification": verification,
        "confidence": confidence,
        "description": description,
    }


def run(base_url, session=None, deadline=None):
    started = time.monotonic()
    owns_session = session is None
    sess = session or requests.Session()
    result = {
        "module": "dir_checker",
        "status": "success",
        "error": None,
        "duration_sec": 0,
        "checked_count": 0,
        "request_errors": 0,
        "soft_404_count": 0,
        "security_txt": None,
        "findings": [],
    }

    try:
        baseline_path = f".scanner-not-found-{secrets.token_urlsafe(12)}"
        baseline = sess.get(
            f"{base_url}/{baseline_path}", timeout=TIMEOUT, allow_redirects=False
        )

        for path in COMMON_SENSITIVE_PATHS:
            if deadline is not None and time.monotonic() >= deadline:
                result.update(status="error", error="Kiểm tra thư mục dừng sớm vì hết thời gian quét.")
                break
            url = f"{base_url}/{path}"
            try:
                response = sess.get(url, timeout=TIMEOUT, allow_redirects=False)
                result["checked_count"] += 1
            except requests.exceptions.RequestException:
                result["request_errors"] += 1
                continue

            if _looks_like_soft_404(response, baseline):
                result["soft_404_count"] += 1
                continue

            if path in PUBLIC_INFORMATION_PATHS:
                if response.status_code == 200 and (response.text or "").strip():
                    result["security_txt"] = {"url": url, "status_code": 200}
                continue

            if response.status_code == 200:
                exposed, evidence = _sensitive_evidence(path, response)
                if exposed:
                    severity = "Medium" if path == ".htaccess" else "High"
                    result["findings"].append(
                        _finding(
                            path,
                            url,
                            response,
                            severity,
                            "verified",
                            "high",
                            f"Path công khai và nội dung khớp chữ ký {evidence}.",
                        )
                    )
                elif path in LOGIN_PATHS:
                    result["findings"].append(
                        _finding(
                            path,
                            url,
                            response,
                            "Info",
                            "suspected",
                            "medium",
                            "Trang quản trị có thể truy cập; chưa có bằng chứng dữ liệu nhạy cảm bị lộ.",
                        )
                    )
                else:
                    result["findings"].append(
                        _finding(
                            path,
                            url,
                            response,
                            "Info",
                            "suspected",
                            "low",
                            "Path trả về 200 nhưng nội dung không khớp chữ ký nhạy cảm.",
                        )
                    )
            elif response.status_code in {401, 403}:
                result["findings"].append(
                    _finding(
                        path,
                        url,
                        response,
                        "Info",
                        "verified",
                        "medium",
                        "Path phản hồi nhưng đang được bảo vệ bằng kiểm soát truy cập.",
                    )
                )
            elif response.status_code in {301, 302, 307, 308}:
                result["findings"].append(
                    _finding(
                        path,
                        url,
                        response,
                        "Info",
                        "suspected",
                        "low",
                        "Path chuyển hướng; chưa có bằng chứng dữ liệu nhạy cảm bị lộ.",
                    )
                )

        if result["request_errors"]:
            result["status"] = "error"
            result["error"] = f"Không thể kiểm tra {result['request_errors']} path; dữ liệu hoàn thành vẫn được giữ lại."
    except requests.exceptions.RequestException:
        result.update(status="error", error="Không thể tạo baseline để phát hiện soft-404.")
    finally:
        if owns_session:
            sess.close()
        result["duration_sec"] = round(time.monotonic() - started, 3)
    return result
