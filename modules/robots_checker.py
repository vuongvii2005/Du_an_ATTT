# -*- coding: utf-8 -*-
"""
Module: robots_checker
Chức năng: Lấy và phân tích file robots.txt để tìm các path bị "Disallow"
(nhiều khi vô tình để lộ tên các khu vực nhạy cảm của website).
Cơ chế: Passive - chỉ gửi 1 GET request duy nhất tới /robots.txt.
"""

import time

import requests

TIMEOUT = 5

# Từ khoá gợi ý các path nhạy cảm khi xuất hiện trong robots.txt
SENSITIVE_KEYWORDS = ["admin", "backup", "config", "private", "secret", "database", "wp-admin", "login"]


def run(base_url, session=None, deadline=None):
    started = time.monotonic()
    sess = session or requests.Session()
    result = {
        "module": "robots_checker",
        "status": "success",
        "exists": False,
        "disallowed_paths": [],
        "sensitive_hints": [],
        "error": None,
        "duration_sec": 0,
    }

    if deadline is not None and time.monotonic() >= deadline:
        result.update(status="skipped", error="Bỏ qua vì đã hết tổng thời gian quét.")
        return result

    url = f"{base_url}/robots.txt"
    try:
        resp = sess.get(url, timeout=TIMEOUT)
        if resp.status_code == 200 and resp.text.strip():
            result["exists"] = True
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if not path:
                        continue
                    result["disallowed_paths"].append(path)
                    for kw in SENSITIVE_KEYWORDS:
                        if kw in path.lower():
                            result["sensitive_hints"].append(
                                {
                                    "path": path,
                                    "keyword": kw,
                                    "severity": "Info",
                                    "verification": "suspected",
                                    "confidence": "medium",
                                    "description": f"Disallow path chứa từ khoá nhạy cảm '{kw}' - có thể gợi ý khu vực quan trọng của site.",
                                }
                            )
                            break

    except requests.exceptions.Timeout:
        result["status"] = "error"
        result["error"] = "Timeout khi lấy robots.txt."
    except requests.exceptions.SSLError:
        result["status"] = "error"
        result["error"] = "Lỗi SSL/TLS khi lấy robots.txt."
    except requests.exceptions.RequestException:
        result["status"] = "error"
        result["error"] = "Không thể lấy robots.txt."

    result["duration_sec"] = round(time.monotonic() - started, 3)
    return result
