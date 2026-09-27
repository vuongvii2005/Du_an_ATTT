# -*- coding: utf-8 -*-
"""
Module: robots_checker
Chức năng: Lấy và phân tích file robots.txt để tìm các path bị "Disallow"
(nhiều khi vô tình để lộ tên các khu vực nhạy cảm của website).
Cơ chế: Passive - chỉ gửi 1 GET request duy nhất tới /robots.txt.
"""

import requests

TIMEOUT = 5

# Từ khoá gợi ý các path nhạy cảm khi xuất hiện trong robots.txt
SENSITIVE_KEYWORDS = ["admin", "backup", "config", "private", "secret", "database", "wp-admin", "login"]


def run(base_url, session=None):
    sess = session or requests.Session()
    result = {
        "module": "robots_checker",
        "exists": False,
        "disallowed_paths": [],
        "sensitive_hints": [],
        "error": None,
    }

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
                                    "severity": "Low",
                                    "description": f"Disallow path chứa từ khoá nhạy cảm '{kw}' - có thể gợi ý khu vực quan trọng của site.",
                                }
                            )
                            break

    except requests.exceptions.Timeout:
        result["error"] = "Timeout khi lấy robots.txt."
    except requests.exceptions.SSLError:
        result["error"] = "Lỗi SSL/TLS khi lấy robots.txt."
    except requests.exceptions.RequestException as e:
        result["error"] = f"Không thể lấy robots.txt: {str(e)}"

    return result
