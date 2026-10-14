# -*- coding: utf-8 -*-
"""
Module: cms_checker
Chức năng: Phát hiện hệ quản trị nội dung (CMS) đang được website sử dụng, dựa trên
các dấu hiệu công khai trong HTML: thẻ meta generator và các đường dẫn tài nguyên
đặc trưng (css/js/ảnh).
Cơ chế: Hoàn toàn passive - chỉ phân tích lại response trang chủ đã có sẵn,
KHÔNG gửi thêm request nào khác.
"""

import time

from bs4 import BeautifulSoup

CMS_SIGNATURES = {
    "WordPress": {
        "paths": ["/wp-content/", "/wp-includes/", "/wp-login.php"],
        "meta_keywords": ["wordpress"],
    },
    "Joomla": {
        "paths": ["/administrator/", "/media/jui/"],
        "meta_keywords": ["joomla"],
    },
    "Drupal": {
        "paths": ["/sites/default/", "/misc/drupal.js"],
        "meta_keywords": ["drupal"],
    },
    "Magento": {
        "paths": ["/skin/frontend/", "/media/catalog/"],
        "meta_keywords": ["magento"],
    },
}


def run(response):
    """
    response: requests.Response của trang chủ (đã fetch từ scanner.py, tái sử dụng
    lại - không gửi thêm request).
    """
    started = time.monotonic()
    result = {
        "module": "cms_checker",
        "status": "success",
        "error": None,
        "duration_sec": 0,
        "detected": [],
    }

    html = response.text or ""
    soup = BeautifulSoup(html, "html.parser")

    # 1. Kiểm tra qua thẻ <meta name="generator">
    generator_tag = soup.find("meta", attrs={"name": "generator"})
    generator_content = generator_tag.get("content", "").lower() if generator_tag else ""

    # 2. Kiểm tra qua các đường dẫn đặc trưng xuất hiện trong link/script/img
    resource_srcs = " ".join(
        (tag.get("href", "") or "") + " " + (tag.get("src", "") or "")
        for tag in soup.find_all(["link", "script", "img"])
    ).lower()

    for cms_name, sig in CMS_SIGNATURES.items():
        matched_by = []

        if any(kw in generator_content for kw in sig["meta_keywords"]):
            matched_by.append("meta-generator")

        if any(path.lower() in resource_srcs for path in sig["paths"]):
            matched_by.append("resource-path")

        if matched_by:
            result["detected"].append(
                {
                    "cms": cms_name,
                    "matched_by": matched_by,
                    "severity": "Info",
                    "verification": "suspected",
                    "confidence": "medium",
                    "description": f"Phát hiện dấu hiệu CMS {cms_name} qua: {', '.join(matched_by)}.",
                }
            )

    if not result["detected"]:
        result["detected"].append(
            {
                "cms": "Unknown",
                "matched_by": [],
                "severity": "Info",
                "verification": "suspected",
                "confidence": "low",
                "description": "Không phát hiện dấu hiệu của các CMS phổ biến (WordPress, Joomla, Drupal, Magento).",
            }
        )

    result["duration_sec"] = round(time.monotonic() - started, 3)
    return result
