# -*- coding: utf-8 -*-
"""
report.py
Chức năng: Phân tích, tổng hợp dữ liệu trả về từ tất cả các module con, tính điểm
rủi ro tổng quan và xuất ra 1 báo cáo có cấu trúc (dict) để scanner.py / app.py sử dụng.
"""

from datetime import datetime

SEVERITY_WEIGHT = {
    "High": 10,
    "Medium": 5,
    "Low": 2,
    "Info": 0,
}

SEVERITY_ORDER = ["High", "Medium", "Low", "Info"]


def _collect_findings(module_results):
    """
    Chuẩn hoá toàn bộ finding từ các module về 1 danh sách phẳng để dễ tính điểm & hiển thị.
    Mỗi finding có dạng: {module, title, severity, description}
    """
    findings = []

    # --- Header checker ---
    header_result = module_results.get("header_checker", {}) or {}
    for item in header_result.get("missing_headers", []):
        findings.append(
            {
                "module": "Header Check",
                "title": f"Thiếu header: {item['header']}",
                "severity": item["severity"],
                "description": item["description"],
            }
        )
    for item in header_result.get("info_leak", []):
        findings.append(
            {
                "module": "Header Check",
                "title": f"Rò rỉ thông tin: {item['header']}",
                "severity": item["severity"],
                "description": f"{item['description']} (Giá trị: {item['value']})",
            }
        )

    # --- Directory checker ---
    dir_result = module_results.get("dir_checker", {}) or {}
    for item in dir_result.get("findings", []):
        findings.append(
            {
                "module": "Directory Check",
                "title": f"Path: /{item['path']} ({item['status_code']})",
                "severity": item["severity"],
                "description": item["description"],
            }
        )

    # --- Robots.txt checker ---
    robots_result = module_results.get("robots_checker", {}) or {}
    for item in robots_result.get("sensitive_hints", []):
        findings.append(
            {
                "module": "Robots.txt Check",
                "title": f"Disallow nhạy cảm: {item['path']}",
                "severity": item["severity"],
                "description": item["description"],
            }
        )

    # --- CMS checker ---
    cms_result = module_results.get("cms_checker", {}) or {}
    for item in cms_result.get("detected", []):
        if item["cms"] != "Unknown":
            findings.append(
                {
                    "module": "CMS Detection",
                    "title": f"CMS phát hiện: {item['cms']}",
                    "severity": item["severity"],
                    "description": item["description"],
                }
            )

    # --- Port checker ---
    port_result = module_results.get("port_checker", {}) or {}
    for item in port_result.get("open_ports", []):
        findings.append(
            {
                "module": "Port Scan",
                "title": f"Cổng mở: {item['port']} ({item['service']})",
                "severity": item["severity"],
                "description": item["description"],
            }
        )

    return findings


def _calculate_risk_score(findings):
    score = sum(SEVERITY_WEIGHT.get(f["severity"], 0) for f in findings)
    capped = min(score, 100)  # giới hạn 0-100 để dễ đọc trên UI

    if capped >= 60:
        level = "High"
    elif capped >= 30:
        level = "Medium"
    elif capped > 0:
        level = "Low"
    else:
        level = "Info"

    return {"score": capped, "level": level}


def generate_report(target_url, module_results, scan_duration=None):
    """
    target_url: URL đã quét (đã chuẩn hoá)
    module_results: dict {module_name: result_dict} trả về từ từng module trong modules/
    scan_duration: thời gian quét tính bằng giây (optional, float)
    """
    findings = _collect_findings(module_results)

    # Sắp xếp finding theo mức độ nghiêm trọng giảm dần: High -> Medium -> Low -> Info
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]) if f["severity"] in SEVERITY_ORDER else 99)

    risk = _calculate_risk_score(findings)

    summary_count = {level: 0 for level in SEVERITY_ORDER}
    for f in findings:
        summary_count[f["severity"]] = summary_count.get(f["severity"], 0) + 1

    report = {
        "target": target_url,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_duration_sec": scan_duration,
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "summary_count": summary_count,
        "findings": findings,
        "raw_module_results": module_results,
    }

    return report
