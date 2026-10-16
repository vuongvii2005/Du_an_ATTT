# -*- coding: utf-8 -*-
"""Normalize module output and calculate a conservative risk assessment."""

from collections import defaultdict
from datetime import datetime


SEVERITY_WEIGHT = {"High": 70, "Medium": 35, "Low": 10, "Info": 0}
SEVERITY_ORDER = ["High", "Medium", "Low", "Info"]
CONFIDENCE_MULTIPLIER = {"verified": 1.0, "suspected": 0.5}


def _finding(module, title, item, description=None):
    finding = {
        "module": module,
        "title": title,
        "severity": item.get("severity", "Info"),
        "verification": item.get("verification", "suspected"),
        "confidence": item.get("confidence", "medium"),
        "description": description if description is not None else item.get("description", ""),
    }
    for field in ("evidence", "cause", "recommendation"):
        if item.get(field):
            finding[field] = item[field]
    return finding


def _collect_findings(module_results):
    findings = []

    header_result = module_results.get("header_checker", {}) or {}
    for item in header_result.get("missing_headers", []):
        findings.append(_finding("Header Check", f"Thiếu header: {item['header']}", item))
    for item in header_result.get("info_leak", []):
        findings.append(
            _finding(
                "Header Check",
                f"Rò rỉ thông tin: {item['header']}",
                item,
                f"{item['description']} (Giá trị: {item['value']})",
            )
        )
    for item in header_result.get("findings", []):
        findings.append(
            _finding(item.get("category", "Header Check"), item.get("title", "HTTP header"), item)
        )

    for item in (module_results.get("dir_checker", {}) or {}).get("findings", []):
        findings.append(
            _finding(
                "Directory Check",
                f"Path: /{item['path']} ({item['status_code']})",
                item,
            )
        )

    for item in (module_results.get("robots_checker", {}) or {}).get("sensitive_hints", []):
        findings.append(_finding("Robots.txt Check", f"Disallow nhạy cảm: {item['path']}", item))

    for item in (module_results.get("cms_checker", {}) or {}).get("detected", []):
        if item.get("cms") != "Unknown":
            findings.append(_finding("CMS Detection", f"CMS phát hiện: {item['cms']}", item))

    for item in (module_results.get("port_checker", {}) or {}).get("open_ports", []):
        findings.append(
            _finding("Port Scan", f"Cổng mở: {item['port']} ({item['service']})", item)
        )

    for item in (module_results.get("tls_checker", {}) or {}).get("findings", []):
        findings.append(_finding("TLS/SSL Check", item.get("title", "TLS/SSL"), item))

    # The same observation must not raise the score more than once.
    unique = {}
    for finding in findings:
        key = (finding["module"], finding["title"])
        current = unique.get(key)
        if current is None or SEVERITY_ORDER.index(finding["severity"]) < SEVERITY_ORDER.index(
            current["severity"]
        ):
            unique[key] = finding
    return list(unique.values())


def _calculate_risk_score(findings, incomplete_modules=None):
    module_scores = defaultdict(float)
    for finding in findings:
        weight = SEVERITY_WEIGHT.get(finding.get("severity"), 0)
        multiplier = CONFIDENCE_MULTIPLIER.get(finding.get("verification"), 0.5)
        module_scores[finding.get("module", "Unknown")] += weight * multiplier

    # Repeated observations from one checker cannot dominate the whole report.
    score = min(100, round(sum(min(value, 85) for value in module_scores.values())))
    if score >= 60:
        level = "High"
    elif score >= 25:
        level = "Medium"
    elif score > 0:
        level = "Low"
    else:
        level = "Info"

    verified_levels = [
        finding["severity"]
        for finding in findings
        if finding.get("verification") == "verified" and finding.get("severity") in SEVERITY_ORDER
    ]
    if verified_levels:
        highest_verified = min(verified_levels, key=SEVERITY_ORDER.index)
        if SEVERITY_ORDER.index(highest_verified) < SEVERITY_ORDER.index(level):
            level = highest_verified
    elif incomplete_modules and score == 0:
        level = "Unknown"

    return {"score": score, "level": level}


def generate_report(target_url, module_results, scan_duration=None, requested_target=None):
    findings = _collect_findings(module_results)
    findings.sort(
        key=lambda finding: SEVERITY_ORDER.index(finding["severity"])
        if finding["severity"] in SEVERITY_ORDER
        else 99
    )

    module_status = []
    incomplete_modules = []
    for module_name, result in module_results.items():
        result = result or {}
        status = result.get("status", "error")
        item = {
            "module": module_name,
            "status": status,
            "error": result.get("error"),
            "duration_sec": result.get("duration_sec"),
        }
        module_status.append(item)
        if status != "success":
            incomplete_modules.append(item)

    risk = _calculate_risk_score(findings, incomplete_modules)
    summary_count = {level: 0 for level in SEVERITY_ORDER}
    verification_count = {"verified": 0, "suspected": 0}
    for finding in findings:
        summary_count[finding["severity"]] = summary_count.get(finding["severity"], 0) + 1
        verification = finding.get("verification", "suspected")
        verification_count[verification] = verification_count.get(verification, 0) + 1

    explanation = (
        "Điểm dùng trọng số High=70, Medium=35, Low=10; phát hiện nghi ngờ nhận 50% trọng số. "
        "Mỗi module đóng góp tối đa 85 điểm và mức tổng không thấp hơn phát hiện đã xác minh nghiêm trọng nhất."
    )
    if incomplete_modules:
        explanation += " Báo cáo chưa hoàn chỉnh vì có module lỗi hoặc bị bỏ qua."

    return {
        "target": target_url,
        "requested_target": requested_target or target_url,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_duration_sec": scan_duration,
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "risk_explanation": explanation,
        "scan_complete": not incomplete_modules,
        "summary_count": summary_count,
        "verification_count": verification_count,
        "findings": findings,
        "module_status": module_status,
        "incomplete_modules": incomplete_modules,
        "raw_module_results": module_results,
    }
