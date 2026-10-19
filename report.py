# -*- coding: utf-8 -*-
"""Normalize module output and calculate a conservative risk assessment."""

from collections import defaultdict
from datetime import datetime

import knowledge


SEVERITY_WEIGHT = {"High": 70, "Medium": 35, "Low": 10, "Info": 0}
SEVERITY_ORDER = ["High", "Medium", "Low", "Info"]
CONFIDENCE_MULTIPLIER = {"verified": 1.0, "suspected": 0.25}
MAX_TOP_ACTIONS = 3
EXPECTED_MODULES = (
    "header_checker",
    "tls_checker",
    "dir_checker",
    "robots_checker",
    "cms_checker",
    "port_checker",
)
MODULE_SCORE_CAP = 70
SUSPECTED_SCORE_CAP = 10

# Several display categories are produced by one checker. Keep their score cap
# together so one response cannot look like many independent vulnerabilities.
SCORE_GROUPS = {
    "Header Check": "header_checker",
    "Security Header": "header_checker",
    "Cookie Check": "header_checker",
    "CORS Check": "header_checker",
    "TLS/SSL Check": "tls_checker",
    "Directory Check": "dir_checker",
    "Robots.txt Check": "robots_checker",
    "CMS Detection": "cms_checker",
    "Port Scan": "port_checker",
}

# Tên dễ hiểu và hậu quả khi module không chạy xong (dùng cho summary_text).
MODULE_INFO = {
    "header_checker": ("kiểm tra header, cookie và CORS", "chưa biết các thiết lập bảo mật của trình duyệt có đủ hay không"),
    "tls_checker": ("kiểm tra HTTPS/chứng chỉ", "chưa biết kết nối có được mã hóa đúng cách hay không"),
    "dir_checker": ("kiểm tra tệp nhạy cảm", "chưa biết có tệp bí mật nào bị lộ hay không"),
    "robots_checker": ("kiểm tra robots.txt", "chưa biết robots.txt có lộ khu vực nhạy cảm hay không"),
    "cms_checker": ("nhận diện CMS", "chưa biết website dùng phần mềm dựng sẵn nào"),
    "port_checker": ("kiểm tra cổng mạng", "chưa biết có cổng dịch vụ nguy hiểm nào đang mở hay không"),
}


def _finding(module, title, item, description=None):
    verification = item.get("verification", "suspected")
    severity = item.get("severity", "Info")
    if severity == "High" and verification != "verified":
        severity = "Medium"
    finding = {
        "module": module,
        "title": title,
        "severity": severity,
        "verification": verification,
        "confidence": item.get("confidence", "medium"),
        "description": description if description is not None else item.get("description", ""),
    }
    for field in ("evidence", "cause", "recommendation"):
        if item.get(field):
            finding[field] = item[field]
    return finding


def _observation(item):
    """Turn a configuration hint into reference-only evidence."""
    observation = dict(item)
    observation.update(severity="Info", verification="suspected", confidence="low")
    return observation


def _is_reference_only(finding):
    """Recognize legacy module output that is only a configuration hint."""
    title = (finding.get("title") or "").lower()
    return (
        title.startswith("thiếu header:")
        or title.startswith("cổng mở:")
        or title.startswith("disallow nhạy cảm:")
    )


def _collect_findings(module_results):
    findings = []

    header_result = module_results.get("header_checker", {}) or {}
    for item in header_result.get("missing_headers", []):
        findings.append(
            _finding(
                "Header Check",
                f"Thiếu header: {item['header']}",
                _observation(item),
            )
        )
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
        findings.append(
            _finding(
                "Robots.txt Check",
                f"Disallow nhạy cảm: {item['path']}",
                _observation(item),
            )
        )

    for item in (module_results.get("cms_checker", {}) or {}).get("detected", []):
        if item.get("cms") != "Unknown":
            findings.append(_finding("CMS Detection", f"CMS phát hiện: {item['cms']}", item))

    for item in (module_results.get("port_checker", {}) or {}).get("open_ports", []):
        findings.append(
            _finding(
                "Port Scan",
                f"Cổng mở: {item['port']} ({item['service']})",
                _observation(item),
            )
        )

    for item in (module_results.get("tls_checker", {}) or {}).get("findings", []):
        findings.append(_finding("TLS/SSL Check", item.get("title", "TLS/SSL"), item))

    # The same observation must not raise the score more than once. Prefer the
    # strongest evidence when duplicate module output disagrees.
    unique = {}
    for finding in findings:
        key = (finding["module"], finding["title"])
        current = unique.get(key)
        candidate_rank = (
            0 if finding.get("verification") == "verified" else 1,
            SEVERITY_ORDER.index(finding["severity"])
            if finding["severity"] in SEVERITY_ORDER
            else len(SEVERITY_ORDER),
            {"high": 0, "medium": 1, "low": 2}.get(finding.get("confidence"), 1),
        )
        current_rank = (
            (
                0 if current.get("verification") == "verified" else 1,
                SEVERITY_ORDER.index(current["severity"])
                if current["severity"] in SEVERITY_ORDER
                else len(SEVERITY_ORDER),
                {"high": 0, "medium": 1, "low": 2}.get(current.get("confidence"), 1),
            )
            if current
            else None
        )
        if current is None or candidate_rank < current_rank:
            unique[key] = finding
    return list(unique.values())


def _attach_explanations(findings):
    """Gắn id (để nhảy tới finding) và nội dung giải thích; không đổi trường cũ."""
    for index, finding in enumerate(findings, start=1):
        finding["id"] = f"finding-{index}"
        finding["explain"] = knowledge.explain(finding)


def _build_top_actions(findings):
    """Tối đa 3 việc nên làm đầu tiên, chỉ lấy từ finding đã xác minh và nghiêm trọng nhất."""
    candidates = [
        finding
        for finding in findings
        if finding.get("verification") == "verified"
        and finding.get("severity") in ("High", "Medium", "Low")
    ]
    candidates.sort(key=lambda finding: SEVERITY_ORDER.index(finding["severity"]))
    actions, seen = [], set()
    for finding in candidates:
        info = finding["explain"]
        key = info["key"] if not info["generic"] else finding["title"]
        if key in seen:
            continue
        seen.add(key)
        actions.append({
            "finding_id": finding["id"],
            "title": finding["title"],
            "severity": finding["severity"],
            "what": info["what"],
            "fix": info["fix"],
        })
        if len(actions) == MAX_TOP_ACTIONS:
            break
    return actions


def _build_summary_text(summary_count, incomplete_modules, action_count):
    serious = summary_count.get("High", 0)
    should_fix = summary_count.get("Medium", 0)
    parts = []
    if incomplete_modules:
        found = []
        if serious:
            found.append(f"{serious} vấn đề nghiêm trọng")
        if should_fix:
            found.append(f"{should_fix} vấn đề nên sửa")
        if found:
            parts.append(
                "Các module đã hoàn thành ghi nhận "
                + " và ".join(found)
                + "; đây chưa phải kết luận về toàn bộ website."
            )
        else:
            parts.append("Chưa ghi nhận vấn đề nghiêm trọng trong các module đã hoàn thành.")
    elif serious or should_fix:
        found = []
        if serious:
            found.append(f"{serious} vấn đề nghiêm trọng")
        if should_fix:
            found.append(f"{should_fix} vấn đề nên sửa")
        sentence = "Website có " + " và ".join(found) + "."
        if action_count:
            sentence += f" Hãy xử lý {action_count} việc dưới đây trước."
        parts.append(sentence)
    else:
        parts.append(
            "Không phát hiện vấn đề nghiêm trọng trong các kiểm tra đã chạy. "
            "Điều này không có nghĩa website hoàn toàn an toàn, chỉ là công cụ chưa tìm thấy lỗi dễ thấy."
        )

    if incomplete_modules:
        names = []
        for item in incomplete_modules:
            label, consequence = MODULE_INFO.get(
                item["module"], (item["module"], "phần này chưa được kiểm tra")
            )
            names.append(f"{label} ({consequence})")
        parts.append(
            "Báo cáo CHƯA hoàn chỉnh vì có phần không chạy xong: "
            + "; ".join(names)
            + ". Vì vậy chưa thể kết luận website an toàn."
        )
    return " ".join(parts)


def _calculate_risk_score(findings, incomplete_modules=None):
    confirmed_scores = defaultdict(float)
    suspected_scores = defaultdict(float)
    seen = set()
    for finding in findings:
        key = (finding.get("module", "Unknown"), finding.get("title", ""))
        if key in seen:
            continue
        seen.add(key)
        if _is_reference_only(finding):
            continue
        weight = SEVERITY_WEIGHT.get(finding.get("severity"), 0)
        multiplier = CONFIDENCE_MULTIPLIER.get(finding.get("verification"), 0.5)
        group = SCORE_GROUPS.get(finding.get("module"), finding.get("module", "Unknown"))
        if finding.get("verification") == "verified":
            confirmed_scores[group] += weight * multiplier
        else:
            suspected_scores[group] += weight * multiplier

    # Repeated observations from one checker cannot dominate the whole report.
    confirmed_total = sum(min(value, MODULE_SCORE_CAP) for value in confirmed_scores.values())
    suspected_total = min(
        SUSPECTED_SCORE_CAP,
        sum(min(value, SUSPECTED_SCORE_CAP) for value in suspected_scores.values()),
    )
    score = min(100, round(confirmed_total + suspected_total))

    if incomplete_modules:
        level = "Unknown"
    elif any(
        not _is_reference_only(finding)
        and finding.get("verification") == "verified"
        and finding.get("severity") == "High"
        for finding in findings
    ):
        # High is reserved for a high-severity finding with direct evidence.
        level = "High"
    elif any(
        not _is_reference_only(finding)
        and finding.get("verification") == "verified"
        and finding.get("severity") == "Medium"
        for finding in findings
    ) or confirmed_total >= 25:
        level = "Medium"
    elif score > 0:
        level = "Low"
    else:
        level = "Info"

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
    module_names = list(EXPECTED_MODULES)
    module_names.extend(name for name in module_results if name not in module_names)
    for module_name in module_names:
        result = module_results.get(module_name)
        if result is None:
            result = {
                "status": "skipped",
                "error": "Module chưa được chạy.",
                "duration_sec": None,
            }
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

    _attach_explanations(findings)
    risk = _calculate_risk_score(findings, incomplete_modules)
    summary_count = {level: 0 for level in SEVERITY_ORDER}
    verification_count = {"verified": 0, "suspected": 0}
    for finding in findings:
        summary_count[finding["severity"]] = summary_count.get(finding["severity"], 0) + 1
        verification = finding.get("verification", "suspected")
        verification_count[verification] = verification_count.get(verification, 0) + 1

    explanation = (
        "Điểm dùng trọng số High=70, Medium=35, Low=10; phát hiện nghi ngờ chỉ nhận 25% trọng số "
        "và tổng phần nghi ngờ bị giới hạn. Phát hiện cấu hình, cổng mở và dấu hiệu chưa đủ bằng chứng "
        "được giữ ở mức tham khảo; mỗi module đóng góp tối đa 70 điểm."
    )
    if incomplete_modules:
        explanation += " Báo cáo chưa hoàn chỉnh vì có module lỗi hoặc bị bỏ qua."

    top_actions = _build_top_actions(findings)
    summary_text = _build_summary_text(summary_count, incomplete_modules, len(top_actions))

    return {
        "target": target_url,
        "requested_target": requested_target or target_url,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_duration_sec": scan_duration,
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "risk_explanation": explanation,
        "scan_complete": not incomplete_modules,
        "summary_text": summary_text,
        "top_actions": top_actions,
        "summary_count": summary_count,
        "verification_count": verification_count,
        "findings": findings,
        "module_status": module_status,
        "incomplete_modules": incomplete_modules,
        "raw_module_results": module_results,
    }
