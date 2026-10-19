import pytest

import report


@pytest.mark.parametrize(
    ("severity", "expected_score", "expected_level"),
    [("High", 70, "High"), ("Medium", 35, "Medium"), ("Low", 10, "Low")],
)
def test_verified_finding_sets_consistent_risk_level(severity, expected_score, expected_level):
    finding = {
        "module": "Test",
        "title": "Finding",
        "severity": severity,
        "verification": "verified",
    }

    risk = report._calculate_risk_score([finding])

    assert risk == {"score": expected_score, "level": expected_level}


def test_incomplete_scan_without_findings_is_unknown_not_safe():
    risk = report._calculate_risk_score([], [{"module": "dir_checker", "status": "error"}])

    assert risk == {"score": 0, "level": "Unknown"}


def test_configuration_hints_and_open_ports_are_reference_only():
    findings = report._collect_findings(
        {
            "header_checker": {
                "missing_headers": [{"header": "Content-Security-Policy", "severity": "High", "verification": "verified"}]
            },
            "port_checker": {
                "open_ports": [{"port": 3306, "service": "MySQL", "severity": "Medium", "verification": "verified"}]
            },
        }
    )

    assert all(item["severity"] == "Info" for item in findings)
    assert all(item["verification"] == "suspected" for item in findings)
    assert report._calculate_risk_score(findings) == {"score": 0, "level": "Info"}


def test_unverified_findings_are_capped_and_cannot_become_high():
    findings = [
        {
            "module": "CORS Check",
            "title": f"Dấu hiệu {index}",
            "severity": "High",
            "verification": "suspected",
        }
        for index in range(20)
    ]

    risk = report._calculate_risk_score(findings)

    assert risk["score"] == report.SUSPECTED_SCORE_CAP
    assert risk["level"] == "Low"


def test_missing_module_makes_report_incomplete_and_unknown():
    result = report.generate_report(
        "https://example.com",
        {"header_checker": {"status": "success", "findings": []}},
    )

    assert result["scan_complete"] is False
    assert result["risk_level"] == "Unknown"
    assert any(item["module"] == "port_checker" for item in result["incomplete_modules"])


def test_duplicate_finding_is_counted_once():
    item = {
        "header": "Content-Security-Policy",
        "severity": "High",
        "verification": "verified",
        "confidence": "high",
        "description": "missing",
    }
    findings = report._collect_findings(
        {"header_checker": {"missing_headers": [item, dict(item)], "info_leak": []}}
    )

    assert len(findings) == 1


def test_header_analyzer_finding_is_integrated_and_deduplicated():
    item = {
        "category": "CORS Check",
        "title": "CORS phản chiếu origin không tin cậy",
        "severity": "High",
        "verification": "verified",
        "confidence": "high",
        "description": "Origin bị phản chiếu.",
        "evidence": "Origin probe được trả lại.",
        "cause": "Thiếu allowlist.",
        "recommendation": "Dùng allowlist chính xác.",
    }

    findings = report._collect_findings({"header_checker": {"findings": [item, dict(item)]}})

    assert len(findings) == 1
    assert findings[0]["module"] == "CORS Check"
    assert findings[0]["evidence"] == item["evidence"]


def test_tls_finding_keeps_remediation_details():
    item = {
        "title": "Chứng chỉ TLS sắp hết hạn",
        "severity": "Medium",
        "verification": "verified",
        "confidence": "high",
        "description": "Còn ít ngày.",
        "evidence": "Còn 10 ngày.",
        "cause": "Chưa gia hạn.",
        "recommendation": "Gia hạn chứng chỉ.",
    }

    findings = report._collect_findings({"tls_checker": {"findings": [item]}})

    assert findings == [
        {
            "module": "TLS/SSL Check",
            "title": item["title"],
            "severity": "Medium",
            "verification": "verified",
            "confidence": "high",
            "description": item["description"],
            "evidence": item["evidence"],
            "cause": item["cause"],
            "recommendation": item["recommendation"],
        }
    ]
