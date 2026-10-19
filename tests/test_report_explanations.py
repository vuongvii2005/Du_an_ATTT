import report
from conftest import sample_module_results, sample_report


def _finding_module_results(count, verification="verified", severity="High"):
    modules = sample_module_results()
    modules["header_checker"]["missing_headers"] = []
    modules["header_checker"]["info_leak"] = []
    modules["dir_checker"]["findings"] = []
    modules["port_checker"]["open_ports"] = []
    modules["header_checker"]["findings"] = [
        {"category": "CORS Check", "title": f"Vấn đề thử nghiệm {index}", "severity": severity,
         "verification": verification, "confidence": "high", "description": "mô tả"}
        for index in range(count)
    ]
    return modules


def test_every_finding_gets_explanation_and_anchor_without_changing_old_fields():
    result = sample_report()

    assert result["findings"]
    ids = [finding["id"] for finding in result["findings"]]
    assert len(ids) == len(set(ids))
    for finding in result["findings"]:
        assert finding["explain"]["what"] and finding["explain"]["why"] and finding["explain"]["fix"]
        for field in ("module", "title", "severity", "verification", "confidence", "description"):
            assert field in finding


def test_scoring_is_unchanged_by_explanations():
    result = sample_report()
    plain = [
        {key: value for key, value in finding.items() if key not in {"id", "explain"}}
        for finding in result["findings"]
    ]

    assert report._calculate_risk_score(plain) == {
        "score": result["risk_score"],
        "level": result["risk_level"],
    }


def test_top_actions_are_at_most_three_and_only_verified():
    modules = sample_module_results()
    result = report.generate_report("https://example.com", modules)

    assert 1 <= len(result["top_actions"]) <= 3
    by_id = {finding["id"]: finding for finding in result["findings"]}
    for action in result["top_actions"]:
        assert by_id[action["finding_id"]]["verification"] == "verified"
        assert action["severity"] != "Info"
    severities = [action["severity"] for action in result["top_actions"]]
    assert severities == sorted(severities, key=report.SEVERITY_ORDER.index)


def test_top_actions_capped_at_three_with_many_findings():
    result = sample_report()
    verified_issues = [
        finding for finding in result["findings"]
        if finding["verification"] == "verified" and finding["severity"] != "Info"
    ]

    assert len(verified_issues) > 3
    assert len(result["top_actions"]) == 3


def test_top_actions_do_not_repeat_the_same_kind_of_problem():
    result = report.generate_report("https://example.com", _finding_module_results(8))
    keys = {
        finding["explain"]["key"]
        for finding in result["findings"]
        if finding["id"] in {action["finding_id"] for action in result["top_actions"]}
    }

    assert len(result["top_actions"]) == len(keys)


def test_suspected_findings_never_become_top_actions():
    result = report.generate_report(
        "https://example.com", _finding_module_results(4, verification="suspected")
    )

    assert result["top_actions"] == []
    assert "việc dưới đây" not in result["summary_text"]


def test_summary_text_for_complete_report_with_problems():
    result = sample_report()
    text = result["summary_text"]

    assert str(result["summary_count"]["High"]) + " vấn đề nghiêm trọng" in text
    assert str(result["summary_count"]["Medium"]) + " vấn đề nên sửa" in text
    assert f"{len(result['top_actions'])} việc dưới đây" in text
    assert "CHƯA hoàn chỉnh" not in text


def test_summary_text_for_clean_complete_report_does_not_claim_safe():
    modules = _finding_module_results(0)
    result = report.generate_report("https://example.com", modules)

    assert result["scan_complete"] is True
    assert "không có nghĩa website hoàn toàn an toàn" in result["summary_text"]


def test_summary_text_for_incomplete_report_names_modules_and_consequence():
    result = sample_report(failed_modules=("dir_checker", "port_checker"))
    text = result["summary_text"]

    assert result["scan_complete"] is False
    assert "CHƯA hoàn chỉnh" in text
    assert "kiểm tra tệp nhạy cảm" in text and "chưa biết có tệp bí mật nào bị lộ" in text
    assert "kiểm tra cổng mạng" in text
    assert "chưa thể kết luận website an toàn" in text


def test_incomplete_report_without_findings_does_not_say_safe():
    modules = _finding_module_results(0)
    modules["tls_checker"].update(status="error", error="lỗi giả lập")
    result = report.generate_report("https://example.com", modules)

    assert "CHƯA hoàn chỉnh" in result["summary_text"]
    assert "không phát hiện vấn đề nghiêm trọng trong các kiểm tra đã chạy" not in result["summary_text"].lower()
