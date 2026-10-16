import re

import app as app_module
import scanner
from conftest import complete_report


def make_client(csrf=False):
    flask_app = app_module.create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-only-secret",
            "CSRF_ENABLED": csrf,
        }
    )
    return flask_app.test_client()


def test_single_scan_form_and_route_work(monkeypatch):
    client = make_client()
    monkeypatch.setattr(
        app_module.scanner, "run_scan", lambda url: complete_report(url)
    )

    index = client.get("/").get_data(as_text=True)
    response = client.post("/scan", data={"url": "https://example.com"})

    assert 'action="/scan"' in index
    assert response.status_code == 200
    assert "https://example.com" in response.get_data(as_text=True)
    assert "TLS/SSL" in response.get_data(as_text=True)


def test_compare_keeps_first_report_when_second_target_fails(monkeypatch):
    client = make_client()

    def run_scan(url):
        if "b.example" in url:
            raise scanner.ScannerError("Mục tiêu B bị chặn")
        return complete_report(url)

    monkeypatch.setattr(app_module.scanner, "run_scan", run_scan)
    response = client.post(
        "/compare",
        data={"url_a": "https://a.example", "url_b": "https://b.example"},
    )
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "https://a.example" in body
    assert "Mục tiêu B bị chặn" in body
    assert "Website A" in body and "Website B" in body
    assert "TLS/SSL" in body


def test_post_without_csrf_token_is_rejected():
    client = make_client(csrf=True)

    assert client.post("/scan", data={"url": "https://example.com"}).status_code == 400
    page = client.get("/").get_data(as_text=True)
    assert re.search(r'name="_csrf_token" value="[^"]+"', page)


def test_result_page_shows_summary_groups_and_explanations(monkeypatch):
    from conftest import sample_report

    client = make_client()
    monkeypatch.setattr(app_module.scanner, "run_scan", lambda url: sample_report(url))

    body = client.post("/scan", data={"url": "https://example.com"}).get_data(as_text=True)

    assert "việc nên làm đầu tiên" in body
    assert "Nghiêm trọng" in body and "Nên sửa" in body and "Chỉ để biết" in body
    assert "Đã xác nhận (có bằng chứng)" in body and "Cần kiểm tra thêm" in body
    assert "<details" in body and "Đây là gì?" in body and "Cách khắc phục" in body
    assert "data-jump=" in body and 'id="finding-1"' in body
    assert "Điểm được tính như thế nào?" in body


def test_result_page_escapes_hostile_data_from_scanned_site(monkeypatch):
    from conftest import sample_report

    hostile = '<script>alert("x")</script>'
    extra = [{
        "category": "CORS Check", "title": f"CORS {hostile}", "severity": "High",
        "verification": "verified", "confidence": "high", "description": hostile,
        "evidence": hostile, "cause": hostile, "recommendation": hostile,
    }]
    client = make_client()
    monkeypatch.setattr(
        app_module.scanner, "run_scan", lambda url: sample_report(url, extra_findings=extra)
    )

    body = client.post("/scan", data={"url": "https://example.com"}).get_data(as_text=True)

    assert hostile not in body
    assert "&lt;script&gt;" in body


def test_incomplete_report_page_warns_instead_of_claiming_safe(monkeypatch):
    from conftest import sample_report

    client = make_client()
    monkeypatch.setattr(
        app_module.scanner, "run_scan",
        lambda url: sample_report(url, failed_modules=("dir_checker",)),
    )

    body = client.post("/scan", data={"url": "https://example.com"}).get_data(as_text=True)

    assert "CHƯA hoàn chỉnh" in body
    assert "summary--incomplete" in body


def test_compare_page_renders_explanations_with_unique_anchors(monkeypatch):
    from conftest import sample_report

    client = make_client()
    monkeypatch.setattr(app_module.scanner, "run_scan", lambda url: sample_report(url))

    body = client.post(
        "/compare", data={"url_a": "https://a.example", "url_b": "https://b.example"}
    ).get_data(as_text=True)

    assert body.count('id="a-finding-1"') == 1
    assert body.count('id="b-finding-1"') == 1
    assert "Cách khắc phục" in body and "việc nên làm đầu tiên" in body


def test_glossary_page_lists_every_entry_and_findings_link_to_it(monkeypatch):
    import knowledge
    from conftest import sample_report

    client = make_client()
    page = client.get("/glossary")
    body = page.get_data(as_text=True)

    assert page.status_code == 200
    for key in knowledge.ENTRIES:
        assert f'id="{key}"' in body

    monkeypatch.setattr(app_module.scanner, "run_scan", lambda url: sample_report(url))
    result = client.post("/scan", data={"url": "https://example.com"}).get_data(as_text=True)
    assert "/glossary#csp_missing" in result
