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
