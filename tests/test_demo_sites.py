import socket
from urllib.parse import urlsplit

import pytest

import report
from demo.site_a import app as site_a
from demo.site_b import app as site_b
from modules import header_checker
from target_guard import TargetGuard, TargetGuardError


class ClientSession:
    def __init__(self, client):
        self.client = client
        self.calls = 0

    def get(self, url, **kwargs):
        self.calls += 1
        parsed = urlsplit(url)
        return self.client.get(
            parsed.path or "/",
            query_string=parsed.query,
            headers=kwargs.get("headers"),
            follow_redirects=kwargs.get("allow_redirects", False),
        )


def _analyze(app, url):
    client = app.test_client()
    response = client.get("/")
    response.url = url
    session = ClientSession(client)
    result = header_checker.run(response, session=session, target_url=url)
    return result, session.calls


def _resolver(_hostname, port, _family, _socktype):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]


def test_demo_mode_allows_only_configured_localhost_on_both_ports(monkeypatch):
    monkeypatch.setenv("SCANNER_DEMO_MODE", "true")
    monkeypatch.setenv("SCANNER_DEMO_CONFIRM", "I_UNDERSTAND_LOCAL_SCAN_RISK")
    monkeypatch.setenv("SCANNER_DEMO_TARGETS", "localhost,127.0.0.1")
    guard = TargetGuard.from_env()
    guard.resolver = _resolver

    assert guard.validate_url("http://localhost:5001").port == 5001
    assert guard.validate_url("http://localhost:5002").port == 5002
    assert guard.validate_url("http://127.0.0.1:5001").port == 5001
    assert guard.validate_url("http://127.0.0.1:5002").port == 5002
    with pytest.raises(TargetGuardError):
        guard.validate_url("http://other-host:5001")


def test_site_a_findings_are_removed_from_site_b_and_score_decreases():
    result_a, cors_calls_a = _analyze(site_a, "http://localhost:5001/")
    result_b, cors_calls_b = _analyze(site_b, "http://localhost:5002/")

    missing_a = {item["header"] for item in result_a["missing_headers"]}
    titles_a = {item["title"] for item in result_a["findings"]}
    titles_b = {item["title"] for item in result_b["findings"]}

    assert {"Content-Security-Policy", "X-Frame-Options"} <= missing_a
    assert "Cookie 'demo_session' thiếu Secure" in titles_a
    assert "Cookie 'demo_session' thiếu HttpOnly" in titles_a
    assert "Cookie 'demo_session' thiếu SameSite" in titles_a
    assert "CORS phản chiếu origin không tin cậy" in titles_a
    assert result_b["missing_headers"] == []
    assert not titles_a.intersection(titles_b)
    assert cors_calls_a == cors_calls_b == 1

    report_a = report.generate_report("http://localhost:5001", {"header_checker": result_a})
    report_b = report.generate_report("http://localhost:5002", {"header_checker": result_b})
    assert report_a["risk_score"] > report_b["risk_score"]
    assert report_a["summary_count"]["High"] > report_b["summary_count"]["High"]
