import requests

import scanner
from modules import robots_checker
from target_guard import TargetGuard
from conftest import FakeResponse, PUBLIC_IP, resolver_for


class DummySession:
    def __init__(self, guard):
        self.guard = guard
        self.headers = {}

    def target_for(self, url):
        return self.guard.validate_url(url)


def _module_result(name, **values):
    result = {"module": name, "status": "success", "error": None, "duration_sec": 0}
    result.update(values)
    return result


def test_module_failure_does_not_stop_other_modules(monkeypatch):
    guard = TargetGuard(resolver=resolver_for(PUBLIC_IP))
    session = DummySession(guard)
    homepage = FakeResponse(200, "<html></html>", url="https://example.com/")
    called = []

    monkeypatch.setattr(scanner, "check_connectivity", lambda *_args: homepage)

    def broken_header(_response, **kwargs):
        assert kwargs["session"] is session
        assert kwargs["target_url"] == homepage.url
        assert kwargs["deadline"] is not None
        raise RuntimeError("parser failed")

    monkeypatch.setattr(scanner.header_checker, "run", broken_header)
    def tls_run(target, **_kwargs):
        called.append(("tls", target.selected_ip))
        return _module_result("tls_checker", https_supported=True, findings=[])

    monkeypatch.setattr(scanner.tls_checker, "run", tls_run)
    monkeypatch.setattr(
        scanner.dir_checker,
        "run",
        lambda *_args, **_kwargs: _module_result("dir_checker", findings=[]),
    )
    monkeypatch.setattr(
        scanner.robots_checker,
        "run",
        lambda *_args, **_kwargs: _module_result(
            "robots_checker", exists=False, disallowed_paths=[], sensitive_hints=[]
        ),
    )
    monkeypatch.setattr(
        scanner.cms_checker,
        "run",
        lambda *_args, **_kwargs: _module_result("cms_checker", detected=[]),
    )

    def port_run(*_args, **_kwargs):
        called.append("port")
        return _module_result("port_checker", resolved_ip=PUBLIC_IP, open_ports=[])

    monkeypatch.setattr(scanner.port_checker, "run", port_run)

    result = scanner.run_scan("https://example.com", guard=guard, session=session)

    assert result["raw_module_results"]["header_checker"]["status"] == "error"
    assert result["scan_complete"] is False
    assert result["risk_level"] == "Unknown"
    assert called == [("tls", PUBLIC_IP), "port"]


def test_robots_timeout_returns_standard_error_result():
    class TimeoutSession:
        def get(self, *_args, **_kwargs):
            raise requests.exceptions.Timeout()

    result = robots_checker.run("https://example.com", TimeoutSession())

    assert result["status"] == "error"
    assert result["error"]
    assert result["duration_sec"] >= 0
