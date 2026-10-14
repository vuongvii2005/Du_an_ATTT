import requests
import pytest

from target_guard import GuardedSession, ScanLimitError, TargetGuard, TargetGuardError
from conftest import FakeResponse, PUBLIC_IP, resolver_for


def test_accepts_http_https_and_rejects_credentials_or_bad_scheme():
    guard = TargetGuard(resolver=resolver_for(PUBLIC_IP))

    assert guard.validate_url("example.com").base_url == "https://example.com"
    assert guard.validate_url("http://example.com:8080/path").port == 8080
    with pytest.raises(TargetGuardError):
        guard.validate_url("ftp://example.com")
    with pytest.raises(TargetGuardError):
        guard.validate_url("https://user:secret@example.com")


@pytest.mark.parametrize("target", ["http://127.0.0.1", "http://[::1]", "http://169.254.169.254"])
def test_blocks_local_private_and_metadata_targets_by_default(target):
    with pytest.raises(TargetGuardError):
        TargetGuard().validate_url(target)


def test_checks_every_dns_address_and_blocks_mixed_public_private_answer():
    guard = TargetGuard(resolver=resolver_for(PUBLIC_IP, "10.0.0.8"))

    with pytest.raises(TargetGuardError):
        guard.validate_url("https://example.com")


def test_ip_allowlist_must_cover_every_resolved_address():
    guard = TargetGuard(
        allowed_targets=(PUBLIC_IP,),
        resolver=resolver_for(PUBLIC_IP, "1.1.1.1"),
    )

    with pytest.raises(TargetGuardError, match="SCANNER_ALLOWED_TARGETS"):
        guard.validate_url("https://example.com")


def test_demo_mode_only_allows_explicit_lab_hostname():
    guard = TargetGuard(
        demo_mode=True,
        demo_targets=("localhost",),
        resolver=resolver_for("127.0.0.1"),
    )

    assert guard.validate_url("http://localhost:5000").selected_ip == "127.0.0.1"
    with pytest.raises(TargetGuardError):
        guard.validate_url("http://other-lab.local")


def test_dns_change_is_rejected_and_original_ip_is_pinned():
    answers = iter(
        [resolver_for(PUBLIC_IP)("example.com", 443, 0, 0), resolver_for("1.1.1.1")("example.com", 443, 0, 0)]
    )

    def changing_resolver(*_args):
        return next(answers)

    guard = TargetGuard(resolver=changing_resolver)
    initial = guard.validate_url("https://example.com")
    session = GuardedSession(guard, initial_target=initial)

    assert session.get_adapter("https://example.com/").target.selected_ip == PUBLIC_IP
    with pytest.raises(TargetGuardError, match="DNS.*thay đổi"):
        session.target_for("https://example.com/next")


def test_redirect_to_unsafe_ip_is_blocked_before_second_request(monkeypatch):
    guard = TargetGuard(resolver=resolver_for(PUBLIC_IP))
    initial = guard.validate_url("https://example.com")
    session = GuardedSession(guard, initial_target=initial)
    calls = []

    def fake_request(_self, method, url, **_kwargs):
        calls.append((method, url))
        return FakeResponse(
            status_code=302,
            headers={"Location": "http://127.0.0.1/admin"},
            url=url,
        )

    monkeypatch.setattr(requests.Session, "request", fake_request)

    with pytest.raises(TargetGuardError):
        session.get("https://example.com", allow_redirects=True)
    assert len(calls) == 1


def test_https_adapter_connects_to_pinned_ip_but_keeps_hostname_for_tls():
    guard = TargetGuard(resolver=resolver_for(PUBLIC_IP))
    target = guard.validate_url("https://example.com")
    session = GuardedSession(guard, initial_target=target)
    adapter = session.get_adapter("https://example.com/")
    prepared = requests.Request("GET", "https://example.com/").prepare()

    connection = adapter.get_connection_with_tls_context(prepared, verify=True, proxies={})
    adapter.add_headers(prepared)

    assert connection.host == PUBLIC_IP
    assert connection.assert_hostname == "example.com"
    assert prepared.headers["Host"] == "example.com"


def test_response_size_limit_stops_oversized_body(monkeypatch):
    guard = TargetGuard(resolver=resolver_for(PUBLIC_IP))
    initial = guard.validate_url("https://example.com")
    session = GuardedSession(guard, initial_target=initial, max_response_bytes=10)

    monkeypatch.setattr(
        requests.Session,
        "request",
        lambda _self, _method, url, **_kwargs: FakeResponse(200, "x" * 11, url=url),
    )

    with pytest.raises(ScanLimitError, match="lớn hơn"):
        session.get("https://example.com")
