from datetime import datetime, timedelta, timezone
import socket
import ssl

from modules import tls_checker
from target_guard import TargetGuard
from conftest import FakeResponse, PUBLIC_IP, resolver_for


NOW = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)


def _cert_time(value):
    return value.strftime("%b %d %H:%M:%S %Y GMT")


def _certificate(days_remaining=120):
    return {
        "subject": ((('commonName', 'example.com'),),),
        "issuer": ((('commonName', 'Example Test CA'),),),
        "serialNumber": "01AB",
        "notBefore": _cert_time(NOW - timedelta(days=30)),
        "notAfter": _cert_time(NOW + timedelta(days=days_remaining)),
    }


class FakeSocket:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class FakeTLSSocket(FakeSocket):
    def __init__(self, certificate=None, protocol="TLSv1.3", cipher=None):
        self._certificate = certificate or _certificate()
        self._protocol = protocol
        self._cipher = cipher or ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    def getpeercert(self):
        return self._certificate

    def version(self):
        return self._protocol

    def cipher(self):
        return self._cipher


class FakeContext:
    def __init__(self, tls_socket):
        self.tls_socket = tls_socket
        self.server_hostname = None

    def wrap_socket(self, _raw_socket, server_hostname):
        self.server_hostname = server_hostname
        return self.tls_socket


def _target(scheme="https"):
    guard = TargetGuard(resolver=resolver_for(PUBLIC_IP))
    return guard.validate_url("{}://example.com".format(scheme))


def _mock_handshake(monkeypatch, tls_socket):
    context = FakeContext(tls_socket)
    calls = []

    def connect(address, timeout):
        calls.append((address, timeout))
        return FakeSocket()

    monkeypatch.setattr(tls_checker.ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(tls_checker.socket, "create_connection", connect)
    return context, calls


def test_valid_certificate_and_negotiated_session(monkeypatch):
    context, calls = _mock_handshake(monkeypatch, FakeTLSSocket())

    result = tls_checker.run(_target(), now=NOW)

    assert result["status"] == "success"
    assert result["https_supported"] is True
    assert result["certificate"]["valid"] is True
    assert result["certificate"]["hostname_matches"] is True
    assert result["certificate"]["days_remaining"] == 120
    assert result["protocol"] == "TLSv1.3"
    assert result["cipher"]["name"] == "TLS_AES_256_GCM_SHA384"
    assert result["findings"] == []
    assert context.server_hostname == "example.com"
    assert calls[0][0] == (PUBLIC_IP, 443)


def test_certificate_expiring_soon_is_medium(monkeypatch):
    _mock_handshake(
        monkeypatch,
        FakeTLSSocket(certificate=_certificate(days_remaining=10)),
    )

    result = tls_checker.run(_target(), now=NOW)

    finding = result["findings"][0]
    assert finding["title"] == "Chứng chỉ TLS sắp hết hạn"
    assert finding["severity"] == "Medium"
    assert all(finding[field] for field in (
        "description", "evidence", "cause", "recommendation"
    ))


def test_expired_certificate_verification_error_is_high(monkeypatch):
    def fail_connect(*_args, **_kwargs):
        raise ssl.SSLCertVerificationError(
            1, "certificate verify failed: certificate has expired"
        )

    monkeypatch.setattr(tls_checker.socket, "create_connection", fail_connect)

    result = tls_checker.run(_target(), now=NOW)

    assert result["status"] == "success"
    assert result["https_supported"] is True
    assert result["certificate"]["valid"] is False
    assert result["findings"][0]["title"] == "Chứng chỉ TLS đã hết hạn"
    assert result["findings"][0]["severity"] == "High"


def test_hostname_mismatch_is_high(monkeypatch):
    def fail_connect(*_args, **_kwargs):
        raise ssl.SSLCertVerificationError(
            1, "Hostname mismatch, certificate is not valid for example.com"
        )

    monkeypatch.setattr(tls_checker.socket, "create_connection", fail_connect)

    result = tls_checker.run(_target(), now=NOW)

    assert result["certificate"]["hostname_matches"] is False
    assert result["findings"][0]["title"] == "Hostname không khớp chứng chỉ TLS"
    assert result["findings"][0]["severity"] == "High"


def test_refused_https_is_verified_high(monkeypatch):
    def refuse(*_args, **_kwargs):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(tls_checker.socket, "create_connection", refuse)

    result = tls_checker.run(_target("http"), homepage_response=FakeResponse(
        url="http://example.com/"
    ))

    assert result["status"] == "success"
    assert result["https_supported"] is False
    assert result["findings"][0]["severity"] == "High"


def test_tls_timeout_is_error_without_security_conclusion(monkeypatch):
    def timeout(*_args, **_kwargs):
        raise socket.timeout("timed out")

    monkeypatch.setattr(tls_checker.socket, "create_connection", timeout)

    result = tls_checker.run(_target())

    assert result["status"] == "error"
    assert result["https_supported"] is None
    assert "thời gian" in result["error"]
    assert result["findings"] == []


def test_tls_handshake_failure_is_incomplete_suspected_finding(monkeypatch):
    class BrokenContext:
        def wrap_socket(self, *_args, **_kwargs):
            raise ssl.SSLError("handshake failure")

    monkeypatch.setattr(tls_checker.ssl, "create_default_context", BrokenContext)
    monkeypatch.setattr(
        tls_checker.socket, "create_connection", lambda *_args, **_kwargs: FakeSocket()
    )

    result = tls_checker.run(_target())

    assert result["status"] == "error"
    assert result["https_supported"] is None
    assert result["findings"][0]["title"] == "TLS handshake thất bại"
    assert result["findings"][0]["verification"] == "suspected"


def test_weak_negotiated_protocol_and_cipher_are_reported(monkeypatch):
    _mock_handshake(
        monkeypatch,
        FakeTLSSocket(protocol="TLSv1", cipher=("RC4-MD5", "TLSv1", 64)),
    )

    result = tls_checker.run(_target(), now=NOW)
    titles = {item["title"] for item in result["findings"]}

    assert "Phiên TLS thương lượng giao thức yếu" in titles
    assert "Phiên TLS thương lượng cipher yếu" in titles
    assert all(item["severity"] == "High" for item in result["findings"])


def test_http_redirect_check_does_not_follow_and_requires_same_target(monkeypatch):
    _mock_handshake(monkeypatch, FakeTLSSocket())

    class RedirectSession:
        def __init__(self):
            self.calls = []

        def get(self, url, **kwargs):
            self.calls.append((url, kwargs))
            return FakeResponse(
                302,
                headers={"Location": "https://other.example/"},
                url=url,
            )

    session = RedirectSession()
    result = tls_checker.run(_target(), session=session, now=NOW)

    assert session.calls[0][1]["allow_redirects"] is False
    assert result["http_redirect"]["redirects_to_https"] is False
    assert any(
        item["title"] == "HTTP không chuyển hướng an toàn sang HTTPS"
        for item in result["findings"]
    )


def test_http_redirect_to_same_https_target_is_accepted(monkeypatch):
    _mock_handshake(monkeypatch, FakeTLSSocket())

    class RedirectSession:
        def get(self, url, **_kwargs):
            return FakeResponse(
                301,
                headers={"Location": "https://example.com/login"},
                url=url,
            )

    result = tls_checker.run(_target(), session=RedirectSession(), now=NOW)

    assert result["http_redirect"]["redirects_to_https"] is True
    assert not any(
        item["title"] == "HTTP không chuyển hướng an toàn sang HTTPS"
        for item in result["findings"]
    )
