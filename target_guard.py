"""Validation and pinned HTTP transport for scanner targets."""

from dataclasses import dataclass
import ipaddress
import os
import socket
import time
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from requests.adapters import HTTPAdapter


METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("168.63.129.16"),
}
REDIRECT_CODES = {301, 302, 303, 307, 308}


class TargetGuardError(ValueError):
    """The target or one of its redirects is not safe to scan."""


class ScanLimitError(requests.RequestException):
    """A request, size, time, or redirect limit was reached."""


@dataclass(frozen=True)
class TargetInfo:
    url: str
    base_url: str
    scheme: str
    hostname: str
    port: int
    host_header: str
    ips: tuple
    selected_ip: str


def _env_list(name):
    return tuple(item.strip().lower() for item in os.getenv(name, "").split(",") if item.strip())


class TargetGuard:
    """Resolve, authorize, and classify every network target before use."""

    def __init__(self, allowed_targets=(), demo_mode=False, demo_targets=(), resolver=None):
        self.allowed_targets = tuple(item.lower() for item in allowed_targets)
        self.demo_mode = bool(demo_mode)
        self.demo_targets = tuple(item.lower().rstrip(".") for item in demo_targets)
        self.resolver = resolver or socket.getaddrinfo

    @classmethod
    def from_env(cls):
        demo_mode = (
            os.getenv("SCANNER_DEMO_MODE", "").lower() in {"1", "true", "yes"}
            and os.getenv("SCANNER_DEMO_CONFIRM", "") == "I_UNDERSTAND_LOCAL_SCAN_RISK"
        )
        return cls(
            allowed_targets=_env_list("SCANNER_ALLOWED_TARGETS"),
            demo_mode=demo_mode,
            demo_targets=_env_list("SCANNER_DEMO_TARGETS"),
        )

    def validate_url(self, raw_url):
        raw_url = (raw_url or "").strip()
        if not raw_url:
            raise TargetGuardError("URL không được để trống.")
        if any(char.isspace() for char in raw_url):
            raise TargetGuardError("URL không được chứa khoảng trắng hoặc ký tự xuống dòng.")
        if "://" not in raw_url:
            raw_url = "https://" + raw_url

        try:
            parsed = urlsplit(raw_url)
            port = parsed.port
        except ValueError as exc:
            raise TargetGuardError("URL không hợp lệ.") from exc

        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise TargetGuardError("URL chỉ được dùng giao thức http:// hoặc https://")
        if parsed.username is not None or parsed.password is not None:
            raise TargetGuardError("URL không được chứa username hoặc password.")
        if not parsed.hostname:
            raise TargetGuardError("URL không hợp lệ, thiếu tên domain hoặc địa chỉ IP.")

        try:
            hostname = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise TargetGuardError("Tên domain không hợp lệ.") from exc
        if not hostname or "%" in hostname:
            raise TargetGuardError("Hostname không hợp lệ.")

        port = port or (443 if scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise TargetGuardError("Port trong URL không hợp lệ.")

        ips = self._resolve_all(hostname, port)
        demo_allowed = self.demo_mode and hostname in self.demo_targets
        for ip in ips:
            if self._is_forbidden(ip) and not demo_allowed:
                raise TargetGuardError(
                    f"Mục tiêu {hostname} phân giải tới địa chỉ không được phép quét: {ip}"
                )

        if self.allowed_targets and not demo_allowed and not self._is_allowlisted(hostname, ips):
            raise TargetGuardError("Mục tiêu không nằm trong SCANNER_ALLOWED_TARGETS.")

        is_ipv6 = ":" in hostname
        display_host = f"[{hostname}]" if is_ipv6 else hostname
        default_port = 443 if scheme == "https" else 80
        netloc = display_host if port == default_port else f"{display_host}:{port}"
        path = parsed.path or "/"
        normalized_url = urlunsplit((scheme, netloc, path, parsed.query, ""))
        base_url = f"{scheme}://{netloc}"
        return TargetInfo(
            url=normalized_url,
            base_url=base_url,
            scheme=scheme,
            hostname=hostname,
            port=port,
            host_header=netloc,
            ips=tuple(str(ip) for ip in ips),
            selected_ip=str(ips[0]),
        )

    def _resolve_all(self, hostname, port):
        try:
            literal = ipaddress.ip_address(hostname)
            return (literal,)
        except ValueError:
            pass

        try:
            answers = self.resolver(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except (socket.gaierror, OSError) as exc:
            raise TargetGuardError(f"Không thể phân giải hostname: {hostname}") from exc

        addresses = []
        for answer in answers:
            try:
                address = ipaddress.ip_address(answer[4][0].split("%", 1)[0])
            except (ValueError, IndexError, TypeError):
                continue
            if address not in addresses:
                addresses.append(address)
        if not addresses:
            raise TargetGuardError(f"Hostname {hostname} không trả về địa chỉ IP hợp lệ.")
        return tuple(addresses)

    @staticmethod
    def _is_forbidden(ip):
        return (
            ip in METADATA_IPS
            or ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
            or not ip.is_global
        )

    def _is_allowlisted(self, hostname, ips):
        for entry in self.allowed_targets:
            if entry.startswith("*."):
                suffix = entry[1:]
                if hostname.endswith(suffix) and hostname != entry[2:]:
                    return True
            elif hostname == entry.rstrip("."):
                return True

        networks = []
        for entry in self.allowed_targets:
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                continue
        return bool(networks) and all(any(ip in network for network in networks) for ip in ips)


class _PinnedAddressAdapter(HTTPAdapter):
    """Connect to the validated IP while preserving HTTP Host and TLS SNI."""

    def __init__(self, target):
        self.target = target
        super().__init__(max_retries=0)

    def get_connection_with_tls_context(self, request, verify, proxies=None, cert=None):
        if proxies:
            raise requests.exceptions.ProxyError("Proxy không được hỗ trợ trong phiên quét an toàn.")
        host_params, pool_kwargs = self.build_connection_pool_key_attributes(request, verify, cert)
        host_params["host"] = self.target.selected_ip
        host_params["port"] = self.target.port
        if self.target.scheme == "https":
            pool_kwargs["server_hostname"] = self.target.hostname
            pool_kwargs["assert_hostname"] = self.target.hostname
        return self.poolmanager.connection_from_host(**host_params, pool_kwargs=pool_kwargs)

    def add_headers(self, request, **kwargs):
        request.headers["Host"] = self.target.host_header


class GuardedSession(requests.Session):
    """Requests session with DNS pinning, safe redirects, and resource limits."""

    def __init__(
        self,
        guard,
        initial_target=None,
        request_budget=20,
        deadline=None,
        max_response_bytes=1024 * 1024,
        max_redirects=5,
    ):
        super().__init__()
        self.guard = guard
        self.request_budget = request_budget
        self.deadline = deadline
        self.max_response_bytes = max_response_bytes
        self.max_redirects = max_redirects
        self.request_count = 0
        self.trust_env = False
        self._targets = {}
        if initial_target:
            self._remember(initial_target)

    def _remember(self, fresh):
        previous = self._targets.get(fresh.base_url)
        if previous:
            if set(previous.ips) != set(fresh.ips):
                raise TargetGuardError(
                    f"DNS của {fresh.hostname} thay đổi trong lúc quét; đã dừng để tránh DNS rebinding."
                )
            return previous
        self._targets[fresh.base_url] = fresh
        self.mount(fresh.base_url + "/", _PinnedAddressAdapter(fresh))
        return fresh

    def target_for(self, url):
        return self._remember(self.guard.validate_url(url))

    def request(self, method, url, **kwargs):
        follow_redirects = kwargs.pop("allow_redirects", True)
        history = []
        current_url = url

        for redirect_index in range(self.max_redirects + 1):
            target = self.target_for(current_url)
            self._check_limits()
            self.request_count += 1

            timeout = kwargs.get("timeout", 5)
            if self.deadline is not None:
                remaining = self.deadline - time.monotonic()
                timeout = min(float(timeout), max(0.05, remaining))
            request_kwargs = dict(kwargs)
            request_kwargs.update(allow_redirects=False, stream=True, timeout=timeout)
            response = super().request(method, target.url, **request_kwargs)
            self._load_bounded_content(response)

            location = response.headers.get("Location")
            if not follow_redirects or response.status_code not in REDIRECT_CODES or not location:
                response.history = history
                return response
            if redirect_index >= self.max_redirects:
                response.close()
                raise ScanLimitError(f"Vượt quá {self.max_redirects} lần redirect cho phép.")

            history.append(response)
            current_url = urljoin(response.url, location)

        raise ScanLimitError("Không thể hoàn tất redirect.")

    def _check_limits(self):
        if self.request_count >= self.request_budget:
            raise ScanLimitError(f"Vượt quá giới hạn {self.request_budget} HTTP request cho một lượt quét.")
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise ScanLimitError("Đã vượt quá tổng thời gian quét cho phép.")

    def _load_bounded_content(self, response):
        content_length = response.headers.get("Content-Length")
        if content_length:
            try:
                if int(content_length) > self.max_response_bytes:
                    response.close()
                    raise ScanLimitError("HTTP response lớn hơn giới hạn cho phép.")
            except ValueError:
                pass

        content = bytearray()
        for chunk in response.iter_content(chunk_size=65536):
            content.extend(chunk)
            if len(content) > self.max_response_bytes:
                response.close()
                raise ScanLimitError("HTTP response lớn hơn giới hạn cho phép.")
        response._content = bytes(content)
        response._content_consumed = True

