# -*- coding: utf-8 -*-
"""Core orchestrator for the bounded web reconnaissance scanner."""

import json
import logging
import os
import sys
import threading
import time

import requests

from modules import (
    cms_checker,
    dir_checker,
    header_checker,
    port_checker,
    robots_checker,
    tls_checker,
)
import report as report_module
from target_guard import GuardedSession, ScanLimitError, TargetGuard, TargetGuardError


USER_AGENT = "LightweightWebVulnScanner/1.1 (+bounded-active-recon)"


def _env_int(name, default, minimum=1, maximum=None):
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    value = max(minimum, value)
    return min(value, maximum) if maximum is not None else value


REQUEST_TIMEOUT = _env_int("SCANNER_REQUEST_TIMEOUT", 15, maximum=60)
MAX_CONCURRENT_SCANS = _env_int("SCANNER_MAX_CONCURRENT", 2, maximum=10)
SCAN_SEMAPHORE = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)
LOGGER = logging.getLogger(__name__)


class ScannerError(Exception):
    """A safe, user-facing failure that prevents the scan from starting."""


def normalize_url(raw_url, guard=None):
    """Validate a URL and return its origin plus hostname."""
    target = (guard or TargetGuard.from_env()).validate_url(raw_url)
    return target.base_url, target.hostname


def check_connectivity(base_url, session):
    """Fetch the target once, following only redirects approved by GuardedSession."""
    try:
        return session.get(
            base_url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
        )
    except TargetGuardError as exc:
        raise ScannerError(str(exc)) from exc
    except requests.exceptions.SSLError as exc:
        raise ScannerError("Lỗi SSL/TLS: chứng chỉ của website không hợp lệ hoặc đã hết hạn.") from exc
    except requests.exceptions.Timeout as exc:
        raise ScannerError(f"Website không phản hồi trong {REQUEST_TIMEOUT} giây.") from exc
    except ScanLimitError as exc:
        raise ScannerError(str(exc)) from exc
    except requests.exceptions.ConnectionError as exc:
        raise ScannerError("Không thể kết nối tới website. Hãy kiểm tra URL và trạng thái máy chủ.") from exc
    except requests.exceptions.RequestException as exc:
        raise ScannerError("Không thể hoàn tất HTTP request tới website.") from exc


def _run_module(module_name, callback, deadline):
    started = time.monotonic()
    if time.monotonic() >= deadline:
        return {
            "module": module_name,
            "status": "skipped",
            "error": "Bỏ qua vì đã hết tổng thời gian quét.",
            "duration_sec": 0,
        }
    try:
        result = callback()
        if not isinstance(result, dict):
            raise TypeError("Module không trả về dictionary.")
        result.setdefault("module", module_name)
        result.setdefault("status", "success")
        result.setdefault("error", None)
    except (TargetGuardError, ScanLimitError) as exc:
        result = {
            "module": module_name,
            "status": "error",
            "error": str(exc) or exc.__class__.__name__,
        }
    except requests.exceptions.Timeout:
        result = {
            "module": module_name,
            "status": "error",
            "error": "Module bị timeout.",
        }
    except requests.exceptions.RequestException:
        result = {
            "module": module_name,
            "status": "error",
            "error": "Module không thể hoàn tất network request.",
        }
    except Exception:
        LOGGER.exception("Lỗi nội bộ trong module %s", module_name)
        result = {
            "module": module_name,
            "status": "error",
            "error": "Module gặp lỗi nội bộ và không thể hoàn tất kiểm tra.",
        }
    result["duration_sec"] = round(time.monotonic() - started, 3)
    return result


def run_scan(raw_url, guard=None, session=None):
    """Run all modules while enforcing target, request, time, and size limits."""
    if not SCAN_SEMAPHORE.acquire(timeout=1):
        raise ScannerError("Hệ thống đang đạt giới hạn lượt quét đồng thời. Vui lòng thử lại sau.")

    started = time.monotonic()
    owns_session = session is None
    try:
        guard = guard or TargetGuard.from_env()
        try:
            initial_target = guard.validate_url(raw_url)
        except TargetGuardError as exc:
            raise ScannerError(str(exc)) from exc

        total_timeout = _env_int("SCANNER_TOTAL_TIMEOUT", 45, minimum=10, maximum=180)
        deadline = started + total_timeout
        if session is None:
            session = GuardedSession(
                guard,
                initial_target=initial_target,
                request_budget=_env_int("SCANNER_REQUEST_BUDGET", 20, minimum=5, maximum=50),
                deadline=deadline,
                max_response_bytes=_env_int(
                    "SCANNER_MAX_RESPONSE_BYTES", 1024 * 1024, minimum=65536, maximum=5 * 1024 * 1024
                ),
                max_redirects=_env_int("SCANNER_MAX_REDIRECTS", 5, minimum=0, maximum=10),
            )
        session.headers.update({"User-Agent": USER_AGENT})

        try:
            homepage_response = check_connectivity(initial_target.base_url, session)
        except ScannerError:
            # Site nhỏ chỉ có HTTP: nếu người dùng không ghi scheme thì thử lại bằng http://.
            if "://" in raw_url or initial_target.scheme != "https":
                raise
            try:
                initial_target = guard.validate_url("http://" + raw_url.strip())
            except TargetGuardError:
                raise ScannerError("Không thể kết nối tới website bằng HTTPS hoặc HTTP.")
            homepage_response = check_connectivity(initial_target.base_url, session)
        response_url = getattr(homepage_response, "url", None) or initial_target.base_url
        try:
            effective_target = (
                session.target_for(response_url)
                if hasattr(session, "target_for")
                else guard.validate_url(response_url)
            )
        except TargetGuardError as exc:
            raise ScannerError(str(exc)) from exc

        module_results = {
            "header_checker": _run_module(
                "header_checker",
                lambda: header_checker.run(
                    homepage_response,
                    session=session,
                    target_url=response_url,
                    deadline=deadline,
                ),
                deadline,
            ),
            "tls_checker": _run_module(
                "tls_checker",
                lambda: tls_checker.run(
                    effective_target,
                    session=session,
                    homepage_response=homepage_response,
                    deadline=deadline,
                ),
                deadline,
            ),
            "dir_checker": _run_module(
                "dir_checker",
                lambda: dir_checker.run(effective_target.base_url, session, deadline=deadline),
                deadline,
            ),
            "robots_checker": _run_module(
                "robots_checker",
                lambda: robots_checker.run(effective_target.base_url, session, deadline=deadline),
                deadline,
            ),
            "cms_checker": _run_module(
                "cms_checker", lambda: cms_checker.run(homepage_response), deadline
            ),
            "port_checker": _run_module(
                "port_checker",
                lambda: port_checker.run(
                    effective_target.hostname,
                    resolved_ip=effective_target.selected_ip,
                    deadline=deadline,
                ),
                deadline,
            ),
        }

        duration = round(time.monotonic() - started, 2)
        return report_module.generate_report(
            effective_target.base_url,
            module_results,
            scan_duration=duration,
            requested_target=initial_target.base_url,
        )
    finally:
        if owns_session and session is not None:
            session.close()
        SCAN_SEMAPHORE.release()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Cách dùng: python scanner.py <url>")
        sys.exit(1)
    try:
        print(json.dumps(run_scan(sys.argv[1]), indent=2, ensure_ascii=False))
    except ScannerError as exc:
        print(f"[LỖI] {exc}")
        sys.exit(1)
