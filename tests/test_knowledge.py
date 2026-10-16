import ast
from pathlib import Path

import pytest

import knowledge
from modules import dir_checker, port_checker

MODULES_DIR = Path(__file__).resolve().parent.parent / "modules"


def _titles_from_source(filename, category=None):
    """Lấy các title cố định được truyền vào _finding(...) trong mã nguồn module."""
    tree = ast.parse((MODULES_DIR / filename).read_text(encoding="utf-8"))
    titles = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "_finding"):
            continue
        args = node.args
        if category is None:  # tls_checker: title là tham số đầu tiên
            candidate = args[0] if args else None
            module = "TLS/SSL Check"
        else:  # header_checker: (category, title, ...)
            if len(args) < 2 or not isinstance(args[0], ast.Constant):
                continue
            module, candidate = args[0].value, args[1]
        if isinstance(candidate, ast.Constant) and isinstance(candidate.value, str):
            titles.append((module, candidate.value))
    return titles


def _all_finding_samples():
    samples = []
    for header in (
        "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
        "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
    ):
        samples.append(("Header Check", f"Thiếu header: {header}", "Medium"))
    for header in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
        samples.append(("Header Check", f"Rò rỉ thông tin: {header}", "Info"))
    samples += [("Cookie Check", "Cookie 'sid' thiếu Secure", "Low"),
                ("Cookie Check", "Cookie 'sid' dùng SameSite=None nhưng thiếu Secure", "Low"),
                ("Cookie Check", "Cookie 'sid' thiếu HttpOnly", "Low"),
                ("Cookie Check", "Cookie 'sid' thiếu SameSite", "Low"),
                ("Cookie Check", "Cookie 'sid' có Domain không phù hợp", "Low"),
                ("Cookie Check", "Cookie 'sid' có Path không hợp lệ", "Low")]
    samples += _titles_with_severity(_titles_from_source("header_checker.py", category=True))
    samples += _titles_with_severity(_titles_from_source("tls_checker.py"))
    for path in dir_checker.COMMON_SENSITIVE_PATHS:
        if path in dir_checker.PUBLIC_INFORMATION_PATHS:
            continue
        for severity, status in (("High", 200), ("Medium", 200), ("Info", 403), ("Info", 200)):
            samples.append(("Directory Check", f"Path: /{path} ({status})", severity))
    for port, service in port_checker.COMMON_PORTS.items():
        samples.append(("Port Scan", f"Cổng mở: {port} ({service})", "Info"))
    for cms in ("WordPress", "Joomla", "Drupal", "Magento"):
        samples.append(("CMS Detection", f"CMS phát hiện: {cms}", "Info"))
    samples.append(("Robots.txt Check", "Disallow nhạy cảm: /admin", "Low"))
    samples += [
        ("TLS/SSL Check", "Hostname không khớp chứng chỉ TLS", "High"),
        ("TLS/SSL Check", "Chứng chỉ TLS không hợp lệ", "High"),
        ("TLS/SSL Check", "Chứng chỉ TLS đã hết hạn", "High"),
    ]
    return samples


def _titles_with_severity(items):
    return [(module, title, "Medium") for module, title in items]


@pytest.mark.parametrize(("module", "title", "severity"), _all_finding_samples())
def test_every_known_finding_type_has_specific_explanation(module, title, severity):
    info = knowledge.explain({"module": module, "title": title, "severity": severity})

    assert info["generic"] is False, f"{module} / {title} chưa có giải thích riêng"
    assert info["key"] in knowledge.ENTRIES


@pytest.mark.parametrize(
    "finding",
    [None, {}, {"module": "Lạ", "title": "Không có trong từ điển"}, {"module": None, "title": None},
     {"module": "Port Scan", "title": "Cổng mở: abc"}, {"module": "Directory Check", "title": ""}],
)
def test_unknown_or_malformed_finding_gets_valid_fallback(finding):
    info = knowledge.explain(finding)

    assert info["generic"] is True
    assert info["key"] == "generic"
    for field in ("what", "why", "fix"):
        assert info[field].strip()
    assert info["learn_more"] == []


def test_all_entries_are_complete_and_links_are_https():
    for key, entry in knowledge.ENTRIES.items():
        for field in ("title", "what", "why", "fix"):
            assert entry[field].strip(), f"{key}.{field} đang trống"
        for link in entry["learn_more"]:
            assert link["url"].startswith("https://"), key
            assert link["label"].strip(), key
