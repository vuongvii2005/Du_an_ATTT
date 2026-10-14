"""Run an end-to-end scan against the local test target."""

import subprocess
import sys
import time
from pathlib import Path

import requests


ROOT = Path(__file__).resolve().parents[1]
TARGET_APP = Path(__file__).with_name("app.py")
TARGET_URL = "http://127.0.0.1:8080"

sys.path.insert(0, str(ROOT))
from scanner import run_scan  # noqa: E402


def wait_for_target():
    for _ in range(30):
        try:
            requests.get(TARGET_URL, timeout=1)
            return
        except requests.RequestException:
            time.sleep(0.2)
    raise RuntimeError("Test target did not start on http://127.0.0.1:8080")


def main():
    process = subprocess.Popen(
        [sys.executable, str(TARGET_APP)],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_for_target()
        report = run_scan(TARGET_URL)
        findings = report["findings"]

        assert report["summary_count"]["High"] > 0
        assert any(f["module"] == "Header Check" for f in findings)
        assert any(f["module"] == "Directory Check" for f in findings)
        assert any(f["module"] == "Robots.txt Check" for f in findings)
        assert any(f["module"] == "CMS Detection" for f in findings)
        assert any(
            port["port"] == 8080
            for port in report["raw_module_results"]["port_checker"]["open_ports"]
        )

        print("PASS: local target was scanned successfully")
        print(f"Risk: {report['risk_level']} ({report['risk_score']}/100)")
        print(f"Findings: {len(findings)}")
    finally:
        process.terminate()
        process.wait(timeout=5)


if __name__ == "__main__":
    main()
