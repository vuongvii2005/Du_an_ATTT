from modules import dir_checker
from conftest import FakeResponse


class DirectorySession:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []

    def get(self, url, **_kwargs):
        self.calls.append(url)
        if ".scanner-not-found-" in url:
            return FakeResponse(200, "Trang không tồn tại", url=url)
        return self.responses.get(url.rsplit("/", 1)[-1], FakeResponse(200, "Trang không tồn tại", url=url))


def test_soft_404_pages_are_not_reported_as_findings():
    session = DirectorySession()

    result = dir_checker.run("https://example.com", session)

    assert result["status"] == "success"
    assert result["findings"] == []
    assert result["soft_404_count"] == len(dir_checker.COMMON_SENSITIVE_PATHS)
    assert len(session.calls) == len(dir_checker.COMMON_SENSITIVE_PATHS) + 1


def test_sensitive_file_requires_content_evidence_and_security_txt_is_not_a_vulnerability():
    session = DirectorySession(
        {
            ".env": FakeResponse(200, "APP_ENV=prod\nDB_HOST=db\nDB_PASSWORD=secret"),
            "security.txt": FakeResponse(200, "Contact: mailto:security@example.com"),
        }
    )

    result = dir_checker.run("https://example.com", session)

    exposed = [item for item in result["findings"] if item["path"] == ".env"]
    assert len(exposed) == 1
    assert exposed[0]["severity"] == "High"
    assert exposed[0]["verification"] == "verified"
    assert all(item["path"] != ".well-known/security.txt" for item in result["findings"])
    assert result["security_txt"]["status_code"] == 200
