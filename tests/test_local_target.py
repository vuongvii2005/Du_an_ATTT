"""The bundled local fixture (test_target/) must stay detectable by the scanner."""

import importlib.util
import os

import pytest

from modules import dir_checker

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# test_target/app.py is also called "app", so load it under a distinct name
# instead of putting its folder on sys.path (which would shadow the scanner UI).
_spec = importlib.util.spec_from_file_location(
    "local_fixture_app", os.path.join(ROOT, "test_target", "app.py")
)
_fixture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fixture)
EXPOSED_FIXTURES = _fixture.EXPOSED_FIXTURES
fixture_app = _fixture.app


class ClientResponse:
    """Adapt a Flask test response to the attributes dir_checker reads."""

    def __init__(self, response):
        self.status_code = response.status_code
        self.headers = response.headers
        self.content = response.get_data()
        self.encoding = "utf-8"

    @property
    def text(self):
        return self.content.decode("utf-8", errors="ignore")


@pytest.mark.parametrize(
    "path",
    [".env", ".git/config", "backup.zip", "backup.sql", "config.php.bak", "phpinfo.php", "web.config"],
)
def test_sensitive_fixture_matches_dir_checker_signature(path):
    client = fixture_app.test_client()
    response = ClientResponse(client.get("/" + path))

    exposed, _evidence = dir_checker._sensitive_evidence(path, response)

    assert path in EXPOSED_FIXTURES
    assert exposed, f"fixture for {path} no longer matches a verified-finding signature"


def test_unknown_path_is_a_plain_404_so_soft_404_baseline_stays_clean():
    client = fixture_app.test_client()
    assert client.get("/.scanner-not-found-abc").status_code == 404
