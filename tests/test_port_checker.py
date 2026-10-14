from modules import port_checker
from conftest import PUBLIC_IP


def test_port_scan_uses_validated_ip_and_mock_socket(monkeypatch):
    destinations = []

    class FakeSocket:
        def __init__(self, family, socktype):
            self.family = family
            self.socktype = socktype

        def settimeout(self, _timeout):
            pass

        def connect_ex(self, destination):
            destinations.append(destination)
            return 0 if destination[1] == 22 else 1

        def close(self):
            pass

    monkeypatch.setattr(port_checker.socket, "socket", FakeSocket)

    result = port_checker.run("example.com", resolved_ip=PUBLIC_IP)

    assert result["status"] == "success"
    assert result["resolved_ip"] == PUBLIC_IP
    assert [item["port"] for item in result["open_ports"]] == [22]
    assert all(destination[0] == PUBLIC_IP for destination in destinations)
