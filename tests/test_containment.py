from app.services.containment import isolate_host


def test_isolate_host_success():
    result = isolate_host("DESKTOP-LAB-01", "192.168.1.20")

    assert result["action_type"] == "host_isolation"
    assert result["target"] == "DESKTOP-LAB-01"
    assert result["ip_address"] == "192.168.1.20"
    assert result["status"] == "success"


def test_isolate_host_missing_hostname():
    result = isolate_host("", "192.168.1.20")

    assert result["action_type"] == "host_isolation"
    assert result["status"] == "failed"
    assert "Hostname is missing" in result["details"]


def test_isolate_host_missing_ip():
    result = isolate_host("DESKTOP-LAB-01", "")

    assert result["action_type"] == "host_isolation"
    assert result["status"] == "failed"
    assert "IP address is missing" in result["details"]