from app.services.alert_parser import parse_edr_alert


def test_parse_edr_alert():
    alert = {
        "alert_id": "EDR-2026-001",
        "severity": "critical",
        "detection_type": "Ransomware Behavior",
        "hostname": "DESKTOP-LAB-01",
        "ip_address": "192.168.1.20",
        "username": "himanshu",
        "process_name": "suspicious_encryptor.exe",
        "process_hash": "9f2a7c4b8e91d3a6f5c2b7d1a0e4f8c9",
        "description": "Multiple file rename and encryption-like behavior detected by mock EDR."
    }

    parsed = parse_edr_alert(alert)

    assert parsed["alert_id"] == "EDR-2026-001"
    assert parsed["severity"] == "critical"
    assert parsed["detection_type"] == "Ransomware Behavior"
    assert parsed["hostname"] == "DESKTOP-LAB-01"
    assert parsed["ip_address"] == "192.168.1.20"
    assert parsed["username"] == "himanshu"
    assert parsed["process_name"] == "suspicious_encryptor.exe"
    assert parsed["process_hash"] == "9f2a7c4b8e91d3a6f5c2b7d1a0e4f8c9"