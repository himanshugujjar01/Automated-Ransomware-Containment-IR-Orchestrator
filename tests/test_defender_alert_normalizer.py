from app.integrations.defender_edr import (
    normalize_defender_alert,
    fetch_and_normalize_high_severity_alerts
)


def test_normalize_defender_alert():
    sample_defender_alert = {
        "id": "12345",
        "severity": "High",
        "title": "Ransomware behavior detected",
        "description": "Suspicious encryption activity detected on endpoint.",
        "computerDnsName": "DESKTOP-LAB-01",
        "ipAddress": "192.168.1.20",
        "userPrincipalName": "himanshu",
        "threatName": "suspicious_encryptor.exe",
        "sha256": "9f2a7c4b8e91d3a6f5c2b7d1a0e4f8c9"
    }

    normalized = normalize_defender_alert(sample_defender_alert)

    assert normalized["alert_id"] == "MDE-12345"
    assert normalized["severity"] == "high"
    assert normalized["detection_type"] == "Ransomware behavior detected"
    assert normalized["hostname"] == "DESKTOP-LAB-01"
    assert normalized["ip_address"] == "192.168.1.20"
    assert normalized["username"] == "himanshu"
    assert normalized["process_name"] == "suspicious_encryptor.exe"
    assert normalized["process_hash"] == "9f2a7c4b8e91d3a6f5c2b7d1a0e4f8c9"


def test_normalize_defender_alert_with_missing_fields():
    sample_defender_alert = {
        "id": "67890",
        "severity": "High",
        "title": "Suspicious activity"
    }

    normalized = normalize_defender_alert(sample_defender_alert)

    assert normalized["alert_id"] == "MDE-67890"
    assert normalized["severity"] == "high"
    assert normalized["hostname"] == "unknown-host"
    assert normalized["ip_address"] == "unknown-ip"
    assert normalized["username"] == "unknown-user"
    assert normalized["process_hash"] == "unknown-hash"


def test_fetch_and_normalize_safe_when_not_configured():
    result = fetch_and_normalize_high_severity_alerts(limit=5)

    assert "configured" in result
    assert "normalized_alerts" in result

    if result["configured"] is False:
        assert result["fetched"] is False
        assert result["normalized_alerts"] == []