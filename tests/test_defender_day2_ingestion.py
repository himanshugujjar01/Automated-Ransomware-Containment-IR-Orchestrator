from app.integrations.defender_edr import (
    is_placeholder,
    normalize_defender_alert,
    fetch_and_normalize_high_severity_alerts
)


def test_is_placeholder_true():
    assert is_placeholder("change_me") is True
    assert is_placeholder("") is True


def test_is_placeholder_false():
    assert is_placeholder("real_value") is False


def test_normalize_defender_alert_basic_fields():
    raw_alert = {
        "id": "abc123",
        "severity": "High",
        "title": "Suspicious ransomware behavior",
        "computerDnsName": "DESKTOP-LAB-01",
        "ipAddress": "192.168.1.20",
        "relatedUser": "himanshu",
        "description": "Possible ransomware activity detected.",
        "evidence": [
            {
                "fileName": "suspicious_encryptor.exe",
                "sha256": "9f2a7c4b8e91d3a6f5c2b7d1a0e4f8c9"
            }
        ]
    }

    result = normalize_defender_alert(raw_alert)

    assert result["alert_id"] == "MDE-abc123"
    assert result["severity"] == "high"
    assert result["detection_type"] == "Suspicious ransomware behavior"
    assert result["hostname"] == "DESKTOP-LAB-01"
    assert result["ip_address"] == "192.168.1.20"
    assert result["username"] == "himanshu"
    assert result["process_name"] == "suspicious_encryptor.exe"
    assert result["process_hash"] == "9f2a7c4b8e91d3a6f5c2b7d1a0e4f8c9"


def test_normalize_defender_alert_with_missing_fields():
    raw_alert = {
        "id": "missing-fields-alert",
        "severity": "High",
        "title": "High severity alert",
        "evidence": []
    }

    result = normalize_defender_alert(raw_alert)

    assert result["alert_id"] == "MDE-missing-fields-alert"
    assert result["severity"] == "high"
    assert result["hostname"] == "unknown"
    assert result["ip_address"] == "unknown"
    assert result["username"] == "unknown"


def test_fetch_without_credentials_returns_safe_response():
    result = fetch_and_normalize_high_severity_alerts(limit=5)

    assert "integration" in result
    assert "configured" in result
    assert "normalized_alerts" in result