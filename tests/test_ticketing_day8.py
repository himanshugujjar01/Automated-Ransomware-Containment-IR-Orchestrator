from app.integrations.ticketing_client import (
    get_ticketing_status,
    build_ticket_payload,
    create_incident_ticket,
    create_mock_ticket,
    map_priority
)


sample_alert = {
    "alert_id": "EDR-TEST-008",
    "severity": "critical",
    "detection_type": "Ransomware Behavior",
    "hostname": "DESKTOP-LAB-01",
    "ip_address": "192.168.1.20",
    "username": "himanshu",
    "process_name": "suspicious_encryptor.exe",
    "process_hash": "9f2a7c4b8e91d3a6f5c2b7d1a0e4f8c9",
    "description": "Multiple file encryption behavior detected."
}


def test_ticketing_status_format():
    result = get_ticketing_status()

    assert result["integration"] == "Incident Ticketing"
    assert "enabled" in result
    assert "provider" in result
    assert "jira" in result
    assert "servicenow" in result


def test_priority_mapping():
    assert map_priority("critical") == "High"
    assert map_priority("high") == "High"
    assert map_priority("medium") == "Medium"
    assert map_priority("low") == "Low"


def test_build_ticket_payload():
    result = build_ticket_payload(
        alert_data=sample_alert,
        actions=[],
        artifacts=[]
    )

    assert "summary" in result
    assert "description" in result
    assert result["priority"] == "High"
    assert result["alert_id"] == "EDR-TEST-008"


def test_create_mock_ticket():
    result = create_mock_ticket(
        alert_data=sample_alert,
        actions=[],
        artifacts=[]
    )

    assert result["provider"] == "mock"
    assert result["status"] == "mock_created"
    assert result["real_action_sent"] is False
    assert result["ticket_id"].startswith("MOCK-IR-")


def test_create_incident_ticket_safe_mock_when_execute_real_false():
    result = create_incident_ticket(
        alert_data=sample_alert,
        provider="jira",
        execute_real=False
    )

    assert result["provider"] == "mock"
    assert result["status"] == "mock_created"
    assert result["real_action_sent"] is False


def test_real_ticket_creation_blocked_when_disabled():
    result = create_incident_ticket(
        alert_data=sample_alert,
        provider="jira",
        execute_real=True
    )

    assert result["status"] in ["blocked", "credentials_pending"]
    assert result["real_action_sent"] is False


def test_invalid_provider_when_execute_real_true():
    result = create_incident_ticket(
        alert_data=sample_alert,
        provider="invalid_provider",
        execute_real=True
    )

    assert result["status"] in ["blocked", "failed", "credentials_pending"]
    assert result["real_action_sent"] is False