from app.integrations.slack_client import (
    build_message,
    get_slack_status,
    send_slack_alert
)

sample_alert = {
    "alert_id": "SIM-001",
    "severity": "High",
    "hostname": "DESKTOP-LAB",
    "username": "himanshu",
    "process_name": "wannacry.exe",
    "process_hash": "ABC123"
}


def test_status():

    result = get_slack_status()

    assert "integration" in result

    assert "status" in result


def test_message():

    msg = build_message(sample_alert)

    assert "SIM-001" in msg

    assert "wannacry.exe" in msg


def test_mock_send():

    result = send_slack_alert(sample_alert)

    assert "status" in result