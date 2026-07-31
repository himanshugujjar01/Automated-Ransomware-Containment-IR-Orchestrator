from app.services.notification_service import (
    notify_soc,
    notification_status
)

sample = {

    "alert_id":"SIM-001",

    "severity":"High",

    "hostname":"LAB-PC",

    "username":"himanshu",

    "process_name":"wannacry.exe",

    "process_hash":"ABC123"
}


def test_notification():

    result = notify_soc(sample)

    assert "slack" in result

    assert "teams" in result


def test_status():

    result = notification_status()

    assert "workflow" in result