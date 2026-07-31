from app.integrations.teams_client import (
    build_message,
    get_teams_status,
    send_teams_alert
)

sample = {

    "alert_id":"SIM-001",

    "severity":"High",

    "hostname":"DESKTOP",

    "username":"himanshu",

    "process_name":"wannacry.exe",

    "process_hash":"ABC123"
}


def test_status():

    result = get_teams_status()

    assert "integration" in result


def test_message():

    message = build_message(sample)

    assert "SIM-001" in message


def test_send():

    result = send_teams_alert(sample)

    assert "status" in result