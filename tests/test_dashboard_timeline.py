from app.services.dashboard_service import build_incident_timeline


def test_timeline_alert_id():
    result = build_incident_timeline("EDR-1001")

    assert result["alert_id"] == "EDR-1001"


def test_timeline_exists():
    result = build_incident_timeline("EDR-1001")

    assert "timeline" in result


def test_timeline_not_empty():
    result = build_incident_timeline("EDR-1001")

    assert len(result["timeline"]) > 0


def test_first_event():
    result = build_incident_timeline("EDR-1001")

    assert result["timeline"][0]["event"] == "Alert Received"


def test_last_event():
    result = build_incident_timeline("EDR-1001")

    assert result["timeline"][-1]["event"] == "Incident Closed"


def test_all_events_completed():
    result = build_incident_timeline("EDR-1001")

    for item in result["timeline"]:
        assert item["status"] == "completed"