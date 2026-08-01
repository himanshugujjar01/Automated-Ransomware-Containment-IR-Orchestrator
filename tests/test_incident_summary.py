from app.services.incident_summary import build_incident_summary


def test_summary():

    result = build_incident_summary("EDR-001")

    assert result["alert_id"] == "EDR-001"


def test_summary_status():

    result = build_incident_summary("EDR-001")

    assert result["summary"]["status"] == "contained"


def test_ticket():

    result = build_incident_summary("EDR-001")

    assert result["summary"]["ticket_created"] is True


def test_host():

    result = build_incident_summary("EDR-001")

    assert result["summary"]["host_isolated"] is True


def test_slack():

    result = build_incident_summary("EDR-001")

    assert result["summary"]["slack_notified"] is True


def test_teams():

    result = build_incident_summary("EDR-001")

    assert result["summary"]["teams_notified"] is True


def test_timeline():

    result = build_incident_summary("EDR-001")

    assert len(result["timeline"]) > 0


def test_metrics():

    result = build_incident_summary("EDR-001")

    assert "containment" in result["metrics"]