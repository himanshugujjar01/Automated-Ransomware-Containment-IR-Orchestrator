from app.services.executive_dashboard import build_executive_dashboard


def test_dashboard():

    result = build_executive_dashboard()

    assert result["platform"] == "Ransomware IR Orchestrator"


def test_status():

    result = build_executive_dashboard()

    assert result["status"] == "Healthy"


def test_metrics():

    result = build_executive_dashboard()

    assert "security_metrics" in result


def test_summary():

    result = build_executive_dashboard()

    assert "incident_summary" in result


def test_timeline():

    result = build_executive_dashboard()

    assert "timeline" in result


def test_simulation():

    result = build_executive_dashboard()

    assert result["simulation"]["status"] == "ready"