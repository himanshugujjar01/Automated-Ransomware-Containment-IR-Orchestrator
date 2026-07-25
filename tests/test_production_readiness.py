from app.services.production_readiness import (
    is_configured,
    get_production_readiness_report
)


def test_is_configured_true():
    result = is_configured("value1", "value2", "value3")

    assert result is True


def test_is_configured_false_for_change_me():
    result = is_configured("value1", "change_me", "value3")

    assert result is False


def test_production_readiness_report_format():
    report = get_production_readiness_report()

    assert report["project"] == "Automated Ransomware Containment & Incident Response Orchestrator"
    assert report["readiness_scope"] == "Production integration setup"
    assert "safety" in report
    assert "integrations" in report


def test_production_readiness_integrations_present():
    report = get_production_readiness_report()

    integrations = report["integrations"]

    assert "microsoft_defender_edr" in integrations
    assert "microsoft_graph_azure_ad" in integrations
    assert "aws_s3_evidence_storage" in integrations
    assert "jira_ticketing" in integrations
    assert "slack_or_teams_notifications" in integrations