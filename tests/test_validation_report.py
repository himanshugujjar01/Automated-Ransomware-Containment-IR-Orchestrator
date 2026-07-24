from app.services.validation_report import get_week1_week2_validation_report


def test_week1_week2_validation_report_format():
    report = get_week1_week2_validation_report()

    assert report["project"] == "Automated Ransomware Containment & Incident Response Orchestrator"
    assert report["validation_scope"] == "Week 1 and Week 2"
    assert "week1" in report
    assert "week2" in report


def test_week1_requirements_completed():
    report = get_week1_week2_validation_report()

    week1_requirements = report["week1"]["requirements"]

    assert len(week1_requirements) >= 4

    statuses = [
        item["status"]
        for item in week1_requirements
    ]

    assert "completed" in statuses
    assert "completed_lab_and_real_ready" in statuses


def test_week2_requirements_completed():
    report = get_week1_week2_validation_report()

    week2_requirements = report["week2"]["requirements"]

    assert len(week2_requirements) >= 6

    statuses = [
        item["status"]
        for item in week2_requirements
    ]

    assert "completed" in statuses
    assert "completed_safe_mode" in statuses
    assert "completed_lab_and_real_ready" in statuses


def test_safety_configuration_present():
    report = get_week1_week2_validation_report()

    assert "real_edr_enabled" in report
    assert "real_idp_enabled" in report
    assert "manual_approval_required" in report
    assert "allowed_test_hosts" in report
    assert "allowed_test_users" in report