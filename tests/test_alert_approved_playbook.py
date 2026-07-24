from app.services.approved_containment_runner import run_full_approved_containment_response


def test_alert_based_approved_workflow_dry_run():
    result = run_full_approved_containment_response(
        hostname="DESKTOP-LAB-01",
        ip_address="192.168.1.20",
        username="himanshu",
        approval_code="confirm_lab_only",
        dry_run=True
    )

    assert result["workflow"] == "approved_full_containment_response"
    assert result["status"] == "completed"
    assert result["dry_run"] is True
    assert result["total_actions"] == 3

    action_types = [
        action["action_type"]
        for action in result["actions"]
    ]

    assert "approved_host_isolation" in action_types
    assert "approved_user_suspension" in action_types
    assert "approved_session_revocation" in action_types


def test_alert_based_approved_workflow_wrong_code():
    result = run_full_approved_containment_response(
        hostname="DESKTOP-LAB-01",
        ip_address="192.168.1.20",
        username="himanshu",
        approval_code="wrong_code",
        dry_run=True
    )

    assert result["workflow"] == "approved_full_containment_response"
    assert result["status"] == "partial_or_blocked"


def test_alert_based_approved_workflow_unknown_host():
    result = run_full_approved_containment_response(
        hostname="UNKNOWN-PC",
        ip_address="192.168.1.20",
        username="himanshu",
        approval_code="confirm_lab_only",
        dry_run=True
    )

    assert result["workflow"] == "approved_full_containment_response"
    assert result["status"] == "partial_or_blocked"