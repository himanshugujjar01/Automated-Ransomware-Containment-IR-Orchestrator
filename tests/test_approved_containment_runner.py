from app.services.edr_response_runner import (
    validate_edr_real_action,
    run_approved_host_isolation
)

from app.services.approved_containment_runner import (
    run_full_approved_containment_response
)


def test_validate_edr_action_success():
    result = validate_edr_real_action(
        hostname="DESKTOP-LAB-01",
        approval_code="confirm_lab_only",
        dry_run=True
    )

    assert result["allowed"] is True
    assert result["status"] == "approved"


def test_validate_edr_action_wrong_approval_code():
    result = validate_edr_real_action(
        hostname="DESKTOP-LAB-01",
        approval_code="wrong_code",
        dry_run=True
    )

    assert result["allowed"] is False
    assert result["status"] == "blocked"
    assert "approval code" in result["reason"].lower()


def test_validate_edr_action_unknown_host():
    result = validate_edr_real_action(
        hostname="UNKNOWN-PC",
        approval_code="confirm_lab_only",
        dry_run=True
    )

    assert result["allowed"] is False
    assert result["status"] == "blocked"
    assert "allowlist" in result["reason"].lower()


def test_approved_host_isolation_dry_run():
    result = run_approved_host_isolation(
        hostname="DESKTOP-LAB-01",
        ip_address="192.168.1.20",
        approval_code="confirm_lab_only",
        dry_run=True
    )

    assert result["action_type"] == "approved_host_isolation"
    assert result["target"] == "DESKTOP-LAB-01"
    assert result["status"] == "dry_run"
    assert result["dry_run"] is True


def test_full_approved_containment_response_dry_run():
    result = run_full_approved_containment_response(
        hostname="DESKTOP-LAB-01",
        ip_address="192.168.1.20",
        username="himanshu",
        approval_code="confirm_lab_only",
        dry_run=True
    )

    assert result["workflow"] == "approved_full_containment_response"
    assert result["status"] == "completed"
    assert result["total_actions"] == 3
    assert len(result["actions"]) == 3


def test_full_approved_containment_response_wrong_code():
    result = run_full_approved_containment_response(
        hostname="DESKTOP-LAB-01",
        ip_address="192.168.1.20",
        username="himanshu",
        approval_code="wrong_code",
        dry_run=True
    )

    assert result["workflow"] == "approved_full_containment_response"
    assert result["status"] == "partial_or_blocked"