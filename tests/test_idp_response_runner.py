from app.services.idp_response_runner import (
    validate_idp_real_action,
    run_approved_user_suspension,
    run_approved_session_revocation,
    run_full_approved_identity_response
)


def test_validate_idp_action_invalid_approval_code():
    result = validate_idp_real_action(
        username="himanshu",
        approval_code="wrong_code",
        dry_run=True
    )

    assert result["allowed"] is False
    assert result["status"] == "blocked"
    assert "approval code" in result["reason"].lower()


def test_validate_idp_action_unknown_user():
    result = validate_idp_real_action(
        username="unknown.user",
        approval_code="confirm_lab_only",
        dry_run=True
    )

    assert result["allowed"] is False
    assert result["status"] == "blocked"
    assert "allowlist" in result["reason"].lower()


def test_approved_user_suspension_dry_run():
    result = run_approved_user_suspension(
        username="himanshu",
        approval_code="confirm_lab_only",
        dry_run=True
    )

    assert result["action_type"] == "approved_user_suspension"
    assert result["target"] == "himanshu"
    assert result["status"] == "dry_run"
    assert result["dry_run"] is True


def test_approved_session_revocation_dry_run():
    result = run_approved_session_revocation(
        username="himanshu",
        approval_code="confirm_lab_only",
        dry_run=True
    )

    assert result["action_type"] == "approved_session_revocation"
    assert result["target"] == "himanshu"
    assert result["status"] == "dry_run"
    assert result["dry_run"] is True


def test_full_approved_identity_response_dry_run():
    result = run_full_approved_identity_response(
        username="himanshu",
        approval_code="confirm_lab_only",
        dry_run=True
    )

    assert result["workflow"] == "approved_identity_response"
    assert result["status"] == "completed"
    assert result["total_actions"] == 2
    assert len(result["actions"]) == 2