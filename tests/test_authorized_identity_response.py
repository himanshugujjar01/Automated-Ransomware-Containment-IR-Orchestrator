from app.services.authorized_identity_response import (
    validate_authorized_identity_response,
    run_authorized_identity_response
)


def test_authorized_identity_response_blocks_unknown_user():
    result = validate_authorized_identity_response(
        username="unknown.user",
        approval_code="confirm_lab_only",
        execute_real=False
    )

    assert result["allowed"] is False
    assert result["status"] == "blocked"
    assert "allowlist" in result["reason"].lower()


def test_authorized_identity_response_blocks_wrong_approval_code():
    result = validate_authorized_identity_response(
        username="himanshu",
        approval_code="wrong_code",
        execute_real=False
    )

    assert result["allowed"] is False
    assert result["status"] == "blocked"
    assert "approval code" in result["reason"].lower()


def test_authorized_identity_response_blocks_real_action_when_real_idp_disabled():
    result = validate_authorized_identity_response(
        username="himanshu",
        approval_code="confirm_lab_only",
        execute_real=True
    )

    assert result["allowed"] is False
    assert result["status"] == "blocked"
    assert "use_real_idp is false" in result["reason"].lower()


def test_authorized_identity_response_safe_preview():
    result = run_authorized_identity_response(
        username="himanshu",
        approval_code="confirm_lab_only",
        execute_real=False
    )

    assert result["workflow"] == "authorized_identity_response"
    assert result["username"] == "himanshu"
    assert result["execute_real"] is False
    assert result["dry_run"] is True
    assert result["real_action_sent"] is False
    assert result["total_actions"] == 2

    action_types = [
        action["action_type"]
        for action in result["actions"]
    ]

    assert "azure_user_suspension" in action_types
    assert "azure_session_revocation" in action_types


def test_authorized_identity_response_wrong_code_response():
    result = run_authorized_identity_response(
        username="himanshu",
        approval_code="wrong_code",
        execute_real=False
    )

    assert result["workflow"] == "authorized_identity_response"
    assert result["status"] == "blocked"
    assert result["real_action_sent"] is False
    assert result["actions"] == []