from app.services.safety_guard import (
    is_allowed_host,
    is_allowed_user,
    validate_sandbox_target
)


def test_allowed_host():
    assert is_allowed_host("DESKTOP-LAB-01") is True


def test_block_unknown_host():
    assert is_allowed_host("UNKNOWN-PC") is False


def test_allowed_user():
    assert is_allowed_user("himanshu") is True


def test_block_unknown_user():
    assert is_allowed_user("unknown.user") is False


def test_validate_sandbox_target_success():
    result = validate_sandbox_target("DESKTOP-LAB-01", "himanshu")

    assert result["approved"] is True
    assert result["host_allowed"] is True
    assert result["user_allowed"] is True


def test_validate_sandbox_target_blocked():
    result = validate_sandbox_target("UNKNOWN-PC", "unknown.user")

    assert result["approved"] is False
    assert result["host_allowed"] is False
    assert result["user_allowed"] is False