from app.services.identity_response import suspend_user, revoke_sessions


def test_suspend_user_success():
    result = suspend_user("himanshu")

    assert result["action_type"] == "user_suspension"
    assert result["target"] == "himanshu"
    assert result["status"] == "success"
    assert "suspended successfully" in result["details"]


def test_suspend_user_missing_username():
    result = suspend_user("")

    assert result["action_type"] == "user_suspension"
    assert result["target"] == "unknown"
    assert result["status"] == "failed"
    assert "Username is missing" in result["details"]


def test_revoke_sessions_success():
    result = revoke_sessions("himanshu")

    assert result["action_type"] == "session_revocation"
    assert result["target"] == "himanshu"
    assert result["status"] == "success"
    assert "revoked successfully" in result["details"]


def test_revoke_sessions_missing_username():
    result = revoke_sessions("")

    assert result["action_type"] == "session_revocation"
    assert result["target"] == "unknown"
    assert result["status"] == "failed"
    assert "Username is missing" in result["details"]