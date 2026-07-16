from app.integrations.mock_idp import mock_suspend_user, mock_revoke_sessions


def suspend_user(username: str) -> dict:
    """
    Runs user suspension action using mock identity provider.
    """

    if not username:
        return {
            "action_type": "user_suspension",
            "target": "unknown",
            "status": "failed",
            "details": "Username is missing. User suspension cannot be performed."
        }

    result = mock_suspend_user(username)

    return {
        "action_type": "user_suspension",
        "target": username,
        "status": result["status"],
        "details": result["message"],
        "timestamp": result["timestamp"]
    }


def revoke_sessions(username: str) -> dict:
    """
    Runs session revocation action using mock identity provider.
    """

    if not username:
        return {
            "action_type": "session_revocation",
            "target": "unknown",
            "status": "failed",
            "details": "Username is missing. Session revocation cannot be performed."
        }

    result = mock_revoke_sessions(username)

    return {
        "action_type": "session_revocation",
        "target": username,
        "status": result["status"],
        "details": result["message"],
        "timestamp": result["timestamp"]
    }