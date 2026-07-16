from datetime import datetime, timezone


def mock_suspend_user(username: str) -> dict:
    """
    Simulates suspending a compromised user account.

    In a real enterprise environment, this function would call
    Active Directory, Azure AD, Entra ID, or Okta API.
    In this lab project, it safely returns a mock success response.
    """

    return {
        "integration": "mock_identity_provider",
        "action": "suspend_user",
        "username": username,
        "status": "success",
        "message": f"User account '{username}' suspended successfully using mock identity provider.",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


def mock_revoke_sessions(username: str) -> dict:
    """
    Simulates revoking active sessions of a compromised user.

    In a real enterprise environment, this function would revoke
    refresh tokens, active sessions, and authentication tokens.
    In this lab project, it safely returns a mock success response.
    """

    return {
        "integration": "mock_identity_provider",
        "action": "revoke_sessions",
        "username": username,
        "status": "success",
        "message": f"Active sessions for user '{username}' revoked successfully using mock identity provider.",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }