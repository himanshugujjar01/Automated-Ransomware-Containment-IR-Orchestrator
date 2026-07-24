from app.config import USE_REAL_IDP
from app.integrations.mock_idp import mock_suspend_user, mock_revoke_sessions
from app.services.safety_guard import is_allowed_user

try:
    from app.integrations.azure_ad import (
        disable_user_account,
        revoke_user_sessions
    )
except Exception:
    disable_user_account = None
    revoke_user_sessions = None


def suspend_user(username: str) -> dict:
    """
    Runs user suspension action.

    Mock mode:
    - Uses mock identity provider.

    Real IDP mode:
    - Uses Microsoft Graph connector.
    - Protected by sandbox allowlist.
    - Uses dry_run=True by default in this project.
    """

    if not username:
        return {
            "action_type": "user_suspension",
            "target": "unknown",
            "status": "failed",
            "details": "Username is missing. User suspension cannot be performed."
        }

    if USE_REAL_IDP:
        if not is_allowed_user(username):
            return {
                "action_type": "user_suspension",
                "target": username,
                "status": "blocked",
                "details": "User is not in approved sandbox allowlist. Real IDP suspension blocked."
            }

        if disable_user_account is None:
            return {
                "action_type": "user_suspension",
                "target": username,
                "status": "failed",
                "details": "Azure AD integration module could not be loaded."
            }

        graph_result = disable_user_account(
            user_id_or_upn=username,
            dry_run=True
        )

        return {
            "action_type": "user_suspension",
            "target": username,
            "status": graph_result["status"],
            "details": graph_result["message"]
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
    Runs session revocation action.

    Mock mode:
    - Uses mock identity provider.

    Real IDP mode:
    - Uses Microsoft Graph connector.
    - Protected by sandbox allowlist.
    - Uses dry_run=True by default in this project.
    """

    if not username:
        return {
            "action_type": "session_revocation",
            "target": "unknown",
            "status": "failed",
            "details": "Username is missing. Session revocation cannot be performed."
        }

    if USE_REAL_IDP:
        if not is_allowed_user(username):
            return {
                "action_type": "session_revocation",
                "target": username,
                "status": "blocked",
                "details": "User is not in approved sandbox allowlist. Real IDP session revocation blocked."
            }

        if revoke_user_sessions is None:
            return {
                "action_type": "session_revocation",
                "target": username,
                "status": "failed",
                "details": "Azure AD integration module could not be loaded."
            }

        graph_result = revoke_user_sessions(
            user_id_or_upn=username,
            dry_run=True
        )

        return {
            "action_type": "session_revocation",
            "target": username,
            "status": graph_result["status"],
            "details": graph_result["message"]
        }

    result = mock_revoke_sessions(username)

    return {
        "action_type": "session_revocation",
        "target": username,
        "status": result["status"],
        "details": result["message"],
        "timestamp": result["timestamp"]
    }