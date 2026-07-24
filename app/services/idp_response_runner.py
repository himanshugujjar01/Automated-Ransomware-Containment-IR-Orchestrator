from app.config import (
    USE_REAL_IDP,
    REQUIRE_MANUAL_APPROVAL,
    REAL_ACTION_APPROVAL_CODE
)

from app.services.safety_guard import is_allowed_user
from app.integrations.azure_ad import (
    is_graph_configured,
    disable_user_account,
    revoke_user_sessions
)


def validate_idp_real_action(
    username: str,
    approval_code: str,
    dry_run: bool = True
) -> dict:
    """
    Validates whether a real identity response action is allowed.

    Safety rules:
    1. Username must be present.
    2. User must be in sandbox allowlist.
    3. USE_REAL_IDP must be true for real execution.
    4. Manual approval code must match if approval is required.
    5. Microsoft Graph must be configured for non-dry-run execution.
    """

    if not username:
        return {
            "allowed": False,
            "status": "blocked",
            "reason": "Username is missing."
        }

    if not is_allowed_user(username):
        return {
            "allowed": False,
            "status": "blocked",
            "reason": "User is not in approved sandbox allowlist."
        }

    if REQUIRE_MANUAL_APPROVAL and approval_code != REAL_ACTION_APPROVAL_CODE:
        return {
            "allowed": False,
            "status": "blocked",
            "reason": "Invalid or missing manual approval code."
        }

    if not dry_run and not USE_REAL_IDP:
        return {
            "allowed": False,
            "status": "blocked",
            "reason": "USE_REAL_IDP is false. Real identity action is disabled."
        }

    if not dry_run and not is_graph_configured():
        return {
            "allowed": False,
            "status": "blocked",
            "reason": "Microsoft Graph credentials are not configured."
        }

    return {
        "allowed": True,
        "status": "approved",
        "reason": "Identity response action passed safety validation."
    }


def run_approved_user_suspension(
    username: str,
    approval_code: str,
    dry_run: bool = True
) -> dict:
    """
    Runs approved user suspension.

    dry_run=True is safe and does not disable any real account.
    dry_run=False should only be used in an authorized lab tenant.
    """

    validation = validate_idp_real_action(
        username=username,
        approval_code=approval_code,
        dry_run=dry_run
    )

    if not validation["allowed"]:
        return {
            "action_type": "approved_user_suspension",
            "target": username,
            "status": validation["status"],
            "dry_run": dry_run,
            "details": validation["reason"]
        }

    result = disable_user_account(
        user_id_or_upn=username,
        dry_run=dry_run
    )

    return {
        "action_type": "approved_user_suspension",
        "target": username,
        "status": result["status"],
        "dry_run": dry_run,
        "details": result["message"]
    }


def run_approved_session_revocation(
    username: str,
    approval_code: str,
    dry_run: bool = True
) -> dict:
    """
    Runs approved user session revocation.

    dry_run=True is safe and does not revoke real sessions.
    dry_run=False should only be used in an authorized lab tenant.
    """

    validation = validate_idp_real_action(
        username=username,
        approval_code=approval_code,
        dry_run=dry_run
    )

    if not validation["allowed"]:
        return {
            "action_type": "approved_session_revocation",
            "target": username,
            "status": validation["status"],
            "dry_run": dry_run,
            "details": validation["reason"]
        }

    result = revoke_user_sessions(
        user_id_or_upn=username,
        dry_run=dry_run
    )

    return {
        "action_type": "approved_session_revocation",
        "target": username,
        "status": result["status"],
        "dry_run": dry_run,
        "details": result["message"]
    }


def run_full_approved_identity_response(
    username: str,
    approval_code: str,
    dry_run: bool = True
) -> dict:
    """
    Runs both user suspension and session revocation in one approved workflow.
    """

    suspension_result = run_approved_user_suspension(
        username=username,
        approval_code=approval_code,
        dry_run=dry_run
    )

    revocation_result = run_approved_session_revocation(
        username=username,
        approval_code=approval_code,
        dry_run=dry_run
    )

    actions = [
        suspension_result,
        revocation_result
    ]

    failed_or_blocked = [
        action for action in actions
        if action["status"] not in ["success", "dry_run"]
    ]

    return {
        "username": username,
        "dry_run": dry_run,
        "workflow": "approved_identity_response",
        "status": "completed" if not failed_or_blocked else "partial_or_blocked",
        "total_actions": len(actions),
        "actions": actions
    }