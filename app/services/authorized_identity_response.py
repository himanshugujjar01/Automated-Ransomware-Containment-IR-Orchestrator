from app.config import (
    USE_REAL_IDP,
    REQUIRE_MANUAL_APPROVAL,
    REAL_ACTION_APPROVAL_CODE
)

from app.services.safety_guard import is_allowed_user

from app.integrations.azure_ad import (
    disable_user_account,
    revoke_user_sessions
)


def validate_authorized_identity_response(
    username: str,
    approval_code: str,
    execute_real: bool = False
) -> dict:
    """
    Validates whether Azure AD identity response is allowed.

    Real identity action is blocked unless:
    1. Username is present.
    2. User is in allowlist.
    3. Approval code is valid.
    4. USE_REAL_IDP=true.
    5. execute_real=true.
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
            "reason": "Invalid or missing approval code."
        }

    if execute_real and not USE_REAL_IDP:
        return {
            "allowed": False,
            "status": "blocked",
            "reason": "USE_REAL_IDP is false. Real Azure AD identity response is disabled."
        }

    return {
        "allowed": True,
        "status": "approved",
        "reason": "Identity response request passed safety validation."
    }


def run_authorized_identity_response(
    username: str,
    approval_code: str,
    execute_real: bool = False
) -> dict:
    """
    Runs authorized Azure AD identity response.

    execute_real=False:
        Safe dry-run preview only.

    execute_real=True:
        Disables user and revokes sessions only if all controls pass.
    """

    validation = validate_authorized_identity_response(
        username=username,
        approval_code=approval_code,
        execute_real=execute_real
    )

    if not validation["allowed"]:
        return {
            "workflow": "authorized_identity_response",
            "username": username,
            "execute_real": execute_real,
            "status": validation["status"],
            "real_action_sent": False,
            "message": validation["reason"],
            "actions": []
        }

    dry_run = not execute_real

    suspension_result = disable_user_account(
        user_id_or_upn=username,
        dry_run=dry_run
    )

    revocation_result = revoke_user_sessions(
        user_id_or_upn=username,
        dry_run=dry_run
    )

    actions = [
        {
            "action_type": "azure_user_suspension",
            "target": username,
            "status": suspension_result.get("status"),
            "dry_run": suspension_result.get("dry_run", dry_run),
            "details": suspension_result.get("message", suspension_result.get("details", "User suspension action completed."))
        },
        {
            "action_type": "azure_session_revocation",
            "target": username,
            "status": revocation_result.get("status"),
            "dry_run": revocation_result.get("dry_run", dry_run),
            "details": revocation_result.get("message", revocation_result.get("details", "Session revocation action completed."))
        }
    ]

    failed_or_blocked = [
        action for action in actions
        if action["status"] not in ["success", "dry_run"]
    ]

    if failed_or_blocked:
        final_status = "partial_or_blocked"
    elif execute_real:
        final_status = "real_identity_response_completed"
    else:
        final_status = "identity_response_preview_completed"

    return {
        "workflow": "authorized_identity_response",
        "username": username,
        "execute_real": execute_real,
        "dry_run": dry_run,
        "status": final_status,
        "real_action_sent": execute_real and final_status == "real_identity_response_completed",
        "total_actions": len(actions),
        "actions": actions,
        "message": (
            "Authorized identity response completed."
            if execute_real
            else "Safe identity response preview completed. No real Azure AD changes were made."
        )
    }