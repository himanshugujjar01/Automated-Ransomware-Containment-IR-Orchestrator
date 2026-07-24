from app.services.edr_response_runner import run_approved_host_isolation
from app.services.idp_response_runner import (
    run_approved_user_suspension,
    run_approved_session_revocation
)


def run_full_approved_containment_response(
    hostname: str,
    ip_address: str,
    username: str,
    approval_code: str,
    dry_run: bool = True
) -> dict:
    """
    Runs full approved containment workflow.

    Actions:
    1. Host isolation
    2. User suspension
    3. Session revocation

    dry_run=True is safe and does not perform real changes.
    """

    host_result = run_approved_host_isolation(
        hostname=hostname,
        ip_address=ip_address,
        approval_code=approval_code,
        dry_run=dry_run
    )

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
        host_result,
        suspension_result,
        revocation_result
    ]

    failed_or_blocked = [
        action for action in actions
        if action["status"] not in ["success", "dry_run"]
    ]

    return {
        "workflow": "approved_full_containment_response",
        "hostname": hostname,
        "ip_address": ip_address,
        "username": username,
        "dry_run": dry_run,
        "status": "completed" if not failed_or_blocked else "partial_or_blocked",
        "total_actions": len(actions),
        "actions": actions
    }