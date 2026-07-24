from app.services.approved_containment_runner import run_full_approved_containment_response
from app.services.playbook_engine import save_action_log


def run_alert_based_approved_playbook(
    db,
    alert,
    approval_code: str,
    dry_run: bool = True
) -> dict:
    """
    Runs approved containment workflow using data from a saved alert.

    Actions:
    1. Host isolation
    2. User suspension
    3. Session revocation
    4. Action logging
    5. Alert status update

    dry_run=True is safe and does not perform real EDR or Azure AD changes.
    """

    alert.status = "approved_containment_started"
    db.commit()

    response_result = run_full_approved_containment_response(
        hostname=alert.hostname,
        ip_address=alert.ip_address,
        username=alert.username,
        approval_code=approval_code,
        dry_run=dry_run
    )

    saved_actions = []

    for action in response_result["actions"]:
        saved_log = save_action_log(
            db=db,
            alert_id=alert.alert_id,
            action_result={
                "action_type": action.get("action_type"),
                "target": action.get("target"),
                "status": action.get("status"),
                "details": action.get("details")
            }
        )

        saved_actions.append({
            "id": saved_log.id,
            "action_type": saved_log.action_type,
            "target": saved_log.target,
            "status": saved_log.status,
            "details": saved_log.details
        })

    if response_result["status"] == "completed":
        if dry_run:
            alert.status = "approved_containment_dry_run_completed"
        else:
            alert.status = "approved_containment_completed"
    else:
        alert.status = "approved_containment_blocked"

    db.commit()

    return {
        "alert_id": alert.alert_id,
        "hostname": alert.hostname,
        "ip_address": alert.ip_address,
        "username": alert.username,
        "dry_run": dry_run,
        "workflow": "alert_based_approved_containment",
        "workflow_status": response_result["status"],
        "final_alert_status": alert.status,
        "total_actions": len(saved_actions),
        "actions": saved_actions,
        "message": "Alert-based approved containment workflow executed"
    }