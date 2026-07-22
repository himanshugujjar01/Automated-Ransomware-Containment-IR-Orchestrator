from app.models.action_model import ActionLog
from app.models.artifact_model import Artifact
from app.services.containment import isolate_host
from app.services.identity_response import suspend_user, revoke_sessions


def save_action_log(db, alert_id: str, action_result: dict):
    """
    Saves an automated response action into the action_logs database table.
    """

    log = ActionLog(
        alert_id=alert_id,
        action_type=action_result.get("action_type"),
        target=action_result.get("target"),
        status=action_result.get("status"),
        details=action_result.get("details")
    )

    db.add(log)
    db.commit()
    db.refresh(log)

    return log

def save_artifact_log(
    db,
    alert_id: str,
    file_path: str,
    sha256_hash: str,
    storage_path: str,
    artifact_type: str = "forensic_evidence"
):
    """
    Saves forensic artifact metadata into the artifacts database table.

    Example:
    - alert_id: EDR-2026-002
    - file_path: artifacts/EDR-2026-002/triage_summary.json
    - sha256_hash: 64-character SHA-256 hash
    - storage_path: local_s3_bucket/forensic-evidence/EDR-2026-002/triage_summary.json
    """

    artifact = Artifact(
        alert_id=alert_id,
        artifact_type=artifact_type,
        file_path=file_path,
        sha256_hash=sha256_hash,
        storage_path=storage_path
    )

    db.add(artifact)
    db.commit()
    db.refresh(artifact)

    return artifact


def run_basic_containment_playbook(db, alert):
    """
    Runs the basic ransomware containment playbook.

    Playbook Steps:
    1. Isolate infected host
    2. Suspend compromised user
    3. Revoke active user sessions
    4. Save every action into database
    5. Update alert status
    """

    actions = []

    alert.status = "containment_started"
    db.commit()

    # Step 1: Isolate host
    host_result = isolate_host(
        hostname=alert.hostname,
        ip_address=alert.ip_address
    )
    save_action_log(db, alert.alert_id, host_result)
    actions.append(host_result)

    # Step 2: Suspend user
    suspend_result = suspend_user(
        username=alert.username
    )
    save_action_log(db, alert.alert_id, suspend_result)
    actions.append(suspend_result)

    # Step 3: Revoke sessions
    revoke_result = revoke_sessions(
        username=alert.username
    )
    save_action_log(db, alert.alert_id, revoke_result)
    actions.append(revoke_result)

    # Step 4: Check final status
    failed_actions = [
        action for action in actions
        if action.get("status") != "success"
    ]

    if failed_actions:
        alert.status = "partial_containment"
        playbook_status = "partial_success"
    else:
        alert.status = "contained"
        playbook_status = "completed"

    db.commit()

    return {
        "alert_id": alert.alert_id,
        "severity": alert.severity,
        "hostname": alert.hostname,
        "ip_address": alert.ip_address,
        "username": alert.username,
        "playbook_status": playbook_status,
        "final_alert_status": alert.status,
        "total_actions": len(actions),
        "actions": actions
    }