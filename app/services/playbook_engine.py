from app.models.action_model import ActionLog
from app.models.artifact_model import Artifact

from app.services.containment import isolate_host
from app.services.identity_response import suspend_user, revoke_sessions
from app.services.forensics import collect_basic_forensic_evidence
from app.services.chain_of_custody import generate_chain_of_custody_for_files
from app.integrations.local_s3 import upload_to_local_s3


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
    Runs the ransomware containment and forensic response playbook.

    Playbook Steps:
    1. Isolate infected host
    2. Suspend compromised user
    3. Revoke active user sessions
    4. Collect forensic evidence
    5. Generate SHA-256 hashes and chain-of-custody log
    6. Upload evidence to local S3 simulation
    7. Save artifact metadata into database
    8. Update alert status
    """

    actions = []
    artifact_records = []

    alert.status = "containment_started"
    db.commit()

    # Step 1: Host Isolation
    host_result = isolate_host(
        hostname=alert.hostname,
        ip_address=alert.ip_address
    )
    save_action_log(db, alert.alert_id, host_result)
    actions.append(host_result)

    # Step 2: User Suspension
    suspend_result = suspend_user(
        username=alert.username
    )
    save_action_log(db, alert.alert_id, suspend_result)
    actions.append(suspend_result)

    # Step 3: Session Revocation
    revoke_result = revoke_sessions(
        username=alert.username
    )
    save_action_log(db, alert.alert_id, revoke_result)
    actions.append(revoke_result)

    # Step 4: Forensic Evidence Collection
    forensic_result = collect_basic_forensic_evidence(alert)

    forensic_action = {
        "action_type": "forensic_collection",
        "target": alert.hostname,
        "status": forensic_result["status"],
        "details": f"Collected {forensic_result['total_files']} forensic evidence files"
    }

    save_action_log(db, alert.alert_id, forensic_action)
    actions.append(forensic_action)

    # Step 5: Chain of Custody
    custody_result = generate_chain_of_custody_for_files(
        alert.alert_id,
        forensic_result["files_created"]
    )

    custody_action = {
        "action_type": "chain_of_custody",
        "target": alert.alert_id,
        "status": custody_result["status"],
        "details": f"Generated chain-of-custody log for {custody_result['total_artifacts']} artifacts"
    }

    save_action_log(db, alert.alert_id, custody_action)
    actions.append(custody_action)

    # Step 6: Upload forensic files to local S3 and save artifact logs
    for custody_entry in custody_result["custody_entries"]:
        file_path = custody_entry["artifact_path"]
        sha256_hash = custody_entry["sha256_hash"]

        storage_path = upload_to_local_s3(
            alert.alert_id,
            file_path
        )

        artifact = save_artifact_log(
            db=db,
            alert_id=alert.alert_id,
            file_path=file_path,
            sha256_hash=sha256_hash,
            storage_path=storage_path
        )

        artifact_records.append({
            "artifact_id": artifact.id,
            "artifact_type": artifact.artifact_type,
            "file_path": artifact.file_path,
            "sha256_hash": artifact.sha256_hash,
            "storage_path": artifact.storage_path
        })

    storage_action = {
        "action_type": "local_s3_upload",
        "target": alert.alert_id,
        "status": "success",
        "details": f"Uploaded {len(artifact_records)} forensic artifacts to local S3 simulation"
    }

    save_action_log(db, alert.alert_id, storage_action)
    actions.append(storage_action)

    # Step 7: Final status check
    failed_actions = [
        action for action in actions
        if action.get("status") != "success"
    ]

    if failed_actions:
        alert.status = "partial_response"
        playbook_status = "partial_success"
    else:
        alert.status = "evidence_collected"
        playbook_status = "forensics_completed"

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
        "total_artifacts": len(artifact_records),
        "actions": actions,
        "forensic_result": forensic_result,
        "chain_of_custody": {
            "status": custody_result["status"],
            "custody_log_path": custody_result["custody_log_path"],
            "total_artifacts": custody_result["total_artifacts"]
        },
        "artifacts": artifact_records
    }