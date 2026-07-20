import os
import json
from datetime import datetime, timezone


def create_artifact_directory(alert_id: str) -> str:
    """
    Creates a dedicated forensic artifact folder for each alert.
    Example: artifacts/EDR-2026-002/
    """

    artifact_dir = os.path.join("artifacts", alert_id)
    os.makedirs(artifact_dir, exist_ok=True)

    return artifact_dir


def collect_basic_forensic_evidence(alert) -> dict:
    """
    Collects safe simulated forensic evidence for a ransomware alert.

    This lab version does not collect real memory dumps or execute malware.
    It creates a triage summary file that represents the evidence collection step.
    """

    artifact_dir = create_artifact_directory(alert.alert_id)

    triage_summary = {
        "alert_id": alert.alert_id,
        "severity": alert.severity,
        "detection_type": alert.detection_type,
        "hostname": alert.hostname,
        "ip_address": alert.ip_address,
        "username": alert.username,
        "process_name": alert.process_name,
        "process_hash": alert.process_hash,
        "collection_time": datetime.now(timezone.utc).isoformat(),
        "collector": "IR-Orchestrator",
        "collection_type": "simulated_forensic_triage",
        "note": "Safe lab-based forensic evidence collection. No real malware or RAM dump was used."
    }

    triage_file_path = os.path.join(artifact_dir, "triage_summary.json")

    with open(triage_file_path, "w", encoding="utf-8") as file:
        json.dump(triage_summary, file, indent=4)

    return {
        "status": "success",
        "alert_id": alert.alert_id,
        "artifact_dir": artifact_dir,
        "files_created": [
            triage_file_path
        ],
        "message": "Basic forensic triage summary collected successfully"
    }