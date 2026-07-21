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


def write_text_file(file_path: str, content: str) -> None:
    """
    Helper function to write text-based forensic evidence files.
    """

    with open(file_path, "w", encoding="utf-8") as file:
        file.write(content)


def collect_basic_forensic_evidence(alert) -> dict:
    """
    Collects safe simulated forensic evidence for a ransomware alert.

    This lab version does not collect real memory dumps or execute malware.
    It creates multiple simulated forensic evidence files for demonstration.
    """

    artifact_dir = create_artifact_directory(alert.alert_id)

    collection_time = datetime.now(timezone.utc).isoformat()

    triage_file_path = os.path.join(artifact_dir, "triage_summary.json")
    process_file_path = os.path.join(artifact_dir, "process_list.txt")
    network_file_path = os.path.join(artifact_dir, "network_connections.txt")
    hash_file_path = os.path.join(artifact_dir, "suspicious_hashes.txt")
    memory_file_path = os.path.join(artifact_dir, "memory_dump_metadata.txt")

    triage_summary = {
        "alert_id": alert.alert_id,
        "severity": alert.severity,
        "detection_type": alert.detection_type,
        "hostname": alert.hostname,
        "ip_address": alert.ip_address,
        "username": alert.username,
        "process_name": alert.process_name,
        "process_hash": alert.process_hash,
        "collection_time": collection_time,
        "collector": "IR-Orchestrator",
        "collection_type": "simulated_forensic_triage",
        "note": "Safe lab-based forensic evidence collection. No real malware or RAM dump was used."
    }

    with open(triage_file_path, "w", encoding="utf-8") as file:
        json.dump(triage_summary, file, indent=4)

    process_content = f"""
Simulated Process List
======================

Alert ID: {alert.alert_id}
Hostname: {alert.hostname}
User: {alert.username}

PID: 4452
Process Name: {alert.process_name}
Process Hash: {alert.process_hash}
Status: Suspicious
Reason: Encryption-like behavior detected

PID: 1104
Process Name: explorer.exe
Status: Normal

PID: 872
Process Name: svchost.exe
Status: Normal

Collection Time: {collection_time}
"""

    network_content = f"""
Simulated Network Connections
=============================

Alert ID: {alert.alert_id}
Hostname: {alert.hostname}
IP Address: {alert.ip_address}

Local Address: {alert.ip_address}:49822
Remote Address: 203.0.113.50:443
Connection Status: Blocked
Reason: Suspicious outbound connection after ransomware behavior

Local Address: {alert.ip_address}:5353
Remote Address: 224.0.0.251:5353
Connection Status: Normal

Collection Time: {collection_time}
"""

    hash_content = f"""
Suspicious File Hashes
======================

Alert ID: {alert.alert_id}
Hostname: {alert.hostname}

Suspicious Process: {alert.process_name}
SHA-256 / Hash Value: {alert.process_hash}
Detection Type: {alert.detection_type}
Severity: {alert.severity}

Collection Time: {collection_time}
"""

    memory_content = f"""
Memory Dump Metadata
====================

Alert ID: {alert.alert_id}
Hostname: {alert.hostname}
User: {alert.username}

Memory Dump Status: Simulated
Tool Reference: Volatility/KAPE-compatible collection placeholder
Actual RAM Dump Created: No
Reason: Safe lab simulation only

Collection Time: {collection_time}
"""

    write_text_file(process_file_path, process_content)
    write_text_file(network_file_path, network_content)
    write_text_file(hash_file_path, hash_content)
    write_text_file(memory_file_path, memory_content)

    files_created = [
        triage_file_path,
        process_file_path,
        network_file_path,
        hash_file_path,
        memory_file_path
    ]

    return {
        "status": "success",
        "alert_id": alert.alert_id,
        "artifact_dir": artifact_dir,
        "files_created": files_created,
        "files": files_created,
        "total_files": len(files_created),
        "message": "Multiple simulated forensic evidence files collected successfully"
    }