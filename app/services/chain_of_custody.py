import os
import json
import hashlib
from datetime import datetime, timezone


def calculate_sha256(file_path: str) -> str:
    """
    Calculates SHA-256 hash of a forensic artifact file.
    """

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as file:
        for block in iter(lambda: file.read(4096), b""):
            sha256_hash.update(block)

    return sha256_hash.hexdigest()


def create_chain_of_custody_entry(alert_id: str, file_path: str) -> dict:
    """
    Creates a chain-of-custody entry for a forensic artifact.
    """

    file_hash = calculate_sha256(file_path)

    return {
        "alert_id": alert_id,
        "artifact_name": os.path.basename(file_path),
        "artifact_path": file_path,
        "sha256_hash": file_hash,
        "collected_by": "IR-Orchestrator",
        "action": "forensic_collection",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "notes": "Artifact collected and hashed automatically for chain-of-custody tracking."
    }


def save_chain_of_custody_log(alert_id: str, custody_entries: list) -> str:
    """
    Saves chain-of-custody entries into a JSON file inside the alert artifact folder.
    """

    custody_dir = os.path.join("artifacts", alert_id)
    os.makedirs(custody_dir, exist_ok=True)

    custody_log_path = os.path.join(custody_dir, "chain_of_custody.json")

    with open(custody_log_path, "w", encoding="utf-8") as file:
        json.dump(custody_entries, file, indent=4)

    return custody_log_path


def generate_chain_of_custody_for_files(alert_id: str, file_paths: list) -> dict:
    """
    Generates chain-of-custody records for multiple forensic files.
    """

    custody_entries = []

    for file_path in file_paths:
        entry = create_chain_of_custody_entry(alert_id, file_path)
        custody_entries.append(entry)

    custody_log_path = save_chain_of_custody_log(alert_id, custody_entries)

    return {
        "status": "success",
        "alert_id": alert_id,
        "total_artifacts": len(custody_entries),
        "custody_log_path": custody_log_path,
        "custody_entries": custody_entries,
        "message": "Chain-of-custody log generated successfully"
    }