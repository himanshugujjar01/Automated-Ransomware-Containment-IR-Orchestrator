import os
import shutil

from app.config import LOCAL_S3_BUCKET


def create_local_s3_alert_folder(alert_id: str) -> str:
    """
    Creates a local S3-style storage folder for forensic evidence.

    Example:
    local_s3_bucket/forensic-evidence/EDR-2026-002/
    """

    destination_dir = os.path.join(
        LOCAL_S3_BUCKET,
        "forensic-evidence",
        alert_id
    )

    os.makedirs(destination_dir, exist_ok=True)

    return destination_dir


def upload_to_local_s3(alert_id: str, file_path: str) -> str:
    """
    Simulates uploading a forensic artifact to AWS S3.

    In this lab version, the file is copied to:
    local_s3_bucket/forensic-evidence/{alert_id}/
    """

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Artifact file not found: {file_path}")

    destination_dir = create_local_s3_alert_folder(alert_id)

    file_name = os.path.basename(file_path)
    destination_path = os.path.join(destination_dir, file_name)

    shutil.copy2(file_path, destination_path)

    return destination_path


def upload_multiple_files_to_local_s3(alert_id: str, file_paths: list) -> dict:
    """
    Uploads multiple forensic artifact files to local S3 simulation.
    """

    uploaded_files = []

    for file_path in file_paths:
        uploaded_path = upload_to_local_s3(alert_id, file_path)
        uploaded_files.append(uploaded_path)

    return {
        "status": "success",
        "alert_id": alert_id,
        "storage_type": "local_s3_simulation",
        "bucket": LOCAL_S3_BUCKET,
        "total_uploaded": len(uploaded_files),
        "uploaded_files": uploaded_files,
        "message": "Forensic artifacts uploaded to local S3 simulation successfully"
    }