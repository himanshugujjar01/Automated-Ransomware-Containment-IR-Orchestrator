from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from app.config import (
    USE_REAL_AWS,
    AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY,
    AWS_REGION,
    S3_BUCKET_NAME,
    S3_EVIDENCE_PREFIX,
    S3_OBJECT_LOCK_MODE,
    S3_RETENTION_DAYS,
    S3_LEGAL_HOLD_ENABLED
)


INTEGRATION_NAME = "AWS S3 Evidence Storage"


def is_placeholder(value: str) -> bool:
    return not value or str(value).strip() == "" or value == "change_me"


def is_aws_configured() -> bool:
    return not any([
        is_placeholder(AWS_ACCESS_KEY_ID),
        is_placeholder(AWS_SECRET_ACCESS_KEY),
        is_placeholder(S3_BUCKET_NAME)
    ])


def get_s3_client():
    return boto3.client(
        "s3",
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY
    )


def calculate_sha256(file_path: str) -> str:
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(8192), b""):
            sha256_hash.update(chunk)

    return sha256_hash.hexdigest()


def build_s3_key(alert_id: str, file_path: str) -> str:
    file_name = Path(file_path).name

    return f"{S3_EVIDENCE_PREFIX}/{alert_id}/{file_name}"


def build_s3_uri(bucket_name: str, object_key: str) -> str:
    return f"s3://{bucket_name}/{object_key}"


def get_retention_until_date():
    return datetime.now(timezone.utc) + timedelta(days=S3_RETENTION_DAYS)


def get_aws_s3_status() -> dict:
    return {
        "integration": INTEGRATION_NAME,
        "configured": is_aws_configured(),
        "enabled": USE_REAL_AWS,
        "safe_mode": True,
        "region": AWS_REGION,
        "bucket_configured": not is_placeholder(S3_BUCKET_NAME),
        "bucket_name": S3_BUCKET_NAME if not is_placeholder(S3_BUCKET_NAME) else "change_me",
        "evidence_prefix": S3_EVIDENCE_PREFIX,
        "object_lock_mode": S3_OBJECT_LOCK_MODE,
        "retention_days": S3_RETENTION_DAYS,
        "legal_hold_enabled": S3_LEGAL_HOLD_ENABLED,
        "status": "ready" if is_aws_configured() else "credentials_pending",
        "message": (
            "AWS S3 configuration is ready."
            if is_aws_configured()
            else "AWS S3 credentials or bucket name are pending."
        )
    }


def build_s3_upload_preview(alert_id: str, file_path: str) -> dict:
    path = Path(file_path)

    if not alert_id:
        return {
            "integration": INTEGRATION_NAME,
            "status": "failed",
            "message": "Alert ID is missing.",
            "real_action_sent": False
        }

    if not path.exists():
        return {
            "integration": INTEGRATION_NAME,
            "alert_id": alert_id,
            "file_path": file_path,
            "status": "failed",
            "message": "Evidence file does not exist.",
            "real_action_sent": False
        }

    object_key = build_s3_key(alert_id, file_path)
    file_hash = calculate_sha256(file_path)

    return {
        "integration": INTEGRATION_NAME,
        "workflow": "s3_evidence_upload_preview",
        "alert_id": alert_id,
        "file_path": file_path,
        "file_name": path.name,
        "sha256_hash": file_hash,
        "bucket_name": S3_BUCKET_NAME,
        "object_key": object_key,
        "s3_uri": build_s3_uri(S3_BUCKET_NAME, object_key),
        "object_lock_mode": S3_OBJECT_LOCK_MODE,
        "retention_days": S3_RETENTION_DAYS,
        "legal_hold_enabled": S3_LEGAL_HOLD_ENABLED,
        "status": "preview_ready",
        "dry_run": True,
        "real_action_sent": False,
        "message": "S3 evidence upload preview generated. No real AWS upload was performed."
    }


def upload_evidence_file_to_s3(
    alert_id: str,
    file_path: str,
    execute_real: bool = False
) -> dict:
    """
    Uploads forensic evidence to AWS S3 only when execute_real=True,
    USE_REAL_AWS=true, and credentials are configured.

    execute_real=False is safe preview mode.
    """

    preview = build_s3_upload_preview(
        alert_id=alert_id,
        file_path=file_path
    )

    if preview["status"] != "preview_ready":
        return preview

    if not execute_real:
        return preview

    if not USE_REAL_AWS:
        return {
            **preview,
            "workflow": "s3_evidence_upload_authorized",
            "status": "blocked",
            "dry_run": False,
            "real_action_sent": False,
            "message": "USE_REAL_AWS is false. Real AWS S3 upload is disabled."
        }

    if not is_aws_configured():
        return {
            **preview,
            "workflow": "s3_evidence_upload_authorized",
            "status": "credentials_pending",
            "dry_run": False,
            "real_action_sent": False,
            "message": "AWS credentials or S3 bucket name are not configured."
        }

    object_key = preview["object_key"]
    file_hash = preview["sha256_hash"]

    put_kwargs = {
        "Bucket": S3_BUCKET_NAME,
        "Key": object_key,
        "Body": Path(file_path).read_bytes(),
        "Metadata": {
            "alert_id": alert_id,
            "sha256": file_hash,
            "source": "ransomware-ir-orchestrator"
        },
        "ServerSideEncryption": "AES256"
    }

    if S3_OBJECT_LOCK_MODE in ["GOVERNANCE", "COMPLIANCE"]:
        put_kwargs["ObjectLockMode"] = S3_OBJECT_LOCK_MODE
        put_kwargs["ObjectLockRetainUntilDate"] = get_retention_until_date()

    if S3_LEGAL_HOLD_ENABLED:
        put_kwargs["ObjectLockLegalHoldStatus"] = "ON"

    try:
        s3_client = get_s3_client()
        response = s3_client.put_object(**put_kwargs)

        return {
            **preview,
            "workflow": "s3_evidence_upload_authorized",
            "status": "success",
            "dry_run": False,
            "real_action_sent": True,
            "version_id": response.get("VersionId"),
            "etag": response.get("ETag"),
            "message": "Evidence file uploaded to AWS S3 successfully."
        }

    except (BotoCoreError, ClientError, Exception) as error:
        return {
            **preview,
            "workflow": "s3_evidence_upload_authorized",
            "status": "failed",
            "dry_run": False,
            "real_action_sent": False,
            "message": str(error)
        }