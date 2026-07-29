from app.integrations.aws_s3 import upload_evidence_file_to_s3

try:
    from app.services.playbook_engine import save_artifact_log
except Exception:
    save_artifact_log = None


def upload_alert_evidence_to_s3(
    db,
    alert_id: str,
    file_path: str,
    execute_real: bool = False,
    log_to_db: bool = True
) -> dict:
    """
    Uploads or previews forensic evidence upload to AWS S3.

    If real upload succeeds, artifact metadata is saved into the database.
    """

    result = upload_evidence_file_to_s3(
        alert_id=alert_id,
        file_path=file_path,
        execute_real=execute_real
    )

    database_result = None

    if (
        log_to_db
        and result.get("status") == "success"
        and save_artifact_log is not None
    ):
        artifact = save_artifact_log(
            db=db,
            alert_id=alert_id,
            file_path=file_path,
            sha256_hash=result.get("sha256_hash"),
            storage_path=result.get("s3_uri"),
            artifact_type="aws_s3_worm_evidence"
        )

        database_result = {
            "logged": True,
            "artifact_id": artifact.id,
            "storage_path": artifact.storage_path
        }

    return {
        "workflow": "alert_evidence_s3_storage",
        "alert_id": alert_id,
        "execute_real": execute_real,
        "database_result": database_result,
        "s3_result": result
    }