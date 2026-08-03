from app.config import USE_REAL_AWS
from app.integrations.aws_s3 import upload_evidence_file_to_s3
from app.lambda_handlers.utils import utc_now_iso, lambda_response


def lambda_handler(event, context=None):
    """
    AWS Lambda entry point for the "EvidenceUpload" state.
    Corresponds to Project 3 Week 3, Day 4-6 (hardened WORM S3 evidence
    storage upload).

    Input:  { "alert": {...}, "chain_of_custody": {"custody_entries": [...]} }
    Output: adds "evidence_upload" (per-file upload results) + timing.

    Runs in safe preview mode (execute_real=False) unless USE_REAL_AWS is
    explicitly enabled in the environment, consistent with the rest of the
    orchestrator's safety model.
    """

    started_at = utc_now_iso()

    alert_id = event["alert"]["alert_id"]
    custody_entries = event["chain_of_custody"]["custody_entries"]

    uploads = [
        upload_evidence_file_to_s3(
            alert_id=alert_id,
            file_path=entry["artifact_path"],
            execute_real=USE_REAL_AWS
        )
        for entry in custody_entries
    ]

    result = {
        "total_files_uploaded": len(uploads),
        "uploads": uploads
    }

    return lambda_response("evidence_upload", event, result, started_at)