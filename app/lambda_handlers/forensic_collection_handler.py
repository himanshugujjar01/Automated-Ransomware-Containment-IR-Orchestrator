from app.services.forensics import collect_basic_forensic_evidence
from app.lambda_handlers.utils import utc_now_iso, lambda_response, alert_namespace


def lambda_handler(event, context=None):
    """
    AWS Lambda entry point for the "ForensicCollection" state.
    Corresponds to Project 3 Week 3, Day 1-3 (KAPE / memory dump collection).

    Input:  { "alert": {...} }
    Output: adds "forensic_collection" (files_created, total_files) + timing.
    """

    started_at = utc_now_iso()

    alert = alert_namespace(event["alert"])

    result = collect_basic_forensic_evidence(alert)

    return lambda_response("forensic_collection", event, result, started_at)