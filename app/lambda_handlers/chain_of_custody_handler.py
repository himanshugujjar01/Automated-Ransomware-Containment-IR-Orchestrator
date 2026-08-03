from app.services.chain_of_custody import generate_chain_of_custody_for_files
from app.lambda_handlers.utils import utc_now_iso, lambda_response


def lambda_handler(event, context=None):
    """
    AWS Lambda entry point for the "ChainOfCustody" state.
    Corresponds to Project 3 Week 3, Day 7 (SHA-256 chain-of-custody logging).

    Input:  { "alert": {...}, "forensic_collection": {"files_created": [...]} }
    Output: adds "chain_of_custody" (custody_entries, custody_log_path) + timing.
    """

    started_at = utc_now_iso()

    alert_id = event["alert"]["alert_id"]
    files_created = event["forensic_collection"]["files_created"]

    result = generate_chain_of_custody_for_files(alert_id, files_created)

    return lambda_response("chain_of_custody", event, result, started_at)