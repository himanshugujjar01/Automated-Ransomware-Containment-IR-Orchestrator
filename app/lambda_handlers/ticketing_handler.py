from app.integrations.ticketing_client import create_incident_ticket
from app.config import USE_REAL_TICKETING, TICKETING_PROVIDER
from app.lambda_handlers.utils import utc_now_iso, lambda_response


def lambda_handler(event, context=None):
    """
    AWS Lambda entry point for the "Ticketing" state.
    Corresponds to Project 3 Week 4, Day 1-2 (Jira/ServiceNow ticketing
    with enriched incident data).

    Input:  { "alert": {...}, "host_isolation": {...}, "identity_response": {...} }
    Output: adds "ticketing" (ticket_id, ticket_url, status) + timing.
    """

    started_at = utc_now_iso()

    alert_data = event["alert"]

    actions = [
        event.get("host_isolation"),
        event.get("identity_response", {}).get("user_suspension"),
        event.get("identity_response", {}).get("session_revocation")
    ]
    actions = [action for action in actions if action]

    artifacts = event.get("chain_of_custody", {}).get("custody_entries", [])

    result = create_incident_ticket(
        alert_data=alert_data,
        actions=actions,
        artifacts=artifacts,
        provider=TICKETING_PROVIDER,
        execute_real=USE_REAL_TICKETING
    )

    return lambda_response("ticketing", event, result, started_at)