from app.services.notification_service import notify_soc
from app.lambda_handlers.utils import utc_now_iso, lambda_response, alert_namespace


def lambda_handler(event, context=None):
    """
    AWS Lambda entry point for the "Notification" state.
    Corresponds to Project 3 Week 4, Day 3-4 (automated Slack/Microsoft
    Teams alerts for the on-call incident response team).

    Input:  { "alert": {...} }
    Output: adds "notification" (slack + teams results) + timing.
    """

    started_at = utc_now_iso()

    alert = alert_namespace(event["alert"])

    result = notify_soc(alert)

    return lambda_response("notification", event, result, started_at)