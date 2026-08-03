from app.services.containment import isolate_host
from app.lambda_handlers.utils import utc_now_iso, lambda_response


def lambda_handler(event, context=None):
    """
    AWS Lambda entry point for the "HostIsolation" branch of the Parallel
    containment state. Runs alongside IdentityResponse.

    Input:  { "alert": {...} }
    Output: adds "host_isolation" + timing to the event and passes it through.
    """

    started_at = utc_now_iso()

    alert = event["alert"]

    result = isolate_host(
        hostname=alert.get("hostname"),
        ip_address=alert.get("ip_address")
    )

    return lambda_response("host_isolation", event, result, started_at)