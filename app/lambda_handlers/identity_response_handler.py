from app.services.identity_response import suspend_user, revoke_sessions
from app.lambda_handlers.utils import utc_now_iso, lambda_response


def lambda_handler(event, context=None):
    """
    AWS Lambda entry point for the "IdentityResponse" branch of the Parallel
    containment state. Runs alongside HostIsolation.

    Input:  { "alert": {...} }
    Output: adds "identity_response" (suspend + revoke sessions) + timing.
    """

    started_at = utc_now_iso()

    alert = event["alert"]
    username = alert.get("username")

    suspend_result = suspend_user(username)
    revoke_result = revoke_sessions(username)

    result = {
        "user_suspension": suspend_result,
        "session_revocation": revoke_result,
        "status": (
            "success"
            if suspend_result.get("status") == "success"
            and revoke_result.get("status") == "success"
            else "partial_or_failed"
        )
    }

    return lambda_response("identity_response", event, result, started_at)