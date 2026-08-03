from app.services.alert_parser import parse_edr_alert
from app.lambda_handlers.utils import utc_now_iso


def lambda_handler(event, context=None):
    """
    AWS Lambda entry point for the "ParseAlert" state of the ransomware
    containment Step Functions workflow.

    Input  (Step Functions execution input): raw EDR webhook payload
    Output: { "alert": {...parsed fields...}, "detection_time": iso8601 }

    This is the first state invoked by AWS Step Functions when an EDR
    high-severity alert triggers the state machine (see
    infrastructure/step_functions/ransomware_containment_state_machine.json).
    """

    detection_time = utc_now_iso()

    parsed_alert = parse_edr_alert(event)

    return {
        "alert": parsed_alert,
        "detection_time": detection_time,
        "timings": {}
    }