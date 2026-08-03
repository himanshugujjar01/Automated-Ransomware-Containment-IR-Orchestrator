from datetime import datetime, timezone

from app.lambda_handlers.utils import seconds_since


def _iso_diff_seconds(start_iso: str, end_iso: str):
    if not start_iso or not end_iso:
        return None

    start = datetime.fromisoformat(start_iso)
    end = datetime.fromisoformat(end_iso)

    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)

    return round((end - start).total_seconds(), 4)


def lambda_handler(event, context=None):
    """
    AWS Lambda entry point for the final "ResponseTimeReport" state.
    Corresponds to Project 3 Week 4, Day 5-7 (measuring the platform's
    response time during table-top / live simulations).

    Reads the per-step timings accumulated by every prior state in the
    Step Functions execution and produces the same stage-by-stage report
    shape as the FastAPI orchestrator's GET /response-time/{alert_id}
    endpoint, so both deployment modes (FastAPI service and Step Functions
    state machine) report response time identically.

    Input:  full event with "detection_time" and "timings" from every state
    Output: { "alert_id", "detection_time", "stages": {...} }
    """

    detection_time = event["detection_time"]
    timings = event.get("timings", {})

    def elapsed_to_step(step_name: str):
        step = timings.get(step_name)
        if not step:
            return None
        return _iso_diff_seconds(detection_time, step["completed_at"])

    total_response_time = seconds_since(detection_time)

    containment_candidates = [
        elapsed_to_step("host_isolation"),
        elapsed_to_step("identity_response")
    ]
    containment_candidates = [c for c in containment_candidates if c is not None]

    stages = {
        "detection_to_first_action_seconds": min(
            [c for c in containment_candidates], default=None
        ),
        "detection_to_containment_seconds": max(
            containment_candidates, default=None
        ),
        "detection_to_evidence_collected_seconds": elapsed_to_step("evidence_upload"),
        "detection_to_ticket_filed_seconds": elapsed_to_step("ticketing"),
        "total_response_time_seconds": total_response_time
    }

    return {
        "alert_id": event["alert"]["alert_id"],
        "hostname": event["alert"]["hostname"],
        "detection_time": detection_time,
        "playbook_status": "forensics_completed",
        "ticket_id": event.get("ticketing", {}).get("ticket_id"),
        "stages": stages
    }