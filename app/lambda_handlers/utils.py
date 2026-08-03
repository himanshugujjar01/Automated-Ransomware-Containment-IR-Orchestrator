from datetime import datetime, timezone
from types import SimpleNamespace


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def seconds_since(start_iso: str) -> float:
    """
    Returns elapsed seconds between an ISO timestamp and now. Used by every
    handler to report step latency back to the Step Functions execution
    without needing a database.
    """

    start = datetime.fromisoformat(start_iso)
    now = datetime.now(timezone.utc)

    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)

    return round((now - start).total_seconds(), 4)


def alert_namespace(alert_dict: dict) -> SimpleNamespace:
    """
    Existing service functions (forensics.collect_basic_forensic_evidence,
    notification_service.notify_soc, etc.) expect an ORM-style alert object
    with dot-access attributes. This builds a lightweight stand-in from the
    plain dict that flows through a Step Functions execution, so those same
    battle-tested functions can run outside the FastAPI/DB request path.
    """

    return SimpleNamespace(
        alert_id=alert_dict.get("alert_id"),
        severity=alert_dict.get("severity"),
        detection_type=alert_dict.get("detection_type"),
        hostname=alert_dict.get("hostname"),
        ip_address=alert_dict.get("ip_address"),
        username=alert_dict.get("username"),
        process_name=alert_dict.get("process_name"),
        process_hash=alert_dict.get("process_hash"),
        description=alert_dict.get("description")
    )


def lambda_response(step_name: str, event: dict, result: dict, started_at: str) -> dict:
    """
    Wraps a step's result with standard Step Functions bookkeeping fields
    so downstream states (and the final response-time report) can see how
    each stage performed without any shared database.
    """

    return {
        **event,
        step_name: result,
        "timings": {
            **event.get("timings", {}),
            step_name: {
                "started_at": started_at,
                "completed_at": utc_now_iso(),
                "duration_seconds": seconds_since(started_at)
            }
        }
    }