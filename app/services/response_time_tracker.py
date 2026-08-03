from app.models.alert_model import Alert
from app.models.action_model import ActionLog
from app.models.artifact_model import Artifact
from app.models.ticket_model import Ticket


CONTAINMENT_ACTION_TYPES = [
    "host_isolation",
    "user_suspension",
    "session_revocation"
]


def _seconds_between(start, end) -> float:
    """
    Returns the number of seconds between two datetimes, rounded to 2dp.
    Returns None if either timestamp is missing.
    """

    if not start or not end:
        return None

    return round((end - start).total_seconds(), 2)


def get_response_time_report(db, alert_id: str) -> dict:
    """
    Builds a stage-by-stage response time report for a single incident.

    Stages measured (all relative to alert detection time):
    1. detection_to_first_action   -> time until the orchestrator took ANY action
    2. detection_to_containment    -> time until host isolation + user suspension +
                                       session revocation actions all completed
    3. detection_to_evidence       -> time until the last forensic artifact was stored
    4. detection_to_ticket         -> time until an incident ticket was filed
    5. total_response_time         -> time from detection to the last recorded event
    """

    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()

    if not alert:
        return {
            "found": False,
            "alert_id": alert_id,
            "message": "No alert found with this alert_id"
        }

    detection_time = alert.created_at

    actions = db.query(ActionLog).filter(
        ActionLog.alert_id == alert_id
    ).order_by(ActionLog.started_at.asc()).all()

    artifacts = db.query(Artifact).filter(
        Artifact.alert_id == alert_id
    ).order_by(Artifact.created_at.asc()).all()

    tickets = db.query(Ticket).filter(
        Ticket.alert_id == alert_id
    ).order_by(Ticket.created_at.asc()).all()

    first_action_time = actions[0].started_at if actions else None

    containment_actions = [
        action for action in actions
        if action.action_type in CONTAINMENT_ACTION_TYPES
    ]

    containment_complete_time = None
    if containment_actions and all(a.completed_at for a in containment_actions):
        containment_complete_time = max(a.completed_at for a in containment_actions)

    evidence_complete_time = artifacts[-1].created_at if artifacts else None

    ticket_filed_time = tickets[0].created_at if tickets else None

    all_event_times = [t for t in [
        first_action_time,
        containment_complete_time,
        evidence_complete_time,
        ticket_filed_time
    ] if t]

    last_event_time = max(all_event_times) if all_event_times else None

    stages = {
        "detection_to_first_action_seconds": _seconds_between(
            detection_time, first_action_time
        ),
        "detection_to_containment_seconds": _seconds_between(
            detection_time, containment_complete_time
        ),
        "detection_to_evidence_collected_seconds": _seconds_between(
            detection_time, evidence_complete_time
        ),
        "detection_to_ticket_filed_seconds": _seconds_between(
            detection_time, ticket_filed_time
        ),
        "total_response_time_seconds": _seconds_between(
            detection_time, last_event_time
        )
    }

    return {
        "found": True,
        "alert_id": alert.alert_id,
        "severity": alert.severity,
        "hostname": alert.hostname,
        "alert_status": alert.status,
        "detection_time": detection_time,
        "total_actions_taken": len(actions),
        "total_artifacts_collected": len(artifacts),
        "ticket_filed": bool(tickets),
        "stages": stages
    }


def get_fleet_response_time_summary(db, limit: int = 50) -> dict:
    """
    Aggregates response-time stats across the most recent alerts, useful for
    tracking whether the orchestrator is meeting response-time SLAs over time.
    """

    alerts = db.query(Alert).order_by(
        Alert.created_at.desc()
    ).limit(limit).all()

    reports = [
        get_response_time_report(db, alert.alert_id)
        for alert in alerts
    ]

    completed_totals = [
        r["stages"]["total_response_time_seconds"]
        for r in reports
        if r["found"] and r["stages"]["total_response_time_seconds"] is not None
    ]

    average_total_seconds = (
        round(sum(completed_totals) / len(completed_totals), 2)
        if completed_totals else None
    )

    return {
        "incidents_analyzed": len(reports),
        "incidents_with_complete_timing": len(completed_totals),
        "average_total_response_time_seconds": average_total_seconds,
        "fastest_response_time_seconds": min(completed_totals) if completed_totals else None,
        "slowest_response_time_seconds": max(completed_totals) if completed_totals else None,
        "reports": reports
    }