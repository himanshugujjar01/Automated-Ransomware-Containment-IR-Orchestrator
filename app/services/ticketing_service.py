from app.integrations.ticketing_client import create_incident_ticket

try:
    from app.models.action_model import ActionLog
except Exception:
    ActionLog = None

try:
    from app.models.artifact_model import Artifact
except Exception:
    Artifact = None

try:
    from app.models.ticket_model import Ticket
except Exception:
    Ticket = None


def build_alert_data(alert) -> dict:
    return {
        "alert_id": alert.alert_id,
        "severity": alert.severity,
        "detection_type": alert.detection_type,
        "hostname": alert.hostname,
        "ip_address": alert.ip_address,
        "username": alert.username,
        "process_name": alert.process_name,
        "process_hash": alert.process_hash,
        "description": alert.description
    }


def get_actions_for_ticket(db, alert_id: str) -> list:
    if ActionLog is None:
        return []

    actions = db.query(ActionLog).filter(
        ActionLog.alert_id == alert_id
    ).order_by(ActionLog.started_at.asc()).all()

    return [
        {
            "action_type": action.action_type,
            "target": action.target,
            "status": action.status,
            "details": action.details
        }
        for action in actions
    ]


def get_artifacts_for_ticket(db, alert_id: str) -> list:
    if Artifact is None:
        return []

    artifacts = db.query(Artifact).filter(
        Artifact.alert_id == alert_id
    ).order_by(Artifact.created_at.asc()).all()

    return [
        {
            "artifact_type": artifact.artifact_type,
            "file_path": artifact.file_path,
            "storage_path": artifact.storage_path,
            "sha256_hash": artifact.sha256_hash
        }
        for artifact in artifacts
    ]


def save_ticket_to_db(
    db,
    alert_id: str,
    ticket_result: dict
):
    if Ticket is None:
        return {
            "logged": False,
            "reason": "Ticket model is not available."
        }

    ticket_id = ticket_result.get("ticket_id")

    if not ticket_id:
        return {
            "logged": False,
            "reason": "Ticket ID missing."
        }

    existing_ticket = db.query(Ticket).filter(
        Ticket.ticket_id == ticket_id
    ).first()

    if existing_ticket:
        return {
            "logged": False,
            "reason": "Ticket already exists.",
            "ticket_id": ticket_id
        }

    payload = ticket_result.get("payload", {})

    db_ticket = Ticket(
        ticket_id=ticket_id,
        alert_id=alert_id,
        priority=payload.get("priority", "High"),
        assigned_team="Incident Response Team",
        status=ticket_result.get("status", "created"),
        summary=payload.get("summary", "Ransomware incident ticket")
    )

    db.add(db_ticket)
    db.commit()
    db.refresh(db_ticket)

    return {
        "logged": True,
        "ticket_db_id": db_ticket.id,
        "ticket_id": db_ticket.ticket_id
    }


def create_ticket_for_alert(
    db,
    alert,
    provider: str = "mock",
    execute_real: bool = False,
    log_to_db: bool = True
) -> dict:
    alert_data = build_alert_data(alert)
    actions = get_actions_for_ticket(db, alert.alert_id)
    artifacts = get_artifacts_for_ticket(db, alert.alert_id)

    ticket_result = create_incident_ticket(
        alert_data=alert_data,
        actions=actions,
        artifacts=artifacts,
        provider=provider,
        execute_real=execute_real
    )

    database_result = None

    if (
        log_to_db
        and ticket_result.get("status") in ["mock_created", "success"]
    ):
        database_result = save_ticket_to_db(
            db=db,
            alert_id=alert.alert_id,
            ticket_result=ticket_result
        )

    return {
        "workflow": "alert_incident_ticketing",
        "alert_id": alert.alert_id,
        "provider": provider,
        "execute_real": execute_real,
        "database_result": database_result,
        "ticket_result": ticket_result
    }


def get_tickets_for_alert(db, alert_id: str) -> dict:
    if Ticket is None:
        return {
            "alert_id": alert_id,
            "total_tickets": 0,
            "tickets": [],
            "message": "Ticket model is not available."
        }

    tickets = db.query(Ticket).filter(
        Ticket.alert_id == alert_id
    ).order_by(Ticket.created_at.desc()).all()

    return {
        "alert_id": alert_id,
        "total_tickets": len(tickets),
        "tickets": [
            {
                "id": ticket.id,
                "ticket_id": ticket.ticket_id,
                "priority": ticket.priority,
                "assigned_team": ticket.assigned_team,
                "status": ticket.status,
                "summary": ticket.summary,
                "created_at": ticket.created_at
            }
            for ticket in tickets
        ]
    }