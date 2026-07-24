import json

from fastapi import FastAPI, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.config import APP_NAME, APP_ENV, WEBHOOK_SECRET
from app.database import Base, engine, get_db

from app.models.alert_model import Alert
from app.models.action_model import ActionLog
from app.models.artifact_model import Artifact
from app.models.ticket_model import Ticket

from app.schemas.edr_schema import EDRAlert
from app.services.alert_parser import parse_edr_alert
from app.services.playbook_engine import run_basic_containment_playbook
from app.config import USE_REAL_EDR, USE_REAL_IDP, REQUIRE_MANUAL_APPROVAL, ALLOWED_TEST_HOSTS, ALLOWED_TEST_USERS
from app.integrations.defender_edr import (
    get_defender_status,
    fetch_and_normalize_high_severity_alerts
)


# Create database tables
Base.metadata.create_all(bind=engine)


app = FastAPI(
    title=APP_NAME,
    description="A safe lab-based SOAR platform for ransomware alert ingestion, containment, forensics, ticketing, and SOC monitoring.",
    version="1.0.0"
)


@app.get("/")
def root():
    return {
        "message": f"{APP_NAME} is running",
        "environment": APP_ENV
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": APP_NAME,
        "environment": APP_ENV
    }


@app.post("/webhooks/edr")
def receive_edr_alert(
    alert: EDRAlert,
    db: Session = Depends(get_db),
    x_webhook_secret: str = Header(None)
):
    """
    Secure webhook endpoint to receive ransomware alerts from a mock EDR system.
    """

    # Step 1: Validate webhook secret
    if x_webhook_secret != WEBHOOK_SECRET:
        raise HTTPException(
            status_code=401,
            detail="Invalid webhook secret"
        )

    # Step 2: Convert Pydantic model to dictionary
    alert_dict = alert.model_dump()

    # Step 3: Parse important alert indicators
    parsed = parse_edr_alert(alert_dict)

    # Step 4: Check if alert already exists
    existing_alert = db.query(Alert).filter(
        Alert.alert_id == parsed["alert_id"]
    ).first()

    if existing_alert:
        raise HTTPException(
            status_code=409,
            detail="Alert ID already exists"
        )

    # Step 5: Save alert into database
    db_alert = Alert(
        alert_id=parsed["alert_id"],
        severity=parsed["severity"],
        detection_type=parsed["detection_type"],
        hostname=parsed["hostname"],
        ip_address=parsed["ip_address"],
        username=parsed["username"],
        process_name=parsed["process_name"],
        process_hash=parsed["process_hash"],
        description=parsed["description"],
        status="received",
        raw_payload=json.dumps(alert_dict)
    )

    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)

    # Step 6: Return success response
    return {
        "received": True,
        "message": "EDR alert received and stored successfully",
        "alert_id": db_alert.alert_id,
        "severity": db_alert.severity,
        "detection_type": db_alert.detection_type,
        "hostname": db_alert.hostname,
        "ip_address": db_alert.ip_address,
        "username": db_alert.username,
        "process_name": db_alert.process_name,
        "process_hash": db_alert.process_hash,
        "status": db_alert.status
    }

@app.get("/alerts")
def get_all_alerts(db: Session = Depends(get_db)):
    """
    Fetch all EDR alerts stored in the database.
    """

    alerts = db.query(Alert).order_by(Alert.created_at.desc()).all()

    return {
        "total_alerts": len(alerts),
        "alerts": alerts
    }


@app.get("/alerts/{alert_id}")
def get_alert_by_id(alert_id: str, db: Session = Depends(get_db)):
    """
    Fetch details of a single EDR alert using alert_id.
    """

    clean_alert_id = alert_id.strip()

    alert = db.query(Alert).filter(Alert.alert_id == clean_alert_id).first()

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    return {
        "alert_id": alert.alert_id,
        "severity": alert.severity,
        "detection_type": alert.detection_type,
        "hostname": alert.hostname,
        "ip_address": alert.ip_address,
        "username": alert.username,
        "process_name": alert.process_name,
        "process_hash": alert.process_hash,
        "description": alert.description,
        "status": alert.status,
        "created_at": alert.created_at
    }

@app.post("/playbooks/{alert_id}/run")
def run_playbook_for_alert(alert_id: str, db: Session = Depends(get_db)):
    """
    Runs the ransomware containment playbook for a specific alert.

    Playbook actions:
    1. Host isolation
    2. User suspension
    3. Session revocation
    4. Action logging
    5. Alert status update
    """

    clean_alert_id = alert_id.strip()

    alert = db.query(Alert).filter(Alert.alert_id == clean_alert_id).first()

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    result = run_basic_containment_playbook(db, alert)

    return {
        "message": "Containment playbook executed successfully",
        "result": result
    }

@app.get("/actions/{alert_id}")
def get_actions_for_alert(alert_id: str, db: Session = Depends(get_db)):
    """
    Fetch all automated response actions performed for a specific alert.

    Example actions:
    - host_isolation
    - user_suspension
    - session_revocation
    """

    clean_alert_id = alert_id.strip()

    alert = db.query(Alert).filter(Alert.alert_id == clean_alert_id).first()

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    actions = db.query(ActionLog).filter(
        ActionLog.alert_id == clean_alert_id
    ).order_by(ActionLog.started_at.asc()).all()

    return {
        "alert_id": clean_alert_id,
        "total_actions": len(actions),
        "actions": [
            {
                "id": action.id,
                "action_type": action.action_type,
                "target": action.target,
                "status": action.status,
                "details": action.details,
                "started_at": action.started_at,
                "completed_at": action.completed_at
            }
            for action in actions
        ]
    }

@app.get("/safety/config")
def get_safety_config():
    """
    Shows current real-mode and sandbox safety configuration.
    """

    return {
        "use_real_edr": USE_REAL_EDR,
        "use_real_idp": USE_REAL_IDP,
        "require_manual_approval": REQUIRE_MANUAL_APPROVAL,
        "allowed_test_hosts": ALLOWED_TEST_HOSTS,
        "allowed_test_users": ALLOWED_TEST_USERS,
        "message": "Safety guard configuration loaded successfully"
    }

@app.get("/integrations/defender/status")
def defender_integration_status():
    """
    Shows Microsoft Defender connector configuration status.
    """

    return get_defender_status()

@app.get("/edr/defender/alerts")
def fetch_defender_alerts(
    save_to_db: bool = False,
    limit: int = 10,
    db: Session = Depends(get_db)
):
    """
    Fetches high-severity Microsoft Defender alerts.

    save_to_db=false:
    - Only fetches and normalizes alerts.

    save_to_db=true:
    - Saves normalized Defender alerts into the local database.
    """

    result = fetch_and_normalize_high_severity_alerts(limit=limit)

    if not result.get("configured"):
        return result

    saved_alerts = []
    duplicate_alerts = []

    if save_to_db:
        for parsed in result["normalized_alerts"]:
            existing_alert = db.query(Alert).filter(
                Alert.alert_id == parsed["alert_id"]
            ).first()

            if existing_alert:
                duplicate_alerts.append(parsed["alert_id"])
                continue

            db_alert = Alert(
                alert_id=parsed["alert_id"],
                severity=parsed["severity"],
                detection_type=parsed["detection_type"],
                hostname=parsed["hostname"],
                ip_address=parsed["ip_address"],
                username=parsed["username"],
                process_name=parsed["process_name"],
                process_hash=parsed["process_hash"],
                description=parsed["description"],
                status="received",
                raw_payload=json.dumps(parsed)
            )

            db.add(db_alert)
            db.commit()
            db.refresh(db_alert)

            saved_alerts.append(db_alert.alert_id)

    return {
        "integration": result["integration"],
        "configured": result["configured"],
        "fetched": result["fetched"],
        "normalized_count": result["normalized_count"],
        "save_to_db": save_to_db,
        "saved_alerts": saved_alerts,
        "duplicate_alerts": duplicate_alerts,
        "normalized_alerts": result["normalized_alerts"]
    }