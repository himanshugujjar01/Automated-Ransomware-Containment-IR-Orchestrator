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
    fetch_and_normalize_high_severity_alerts,
    find_machine_by_hostname,
    isolate_machine_by_hostname
)

from app.integrations.azure_ad import (
    get_graph_status,
    find_user_by_username,
    disable_user_account,
    revoke_user_sessions
)

from app.services.idp_response_runner import (
    run_approved_user_suspension,
    run_approved_session_revocation,
    run_full_approved_identity_response
)

from app.services.edr_response_runner import run_approved_host_isolation
from app.services.approved_containment_runner import run_full_approved_containment_response
from app.services.alert_approved_playbook import run_alert_based_approved_playbook
from app.services.validation_report import get_week1_week2_validation_report

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

@app.get("/edr/defender/machines/lookup")
def lookup_defender_machine(hostname: str):
    """
    Looks up a Microsoft Defender machine by hostname.

    This is read-only and does not isolate any device.
    """

    return find_machine_by_hostname(hostname)

@app.post("/edr/defender/machines/isolate-preview")
def defender_isolation_preview(hostname: str):
    """
    Safe isolation preview.

    This always runs in dry-run mode.
    It does not isolate a real device.
    """

    result = isolate_machine_by_hostname(
        hostname=hostname,
        comment=f"Dry-run isolation preview for {hostname}",
        isolation_type="Selective",
        dry_run=True
    )

    return result

@app.get("/integrations/graph/status")
def graph_integration_status():
    """
    Shows Microsoft Graph / Azure AD connector configuration status.
    """

    return get_graph_status()

@app.get("/idp/azure/users/lookup")
def lookup_azure_user(username: str):
    """
    Looks up a Microsoft Graph / Azure AD user.

    This is read-only.
    """

    return find_user_by_username(username)

@app.post("/idp/azure/users/suspend-preview")
def azure_user_suspend_preview(username: str):
    """
    Safe user suspension preview.

    This always runs in dry-run mode.
    It does not disable a real user.
    """

    return disable_user_account(
        user_id_or_upn=username,
        dry_run=True
    )

@app.post("/idp/azure/users/revoke-sessions-preview")
def azure_user_revoke_sessions_preview(username: str):
    """
    Safe session revocation preview.

    This always runs in dry-run mode.
    It does not revoke real user sessions.
    """

    return revoke_user_sessions(
        user_id_or_upn=username,
        dry_run=True
    )

@app.post("/idp/azure/users/suspend-approved")
def azure_user_suspend_approved(
    username: str,
    approval_code: str,
    dry_run: bool = True
):
    """
    Approved Azure AD user suspension workflow.

    dry_run=True is safe and does not disable a real account.
    dry_run=False should only be used in an authorized lab tenant.
    """

    return run_approved_user_suspension(
        username=username,
        approval_code=approval_code,
        dry_run=dry_run
    )

@app.post("/idp/azure/users/revoke-sessions-approved")
def azure_user_revoke_sessions_approved(
    username: str,
    approval_code: str,
    dry_run: bool = True
):
    """
    Approved Azure AD session revocation workflow.

    dry_run=True is safe and does not revoke real sessions.
    dry_run=False should only be used in an authorized lab tenant.
    """

    return run_approved_session_revocation(
        username=username,
        approval_code=approval_code,
        dry_run=dry_run
    )

@app.post("/idp/azure/users/respond-approved")
def azure_user_full_identity_response(
    username: str,
    approval_code: str,
    dry_run: bool = True
):
    """
    Full approved identity response workflow.

    Actions:
    1. Suspend user
    2. Revoke sessions

    dry_run=True is safe and does not change real Azure AD accounts.
    """

    return run_full_approved_identity_response(
        username=username,
        approval_code=approval_code,
        dry_run=dry_run
    )

@app.post("/edr/defender/host/isolate-approved")
def approved_host_isolation(
    hostname: str,
    ip_address: str,
    approval_code: str,
    dry_run: bool = True
):
    """
    Approved host isolation workflow.

    dry_run=True is safe and does not isolate a real machine.
    dry_run=False should only be used in an authorized lab tenant.
    """

    return run_approved_host_isolation(
        hostname=hostname,
        ip_address=ip_address,
        approval_code=approval_code,
        dry_run=dry_run
    )

@app.post("/response/full-containment-approved")
def full_approved_containment_response(
    hostname: str,
    ip_address: str,
    username: str,
    approval_code: str,
    dry_run: bool = True
):
    """
    Full approved containment workflow.

    Actions:
    1. Host isolation
    2. User suspension
    3. Session revocation

    dry_run=True is safe and does not perform real EDR or Azure AD changes.
    """

    return run_full_approved_containment_response(
        hostname=hostname,
        ip_address=ip_address,
        username=username,
        approval_code=approval_code,
        dry_run=dry_run
    )

@app.post("/playbooks/{alert_id}/approved-run")
def run_approved_playbook_for_alert(
    alert_id: str,
    approval_code: str,
    dry_run: bool = True,
    db: Session = Depends(get_db)
):
    """
    Runs approved containment workflow for a saved EDR alert.

    Actions:
    1. Host isolation
    2. User suspension
    3. Session revocation

    dry_run=True is safe and does not perform real EDR or Azure AD changes.
    """

    clean_alert_id = alert_id.strip()

    alert = db.query(Alert).filter(Alert.alert_id == clean_alert_id).first()

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    return run_alert_based_approved_playbook(
        db=db,
        alert=alert,
        approval_code=approval_code,
        dry_run=dry_run
    )

@app.get(
    "/validation",
    summary="Validation Report"
)
def validation_report():
    """
    Shows Project 3 Week 1 and Week 2 requirement completion report.
    """

    return get_week1_week2_validation_report()