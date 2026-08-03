import time
import json

from app.models.alert_model import Alert
from app.services.ransomware_simulator import generate_fake_alert
from app.services.alert_parser import parse_edr_alert
from app.services.playbook_engine import run_basic_containment_playbook
from app.services.ticketing_service import create_ticket_for_alert
from app.services.response_time_tracker import get_response_time_report


def run_tabletop_exercise(
    db,
    hostname: str = "SIM-WORKSTATION-01",
    username: str = "sim.user",
    severity: str = "high"
) -> dict:
    """
    Runs a full, self-contained ransomware table-top exercise:

      1. Generate a simulated EDR ransomware alert
      2. Ingest it exactly as the /webhooks/edr endpoint would
      3. Run the full containment + forensics playbook
      4. File an incident ticket
      5. Measure response time at every stage

    This is safe to run repeatedly: it never touches real EDR, IdP, AWS,
    or ticketing systems (all downstream calls stay in mock/dry-run mode
    unless USE_REAL_* flags are explicitly enabled).

    Returns a full exercise report including wall-clock execution time
    and the same stage-by-stage response-time breakdown used for real
    incidents.
    """

    exercise_start = time.perf_counter()

    # Step 1: Generate simulated alert payload
    fake_alert = generate_fake_alert(
        hostname=hostname,
        username=username,
        severity=severity
    )

    # Step 2: Ingest it the same way the EDR webhook would
    parsed = parse_edr_alert(fake_alert)

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
        raw_payload=json.dumps(fake_alert)
    )

    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)

    # Step 3: Run the full containment + forensics playbook
    playbook_result = run_basic_containment_playbook(db, db_alert)

    # Step 4: File an incident ticket (mock provider, safe by default)
    ticket_result = create_ticket_for_alert(
        db=db,
        alert=db_alert,
        provider="mock",
        execute_real=False,
        log_to_db=True
    )

    exercise_end = time.perf_counter()
    wall_clock_seconds = round(exercise_end - exercise_start, 4)

    # Step 5: Build the stage-by-stage response time report
    response_time_report = get_response_time_report(db, db_alert.alert_id)

    return {
        "exercise_type": "simulated_ransomware_tabletop",
        "alert_id": db_alert.alert_id,
        "hostname": hostname,
        "username": username,
        "severity": severity,
        "wall_clock_execution_seconds": wall_clock_seconds,
        "playbook_status": playbook_result["playbook_status"],
        "final_alert_status": playbook_result["final_alert_status"],
        "total_actions_taken": playbook_result["total_actions"],
        "total_artifacts_collected": playbook_result["total_artifacts"],
        "ticket_status": ticket_result.get("ticket_result", {}).get("status"),
        "response_time": response_time_report["stages"]
    }