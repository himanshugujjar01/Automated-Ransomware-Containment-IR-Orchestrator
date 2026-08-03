from app.lambda_handlers.parse_alert_handler import lambda_handler as parse_alert
from app.lambda_handlers.host_isolation_handler import lambda_handler as host_isolation
from app.lambda_handlers.identity_response_handler import lambda_handler as identity_response
from app.lambda_handlers.merge_containment_handler import lambda_handler as merge_containment
from app.lambda_handlers.forensic_collection_handler import lambda_handler as forensic_collection
from app.lambda_handlers.chain_of_custody_handler import lambda_handler as chain_of_custody
from app.lambda_handlers.evidence_upload_handler import lambda_handler as evidence_upload
from app.lambda_handlers.ticketing_handler import lambda_handler as ticketing
from app.lambda_handlers.notification_handler import lambda_handler as notification
from app.lambda_handlers.response_time_report_handler import lambda_handler as response_time_report


SAMPLE_RAW_ALERT = {
    "alert_id": "SF-TEST-0001",
    "severity": "high",
    "detection_type": "Ransomware",
    "hostname": "DESKTOP-LAB-01",
    "ip_address": "192.168.1.20",
    "username": "himanshu",
    "process_name": "lockbit.exe",
    "process_hash": "abc123def456",
    "description": "Simulated ransomware detection for Step Functions test"
}


def run_full_state_machine_locally(raw_alert: dict) -> dict:
    """
    Chains every Lambda handler exactly as AWS Step Functions would,
    including the Parallel containment branch, entirely in-process.
    """

    event = parse_alert(raw_alert)

    branch_a = host_isolation(event)
    branch_b = identity_response(event)
    event = merge_containment([branch_a, branch_b])

    event = forensic_collection(event)
    event = chain_of_custody(event)
    event = evidence_upload(event)
    event = ticketing(event)
    event = notification(event)

    return response_time_report(event)


def test_parse_alert_handler():
    result = parse_alert(SAMPLE_RAW_ALERT)

    assert result["alert"]["alert_id"] == "SF-TEST-0001"
    assert result["alert"]["hostname"] == "DESKTOP-LAB-01"
    assert "detection_time" in result


def test_host_isolation_handler():
    event = parse_alert(SAMPLE_RAW_ALERT)
    result = host_isolation(event)

    assert result["host_isolation"]["action_type"] == "host_isolation"
    assert result["host_isolation"]["status"] == "success"
    assert "host_isolation" in result["timings"]


def test_identity_response_handler():
    event = parse_alert(SAMPLE_RAW_ALERT)
    result = identity_response(event)

    assert result["identity_response"]["status"] == "success"
    assert result["identity_response"]["user_suspension"]["status"] == "success"
    assert result["identity_response"]["session_revocation"]["status"] == "success"


def test_merge_containment_handler():
    event = parse_alert(SAMPLE_RAW_ALERT)
    branch_a = host_isolation(event)
    branch_b = identity_response(event)

    merged = merge_containment([branch_a, branch_b])

    assert "host_isolation" in merged
    assert "identity_response" in merged
    assert "host_isolation" in merged["timings"]
    assert "identity_response" in merged["timings"]


def test_full_state_machine_runs_end_to_end():
    report = run_full_state_machine_locally(SAMPLE_RAW_ALERT)

    assert report["alert_id"] == "SF-TEST-0001"
    assert report["stages"]["total_response_time_seconds"] is not None
    assert report["stages"]["detection_to_containment_seconds"] is not None
    assert report["stages"]["detection_to_evidence_collected_seconds"] is not None
    assert report["stages"]["detection_to_ticket_filed_seconds"] is not None
    assert report["ticket_id"] is not None


def test_state_machine_is_repeatable_with_different_alert_ids():
    first_alert = {**SAMPLE_RAW_ALERT, "alert_id": "SF-TEST-0002"}
    second_alert = {**SAMPLE_RAW_ALERT, "alert_id": "SF-TEST-0003"}

    first_report = run_full_state_machine_locally(first_alert)
    second_report = run_full_state_machine_locally(second_alert)

    assert first_report["alert_id"] != second_report["alert_id"]