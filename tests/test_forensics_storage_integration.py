from types import SimpleNamespace

from app.services.forensics import collect_basic_forensic_evidence
from app.services.chain_of_custody import generate_chain_of_custody_for_files
from app.integrations.local_s3 import upload_to_local_s3


def test_forensics_chain_and_storage_integration():
    fake_alert = SimpleNamespace(
        alert_id="TEST-DAY20-001",
        severity="critical",
        detection_type="Ransomware Behavior",
        hostname="DESKTOP-LAB-01",
        ip_address="192.168.1.20",
        username="himanshu",
        process_name="suspicious_encryptor.exe",
        process_hash="9f2a7c4b8e91d3a6f5c2b7d1a0e4f8c9"
    )

    forensic_result = collect_basic_forensic_evidence(fake_alert)

    custody_result = generate_chain_of_custody_for_files(
        fake_alert.alert_id,
        forensic_result["files_created"]
    )

    uploaded_files = []

    for entry in custody_result["custody_entries"]:
        uploaded_path = upload_to_local_s3(
            fake_alert.alert_id,
            entry["artifact_path"]
        )
        uploaded_files.append(uploaded_path)

    assert forensic_result["status"] == "success"
    assert forensic_result["total_files"] == 5
    assert custody_result["status"] == "success"
    assert custody_result["total_artifacts"] == 5
    assert len(uploaded_files) == 5

    for uploaded_file in uploaded_files:
        assert "local_s3_bucket" in uploaded_file
        assert "forensic-evidence" in uploaded_file