import os
from types import SimpleNamespace

from app.services.forensics import create_artifact_directory, collect_basic_forensic_evidence


def test_create_artifact_directory():
    alert_id = "TEST-FORENSICS-001"

    artifact_dir = create_artifact_directory(alert_id)

    assert os.path.exists(artifact_dir)
    assert artifact_dir == os.path.join("artifacts", alert_id)


def test_collect_basic_forensic_evidence():
    fake_alert = SimpleNamespace(
        alert_id="TEST-FORENSICS-002",
        severity="critical",
        detection_type="Ransomware Behavior",
        hostname="DESKTOP-LAB-01",
        ip_address="192.168.1.20",
        username="himanshu",
        process_name="suspicious_encryptor.exe",
        process_hash="9f2a7c4b8e91d3a6f5c2b7d1a0e4f8c9"
    )

    result = collect_basic_forensic_evidence(fake_alert)

    assert result["status"] == "success"
    assert result["alert_id"] == "TEST-FORENSICS-002"
    assert os.path.exists(result["artifact_dir"])
    assert len(result["files_created"]) == 1
    assert os.path.exists(result["files_created"][0])
    assert result["files_created"][0].endswith("triage_summary.json")