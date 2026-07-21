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
    assert result["total_files"] == 5
    assert len(result["files_created"]) == 5

    expected_files = [
        "triage_summary.json",
        "process_list.txt",
        "network_connections.txt",
        "suspicious_hashes.txt",
        "memory_dump_metadata.txt"
    ]

    for expected_file in expected_files:
        full_path = os.path.join(result["artifact_dir"], expected_file)
        assert os.path.exists(full_path)

    for file_path in result["files_created"]:
        assert os.path.exists(file_path)