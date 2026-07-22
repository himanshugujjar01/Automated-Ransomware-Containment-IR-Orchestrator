import os
from types import SimpleNamespace

from app.services.forensics import collect_basic_forensic_evidence
from app.services.chain_of_custody import (
    calculate_sha256,
    create_chain_of_custody_entry,
    generate_chain_of_custody_for_files
)


def test_calculate_sha256():
    test_file_path = "test_hash_file.txt"

    with open(test_file_path, "w", encoding="utf-8") as file:
        file.write("test forensic evidence")

    file_hash = calculate_sha256(test_file_path)

    assert isinstance(file_hash, str)
    assert len(file_hash) == 64

    os.remove(test_file_path)


def test_create_chain_of_custody_entry():
    test_file_path = "test_custody_file.txt"

    with open(test_file_path, "w", encoding="utf-8") as file:
        file.write("sample artifact data")

    entry = create_chain_of_custody_entry("TEST-ALERT-001", test_file_path)

    assert entry["alert_id"] == "TEST-ALERT-001"
    assert entry["artifact_name"] == "test_custody_file.txt"
    assert entry["artifact_path"] == test_file_path
    assert len(entry["sha256_hash"]) == 64
    assert entry["collected_by"] == "IR-Orchestrator"
    assert entry["action"] == "forensic_collection"

    os.remove(test_file_path)


def test_generate_chain_of_custody_for_files():
    fake_alert = SimpleNamespace(
        alert_id="TEST-CUSTODY-001",
        severity="critical",
        detection_type="Ransomware Behavior",
        hostname="DESKTOP-LAB-01",
        ip_address="192.168.1.20",
        username="himanshu",
        process_name="suspicious_encryptor.exe",
        process_hash="9f2a7c4b8e91d3a6f5c2b7d1a0e4f8c9"
    )

    forensic_result = collect_basic_forensic_evidence(fake_alert)

    result = generate_chain_of_custody_for_files(
        fake_alert.alert_id,
        forensic_result["files_created"]
    )

    assert result["status"] == "success"
    assert result["alert_id"] == "TEST-CUSTODY-001"
    assert result["total_artifacts"] == 5
    assert os.path.exists(result["custody_log_path"])

    for entry in result["custody_entries"]:
        assert len(entry["sha256_hash"]) == 64
        assert entry["collected_by"] == "IR-Orchestrator"