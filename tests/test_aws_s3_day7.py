from app.integrations.aws_s3 import (
    get_aws_s3_status,
    build_s3_key,
    build_s3_uri,
    calculate_sha256,
    build_s3_upload_preview,
    upload_evidence_file_to_s3
)


def test_aws_s3_status_format():
    result = get_aws_s3_status()

    assert result["integration"] == "AWS S3 Evidence Storage"
    assert "configured" in result
    assert "enabled" in result
    assert "status" in result


def test_build_s3_key():
    key = build_s3_key(
        alert_id="EDR-TEST-001",
        file_path="artifacts/EDR-TEST-001/triage_summary.json"
    )

    assert "forensic-evidence" in key
    assert "EDR-TEST-001" in key
    assert key.endswith("triage_summary.json")


def test_build_s3_uri():
    uri = build_s3_uri(
        bucket_name="test-bucket",
        object_key="forensic-evidence/EDR-1/file.txt"
    )

    assert uri == "s3://test-bucket/forensic-evidence/EDR-1/file.txt"


def test_calculate_sha256(tmp_path):
    test_file = tmp_path / "evidence.txt"
    test_file.write_text("forensic evidence", encoding="utf-8")

    file_hash = calculate_sha256(str(test_file))

    assert len(file_hash) == 64


def test_s3_upload_preview(tmp_path):
    test_file = tmp_path / "evidence.txt"
    test_file.write_text("forensic evidence", encoding="utf-8")

    result = build_s3_upload_preview(
        alert_id="EDR-TEST-001",
        file_path=str(test_file)
    )

    assert result["workflow"] == "s3_evidence_upload_preview"
    assert result["status"] == "preview_ready"
    assert result["dry_run"] is True
    assert result["real_action_sent"] is False
    assert result["sha256_hash"]


def test_s3_upload_preview_missing_file():
    result = build_s3_upload_preview(
        alert_id="EDR-TEST-001",
        file_path="missing-file.txt"
    )

    assert result["status"] == "failed"
    assert result["real_action_sent"] is False


def test_real_s3_upload_blocked_when_disabled(tmp_path):
    test_file = tmp_path / "evidence.txt"
    test_file.write_text("forensic evidence", encoding="utf-8")

    result = upload_evidence_file_to_s3(
        alert_id="EDR-TEST-001",
        file_path=str(test_file),
        execute_real=True
    )

    assert result["status"] in ["blocked", "credentials_pending"]
    assert result["real_action_sent"] is False