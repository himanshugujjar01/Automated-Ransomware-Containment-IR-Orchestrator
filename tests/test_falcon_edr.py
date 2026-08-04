from app.integrations import falcon_edr


def test_falcon_not_configured_by_default():
    assert falcon_edr.is_falcon_configured() is False


def test_falcon_status_reports_credentials_pending():
    status = falcon_edr.get_falcon_status()
    assert status["configured"] is False
    assert status["status"] == "credentials_pending"


def test_preview_missing_hostname():
    result = falcon_edr.preview_host_containment_by_hostname("")
    assert result["status"] == "failed"


def test_preview_without_credentials():
    result = falcon_edr.preview_host_containment_by_hostname("WIN-LAB-01")
    assert result["status"] == "credentials_pending"
    assert result["ready_for_real_containment"] is False


def test_contain_host_dry_run_never_calls_api():
    result = falcon_edr.contain_host_by_id("device-123", dry_run=True)
    assert result["status"] == "dry_run"
    assert result["dry_run"] is True


def test_normalize_falcon_detection_maps_fields():
    raw = {
        "detection_id": "abc123",
        "max_severity_displayname": "High",
        "device": {"hostname": "WIN-LAB-01", "local_ip": "10.0.0.5"},
        "behaviors": [{"tactic": "Ransomware", "user_name": "j.doe",
                        "filename": "lockbit.exe", "sha256": "deadbeef"}],
    }
    normalized = falcon_edr.normalize_falcon_detection(raw)
    assert normalized["alert_id"] == "FALCON-abc123"
    assert normalized["hostname"] == "WIN-LAB-01"
    assert normalized["source"] == "crowdstrike_falcon"