from app.integrations.defender_edr import (
    get_defender_status,
    is_defender_configured
)


def test_defender_status_format():
    status = get_defender_status()

    assert status["integration"] == "Microsoft Defender for Endpoint"
    assert "configured" in status
    assert "api_base_url" in status
    assert "auth_url" in status
    assert "scope" in status
    assert status["safe_mode"] is True


def test_defender_configured_returns_boolean():
    result = is_defender_configured()

    assert isinstance(result, bool)