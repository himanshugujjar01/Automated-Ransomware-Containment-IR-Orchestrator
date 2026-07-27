from app.services.edr_machine_readiness import get_machine_isolation_readiness
from app.integrations.defender_edr import preview_machine_isolation_by_hostname


def test_machine_readiness_blocks_unknown_host():
    result = get_machine_isolation_readiness(
        hostname="UNKNOWN-PC",
        approval_code="confirm_lab_only",
        isolation_type="Selective"
    )

    assert result["workflow"] == "edr_machine_isolation_readiness"
    assert result["status"] == "blocked"
    assert result["ready"] is False
    assert "allowlist" in result["message"].lower()


def test_machine_readiness_blocks_wrong_approval_code():
    result = get_machine_isolation_readiness(
        hostname="DESKTOP-LAB-01",
        approval_code="wrong_code",
        isolation_type="Selective"
    )

    assert result["workflow"] == "edr_machine_isolation_readiness"
    assert result["status"] == "blocked"
    assert result["ready"] is False
    assert "approval code" in result["message"].lower()


def test_machine_readiness_with_allowed_host_safe_response():
    result = get_machine_isolation_readiness(
        hostname="DESKTOP-LAB-01",
        approval_code="confirm_lab_only",
        isolation_type="Selective"
    )

    assert result["workflow"] == "edr_machine_isolation_readiness"
    assert result["hostname"] == "DESKTOP-LAB-01"
    assert result["dry_run"] is True
    assert "defender_result" in result


def test_preview_machine_isolation_invalid_type():
    result = preview_machine_isolation_by_hostname(
        hostname="DESKTOP-LAB-01",
        isolation_type="InvalidType"
    )

    assert result["action"] == "machine_isolation_preview"
    assert result["status"] == "failed"
    assert result["ready_for_real_isolation"] is False


def test_preview_machine_isolation_missing_hostname():
    result = preview_machine_isolation_by_hostname(
        hostname="",
        isolation_type="Selective"
    )

    assert result["action"] == "machine_isolation_preview"
    assert result["status"] == "failed"
    assert result["ready_for_real_isolation"] is False