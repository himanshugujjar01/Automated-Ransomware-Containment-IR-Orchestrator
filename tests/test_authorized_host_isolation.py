from app.services.authorized_host_isolation import (
    validate_authorized_host_isolation,
    run_authorized_host_isolation
)


def test_authorized_host_isolation_blocks_unknown_host():
    result = validate_authorized_host_isolation(
        hostname="UNKNOWN-PC",
        approval_code="confirm_lab_only",
        isolation_type="Selective",
        execute_real=False
    )

    assert result["allowed"] is False
    assert result["status"] == "blocked"
    assert "allowlist" in result["reason"].lower()


def test_authorized_host_isolation_blocks_wrong_approval_code():
    result = validate_authorized_host_isolation(
        hostname="DESKTOP-LAB-01",
        approval_code="wrong_code",
        isolation_type="Selective",
        execute_real=False
    )

    assert result["allowed"] is False
    assert result["status"] == "blocked"
    assert "approval code" in result["reason"].lower()


def test_authorized_host_isolation_blocks_invalid_isolation_type():
    result = validate_authorized_host_isolation(
        hostname="DESKTOP-LAB-01",
        approval_code="confirm_lab_only",
        isolation_type="InvalidType",
        execute_real=False
    )

    assert result["allowed"] is False
    assert result["status"] == "blocked"
    assert "invalid isolation type" in result["reason"].lower()


def test_authorized_host_isolation_blocks_real_action_when_real_edr_disabled():
    result = validate_authorized_host_isolation(
        hostname="DESKTOP-LAB-01",
        approval_code="confirm_lab_only",
        isolation_type="Selective",
        execute_real=True
    )

    assert result["allowed"] is False
    assert result["status"] == "blocked"
    assert "use_real_edr is false" in result["reason"].lower()


def test_authorized_host_isolation_safe_preview_response():
    result = run_authorized_host_isolation(
        hostname="DESKTOP-LAB-01",
        approval_code="confirm_lab_only",
        isolation_type="Selective",
        execute_real=False
    )

    assert result["workflow"] == "authorized_host_isolation"
    assert result["hostname"] == "DESKTOP-LAB-01"
    assert result["execute_real"] is False
    assert result["real_action_sent"] is False
    assert "defender_result" in result