from app.integrations.defender_edr import isolate_machine_by_id


def test_isolate_machine_by_id_dry_run():
    result = isolate_machine_by_id(
        machine_id="test-machine-id-123",
        comment="Dry-run test isolation",
        isolation_type="Selective",
        dry_run=True
    )

    assert result["status"] == "dry_run"
    assert result["machine_id"] == "test-machine-id-123"
    assert result["isolation_type"] == "Selective"
    assert "No real Defender isolation API call" in result["message"]


def test_isolate_machine_by_id_missing_machine_id():
    result = isolate_machine_by_id(
        machine_id="",
        comment="Missing machine ID test",
        isolation_type="Selective",
        dry_run=True
    )

    assert result["status"] == "failed"
    assert "Machine ID is missing" in result["message"]


def test_isolate_machine_by_id_invalid_isolation_type():
    result = isolate_machine_by_id(
        machine_id="test-machine-id-123",
        comment="Invalid isolation type test",
        isolation_type="WrongType",
        dry_run=True
    )

    assert result["status"] == "failed"
    assert "Invalid isolation type" in result["message"]