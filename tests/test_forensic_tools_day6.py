from app.services.forensic_tool_status import (
    is_tool_path_configured,
    get_forensic_tools_status
)

from app.services.kape_runner import (
    build_kape_command,
    run_kape_collection_authorized
)

from app.services.volatility_runner import (
    build_volatility_command,
    run_volatility_authorized
)


def test_tool_path_configured_false_for_change_me():
    assert is_tool_path_configured("change_me") is False


def test_tool_path_configured_true_for_value():
    assert is_tool_path_configured("C:/Tools/KAPE/kape.exe") is True


def test_forensic_tools_status_format():
    result = get_forensic_tools_status()

    assert "forensic_tools" in result
    assert "kape" in result["forensic_tools"]
    assert "volatility" in result["forensic_tools"]
    assert result["safe_mode"] is True


def test_build_kape_command():
    result = build_kape_command(
        alert_id="EDR-TEST-001",
        target_source="C:",
        module_set="!BasicCollection"
    )

    assert result["alert_id"] == "EDR-TEST-001"
    assert result["tool"] == "KAPE"
    assert "--tsource" in result["command"]
    assert "--tdest" in result["command"]


def test_kape_preview_when_execute_real_false():
    result = run_kape_collection_authorized(
        alert_id="EDR-TEST-001",
        target_source="C:",
        module_set="!BasicCollection",
        execute_real=False
    )

    assert result["workflow"] == "kape_collection_preview"
    assert result["dry_run"] is True
    assert result["real_action_sent"] is False
    assert result["status"] == "preview_ready"


def test_kape_real_execution_blocked_when_disabled():
    result = run_kape_collection_authorized(
        alert_id="EDR-TEST-001",
        target_source="C:",
        module_set="!BasicCollection",
        execute_real=True
    )

    assert result["workflow"] == "kape_collection_authorized"
    assert result["status"] == "blocked"
    assert result["real_action_sent"] is False


def test_build_volatility_command():
    result = build_volatility_command(
        alert_id="EDR-TEST-001",
        memory_dump_path="artifacts/memory/sample.raw",
        plugin="windows.info"
    )

    assert result["alert_id"] == "EDR-TEST-001"
    assert result["tool"] == "Volatility"
    assert "windows.info" in result["command"]


def test_volatility_preview_when_execute_real_false():
    result = run_volatility_authorized(
        alert_id="EDR-TEST-001",
        memory_dump_path="artifacts/memory/sample.raw",
        plugin="windows.info",
        execute_real=False
    )

    assert result["workflow"] == "volatility_analysis_preview"
    assert result["dry_run"] is True
    assert result["real_action_sent"] is False
    assert result["status"] == "preview_ready"


def test_volatility_real_execution_blocked_when_disabled():
    result = run_volatility_authorized(
        alert_id="EDR-TEST-001",
        memory_dump_path="artifacts/memory/sample.raw",
        plugin="windows.info",
        execute_real=True
    )

    assert result["workflow"] == "volatility_analysis_authorized"
    assert result["status"] == "blocked"
    assert result["real_action_sent"] is False