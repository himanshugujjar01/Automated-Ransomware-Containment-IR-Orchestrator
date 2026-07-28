from pathlib import Path
import subprocess

from app.config import (
    VOLATILITY_ENABLED,
    VOLATILITY_PATH,
    MEMORY_DUMP_DIR
)

from app.services.forensic_tool_status import tool_exists


def build_volatility_command(
    alert_id: str,
    memory_dump_path: str,
    plugin: str = "windows.info"
) -> dict:
    """
    Builds a Volatility command for memory analysis.

    This does not execute the command.
    """

    output_dir = Path(MEMORY_DUMP_DIR) / alert_id
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / f"{plugin.replace('.', '_')}_output.txt"

    command = [
        VOLATILITY_PATH,
        "-f",
        memory_dump_path,
        plugin
    ]

    return {
        "alert_id": alert_id,
        "tool": "Volatility",
        "memory_dump_path": memory_dump_path,
        "plugin": plugin,
        "output_dir": str(output_dir),
        "output_file": str(output_file),
        "command": command,
        "command_preview": " ".join(command)
    }


def run_volatility_preview(
    alert_id: str,
    memory_dump_path: str,
    plugin: str = "windows.info"
) -> dict:
    """
    Safe Volatility preview.

    It only builds the command and prepares output folders.
    No real memory analysis is executed.
    """

    command_data = build_volatility_command(
        alert_id=alert_id,
        memory_dump_path=memory_dump_path,
        plugin=plugin
    )

    return {
        "workflow": "volatility_analysis_preview",
        "alert_id": alert_id,
        "dry_run": True,
        "real_action_sent": False,
        "status": "preview_ready",
        "message": "Volatility command preview generated. No real memory analysis was executed.",
        "volatility": command_data
    }


def run_volatility_authorized(
    alert_id: str,
    memory_dump_path: str,
    plugin: str = "windows.info",
    execute_real: bool = False
) -> dict:
    """
    Runs Volatility only when execute_real=True and Volatility is enabled/configured.

    Default behavior is safe preview.
    """

    if not execute_real:
        return run_volatility_preview(
            alert_id=alert_id,
            memory_dump_path=memory_dump_path,
            plugin=plugin
        )

    if not VOLATILITY_ENABLED:
        return {
            "workflow": "volatility_analysis_authorized",
            "alert_id": alert_id,
            "status": "blocked",
            "real_action_sent": False,
            "message": "VOLATILITY_ENABLED is false. Real Volatility execution is disabled."
        }

    if not tool_exists(VOLATILITY_PATH):
        return {
            "workflow": "volatility_analysis_authorized",
            "alert_id": alert_id,
            "status": "blocked",
            "real_action_sent": False,
            "message": "Volatility executable path is not configured or not found."
        }

    command_data = build_volatility_command(
        alert_id=alert_id,
        memory_dump_path=memory_dump_path,
        plugin=plugin
    )

    try:
        completed = subprocess.run(
            command_data["command"],
            capture_output=True,
            text=True,
            timeout=600,
            check=False
        )

        output_file = Path(command_data["output_file"])
        output_file.write_text(
            completed.stdout,
            encoding="utf-8"
        )

        return {
            "workflow": "volatility_analysis_authorized",
            "alert_id": alert_id,
            "status": "success" if completed.returncode == 0 else "failed",
            "real_action_sent": True,
            "return_code": completed.returncode,
            "output_file": str(output_file),
            "stderr": completed.stderr,
            "volatility": command_data
        }

    except Exception as error:
        return {
            "workflow": "volatility_analysis_authorized",
            "alert_id": alert_id,
            "status": "failed",
            "real_action_sent": False,
            "message": str(error),
            "volatility": command_data
        }