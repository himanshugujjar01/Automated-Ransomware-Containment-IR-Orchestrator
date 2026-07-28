from pathlib import Path
import subprocess

from app.config import (
    KAPE_ENABLED,
    KAPE_PATH,
    KAPE_OUTPUT_DIR
)

from app.services.forensic_tool_status import tool_exists


def build_kape_command(
    alert_id: str,
    target_source: str = "C:",
    module_set: str = "!BasicCollection"
) -> dict:
    """
    Builds a KAPE command for forensic collection.

    This does not execute the command.
    """

    output_dir = Path(KAPE_OUTPUT_DIR) / alert_id
    output_dir.mkdir(parents=True, exist_ok=True)

    command = [
        KAPE_PATH,
        "--tsource",
        target_source,
        "--tdest",
        str(output_dir),
        "--target",
        module_set
    ]

    return {
        "alert_id": alert_id,
        "tool": "KAPE",
        "target_source": target_source,
        "module_set": module_set,
        "output_dir": str(output_dir),
        "command": command,
        "command_preview": " ".join(command)
    }


def run_kape_collection_preview(
    alert_id: str,
    target_source: str = "C:",
    module_set: str = "!BasicCollection"
) -> dict:
    """
    Safe KAPE preview.

    It only builds the command and prepares output folders.
    No real collection is executed.
    """

    command_data = build_kape_command(
        alert_id=alert_id,
        target_source=target_source,
        module_set=module_set
    )

    return {
        "workflow": "kape_collection_preview",
        "alert_id": alert_id,
        "dry_run": True,
        "real_action_sent": False,
        "status": "preview_ready",
        "message": "KAPE command preview generated. No real forensic collection was executed.",
        "kape": command_data
    }


def run_kape_collection_authorized(
    alert_id: str,
    target_source: str = "C:",
    module_set: str = "!BasicCollection",
    execute_real: bool = False
) -> dict:
    """
    Runs KAPE only when execute_real=True and KAPE is enabled/configured.

    Default behavior is safe preview.
    """

    if not execute_real:
        return run_kape_collection_preview(
            alert_id=alert_id,
            target_source=target_source,
            module_set=module_set
        )

    if not KAPE_ENABLED:
        return {
            "workflow": "kape_collection_authorized",
            "alert_id": alert_id,
            "status": "blocked",
            "real_action_sent": False,
            "message": "KAPE_ENABLED is false. Real KAPE execution is disabled."
        }

    if not tool_exists(KAPE_PATH):
        return {
            "workflow": "kape_collection_authorized",
            "alert_id": alert_id,
            "status": "blocked",
            "real_action_sent": False,
            "message": "KAPE executable path is not configured or not found."
        }

    command_data = build_kape_command(
        alert_id=alert_id,
        target_source=target_source,
        module_set=module_set
    )

    try:
        completed = subprocess.run(
            command_data["command"],
            capture_output=True,
            text=True,
            timeout=600,
            check=False
        )

        return {
            "workflow": "kape_collection_authorized",
            "alert_id": alert_id,
            "status": "success" if completed.returncode == 0 else "failed",
            "real_action_sent": True,
            "return_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "kape": command_data
        }

    except Exception as error:
        return {
            "workflow": "kape_collection_authorized",
            "alert_id": alert_id,
            "status": "failed",
            "real_action_sent": False,
            "message": str(error),
            "kape": command_data
        }