from pathlib import Path

from app.config import (
    KAPE_ENABLED,
    KAPE_PATH,
    KAPE_OUTPUT_DIR,
    VOLATILITY_ENABLED,
    VOLATILITY_PATH,
    MEMORY_DUMP_DIR
)


def is_tool_path_configured(tool_path: str) -> bool:
    return bool(tool_path and tool_path != "change_me")


def tool_exists(tool_path: str) -> bool:
    if not is_tool_path_configured(tool_path):
        return False

    return Path(tool_path).exists()


def ensure_forensic_directories() -> dict:
    """
    Creates local output directories for forensic artifacts.
    """

    kape_output = Path(KAPE_OUTPUT_DIR)
    memory_output = Path(MEMORY_DUMP_DIR)

    kape_output.mkdir(parents=True, exist_ok=True)
    memory_output.mkdir(parents=True, exist_ok=True)

    return {
        "kape_output_dir": str(kape_output),
        "memory_dump_dir": str(memory_output)
    }


def get_forensic_tools_status() -> dict:
    """
    Returns readiness status for KAPE and Volatility.
    """

    directories = ensure_forensic_directories()

    kape_configured = is_tool_path_configured(KAPE_PATH)
    volatility_configured = is_tool_path_configured(VOLATILITY_PATH)

    kape_available = tool_exists(KAPE_PATH)
    volatility_available = tool_exists(VOLATILITY_PATH)

    return {
        "forensic_tools": {
            "kape": {
                "enabled": KAPE_ENABLED,
                "configured": kape_configured,
                "path": KAPE_PATH,
                "available_on_disk": kape_available,
                "output_dir": directories["kape_output_dir"],
                "status": "ready" if KAPE_ENABLED and kape_available else "not_ready"
            },
            "volatility": {
                "enabled": VOLATILITY_ENABLED,
                "configured": volatility_configured,
                "path": VOLATILITY_PATH,
                "available_on_disk": volatility_available,
                "memory_dump_dir": directories["memory_dump_dir"],
                "status": "ready" if VOLATILITY_ENABLED and volatility_available else "not_ready"
            }
        },
        "safe_mode": True,
        "message": "Forensic tool readiness checked successfully."
    }