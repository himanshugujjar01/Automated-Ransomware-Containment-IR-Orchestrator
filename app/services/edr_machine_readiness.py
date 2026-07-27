from app.config import REAL_ACTION_APPROVAL_CODE
from app.services.safety_guard import is_allowed_host
from app.integrations.defender_edr import preview_machine_isolation_by_hostname


def get_machine_isolation_readiness(
    hostname: str,
    approval_code: str,
    isolation_type: str = "Selective"
) -> dict:
    """
    Checks whether a host is ready for Microsoft Defender isolation.

    This is a safe readiness check.
    It does not perform real isolation.
    """

    if not hostname:
        return {
            "workflow": "edr_machine_isolation_readiness",
            "hostname": hostname,
            "status": "blocked",
            "ready": False,
            "message": "Hostname is missing."
        }

    if not is_allowed_host(hostname):
        return {
            "workflow": "edr_machine_isolation_readiness",
            "hostname": hostname,
            "status": "blocked",
            "ready": False,
            "message": "Host is not in approved sandbox allowlist."
        }

    if approval_code != REAL_ACTION_APPROVAL_CODE:
        return {
            "workflow": "edr_machine_isolation_readiness",
            "hostname": hostname,
            "status": "blocked",
            "ready": False,
            "message": "Invalid approval code."
        }

    preview_result = preview_machine_isolation_by_hostname(
        hostname=hostname,
        isolation_type=isolation_type
    )

    return {
        "workflow": "edr_machine_isolation_readiness",
        "hostname": hostname,
        "isolation_type": isolation_type,
        "status": preview_result["status"],
        "ready": preview_result.get("ready_for_real_isolation", False),
        "dry_run": True,
        "defender_result": preview_result,
        "message": preview_result["message"]
    }