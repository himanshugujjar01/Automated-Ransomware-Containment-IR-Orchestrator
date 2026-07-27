from app.config import (
    USE_REAL_EDR,
    REQUIRE_MANUAL_APPROVAL,
    REAL_ACTION_APPROVAL_CODE
)

from app.services.safety_guard import is_allowed_host
from app.integrations.defender_edr import (
    preview_machine_isolation_by_hostname,
    isolate_machine_by_hostname
)


def validate_authorized_host_isolation(
    hostname: str,
    approval_code: str,
    isolation_type: str = "Selective",
    execute_real: bool = False
) -> dict:
    """
    Validates whether host isolation is allowed.

    Real isolation is blocked unless:
    1. Hostname is present.
    2. Host is in allowlist.
    3. Approval code is valid.
    4. USE_REAL_EDR=true.
    5. execute_real=true.
    """

    allowed_isolation_types = [
        "Full",
        "Selective",
        "UnManagedDevice"
    ]

    if not hostname:
        return {
            "allowed": False,
            "status": "blocked",
            "reason": "Hostname is missing."
        }

    if isolation_type not in allowed_isolation_types:
        return {
            "allowed": False,
            "status": "blocked",
            "reason": "Invalid isolation type. Allowed values are Full, Selective, and UnManagedDevice."
        }

    if not is_allowed_host(hostname):
        return {
            "allowed": False,
            "status": "blocked",
            "reason": "Host is not in approved sandbox allowlist."
        }

    if REQUIRE_MANUAL_APPROVAL and approval_code != REAL_ACTION_APPROVAL_CODE:
        return {
            "allowed": False,
            "status": "blocked",
            "reason": "Invalid or missing approval code."
        }

    if execute_real and not USE_REAL_EDR:
        return {
            "allowed": False,
            "status": "blocked",
            "reason": "USE_REAL_EDR is false. Real EDR isolation is disabled."
        }

    return {
        "allowed": True,
        "status": "approved",
        "reason": "Host isolation request passed safety validation."
    }


def run_authorized_host_isolation(
    hostname: str,
    approval_code: str,
    isolation_type: str = "Selective",
    execute_real: bool = False
) -> dict:
    """
    Runs authorized host isolation workflow.

    execute_real=False:
        Safe preview only.

    execute_real=True:
        Sends real Defender isolation request only if all controls pass.
    """

    validation = validate_authorized_host_isolation(
        hostname=hostname,
        approval_code=approval_code,
        isolation_type=isolation_type,
        execute_real=execute_real
    )

    if not validation["allowed"]:
        return {
            "workflow": "authorized_host_isolation",
            "hostname": hostname,
            "isolation_type": isolation_type,
            "execute_real": execute_real,
            "status": validation["status"],
            "real_action_sent": False,
            "message": validation["reason"]
        }

    if not execute_real:
        preview_result = preview_machine_isolation_by_hostname(
            hostname=hostname,
            isolation_type=isolation_type
        )

        return {
            "workflow": "authorized_host_isolation",
            "hostname": hostname,
            "isolation_type": isolation_type,
            "execute_real": False,
            "status": preview_result["status"],
            "real_action_sent": False,
            "dry_run": True,
            "message": preview_result["message"],
            "defender_result": preview_result
        }

    isolation_result = isolate_machine_by_hostname(
        hostname=hostname,
        comment=f"Authorized ransomware containment isolation for {hostname}",
        isolation_type=isolation_type,
        dry_run=False
    )

    return {
        "workflow": "authorized_host_isolation",
        "hostname": hostname,
        "isolation_type": isolation_type,
        "execute_real": True,
        "status": isolation_result["status"],
        "real_action_sent": isolation_result["status"] == "success",
        "dry_run": False,
        "message": isolation_result["message"],
        "defender_result": isolation_result
    }