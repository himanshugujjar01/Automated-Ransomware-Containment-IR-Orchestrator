from app.config import (
    USE_REAL_EDR,
    REQUIRE_MANUAL_APPROVAL,
    REAL_ACTION_APPROVAL_CODE
)

from app.services.safety_guard import is_allowed_host
from app.services.containment import isolate_host


def validate_edr_real_action(
    hostname: str,
    approval_code: str,
    dry_run: bool = True
) -> dict:
    """
    Validates whether a host isolation action is allowed.

    Safety rules:
    1. Hostname must be present.
    2. Host must be in sandbox allowlist.
    3. Approval code must match.
    4. Real EDR action is blocked unless USE_REAL_EDR=true.
    """

    if not hostname:
        return {
            "allowed": False,
            "status": "blocked",
            "reason": "Hostname is missing."
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
            "reason": "Invalid or missing manual approval code."
        }

    if not dry_run and not USE_REAL_EDR:
        return {
            "allowed": False,
            "status": "blocked",
            "reason": "USE_REAL_EDR is false. Real EDR isolation is disabled."
        }

    return {
        "allowed": True,
        "status": "approved",
        "reason": "EDR containment action passed safety validation."
    }


def run_approved_host_isolation(
    hostname: str,
    ip_address: str,
    approval_code: str,
    dry_run: bool = True
) -> dict:
    """
    Runs approved host isolation.

    dry_run=True is safe.
    It does not isolate a real machine.
    """

    validation = validate_edr_real_action(
        hostname=hostname,
        approval_code=approval_code,
        dry_run=dry_run
    )

    if not validation["allowed"]:
        return {
            "action_type": "approved_host_isolation",
            "target": hostname,
            "ip_address": ip_address,
            "status": validation["status"],
            "dry_run": dry_run,
            "details": validation["reason"]
        }

    if dry_run:
        return {
            "action_type": "approved_host_isolation",
            "target": hostname,
            "ip_address": ip_address,
            "status": "dry_run",
            "dry_run": True,
            "details": "Dry-run only. No real EDR host isolation command was sent."
        }

    result = isolate_host(
        hostname=hostname,
        ip_address=ip_address
    )

    return {
        "action_type": "approved_host_isolation",
        "target": hostname,
        "ip_address": ip_address,
        "status": result["status"],
        "dry_run": False,
        "details": result["details"]
    }