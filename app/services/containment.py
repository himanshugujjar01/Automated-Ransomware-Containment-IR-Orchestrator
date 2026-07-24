from app.config import USE_REAL_EDR
from app.integrations.mock_edr import mock_isolate_host
from app.services.safety_guard import is_allowed_host

try:
    from app.integrations.defender_edr import isolate_machine_by_hostname
except Exception:
    isolate_machine_by_hostname = None


def isolate_host(hostname: str, ip_address: str) -> dict:
    """
    Runs host isolation action.

    Mock mode:
    - Uses mock EDR.

    Real EDR mode:
    - Uses Microsoft Defender connector.
    - Protected by sandbox allowlist.
    - Uses dry_run=True by default in this project.
    """

    if not hostname:
        return {
            "action_type": "host_isolation",
            "target": "unknown",
            "status": "failed",
            "details": "Hostname is missing. Host isolation cannot be performed."
        }

    if not ip_address:
        return {
            "action_type": "host_isolation",
            "target": hostname,
            "status": "failed",
            "details": "IP address is missing. Host isolation cannot be performed."
        }

    if USE_REAL_EDR:
        if not is_allowed_host(hostname):
            return {
                "action_type": "host_isolation",
                "target": hostname,
                "ip_address": ip_address,
                "status": "blocked",
                "details": "Host is not in approved sandbox allowlist. Real EDR isolation blocked."
            }

        if isolate_machine_by_hostname is None:
            return {
                "action_type": "host_isolation",
                "target": hostname,
                "ip_address": ip_address,
                "status": "failed",
                "details": "Defender integration module could not be loaded."
            }

        defender_result = isolate_machine_by_hostname(
            hostname=hostname,
            comment=f"Automated IR Orchestrator containment for host {hostname}",
            isolation_type="Selective",
            dry_run=True
        )

        return {
            "action_type": "host_isolation",
            "target": hostname,
            "ip_address": ip_address,
            "status": defender_result["status"],
            "details": defender_result["message"]
        }

    result = mock_isolate_host(hostname, ip_address)

    return {
        "action_type": "host_isolation",
        "target": hostname,
        "ip_address": ip_address,
        "status": result["status"],
        "details": result["message"],
        "timestamp": result["timestamp"]
    }