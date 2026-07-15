from app.integrations.mock_edr import mock_isolate_host


def isolate_host(hostname: str, ip_address: str) -> dict:
    """
    Runs host isolation action using mock EDR integration.
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

    result = mock_isolate_host(hostname, ip_address)

    return {
        "action_type": "host_isolation",
        "target": hostname,
        "ip_address": ip_address,
        "status": result["status"],
        "details": result["message"],
        "timestamp": result["timestamp"]
    }