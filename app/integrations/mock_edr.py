from datetime import datetime, timezone


def mock_isolate_host(hostname: str, ip_address: str) -> dict:
    """
    Simulates EDR host isolation.

    In a real enterprise environment, this function would call
    CrowdStrike Falcon API or Microsoft Defender for Endpoint API.
    In this lab project, it safely returns a mock success response.
    """

    return {
        "integration": "mock_edr",
        "action": "network_containment",
        "hostname": hostname,
        "ip_address": ip_address,
        "status": "success",
        "message": f"Host {hostname} with IP {ip_address} isolated successfully using mock EDR API.",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }