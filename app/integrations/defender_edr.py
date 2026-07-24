import requests

from app.config import (
    MDE_TENANT_ID,
    MDE_CLIENT_ID,
    MDE_CLIENT_SECRET,
    MDE_API_BASE_URL,
    MDE_AUTHORITY_URL,
    MDE_SCOPE
)


def is_defender_configured() -> bool:
    """
    Checks whether Microsoft Defender credentials are configured.
    This does not call Microsoft APIs.
    """

    required_values = [
        MDE_TENANT_ID,
        MDE_CLIENT_ID,
        MDE_CLIENT_SECRET
    ]

    return all(
        value and value != "change_me"
        for value in required_values
    )


def get_defender_status() -> dict:
    """
    Returns Microsoft Defender connector readiness status.
    """

    configured = is_defender_configured()

    return {
        "integration": "Microsoft Defender for Endpoint",
        "configured": configured,
        "api_base_url": MDE_API_BASE_URL,
        "auth_url": f"{MDE_AUTHORITY_URL}/{MDE_TENANT_ID}/oauth2/v2.0/token",
        "scope": MDE_SCOPE,
        "safe_mode": True,
        "message": (
            "Defender connector is configured."
            if configured
            else "Defender connector is not configured. Add real tenant ID, client ID, and client secret in .env."
        )
    }


def get_mde_token() -> str:
    """
    Gets Microsoft Defender access token using OAuth2 client credentials.

    Use this only in your own authorized Microsoft Defender lab tenant.
    """

    if not is_defender_configured():
        raise ValueError(
            "Microsoft Defender credentials are not configured. "
            "Update MDE_TENANT_ID, MDE_CLIENT_ID, and MDE_CLIENT_SECRET in .env."
        )

    token_url = f"{MDE_AUTHORITY_URL}/{MDE_TENANT_ID}/oauth2/v2.0/token"

    payload = {
        "client_id": MDE_CLIENT_ID,
        "client_secret": MDE_CLIENT_SECRET,
        "scope": MDE_SCOPE,
        "grant_type": "client_credentials"
    }

    response = requests.post(token_url, data=payload, timeout=30)

    if response.status_code != 200:
        raise RuntimeError(
            f"Failed to get Defender token. "
            f"Status: {response.status_code}, Response: {response.text}"
        )

    return response.json()["access_token"]


def list_high_severity_alerts(limit: int = 10) -> dict:
    """
    Fetches high-severity alerts from Microsoft Defender for Endpoint.

    This is read-only. It does not isolate machines or modify users.
    """

    token = get_mde_token()

    url = f"{MDE_API_BASE_URL}/api/alerts"

    params = {
        "$filter": "severity eq 'High'",
        "$top": limit
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }

    response = requests.get(url, headers=headers, params=params, timeout=30)

    if response.status_code != 200:
        raise RuntimeError(
            f"Failed to fetch Defender alerts. "
            f"Status: {response.status_code}, Response: {response.text}"
        )

    return response.json()


def normalize_defender_alert(defender_alert: dict) -> dict:
    """
    Converts a Microsoft Defender alert object into this project's EDRAlert format.
    """

    evidence = defender_alert.get("evidence") or []
    first_evidence = evidence[0] if isinstance(evidence, list) and evidence else {}

    defender_id = (
        defender_alert.get("id")
        or defender_alert.get("alertId")
        or defender_alert.get("incidentId")
        or "UNKNOWN"
    )

    hostname = (
        defender_alert.get("computerDnsName")
        or defender_alert.get("deviceName")
        or defender_alert.get("machineName")
        or first_evidence.get("deviceName")
        or first_evidence.get("computerDnsName")
        or "unknown-host"
    )

    ip_address = (
        defender_alert.get("ipAddress")
        or first_evidence.get("ipAddress")
        or first_evidence.get("localIP")
        or "unknown-ip"
    )

    username = (
        defender_alert.get("assignedTo")
        or defender_alert.get("userPrincipalName")
        or first_evidence.get("accountName")
        or first_evidence.get("userName")
        or "unknown-user"
    )

    process_name = (
        defender_alert.get("threatName")
        or defender_alert.get("title")
        or first_evidence.get("processFileName")
        or first_evidence.get("fileName")
        or "unknown-process"
    )

    process_hash = (
        defender_alert.get("sha256")
        or first_evidence.get("sha256")
        or first_evidence.get("fileHash")
        or "unknown-hash"
    )

    return {
        "alert_id": f"MDE-{defender_id}",
        "severity": str(defender_alert.get("severity", "high")).lower(),
        "detection_type": defender_alert.get("title", "Microsoft Defender Alert"),
        "hostname": hostname,
        "ip_address": ip_address,
        "username": username,
        "process_name": process_name,
        "process_hash": process_hash,
        "description": defender_alert.get(
            "description",
            "High-severity Microsoft Defender alert imported into IR orchestrator."
        )
    }


def fetch_and_normalize_high_severity_alerts(limit: int = 10) -> dict:
    """
    Safely fetches and normalizes Defender high-severity alerts.

    If credentials are not configured, it returns a safe message instead of failing.
    """

    if not is_defender_configured():
        return {
            "integration": "Microsoft Defender for Endpoint",
            "configured": False,
            "fetched": False,
            "normalized_alerts": [],
            "message": "Defender credentials are not configured. Keep using mock alerts or add real lab credentials in .env."
        }

    raw_response = list_high_severity_alerts(limit=limit)

    raw_alerts = raw_response.get("value", [])

    normalized_alerts = [
        normalize_defender_alert(alert)
        for alert in raw_alerts
    ]

    return {
        "integration": "Microsoft Defender for Endpoint",
        "configured": True,
        "fetched": True,
        "raw_count": len(raw_alerts),
        "normalized_count": len(normalized_alerts),
        "normalized_alerts": normalized_alerts
    }

def list_machines(limit: int = 100) -> dict:
    """
    Lists machines from Microsoft Defender for Endpoint.

    This is read-only. It does not isolate or modify devices.
    """

    token = get_mde_token()

    url = f"{MDE_API_BASE_URL}/api/machines"

    params = {
        "$top": limit
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }

    response = requests.get(url, headers=headers, params=params, timeout=30)

    if response.status_code not in [200, 404]:
        raise RuntimeError(
            f"Failed to list Defender machines. "
            f"Status: {response.status_code}, Response: {response.text}"
        )

    if response.status_code == 404:
        return {
            "value": []
        }

    return response.json()


def find_machine_by_hostname(hostname: str) -> dict:
    """
    Finds a Defender machine by hostname/computerDnsName.

    This is read-only. It only searches device information.
    """

    if not hostname:
        return {
            "found": False,
            "machine": None,
            "message": "Hostname is missing."
        }

    if not is_defender_configured():
        return {
            "found": False,
            "machine": None,
            "message": "Defender credentials are not configured."
        }

    machines_response = list_machines(limit=1000)
    machines = machines_response.get("value", [])

    hostname_lower = hostname.lower()

    for machine in machines:
        computer_dns_name = str(machine.get("computerDnsName", "")).lower()
        machine_id = machine.get("id")

        short_name = computer_dns_name.split(".")[0] if computer_dns_name else ""

        if hostname_lower in [computer_dns_name, short_name]:
            return {
                "found": True,
                "machine": machine,
                "machine_id": machine_id,
                "computer_dns_name": machine.get("computerDnsName"),
                "message": "Machine found in Microsoft Defender."
            }

    return {
        "found": False,
        "machine": None,
        "message": f"No Defender machine found for hostname: {hostname}"
    }


def isolate_machine_by_id(
    machine_id: str,
    comment: str,
    isolation_type: str = "Selective",
    dry_run: bool = True
) -> dict:
    """
    Sends machine isolation request to Microsoft Defender.

    dry_run=True means no real isolation API call is made.
    Use dry_run=False only in an authorized sandbox/lab tenant.
    """

    if not machine_id:
        return {
            "status": "failed",
            "message": "Machine ID is missing."
        }

    if isolation_type not in ["Full", "Selective", "UnManagedDevice"]:
        return {
            "status": "failed",
            "message": "Invalid isolation type. Use Full, Selective, or UnManagedDevice."
        }

    if dry_run:
        return {
            "status": "dry_run",
            "machine_id": machine_id,
            "isolation_type": isolation_type,
            "comment": comment,
            "message": "Dry-run only. No real Defender isolation API call was made."
        }

    token = get_mde_token()

    url = f"{MDE_API_BASE_URL}/api/machines/{machine_id}/isolate"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "Comment": comment,
        "IsolationType": isolation_type
    }

    response = requests.post(url, headers=headers, json=payload, timeout=30)

    if response.status_code != 201:
        raise RuntimeError(
            f"Failed to isolate machine. "
            f"Status: {response.status_code}, Response: {response.text}"
        )

    return {
        "status": "success",
        "machine_id": machine_id,
        "isolation_type": isolation_type,
        "response": response.json(),
        "message": "Machine isolation command sent successfully to Microsoft Defender."
    }


def isolate_machine_by_hostname(
    hostname: str,
    comment: str,
    isolation_type: str = "Selective",
    dry_run: bool = True
) -> dict:
    """
    Finds a Defender machine by hostname and isolates it.

    dry_run=True is the safe default.
    """

    lookup_result = find_machine_by_hostname(hostname)

    if not lookup_result["found"]:
        return {
            "status": "failed",
            "hostname": hostname,
            "message": lookup_result["message"]
        }

    machine_id = lookup_result["machine_id"]

    isolation_result = isolate_machine_by_id(
        machine_id=machine_id,
        comment=comment,
        isolation_type=isolation_type,
        dry_run=dry_run
    )

    isolation_result["hostname"] = hostname
    isolation_result["computer_dns_name"] = lookup_result.get("computer_dns_name")

    return isolation_result