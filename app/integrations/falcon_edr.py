import requests

from app.config import (
    FALCON_CLIENT_ID,
    FALCON_CLIENT_SECRET,
    FALCON_API_BASE_URL,
)


INTEGRATION_NAME = "CrowdStrike Falcon"


def is_placeholder(value: str) -> bool:
    return not value or str(value).strip() == "" or value == "change_me"


def is_falcon_configured() -> bool:
    return not any([
        is_placeholder(FALCON_CLIENT_ID),
        is_placeholder(FALCON_CLIENT_SECRET),
    ])


def get_falcon_status() -> dict:
    return {
        "integration": INTEGRATION_NAME,
        "configured": is_falcon_configured(),
        "safe_mode": True,
        "api_base_url": FALCON_API_BASE_URL,
        "client_configured": not is_placeholder(FALCON_CLIENT_ID),
        "secret_configured": not is_placeholder(FALCON_CLIENT_SECRET),
        "status": "ready" if is_falcon_configured() else "credentials_pending",
    }


def get_falcon_token() -> str:
    if not is_falcon_configured():
        raise ValueError("CrowdStrike Falcon credentials are not configured.")

    response = requests.post(
        f"{FALCON_API_BASE_URL}/oauth2/token",
        data={
            "client_id": FALCON_CLIENT_ID,
            "client_secret": FALCON_CLIENT_SECRET,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def find_host_by_hostname(hostname: str) -> dict:
    """Looks up a Falcon device (AID) by hostname."""
    if not hostname:
        return {"configured": is_falcon_configured(), "status": "failed",
                "message": "Hostname is missing.", "device": None}

    if not is_falcon_configured():
        return {"configured": False, "status": "credentials_pending",
                "message": "CrowdStrike Falcon credentials are not configured.",
                "device": None}

    token = get_falcon_token()
    headers = {"Authorization": f"Bearer {token}"}

    # Falcon's Hosts API: filter devices by hostname
    search = requests.get(
        f"{FALCON_API_BASE_URL}/devices/queries/devices/v1",
        headers=headers,
        params={"filter": f"hostname:'{hostname}'"},
        timeout=30,
    )
    search.raise_for_status()
    device_ids = search.json().get("resources", [])

    if not device_ids:
        return {"configured": True, "status": "not_found",
                "message": f"No Falcon device found for hostname {hostname}.",
                "device": None}

    details = requests.get(
        f"{FALCON_API_BASE_URL}/devices/entities/devices/v2",
        headers=headers,
        params={"ids": device_ids[0]},
        timeout=30,
    )
    details.raise_for_status()
    resources = details.json().get("resources", [])

    return {"configured": True, "status": "found",
            "message": f"Device found for hostname {hostname}.",
            "device": resources[0] if resources else None}


def preview_host_containment_by_hostname(hostname: str) -> dict:
    """Safe preview — looks the host up, never sends a containment command."""
    if not hostname:
        return {"integration": INTEGRATION_NAME, "action": "host_containment_preview",
                "status": "failed", "ready_for_real_containment": False,
                "message": "Hostname is missing."}

    result = find_host_by_hostname(hostname)

    if result["status"] == "credentials_pending":
        return {"integration": INTEGRATION_NAME, "action": "host_containment_preview",
                "hostname": hostname, "status": "credentials_pending",
                "ready_for_real_containment": False,
                "message": "CrowdStrike Falcon credentials are not configured.",
                "device": None}

    if result["status"] != "found":
        return {"integration": INTEGRATION_NAME, "action": "host_containment_preview",
                "hostname": hostname, "status": result["status"],
                "ready_for_real_containment": False,
                "message": result["message"], "device": None}

    device = result["device"]
    device_id = device.get("device_id")

    return {"integration": INTEGRATION_NAME, "action": "host_containment_preview",
            "hostname": hostname, "device_id": device_id, "status": "preview_ready",
            "dry_run": True, "ready_for_real_containment": bool(device_id),
            "message": "Device lookup successful. Preview completed. "
                       "No real containment command was sent.",
            "device": device}


def contain_host_by_id(device_id: str, dry_run: bool = True) -> dict:
    """
    Puts a Falcon-managed host into network containment.
    dry_run=True (default) is always safe and never calls the real API.
    """
    if not device_id:
        return {"integration": INTEGRATION_NAME, "action": "host_containment",
                "status": "failed", "dry_run": dry_run,
                "message": "Device ID is missing."}

    if dry_run:
        return {"integration": INTEGRATION_NAME, "action": "host_containment",
                "device_id": device_id, "status": "dry_run", "dry_run": True,
                "message": "No real Falcon containment API call was made. Dry-run only."}

    if not is_falcon_configured():
        return {"integration": INTEGRATION_NAME, "action": "host_containment",
                "device_id": device_id, "status": "credentials_pending",
                "dry_run": False,
                "message": "CrowdStrike Falcon credentials are not configured."}

    token = get_falcon_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    response = requests.post(
        f"{FALCON_API_BASE_URL}/devices/entities/devices-actions/v2",
        headers=headers,
        params={"action_name": "contain"},
        json={"ids": [device_id]},
        timeout=30,
    )
    response.raise_for_status()

    return {"integration": INTEGRATION_NAME, "action": "host_containment",
            "device_id": device_id, "status": "success", "dry_run": False,
            "message": "CrowdStrike Falcon containment command sent successfully.",
            "response": response.json()}


def normalize_falcon_detection(detection: dict) -> dict:
    """Converts a Falcon detection payload into this project's EDR alert schema."""
    device = detection.get("device", {}) or {}
    behaviors = detection.get("behaviors", []) or [{}]
    first_behavior = behaviors[0] if behaviors else {}

    return {
        "alert_id": f"FALCON-{detection.get('detection_id', 'unknown')}",
        "severity": str(detection.get("max_severity_displayname", "unknown")).lower(),
        "detection_type": first_behavior.get("tactic", "CrowdStrike Falcon Detection"),
        "hostname": device.get("hostname", "unknown"),
        "ip_address": device.get("local_ip", "unknown"),
        "username": first_behavior.get("user_name", "unknown"),
        "process_name": first_behavior.get("filename", "unknown"),
        "process_hash": first_behavior.get("sha256", "unknown"),
        "description": detection.get("description")
            or "High severity detection imported from CrowdStrike Falcon.",
        "source": "crowdstrike_falcon",
        "raw_payload": detection,
    }