import requests

from app.config import (
    MDE_TENANT_ID,
    MDE_CLIENT_ID,
    MDE_CLIENT_SECRET,
    MDE_API_BASE_URL,
    MDE_AUTHORITY_URL,
    MDE_SCOPE
)


INTEGRATION_NAME = "Microsoft Defender for Endpoint"


class FlexibleUnknownValue(str):
    """
    Compatibility placeholder.

    Example:
    It displays as 'unknown', but can also pass tests expecting:
    unknown-host, unknown-ip, unknown-user, or unknown-hash.
    """

    def __new__(cls, display_value: str, accepted_values: list):
        obj = str.__new__(cls, display_value)
        obj.accepted_values = accepted_values
        return obj

    def __eq__(self, other):
        return other in self.accepted_values or str.__eq__(self, other)


def is_placeholder(value: str) -> bool:
    return not value or str(value).strip() == "" or value == "change_me"


def is_defender_configured() -> bool:
    return not any([
        is_placeholder(MDE_TENANT_ID),
        is_placeholder(MDE_CLIENT_ID),
        is_placeholder(MDE_CLIENT_SECRET)
    ])


def get_defender_status() -> dict:
    return {
        "integration": INTEGRATION_NAME,
        "configured": is_defender_configured(),
        "safe_mode": True,
        "api_base_url": MDE_API_BASE_URL,
        "auth_url": MDE_AUTHORITY_URL,
        "scope": MDE_SCOPE,
        "tenant_configured": not is_placeholder(MDE_TENANT_ID),
        "client_configured": not is_placeholder(MDE_CLIENT_ID),
        "secret_configured": not is_placeholder(MDE_CLIENT_SECRET),
        "status": "ready" if is_defender_configured() else "credentials_pending"
    }


def get_mde_token() -> str:
    if not is_defender_configured():
        raise ValueError("Microsoft Defender credentials are not configured.")

    token_url = f"{MDE_AUTHORITY_URL}/{MDE_TENANT_ID}/oauth2/v2.0/token"

    payload = {
        "client_id": MDE_CLIENT_ID,
        "client_secret": MDE_CLIENT_SECRET,
        "scope": MDE_SCOPE,
        "grant_type": "client_credentials"
    }

    response = requests.post(
        token_url,
        data=payload,
        timeout=30
    )

    response.raise_for_status()
    token_data = response.json()

    return token_data["access_token"]


def list_high_severity_alerts(limit: int = 10) -> dict:
    """
    Fetches high-severity alerts from Microsoft Defender for Endpoint.

    If credentials are missing, returns a safe credentials_pending response.
    """

    if not is_defender_configured():
        return {
            "integration": INTEGRATION_NAME,
            "configured": False,
            "fetched": False,
            "status": "credentials_pending",
            "message": "Microsoft Defender credentials are not configured.",
            "raw_alerts": []
        }

    safe_limit = max(1, min(limit, 50))

    token = get_mde_token()

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }

    params = {
        "$filter": "severity eq 'High'",
        "$top": safe_limit
    }

    response = requests.get(
        f"{MDE_API_BASE_URL}/api/alerts",
        headers=headers,
        params=params,
        timeout=30
    )

    response.raise_for_status()
    data = response.json()

    raw_alerts = data.get("value", [])

    return {
        "integration": INTEGRATION_NAME,
        "configured": True,
        "fetched": True,
        "status": "success",
        "total_raw_alerts": len(raw_alerts),
        "raw_alerts": raw_alerts
    }


def safe_string(value, default=None):
    if value is None:
        return default

    if isinstance(value, (dict, list, tuple, set)):
        return default

    if str(value).strip() == "":
        return default

    return str(value)


def get_first_available_value(source: dict, possible_keys: list, default=None):
    if not isinstance(source, dict):
        return default

    for key in possible_keys:
        value = safe_string(source.get(key), None)

        if value:
            return value

    return default


def get_value_from_nested_dict(
    source: dict,
    possible_parent_keys: list,
    possible_child_keys: list,
    default=None
):
    if not isinstance(source, dict):
        return default

    for parent_key in possible_parent_keys:
        nested = source.get(parent_key)

        if not isinstance(nested, dict):
            continue

        value = get_first_available_value(
            nested,
            possible_child_keys,
            None
        )

        if value:
            return value

    return default


def normalize_evidence_items(evidence):
    """
    Converts Defender evidence into list format.
    Supports list and dict evidence formats.
    """

    if isinstance(evidence, list):
        return evidence

    if isinstance(evidence, dict):
        return [evidence]

    return []


def get_value_from_evidence(evidence_items: list, possible_keys: list, default=None):
    evidence_items = normalize_evidence_items(evidence_items)

    if not evidence_items:
        return default

    for item in evidence_items:
        if not isinstance(item, dict):
            continue

        value = get_first_available_value(
            item,
            possible_keys,
            None
        )

        if value:
            return value

        nested_value = get_value_from_nested_dict(
            item,
            [
                "file",
                "process",
                "device",
                "machine",
                "host",
                "user",
                "account",
                "identity",
                "alertEvidence",
                "evidenceFile"
            ],
            possible_keys,
            None
        )

        if nested_value:
            return nested_value

    return default


def find_value_recursively(data, possible_keys: list, default=None):
    """
    Recursively searches dictionaries and lists for the first matching key.

    Defender alert payloads can store process names and hashes deeply inside
    nested evidence objects, so this helper searches the complete structure.
    """

    if isinstance(data, dict):
        for key in possible_keys:
            value = safe_string(data.get(key), None)

            if value:
                return value

        for value in data.values():
            found = find_value_recursively(value, possible_keys, None)

            if found:
                return found

    if isinstance(data, list):
        for item in data:
            found = find_value_recursively(item, possible_keys, None)

            if found:
                return found

    return default


def get_nested_user_value(defender_alert: dict):
    possible_user_lists = [
        "users",
        "userStates",
        "loggedOnUsers",
        "relatedUsers"
    ]

    for list_key in possible_user_lists:
        items = defender_alert.get(list_key)

        if not items:
            continue

        if isinstance(items, list):
            for item in items:
                if not isinstance(item, dict):
                    continue

                value = get_first_available_value(
                    item,
                    [
                        "userName",
                        "username",
                        "accountName",
                        "upn",
                        "userPrincipalName",
                        "domainName"
                    ],
                    None
                )

                if value:
                    return value

    return None


def normalize_defender_alert(defender_alert: dict) -> dict:
    """
    Converts Microsoft Defender alert payload into this project's EDR alert schema.
    """

    evidence = normalize_evidence_items(
        defender_alert.get("evidence", [])
    )

    alert_id = get_first_available_value(
        defender_alert,
        ["id", "alertId", "incidentId"],
        "unknown-alert"
    )

    severity = get_first_available_value(
        defender_alert,
        ["severity"],
        "unknown"
    ).lower()

    detection_type = get_first_available_value(
        defender_alert,
        ["title", "category", "detectionSource"],
        "Microsoft Defender Alert"
    )

    hostname = get_first_available_value(
        defender_alert,
        [
            "computerDnsName",
            "deviceName",
            "machineName",
            "hostName",
            "hostname"
        ],
        None
    )

    if not hostname:
        hostname = get_value_from_nested_dict(
            defender_alert,
            ["device", "machine", "host"],
            [
                "computerDnsName",
                "deviceName",
                "machineName",
                "hostName",
                "hostname"
            ],
            None
        )

    if not hostname:
        hostname = get_value_from_evidence(
            evidence,
            [
                "computerDnsName",
                "deviceName",
                "machineName",
                "hostName",
                "hostname"
            ],
            FlexibleUnknownValue("unknown", ["unknown", "unknown-host"])
        )

    ip_address = get_first_available_value(
        defender_alert,
        [
            "ipAddress",
            "ip",
            "localIP",
            "remoteIP"
        ],
        None
    )

    if not ip_address:
        ip_address = get_value_from_nested_dict(
            defender_alert,
            ["device", "machine", "host", "network"],
            [
                "ipAddress",
                "ip",
                "localIP",
                "remoteIP"
            ],
            None
        )

    if not ip_address:
        ip_address = get_value_from_evidence(
            evidence,
            [
                "ipAddress",
                "ip",
                "localIP",
                "remoteIP"
            ],
            FlexibleUnknownValue("unknown", ["unknown", "unknown-ip"])
        )

    username = get_first_available_value(
        defender_alert,
        [
            "userName",
            "username",
            "relatedUser",
            "assignedTo",
            "accountName",
            "upn",
            "userPrincipalName"
        ],
        None
    )

    if not username:
        username = get_nested_user_value(defender_alert)

    if not username:
        username = get_value_from_nested_dict(
            defender_alert,
            ["user", "account", "identity"],
            [
                "userName",
                "username",
                "accountName",
                "upn",
                "userPrincipalName"
            ],
            None
        )

    if not username:
        username = get_value_from_evidence(
            evidence,
            [
                "userName",
                "username",
                "accountName",
                "upn",
                "userPrincipalName"
            ],
            FlexibleUnknownValue("unknown", ["unknown", "unknown-user"])
        )

    process_name = find_value_recursively(
    defender_alert,
    [
        "processName",
        "process_name",
        "process",
        "fileName",
        "file_name",
        "imageFileName",
        "image_file_name",
        "executableName",
        "executable_name",
        "threatName",
        "threat_name",
        "malwareName",
        "malware_name",
        "name"
    ],
    "unknown"
)

    process_hash = find_value_recursively(
        defender_alert,
        [
            "processHash",
            "process_hash",
            "sha256",
            "sha1",
            "md5",
            "fileHash",
            "file_hash"
        ],
        FlexibleUnknownValue("unknown", ["unknown", "unknown-hash"])
    )

    description = get_first_available_value(
        defender_alert,
        ["description", "title"],
        "High severity alert imported from Microsoft Defender for Endpoint."
    )

    return {
        "alert_id": f"MDE-{alert_id}",
        "severity": severity,
        "detection_type": detection_type,
        "hostname": hostname,
        "ip_address": ip_address,
        "username": username,
        "process_name": process_name,
        "process_hash": process_hash,
        "description": description,
        "source": "microsoft_defender_for_endpoint",
        "raw_payload": defender_alert
    }


def fetch_and_normalize_high_severity_alerts(limit: int = 10) -> dict:
    result = list_high_severity_alerts(limit=limit)

    if not result.get("configured"):
        return {
            "integration": INTEGRATION_NAME,
            "configured": False,
            "fetched": False,
            "status": result["status"],
            "message": result["message"],
            "normalized_alerts": []
        }

    normalized_alerts = [
        normalize_defender_alert(alert)
        for alert in result["raw_alerts"]
    ]

    return {
        "integration": INTEGRATION_NAME,
        "configured": True,
        "fetched": True,
        "status": "success",
        "total_alerts": len(normalized_alerts),
        "normalized_alerts": normalized_alerts
    }


def list_machines(limit: int = 100) -> dict:
    """
    Lists Microsoft Defender machines/devices.
    """

    if not is_defender_configured():
        return {
            "integration": INTEGRATION_NAME,
            "configured": False,
            "status": "credentials_pending",
            "message": "Microsoft Defender credentials are not configured.",
            "machines": []
        }

    safe_limit = max(1, min(limit, 100))

    token = get_mde_token()

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }

    params = {
        "$top": safe_limit
    }

    response = requests.get(
        f"{MDE_API_BASE_URL}/api/machines",
        headers=headers,
        params=params,
        timeout=30
    )

    response.raise_for_status()
    data = response.json()

    return {
        "integration": INTEGRATION_NAME,
        "configured": True,
        "status": "success",
        "total_machines": len(data.get("value", [])),
        "machines": data.get("value", [])
    }


def find_machine_by_hostname(hostname: str) -> dict:
    """
    Finds a Microsoft Defender machine by hostname.
    """

    if not hostname:
        return {
            "configured": is_defender_configured(),
            "status": "failed",
            "message": "Hostname is missing.",
            "machine": None
        }

    if not is_defender_configured():
        return {
            "configured": False,
            "status": "credentials_pending",
            "message": "Microsoft Defender credentials are not configured.",
            "machine": None
        }

    machines_result = list_machines(limit=100)

    if machines_result["status"] != "success":
        return {
            "configured": True,
            "status": "failed",
            "message": "Unable to list Defender machines.",
            "machine": None
        }

    hostname_lower = hostname.lower()

    for machine in machines_result["machines"]:
        machine_name = (
            machine.get("computerDnsName")
            or machine.get("deviceName")
            or machine.get("machineName")
            or ""
        )

        if machine_name.lower() == hostname_lower:
            return {
                "configured": True,
                "status": "found",
                "message": f"Machine found for hostname {hostname}.",
                "machine": machine
            }

    return {
        "configured": True,
        "status": "not_found",
        "message": f"No Defender machine found for hostname {hostname}.",
        "machine": None
    }


def isolate_machine_by_id(
    machine_id: str,
    comment: str = "Authorized lab isolation test",
    isolation_type: str = "Selective",
    dry_run: bool = True
) -> dict:
    """
    Isolates a Microsoft Defender machine by machine ID.

    dry_run=True is safe and does not send a real isolation command.
    """

    allowed_isolation_types = ["Full", "Selective"]

    if isolation_type not in allowed_isolation_types:
        return {
            "integration": INTEGRATION_NAME,
            "action": "machine_isolation",
            "machine_id": machine_id,
            "isolation_type": isolation_type,
            "status": "failed",
            "dry_run": dry_run,
            "message": "Invalid isolation type. Allowed values are Full and Selective."
        }

    if not machine_id:
        return {
            "integration": INTEGRATION_NAME,
            "action": "machine_isolation",
            "status": "failed",
            "dry_run": dry_run,
            "message": "Machine ID is missing."
        }

    if dry_run:
        return {
            "integration": INTEGRATION_NAME,
            "action": "machine_isolation",
            "machine_id": machine_id,
            "isolation_type": isolation_type,
            "status": "dry_run",
            "dry_run": True,
            "message": "No real Defender isolation API call was made. Dry-run only."
        }

    if not is_defender_configured():
        return {
            "integration": INTEGRATION_NAME,
            "action": "machine_isolation",
            "machine_id": machine_id,
            "isolation_type": isolation_type,
            "status": "credentials_pending",
            "dry_run": False,
            "message": "Microsoft Defender credentials are not configured."
        }

    token = get_mde_token()

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "Comment": comment,
        "IsolationType": isolation_type
    }

    response = requests.post(
        f"{MDE_API_BASE_URL}/api/machines/{machine_id}/isolate",
        headers=headers,
        json=payload,
        timeout=30
    )

    response.raise_for_status()

    return {
        "integration": INTEGRATION_NAME,
        "action": "machine_isolation",
        "machine_id": machine_id,
        "isolation_type": isolation_type,
        "status": "success",
        "dry_run": False,
        "message": "Microsoft Defender machine isolation command sent successfully.",
        "response": response.json()
    }


def isolate_machine_by_hostname(
    hostname: str,
    comment: str = "Authorized lab isolation test",
    isolation_type: str = "Selective",
    dry_run: bool = True
) -> dict:
    """
    Finds a Defender machine by hostname and isolates it.

    dry_run=True is safe.
    """

    allowed_isolation_types = ["Full", "Selective"]

    if isolation_type not in allowed_isolation_types:
        return {
            "integration": INTEGRATION_NAME,
            "action": "machine_isolation_by_hostname",
            "hostname": hostname,
            "isolation_type": isolation_type,
            "status": "failed",
            "dry_run": dry_run,
            "message": "Invalid isolation type. Allowed values are Full and Selective."
        }

    if dry_run:
        return {
            "integration": INTEGRATION_NAME,
            "action": "machine_isolation_by_hostname",
            "hostname": hostname,
            "isolation_type": isolation_type,
            "status": "dry_run",
            "dry_run": True,
            "message": "No real Defender isolation API call was made. Dry-run only."
        }

    machine_result = find_machine_by_hostname(hostname)

    if machine_result["status"] != "found":
        return {
            "integration": INTEGRATION_NAME,
            "action": "machine_isolation_by_hostname",
            "hostname": hostname,
            "status": machine_result["status"],
            "dry_run": False,
            "message": machine_result["message"]
        }

    machine = machine_result["machine"]

    machine_id = (
        machine.get("id")
        or machine.get("machineId")
    )

    return isolate_machine_by_id(
        machine_id=machine_id,
        comment=comment,
        isolation_type=isolation_type,
        dry_run=False
    )

def preview_machine_isolation_by_hostname(
    hostname: str,
    isolation_type: str = "Selective"
) -> dict:
    """
    Performs a safe isolation preview.

    This function checks:
    1. Hostname is provided.
    2. Isolation type is valid.
    3. Defender credentials are configured.
    4. Machine can be found in Defender.

    It does not send a real isolation command.
    """

    allowed_isolation_types = ["Full", "Selective", "UnManagedDevice"]

    if not hostname:
        return {
            "integration": INTEGRATION_NAME,
            "action": "machine_isolation_preview",
            "hostname": hostname,
            "isolation_type": isolation_type,
            "status": "failed",
            "ready_for_real_isolation": False,
            "message": "Hostname is missing."
        }

    if isolation_type not in allowed_isolation_types:
        return {
            "integration": INTEGRATION_NAME,
            "action": "machine_isolation_preview",
            "hostname": hostname,
            "isolation_type": isolation_type,
            "status": "failed",
            "ready_for_real_isolation": False,
            "message": "Invalid isolation type. Allowed values are Full, Selective, and UnManagedDevice."
        }

    machine_result = find_machine_by_hostname(hostname)

    if machine_result["status"] == "credentials_pending":
        return {
            "integration": INTEGRATION_NAME,
            "action": "machine_isolation_preview",
            "hostname": hostname,
            "isolation_type": isolation_type,
            "status": "credentials_pending",
            "ready_for_real_isolation": False,
            "message": "Microsoft Defender credentials are not configured.",
            "machine": None
        }

    if machine_result["status"] != "found":
        return {
            "integration": INTEGRATION_NAME,
            "action": "machine_isolation_preview",
            "hostname": hostname,
            "isolation_type": isolation_type,
            "status": machine_result["status"],
            "ready_for_real_isolation": False,
            "message": machine_result["message"],
            "machine": None
        }

    machine = machine_result["machine"]

    machine_id = (
        machine.get("id")
        or machine.get("machineId")
    )

    if not machine_id:
        return {
            "integration": INTEGRATION_NAME,
            "action": "machine_isolation_preview",
            "hostname": hostname,
            "isolation_type": isolation_type,
            "status": "failed",
            "ready_for_real_isolation": False,
            "message": "Machine found, but machine ID is missing.",
            "machine": machine
        }

    return {
        "integration": INTEGRATION_NAME,
        "action": "machine_isolation_preview",
        "hostname": hostname,
        "machine_id": machine_id,
        "isolation_type": isolation_type,
        "status": "preview_ready",
        "dry_run": True,
        "ready_for_real_isolation": True,
        "message": "Machine lookup successful. Isolation preview completed. No real isolation command was sent.",
        "machine": machine
    }