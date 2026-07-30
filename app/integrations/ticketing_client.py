from datetime import datetime, timezone
import uuid
import requests

from app.config import (
    USE_REAL_TICKETING,
    TICKETING_PROVIDER,
    JIRA_BASE_URL,
    JIRA_EMAIL,
    JIRA_API_TOKEN,
    JIRA_PROJECT_KEY,
    SERVICENOW_INSTANCE_URL,
    SERVICENOW_USERNAME,
    SERVICENOW_PASSWORD,
    SERVICENOW_API_PATH
)


INTEGRATION_NAME = "Incident Ticketing"


def is_placeholder(value: str) -> bool:
    return not value or str(value).strip() == "" or value == "change_me"


def is_jira_configured() -> bool:
    return not any([
        is_placeholder(JIRA_BASE_URL),
        is_placeholder(JIRA_EMAIL),
        is_placeholder(JIRA_API_TOKEN),
        is_placeholder(JIRA_PROJECT_KEY)
    ])


def is_servicenow_configured() -> bool:
    return not any([
        is_placeholder(SERVICENOW_INSTANCE_URL),
        is_placeholder(SERVICENOW_USERNAME),
        is_placeholder(SERVICENOW_PASSWORD)
    ])


def get_ticketing_status() -> dict:
    return {
        "integration": INTEGRATION_NAME,
        "enabled": USE_REAL_TICKETING,
        "provider": TICKETING_PROVIDER,
        "safe_mode": True,
        "jira": {
            "configured": is_jira_configured(),
            "base_url": JIRA_BASE_URL,
            "project_key": JIRA_PROJECT_KEY,
            "status": "ready" if is_jira_configured() else "credentials_pending"
        },
        "servicenow": {
            "configured": is_servicenow_configured(),
            "instance_url": SERVICENOW_INSTANCE_URL,
            "api_path": SERVICENOW_API_PATH,
            "status": "ready" if is_servicenow_configured() else "credentials_pending"
        },
        "status": "ready" if is_jira_configured() or is_servicenow_configured() else "credentials_pending",
        "message": "Ticketing configuration checked successfully."
    }


def build_incident_summary(alert_data: dict) -> str:
    alert_id = alert_data.get("alert_id", "unknown-alert")
    hostname = alert_data.get("hostname", "unknown-host")
    severity = alert_data.get("severity", "unknown")

    return f"[{severity.upper()}] Ransomware IR Alert {alert_id} on {hostname}"


def build_incident_description(
    alert_data: dict,
    actions: list | None = None,
    artifacts: list | None = None
) -> str:
    actions = actions or []
    artifacts = artifacts or []

    lines = [
        "Automated Ransomware Incident Response Ticket",
        "",
        f"Alert ID: {alert_data.get('alert_id', 'unknown')}",
        f"Severity: {alert_data.get('severity', 'unknown')}",
        f"Detection Type: {alert_data.get('detection_type', 'unknown')}",
        f"Hostname: {alert_data.get('hostname', 'unknown')}",
        f"IP Address: {alert_data.get('ip_address', 'unknown')}",
        f"Username: {alert_data.get('username', 'unknown')}",
        f"Process Name: {alert_data.get('process_name', 'unknown')}",
        f"Process Hash: {alert_data.get('process_hash', 'unknown')}",
        f"Description: {alert_data.get('description', 'No description provided.')}",
        "",
        "Containment Actions:"
    ]

    if actions:
        for action in actions:
            lines.append(
                f"- {action.get('action_type', 'unknown')} | "
                f"Target: {action.get('target', 'unknown')} | "
                f"Status: {action.get('status', 'unknown')}"
            )
    else:
        lines.append("- No actions logged yet.")

    lines.append("")
    lines.append("Forensic Artifacts:")

    if artifacts:
        for artifact in artifacts:
            lines.append(
                f"- {artifact.get('artifact_type', 'artifact')} | "
                f"{artifact.get('storage_path', artifact.get('file_path', 'unknown'))}"
            )
    else:
        lines.append("- No artifacts attached yet.")

    lines.append("")
    lines.append(f"Generated At UTC: {datetime.now(timezone.utc).isoformat()}")

    return "\n".join(lines)


def map_priority(severity: str) -> str:
    severity_lower = str(severity).lower()

    if severity_lower in ["critical", "high"]:
        return "High"

    if severity_lower == "medium":
        return "Medium"

    return "Low"


def build_ticket_payload(
    alert_data: dict,
    actions: list | None = None,
    artifacts: list | None = None
) -> dict:
    return {
        "summary": build_incident_summary(alert_data),
        "description": build_incident_description(
            alert_data=alert_data,
            actions=actions,
            artifacts=artifacts
        ),
        "priority": map_priority(alert_data.get("severity", "unknown")),
        "alert_id": alert_data.get("alert_id", "unknown-alert"),
        "hostname": alert_data.get("hostname", "unknown-host"),
        "username": alert_data.get("username", "unknown-user")
    }


def create_mock_ticket(
    alert_data: dict,
    actions: list | None = None,
    artifacts: list | None = None
) -> dict:
    payload = build_ticket_payload(
        alert_data=alert_data,
        actions=actions,
        artifacts=artifacts
    )

    ticket_id = f"MOCK-IR-{uuid.uuid4().hex[:8].upper()}"

    return {
        "integration": INTEGRATION_NAME,
        "provider": "mock",
        "workflow": "incident_ticket_creation",
        "status": "mock_created",
        "real_action_sent": False,
        "ticket_id": ticket_id,
        "ticket_url": None,
        "payload": payload,
        "message": "Mock incident ticket created safely. No real Jira or ServiceNow ticket was created."
    }


def create_jira_ticket(
    alert_data: dict,
    actions: list | None = None,
    artifacts: list | None = None
) -> dict:
    payload = build_ticket_payload(
        alert_data=alert_data,
        actions=actions,
        artifacts=artifacts
    )

    jira_url = JIRA_BASE_URL.rstrip("/") + "/rest/api/3/issue"

    jira_body = {
        "fields": {
            "project": {
                "key": JIRA_PROJECT_KEY
            },
            "summary": payload["summary"],
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": payload["description"]
                            }
                        ]
                    }
                ]
            },
            "issuetype": {
                "name": "Task"
            },
            "priority": {
                "name": payload["priority"]
            }
        }
    }

    try:
        response = requests.post(
            jira_url,
            auth=(JIRA_EMAIL, JIRA_API_TOKEN),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json"
            },
            json=jira_body,
            timeout=30
        )

        response.raise_for_status()
        response_data = response.json()

        ticket_id = response_data.get("key", response_data.get("id"))

        return {
            "integration": INTEGRATION_NAME,
            "provider": "jira",
            "workflow": "incident_ticket_creation",
            "status": "success",
            "real_action_sent": True,
            "ticket_id": ticket_id,
            "ticket_url": f"{JIRA_BASE_URL.rstrip('/')}/browse/{ticket_id}" if ticket_id else None,
            "payload": payload,
            "response": response_data,
            "message": "Jira incident ticket created successfully."
        }

    except Exception as error:
        return {
            "integration": INTEGRATION_NAME,
            "provider": "jira",
            "workflow": "incident_ticket_creation",
            "status": "failed",
            "real_action_sent": False,
            "ticket_id": None,
            "ticket_url": None,
            "payload": payload,
            "message": str(error)
        }


def create_servicenow_ticket(
    alert_data: dict,
    actions: list | None = None,
    artifacts: list | None = None
) -> dict:
    payload = build_ticket_payload(
        alert_data=alert_data,
        actions=actions,
        artifacts=artifacts
    )

    servicenow_url = SERVICENOW_INSTANCE_URL.rstrip("/") + SERVICENOW_API_PATH

    servicenow_body = {
        "short_description": payload["summary"],
        "description": payload["description"],
        "urgency": "1" if payload["priority"] == "High" else "2",
        "impact": "1" if payload["priority"] == "High" else "2",
        "category": "security",
        "subcategory": "ransomware"
    }

    try:
        response = requests.post(
            servicenow_url,
            auth=(SERVICENOW_USERNAME, SERVICENOW_PASSWORD),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json"
            },
            json=servicenow_body,
            timeout=30
        )

        response.raise_for_status()
        response_data = response.json()
        result = response_data.get("result", {})

        ticket_id = (
            result.get("number")
            or result.get("sys_id")
        )

        return {
            "integration": INTEGRATION_NAME,
            "provider": "servicenow",
            "workflow": "incident_ticket_creation",
            "status": "success",
            "real_action_sent": True,
            "ticket_id": ticket_id,
            "ticket_url": None,
            "payload": payload,
            "response": response_data,
            "message": "ServiceNow incident ticket created successfully."
        }

    except Exception as error:
        return {
            "integration": INTEGRATION_NAME,
            "provider": "servicenow",
            "workflow": "incident_ticket_creation",
            "status": "failed",
            "real_action_sent": False,
            "ticket_id": None,
            "ticket_url": None,
            "payload": payload,
            "message": str(error)
        }


def create_incident_ticket(
    alert_data: dict,
    actions: list | None = None,
    artifacts: list | None = None,
    provider: str | None = None,
    execute_real: bool = False
) -> dict:
    selected_provider = provider or TICKETING_PROVIDER

    if not execute_real:
        return create_mock_ticket(
            alert_data=alert_data,
            actions=actions,
            artifacts=artifacts
        )

    if not USE_REAL_TICKETING:
        return {
            "integration": INTEGRATION_NAME,
            "provider": selected_provider,
            "workflow": "incident_ticket_creation",
            "status": "blocked",
            "real_action_sent": False,
            "ticket_id": None,
            "ticket_url": None,
            "payload": build_ticket_payload(alert_data, actions, artifacts),
            "message": "USE_REAL_TICKETING is false. Real ticket creation is disabled."
        }

    if selected_provider == "jira":
        if not is_jira_configured():
            return {
                "integration": INTEGRATION_NAME,
                "provider": "jira",
                "workflow": "incident_ticket_creation",
                "status": "credentials_pending",
                "real_action_sent": False,
                "ticket_id": None,
                "ticket_url": None,
                "payload": build_ticket_payload(alert_data, actions, artifacts),
                "message": "Jira credentials are not configured."
            }

        return create_jira_ticket(
            alert_data=alert_data,
            actions=actions,
            artifacts=artifacts
        )

    if selected_provider == "servicenow":
        if not is_servicenow_configured():
            return {
                "integration": INTEGRATION_NAME,
                "provider": "servicenow",
                "workflow": "incident_ticket_creation",
                "status": "credentials_pending",
                "real_action_sent": False,
                "ticket_id": None,
                "ticket_url": None,
                "payload": build_ticket_payload(alert_data, actions, artifacts),
                "message": "ServiceNow credentials are not configured."
            }

        return create_servicenow_ticket(
            alert_data=alert_data,
            actions=actions,
            artifacts=artifacts
        )

    return {
        "integration": INTEGRATION_NAME,
        "provider": selected_provider,
        "workflow": "incident_ticket_creation",
        "status": "failed",
        "real_action_sent": False,
        "ticket_id": None,
        "ticket_url": None,
        "payload": build_ticket_payload(alert_data, actions, artifacts),
        "message": "Invalid ticketing provider. Use mock, jira, or servicenow."
    }