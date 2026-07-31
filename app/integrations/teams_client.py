import requests
from datetime import datetime, timezone

from app.config import (
    ENABLE_TEAMS_ALERTS,
    USE_REAL_TEAMS,
    TEAMS_WEBHOOK_URL
)

INTEGRATION_NAME = "Microsoft Teams"


def is_placeholder(value: str):
    return (
        value is None
        or value.strip() == ""
        or value == "change_me"
    )


def get_teams_status():

    configured = not is_placeholder(
        TEAMS_WEBHOOK_URL
    )

    return {

        "integration": INTEGRATION_NAME,

        "enabled": ENABLE_TEAMS_ALERTS,

        "use_real": USE_REAL_TEAMS,

        "configured": configured,

        "status":
            "ready"
            if configured
            else "credentials_pending"
    }


def build_message(alert):

    return (
        "🚨 Ransomware Alert\n\n"

        f"Alert ID : {alert.get('alert_id')}\n"

        f"Severity : {alert.get('severity')}\n"

        f"Hostname : {alert.get('hostname')}\n"

        f"Username : {alert.get('username')}\n"

        f"Process : {alert.get('process_name')}\n"

        f"SHA256 : {alert.get('process_hash')}\n"

        f"Time : {datetime.now(timezone.utc)}"
    )


def create_mock_response(alert):

    return {

        "integration": INTEGRATION_NAME,

        "status": "mock_sent",

        "real_action_sent": False,

        "message": build_message(alert)
    }


def send_teams_alert(alert):

    if not ENABLE_TEAMS_ALERTS:

        return {

            "integration": INTEGRATION_NAME,

            "status": "disabled"
        }

    if not USE_REAL_TEAMS:

        return create_mock_response(alert)

    if is_placeholder(TEAMS_WEBHOOK_URL):

        return {

            "integration": INTEGRATION_NAME,

            "status": "credentials_pending"
        }

    payload = {

        "text": build_message(alert)
    }

    try:

        response = requests.post(

            TEAMS_WEBHOOK_URL,

            json=payload,

            timeout=20
        )

        response.raise_for_status()

        return {

            "integration": INTEGRATION_NAME,

            "status": "sent",

            "http_status": response.status_code,

            "real_action_sent": True
        }

    except Exception as ex:

        return {

            "integration": INTEGRATION_NAME,

            "status": "failed",

            "reason": str(ex),

            "real_action_sent": False
        }