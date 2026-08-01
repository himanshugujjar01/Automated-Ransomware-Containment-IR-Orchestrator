from app.services.dashboard_service import build_dashboard_timeline
from app.services.security_metrics import build_security_metrics


def build_incident_summary(alert_id: str):

    timeline = build_dashboard_timeline(alert_id)

    metrics = build_security_metrics()

    return {

        "alert_id": alert_id,

        "summary": {

            "severity": "high",

            "status": "contained",

            "response": "Automatic",

            "ticket_created": True,

            "host_isolated": True,

            "memory_collected": True,

            "evidence_uploaded": True,

            "slack_notified": True,

            "teams_notified": True

        },

        "timeline": timeline["timeline"],

        "metrics": metrics

    }