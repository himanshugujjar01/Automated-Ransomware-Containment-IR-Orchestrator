from datetime import datetime


def build_executive_dashboard():
    return {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "total_alerts": 125,
            "critical": 8,
            "high": 24,
            "medium": 47,
            "low": 46,
            "contained_hosts": 17,
            "tickets_created": 21,
            "slack_notifications": 18,
            "teams_notifications": 18,
            "evidence_uploaded": 16,
            "forensics_completed": 15,
            "simulations": 9
        },
        "status": "healthy"
    }

def build_incident_timeline(alert_id: str):
    """
    Build a chronological incident timeline.
    """

    now = datetime.now().strftime("%Y-%m-%d")

    return {
        "alert_id": alert_id,
        "timeline": [
            {
                "time": f"{now} 09:00",
                "event": "Alert Received",
                "status": "completed"
            },
            {
                "time": f"{now} 09:01",
                "event": "IOC Extraction",
                "status": "completed"
            },
            {
                "time": f"{now} 09:02",
                "event": "Host Isolation",
                "status": "completed"
            },
            {
                "time": f"{now} 09:03",
                "event": "Ticket Created",
                "status": "completed"
            },
            {
                "time": f"{now} 09:04",
                "event": "Slack Notification",
                "status": "completed"
            },
            {
                "time": f"{now} 09:05",
                "event": "Teams Notification",
                "status": "completed"
            },
            {
                "time": f"{now} 09:06",
                "event": "Evidence Uploaded",
                "status": "completed"
            },
            {
                "time": f"{now} 09:07",
                "event": "Memory Collection",
                "status": "completed"
            },
            {
                "time": f"{now} 09:08",
                "event": "Simulation Completed",
                "status": "completed"
            },
            {
                "time": f"{now} 09:09",
                "event": "Incident Closed",
                "status": "completed"
            }
        ]
    }