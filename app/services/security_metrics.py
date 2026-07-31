from datetime import datetime


def build_security_metrics():
    return {
        "generated_at": datetime.now().isoformat(),

        "alerts": {
            "total": 127,
            "critical": 7,
            "high": 18,
            "medium": 42,
            "low": 60
        },

        "containment": {
            "attempted": 18,
            "successful": 17,
            "failed": 1
        },

        "forensics": {
            "volatility": 14,
            "kape": 13
        },

        "ticketing": {
            "created": 21,
            "closed": 16
        },

        "notifications": {
            "slack": 20,
            "teams": 20
        },

        "evidence": {
            "uploaded": 16,
            "failed": 0
        }
    }