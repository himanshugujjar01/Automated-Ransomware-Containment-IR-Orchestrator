from datetime import datetime
from app.services.threat_intelligence import (
    bulk_import,
    get_all_iocs,
)

# Simulated external IOC feed
EXTERNAL_IOC_FEED = [
    {
        "ioc_type": "ip",
        "value": "103.45.67.89",
        "severity": "Critical",
        "category": "Botnet",
        "source": "External Feed",
        "description": "Known botnet C2 server",
        "created_at": datetime.now().isoformat(),
    },
    {
        "ioc_type": "domain",
        "value": "malicious-update.com",
        "severity": "High",
        "category": "Phishing",
        "source": "External Feed",
        "description": "Known phishing domain",
        "created_at": datetime.now().isoformat(),
    },
]


def fetch_ioc_feed():
    """
    Simulate downloading an IOC feed.
    """
    return EXTERNAL_IOC_FEED


def synchronize_ioc_feed():
    """
    Import new IOCs into the local database.
    """
    feed = fetch_ioc_feed()
    added = bulk_import(feed)

    return {
        "feed_size": len(feed),
        "added": added,
        "total_iocs": len(get_all_iocs()),
        "last_sync": datetime.now().isoformat(),
    }