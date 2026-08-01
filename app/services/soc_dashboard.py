from datetime import datetime
from collections import Counter

MITRE_ATTACK_MAP = {

    "Ransomware": {
        "tactic": "Impact",
        "technique_id": "T1486",
        "technique": "Data Encrypted for Impact"
    },

    "PowerShell Abuse": {
        "tactic": "Execution",
        "technique_id": "T1059.001",
        "technique": "PowerShell"
    },

    "Credential Dumping": {
        "tactic": "Credential Access",
        "technique_id": "T1003",
        "technique": "OS Credential Dumping"
    },

    "Suspicious Login": {
        "tactic": "Initial Access",
        "technique_id": "T1078",
        "technique": "Valid Accounts"
    },

    "Data Encryption": {
        "tactic": "Impact",
        "technique_id": "T1486",
        "technique": "Data Encrypted for Impact"
    }
}

INCIDENTS = [

    {
        "alert_id": "ALERT-1001",
        "hostname": "LAB-PC-01",
        "username": "john.doe",
        "ip": "192.168.1.15",
        "severity": "Critical",
        "status": "Open",
        "ticket": "INC-1001",
        "contained": True,
        "attack": "Ransomware",
        "created_at": datetime.now().isoformat()
    },

    {
        "alert_id": "ALERT-1002",
        "hostname": "LAB-PC-02",
        "username": "alice",
        "ip": "192.168.1.16",
        "severity": "High",
        "status": "Open",
        "ticket": "INC-1002",
        "contained": True,
        "attack": "PowerShell Abuse",
        "created_at": datetime.now().isoformat()
    },

    {
        "alert_id": "ALERT-1003",
        "hostname": "FINANCE-PC",
        "username": "finance.user",
        "ip": "192.168.1.25",
        "severity": "Medium",
        "status": "Closed",
        "ticket": "INC-1003",
        "contained": False,
        "attack": "Credential Dumping",
        "created_at": datetime.now().isoformat()
    },

    {
        "alert_id": "ALERT-1004",
        "hostname": "HR-PC",
        "username": "hr.admin",
        "ip": "192.168.1.35",
        "severity": "Low",
        "status": "Closed",
        "ticket": "INC-1004",
        "contained": False,
        "attack": "Suspicious Login",
        "created_at": datetime.now().isoformat()
    },

    {
        "alert_id": "ALERT-1005",
        "hostname": "DEV-SERVER",
        "username": "developer",
        "ip": "10.0.0.5",
        "severity": "Critical",
        "status": "Open",
        "ticket": "INC-1005",
        "contained": True,
        "attack": "Data Encryption",
        "created_at": datetime.now().isoformat()
    }

]

def get_all_incidents():

    return INCIDENTS

def build_soc_dashboard():

    incidents = get_all_incidents()

    total = len(incidents)

    critical = sum(1 for i in incidents if i["severity"] == "Critical")
    high = sum(1 for i in incidents if i["severity"] == "High")
    medium = sum(1 for i in incidents if i["severity"] == "Medium")
    low = sum(1 for i in incidents if i["severity"] == "Low")

    open_incidents = sum(1 for i in incidents if i["status"] == "Open")
    closed_incidents = sum(1 for i in incidents if i["status"] == "Closed")

    contained = sum(1 for i in incidents if i["contained"])
    active = total - contained

    return {

        "total_incidents": total,

        "critical": critical,

        "high": high,

        "medium": medium,

        "low": low,

        "open": open_incidents,

        "closed": closed_incidents,

        "contained_hosts": contained,

        "active_hosts": active,

        "incidents": incidents,

        "severity_distribution": build_severity_distribution(),

        "ticket_statistics": build_ticket_statistics(),

        "attack_distribution": build_attack_distribution(),

        "top_hosts": build_top_hosts(),

        "mitre_mapping": build_mitre_mapping(),

        "last_updated": datetime.now().isoformat()

    }


def build_severity_distribution():

    incidents = get_all_incidents()

    return {
        "Critical": sum(i["severity"] == "Critical" for i in incidents),
        "High": sum(i["severity"] == "High" for i in incidents),
        "Medium": sum(i["severity"] == "Medium" for i in incidents),
        "Low": sum(i["severity"] == "Low" for i in incidents)
    }

def build_ticket_statistics():

    incidents = get_all_incidents()

    return {

        "open": sum(i["status"] == "Open" for i in incidents),

        "closed": sum(i["status"] == "Closed" for i in incidents),

        "total": len(incidents)

    }

def build_attack_distribution():

    incidents = get_all_incidents()

    attacks = Counter(i["attack"] for i in incidents)

    return dict(attacks)

def build_top_hosts():

    incidents = get_all_incidents()

    hosts = Counter(i["hostname"] for i in incidents)

    return dict(hosts)

def search_incidents(
    alert_id: str = None,
    hostname: str = None,
    username: str = None,
    ip: str = None,
    severity: str = None,
    attack: str = None
):

    incidents = get_all_incidents()

    results = incidents

    if alert_id:
        results = [
            i for i in results
            if i["alert_id"].lower() == alert_id.lower()
        ]

    if hostname:
        results = [
            i for i in results
            if hostname.lower() in i["hostname"].lower()
        ]

    if username:
        results = [
            i for i in results
            if username.lower() in i["username"].lower()
        ]

    if ip:
        results = [
            i for i in results
            if ip == i["ip"]
        ]

    if severity:
        results = [
            i for i in results
            if severity.lower() == i["severity"].lower()
        ]

    if attack:
        results = [
            i for i in results
            if attack.lower() in i["attack"].lower()
        ]

    return results

def filter_incidents(
    severity: str = None,
    status: str = None,
    contained: bool = None,
    attack: str = None,
    username: str = None,
    hostname: str = None
):

    incidents = get_all_incidents()

    results = incidents

    if severity:

        results = [
            i for i in results
            if i["severity"].lower() == severity.lower()
        ]

    if status:

        results = [
            i for i in results
            if i["status"].lower() == status.lower()
        ]

    if contained is not None:

        results = [
            i for i in results
            if i["contained"] == contained
        ]

    if attack:

        results = [
            i for i in results
            if attack.lower() in i["attack"].lower()
        ]

    if username:

        results = [
            i for i in results
            if username.lower() in i["username"].lower()
        ]

    if hostname:

        results = [
            i for i in results
            if hostname.lower() in i["hostname"].lower()
        ]

    return results

def build_mitre_mapping():

    incidents = get_all_incidents()

    enriched = []

    for incident in incidents:

        attack = incident["attack"]

        mapping = MITRE_ATTACK_MAP.get(
            attack,
            {
                "tactic": "Unknown",
                "technique_id": "N/A",
                "technique": "Unknown"
            }
        )

        item = incident.copy()

        item["mitre"] = mapping

        enriched.append(item)

    return enriched