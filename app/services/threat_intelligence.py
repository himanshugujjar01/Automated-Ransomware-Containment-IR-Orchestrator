from datetime import datetime
from collections import Counter
from app.services.soc_dashboard import get_all_incidents
import json
import csv
from pathlib import Path

IP_REPUTATION_DB = {

    "192.168.1.15": {
        "reputation": "Malicious",
        "score": 98,
        "category": "Ransomware C2",
        "description": "Known ransomware command-and-control server"
    },

    "192.168.1.16": {
        "reputation": "Suspicious",
        "score": 72,
        "category": "PowerShell Abuse",
        "description": "Associated with malicious PowerShell activity"
    },

    "192.168.1.25": {
        "reputation": "Suspicious",
        "score": 65,
        "category": "Credential Theft",
        "description": "Observed in credential dumping campaigns"
    }

}

DOMAIN_REPUTATION_DB = {

    "evil-domain.com": {
        "risk": "Critical",
        "reputation_score": 100,
        "category": "Phishing",
        "source": "VirusTotal",
        "description": "Credential harvesting website"
    },

    "malware-download.net": {
        "risk": "High",
        "reputation_score": 85,
        "category": "Malware Distribution",
        "source": "AlienVault OTX",
        "description": "Hosts known malware payloads"
    },

    "fakebank-login.org": {
        "risk": "Critical",
        "reputation_score": 98,
        "category": "Banking Phishing",
        "source": "Google Safe Browsing",
        "description": "Fake banking login portal"
    }

}

HASH_REPUTATION_DB = {

    "5d41402abc4b2a76b9719d911017c592": {
        "hash_type": "MD5",
        "risk": "Medium",
        "reputation_score": 60,
        "category": "Trojan",
        "source": "Hybrid Analysis",
        "description": "Known Trojan executable"
    },

    "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed": {
        "hash_type": "SHA1",
        "risk": "High",
        "reputation_score": 85,
        "category": "Backdoor",
        "source": "VirusTotal",
        "description": "Known backdoor sample"
    },

    "5d41402abc4b2a76b9719d911017c5926c4c8d0d89e74e8f2f4b3f8b8f8b8f8b": {
        "hash_type": "SHA256",
        "risk": "Critical",
        "reputation_score": 100,
        "category": "Ransomware",
        "source": "MISP",
        "description": "Known ransomware sample"
    }

}

def check_ip_reputation(ip: str):

    if ip == "185.220.101.1":
        return {
            "found": True,
            "risk": "Critical",
            "reputation_score": 100,
            "category": "Command and Control",
            "description": "Known ransomware command-and-control server"
        }

    if ip == "45.155.205.233":
        return {
            "found": True,
            "risk": "High",
            "reputation_score": 80,
            "category": "Malware",
            "description": "Known malware distribution server"
        }

    return {
        "found": False,
        "risk": "Clean",
        "reputation_score": 0,
        "category": "None",
        "description": "No known malicious activity"
    }

def check_domain_reputation(domain: str):

    domain = domain.lower().strip()

    if domain in DOMAIN_REPUTATION_DB:

        result = DOMAIN_REPUTATION_DB[domain].copy()

        result["found"] = True
        result["domain"] = domain

        return result

    return {

        "found": False,
        "domain": domain,
        "risk": "Clean",
        "reputation_score": 0,
        "category": "None",
        "source": None,
        "description": "No known malicious activity"

    }

def check_hash_reputation(file_hash: str):

    file_hash = file_hash.lower().strip()

    if file_hash in HASH_REPUTATION_DB:

        result = HASH_REPUTATION_DB[file_hash].copy()

        result["found"] = True
        result["hash"] = file_hash

        return result

    return {

        "found": False,
        "hash": file_hash,
        "risk": "Clean",
        "reputation_score": 0,
        "category": "None",
        "source": None,
        "description": "Hash not found in threat intelligence"

    }

IOC_DATABASE = [

    {
        "ioc_type": "ip",
        "value": "185.220.101.1",
        "severity": "Critical",
        "category": "Command and Control",
        "source": "AbuseIPDB",
        "description": "Known Tor exit node used by ransomware operators",
        "created_at": datetime.now().isoformat()
    },

    {
        "ioc_type": "ip",
        "value": "45.155.205.233",
        "severity": "High",
        "category": "Malware",
        "source": "AlienVault OTX",
        "description": "Known malware distribution server",
        "created_at": datetime.now().isoformat()
    },

    {
        "ioc_type": "domain",
        "value": "evil-domain.com",
        "severity": "Critical",
        "category": "Phishing",
        "source": "VirusTotal",
        "description": "Credential harvesting domain",
        "created_at": datetime.now().isoformat()
    },

    {
        "ioc_type": "url",
        "value": "https://evil-domain.com/login",
        "severity": "Critical",
        "category": "Phishing",
        "source": "VirusTotal",
        "description": "Fake Microsoft login page",
        "created_at": datetime.now().isoformat()
    },

    {
        "ioc_type": "sha256",
        "value": "5d41402abc4b2a76b9719d911017c5926c4c8d0d89e74e8f2f4b3f8b8f8b8f8b",
        "severity": "Critical",
        "category": "Ransomware",
        "source": "MISP",
        "description": "Known ransomware sample",
        "created_at": datetime.now().isoformat()
    },

    {
        "ioc_type": "md5",
        "value": "5d41402abc4b2a76b9719d911017c592",
        "severity": "Medium",
        "category": "Trojan",
        "source": "Hybrid Analysis",
        "description": "Known trojan executable",
        "created_at": datetime.now().isoformat()
    }

]

import copy

ORIGINAL_IOC_DATABASE = copy.deepcopy(IOC_DATABASE)

def reset_ioc_database():
    global IOC_DATABASE
    IOC_DATABASE = copy.deepcopy(ORIGINAL_IOC_DATABASE)

def get_all_iocs():
    return IOC_DATABASE


def build_ioc_statistics():

    iocs = get_all_iocs()

    severity = Counter(i["severity"] for i in iocs)

    categories = Counter(i["category"] for i in iocs)

    types = Counter(i["ioc_type"] for i in iocs)

    return {

        "total_iocs": len(iocs),

        "severity_distribution": dict(severity),

        "category_distribution": dict(categories),

        "type_distribution": dict(types)

    }

def search_ioc(value: str):

    value = value.lower()

    return [

        i

        for i in IOC_DATABASE

        if value in i["value"].lower()

    ]

def lookup_ioc(value: str):

    for ioc in IOC_DATABASE:

        if ioc["value"].lower() == value.lower():

            return ioc

    return None

def match_iocs_with_incidents():

    incidents = get_all_incidents()

    matches = []

    for incident in incidents:

        attack = incident.get("attack", "").lower()

        hostname = incident.get("hostname", "").lower()

        username = incident.get("username", "").lower()

        matched = []

        for ioc in IOC_DATABASE:

            value = ioc["value"].lower()

            if value in attack:

                matched.append(ioc)

            elif value in hostname:

                matched.append(ioc)

            elif value in username:

                matched.append(ioc)

        if matched:

            matches.append(
                {
                    "alert_id": incident["alert_id"],
                    "hostname": incident["hostname"],
                    "attack": incident["attack"],
                    "matched_iocs": matched,
                    "ioc_count": len(matched)
                }
            )

    return matches

def build_ioc_match_statistics():

    matches = match_iocs_with_incidents()

    return {

        "matched_incidents": len(matches),

        "total_ioc_matches": sum(
            m["ioc_count"] for m in matches
        )

    }

def build_threat_dashboard():

    iocs = get_all_iocs()

    stats = build_ioc_statistics()

    matches = build_ioc_match_statistics()

    severity = Counter(i["severity"] for i in iocs)

    categories = Counter(i["category"] for i in iocs)

    types = Counter(i["ioc_type"] for i in iocs)

    sources = Counter(i["source"] for i in iocs)

    return {

        "generated_at": datetime.now().isoformat(),

        "total_iocs": len(iocs),

        "severity_distribution": dict(severity),

        "category_distribution": dict(categories),

        "type_distribution": dict(types),

        "source_distribution": dict(sources),

        "ioc_statistics": stats,

        "ioc_matches": matches

    }

def get_top_iocs(limit: int = 5):

    iocs = sorted(

        IOC_DATABASE,

        key=lambda x: (
            x["severity"],
            x["category"]
        ),

        reverse=True

    )

    return iocs[:limit]

def get_top_sources():

    counter = Counter(

        i["source"]

        for i in IOC_DATABASE

    )

    return dict(counter)

def export_iocs_json(filename: str):

    path = Path(filename)

    with open(path, "w", encoding="utf-8") as f:

        json.dump(
            IOC_DATABASE,
            f,
            indent=4
        )

    return str(path)

def export_iocs_csv(filename: str):

    path = Path(filename)

    with open(
        path,
        "w",
        newline="",
        encoding="utf-8"
    ) as csvfile:

        writer = csv.DictWriter(
            csvfile,
            fieldnames=[
                "ioc_type",
                "value",
                "severity",
                "category",
                "source",
                "description",
                "created_at"
            ]
        )

        writer.writeheader()

        writer.writerows(IOC_DATABASE)

    return str(path)

def import_iocs_json(path):
    import json

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    added = 0

    for ioc in data:
        if validate_ioc(ioc):
            added += 1

    return added

def validate_ioc(ioc: dict):

    required = [

        "ioc_type",

        "value",

        "severity",

        "category",

        "source",

        "description"

    ]

    for field in required:

        if field not in ioc:

            return False

    return True

def bulk_import(iocs):
    added = 0

    for ioc in iocs:
        if not validate_ioc(ioc):
            continue

        exists = any(
            x["value"].lower() == ioc["value"].lower()
            for x in IOC_DATABASE
        )

        if exists:
            continue

        IOC_DATABASE.append(ioc)
        added += 1

    return added
