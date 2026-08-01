from datetime import datetime
from collections import Counter

IOC_DATABASE = {

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

def check_ip_reputation(ip: str):

    return IOC_DATABASE.get(
        ip,
        {
            "reputation": "Clean",
            "score": 0,
            "category": "None",
            "description": "No known malicious activity"
        }
    )

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