from app.services.threat_intelligence import (
    get_all_iocs,
    build_ioc_statistics,
    search_ioc,
    lookup_ioc
)
from app.services.threat_intelligence import (
    check_ip_reputation,
    IOC_DATABASE,
)

def test_total_iocs():

    assert len(get_all_iocs()) == 6


def test_statistics():

    stats = build_ioc_statistics()

    assert stats["total_iocs"] == 6


def test_search_ip():

    result = search_ioc("185.220")

    assert len(result) == 1


def test_search_domain():

    result = search_ioc("evil-domain")

    assert len(result) == 2


def test_lookup():

    result = lookup_ioc("185.220.101.1")

    assert result["severity"] == "Critical"


def test_unknown():

    assert lookup_ioc("8.8.8.8") is None

def check_ip_reputation(ip: str):

    for ioc in IOC_DATABASE:

        if (
            ioc["ioc_type"] == "ip"
            and ioc["value"] == ip
        ):

            severity = ioc["severity"]

            if severity == "Critical":
                score = 100
                risk = "Critical"

            elif severity == "High":
                score = 80
                risk = "High"

            elif severity == "Medium":
                score = 60
                risk = "Medium"

            else:
                score = 20
                risk = "Low"

            return {

                "found": True,

                "ip": ip,

                "reputation_score": score,

                "risk": risk,

                "threat_source": ioc["source"],

                "category": ioc["category"],

                "description": ioc["description"]

            }

    return {

        "found": False,

        "ip": ip,

        "reputation_score": 0,

        "risk": "Clean",

        "threat_source": None,

        "category": None,

        "description": "No known malicious activity"

    }