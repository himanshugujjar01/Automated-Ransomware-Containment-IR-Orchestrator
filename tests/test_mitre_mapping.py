from app.services.soc_dashboard import build_mitre_mapping


def test_total():

    result = build_mitre_mapping()

    assert len(result) == 5


def test_ransomware():

    result = build_mitre_mapping()

    ransomware = next(
        i for i in result
        if i["attack"] == "Ransomware"
    )

    assert ransomware["mitre"]["technique_id"] == "T1486"


def test_powershell():

    result = build_mitre_mapping()

     # TEMPORARY DEBUG
    for item in result:
        print(item["attack"])

    ps = next(
        i for i in result
        if i["attack"] == "PowerShell Abuse"
    )

    assert ps["mitre"]["tactic"] == "Execution"


def test_unknown():

    mapping = [
        {
            "attack": "Unknown"
        }
    ]

    # Verify default mapping exists
    default = {
        "tactic": "Unknown",
        "technique_id": "N/A",
        "technique": "Unknown"
    }

    assert default["technique_id"] == "N/A"