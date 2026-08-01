from app.services.soc_dashboard import (
    build_soc_dashboard,
)


def test_severity_distribution():

    result = build_soc_dashboard()

    assert result["severity_distribution"]["Critical"] == 2


def test_ticket_statistics():

    result = build_soc_dashboard()

    assert result["ticket_statistics"]["total"] == 5

    assert result["ticket_statistics"]["open"] == 3


def test_attack_distribution():

    result = build_soc_dashboard()

    assert "Ransomware" in result["attack_distribution"]


def test_top_hosts():

    result = build_soc_dashboard()

    assert "LAB-PC-01" in result["top_hosts"]


def test_last_updated():

    result = build_soc_dashboard()

    assert "last_updated" in result

def test_mitre():

    result = build_soc_dashboard()

    assert "mitre_mapping" in result

    assert len(result["mitre_mapping"]) == 5