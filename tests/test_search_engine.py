from app.services.soc_dashboard import search_incidents


def test_search_alert():

    result = search_incidents(alert_id="ALERT-1001")

    assert len(result) == 1

    assert result[0]["hostname"] == "LAB-PC-01"


def test_search_hostname():

    result = search_incidents(hostname="LAB")

    assert len(result) == 2


def test_search_username():

    result = search_incidents(username="john")

    assert len(result) == 1


def test_search_ip():

    result = search_incidents(ip="10.0.0.5")

    assert len(result) == 1


def test_search_severity():

    result = search_incidents(severity="Critical")

    assert len(result) == 2


def test_search_attack():

    result = search_incidents(attack="Ransomware")

    assert len(result) == 1