from app.services.threat_intelligence import check_ip_reputation


def test_known_critical_ip():

    result = check_ip_reputation("185.220.101.1")

    assert result["found"] is True
    assert result["risk"] == "Critical"
    assert result["reputation_score"] == 100


def test_known_high_ip():

    result = check_ip_reputation("45.155.205.233")

    assert result["found"] is True
    assert result["risk"] == "High"
    assert result["reputation_score"] == 80


def test_unknown_ip():

    result = check_ip_reputation("8.8.8.8")

    assert result["found"] is False
    assert result["risk"] == "Clean"
    assert result["reputation_score"] == 0