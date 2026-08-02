from app.services.threat_intelligence import check_domain_reputation


def test_known_domain():

    result = check_domain_reputation("evil-domain.com")

    assert result["found"] is True
    assert result["risk"] == "Critical"
    assert result["reputation_score"] == 100


def test_known_domain_high():

    result = check_domain_reputation("malware-download.net")

    assert result["found"] is True
    assert result["risk"] == "High"
    assert result["reputation_score"] == 85


def test_unknown_domain():

    result = check_domain_reputation("google.com")

    assert result["found"] is False
    assert result["risk"] == "Clean"
    assert result["reputation_score"] == 0