from app.services.security_metrics import build_security_metrics


def test_metrics_exists():
    result = build_security_metrics()

    assert "alerts" in result


def test_alert_total():
    result = build_security_metrics()

    assert result["alerts"]["total"] > 0


def test_containment():
    result = build_security_metrics()

    assert result["containment"]["successful"] >= 0


def test_forensics():
    result = build_security_metrics()

    assert "volatility" in result["forensics"]


def test_ticketing():
    result = build_security_metrics()

    assert "created" in result["ticketing"]


def test_notifications():
    result = build_security_metrics()

    assert "slack" in result["notifications"]


def test_evidence():
    result = build_security_metrics()

    assert "uploaded" in result["evidence"]