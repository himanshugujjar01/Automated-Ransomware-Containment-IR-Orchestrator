from app.services.soc_dashboard import build_soc_dashboard


def test_total():

    result = build_soc_dashboard()

    assert result["total_incidents"] == 5


def test_critical():

    result = build_soc_dashboard()

    assert result["critical"] == 2


def test_high():

    result = build_soc_dashboard()

    assert result["high"] == 1


def test_medium():

    result = build_soc_dashboard()

    assert result["medium"] == 1


def test_low():

    result = build_soc_dashboard()

    assert result["low"] == 1


def test_open():

    result = build_soc_dashboard()

    assert result["open"] == 3


def test_closed():

    result = build_soc_dashboard()

    assert result["closed"] == 2


def test_incidents():

    result = build_soc_dashboard()

    assert len(result["incidents"]) == 5