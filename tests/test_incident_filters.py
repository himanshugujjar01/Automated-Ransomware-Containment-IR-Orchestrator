from app.services.soc_dashboard import filter_incidents


def test_filter_critical():

    result = filter_incidents(severity="Critical")

    assert len(result) == 2


def test_filter_open():

    result = filter_incidents(status="Open")

    assert len(result) == 3


def test_filter_closed():

    result = filter_incidents(status="Closed")

    assert len(result) == 2


def test_filter_contained():

    result = filter_incidents(contained=True)

    assert len(result) == 3


def test_filter_attack():

    result = filter_incidents(attack="PowerShell")

    assert len(result) == 1


def test_filter_username():

    result = filter_incidents(username="john")

    assert len(result) == 1


def test_filter_hostname():

    result = filter_incidents(hostname="LAB")

    assert len(result) == 2


def test_multiple_filters():

    result = filter_incidents(
        severity="Critical",
        status="Open",
        contained=True
    )

    assert len(result) == 2