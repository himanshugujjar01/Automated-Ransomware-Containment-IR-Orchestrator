from app.services.threat_intelligence import (
    build_threat_dashboard,
    get_top_iocs,
    get_top_sources
)


def test_dashboard():

    dashboard = build_threat_dashboard()

    assert dashboard["total_iocs"] > 0


def test_top_iocs():

    top = get_top_iocs()

    assert len(top) > 0


def test_sources():

    sources = get_top_sources()

    assert isinstance(sources, dict)