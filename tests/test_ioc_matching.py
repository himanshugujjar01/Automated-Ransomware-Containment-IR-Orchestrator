from app.services.threat_intelligence import (
    match_iocs_with_incidents,
    build_ioc_match_statistics
)


def test_match_returns_list():

    result = match_iocs_with_incidents()

    assert isinstance(result, list)


def test_statistics():

    stats = build_ioc_match_statistics()

    assert "matched_incidents" in stats
    assert "total_ioc_matches" in stats


def test_statistics_type():

    stats = build_ioc_match_statistics()

    assert isinstance(stats["matched_incidents"], int)
    assert isinstance(stats["total_ioc_matches"], int)