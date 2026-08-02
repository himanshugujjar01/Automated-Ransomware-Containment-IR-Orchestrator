from app.services.ioc_feed_sync import (
    fetch_ioc_feed,
    synchronize_ioc_feed,
)


def test_fetch_feed():

    feed = fetch_ioc_feed()

    assert isinstance(feed, list)
    assert len(feed) > 0


def test_sync_feed():

    result = synchronize_ioc_feed()

    assert "feed_size" in result
    assert "added" in result
    assert "total_iocs" in result
    assert "last_sync" in result

    assert result["feed_size"] >= 2