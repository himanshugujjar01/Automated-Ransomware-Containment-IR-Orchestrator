from app.services.threat_intelligence import check_hash_reputation


def test_md5():

    result = check_hash_reputation(
        "5d41402abc4b2a76b9719d911017c592"
    )

    assert result["found"] is True
    assert result["hash_type"] == "MD5"
    assert result["risk"] == "Medium"


def test_sha1():

    result = check_hash_reputation(
        "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
    )

    assert result["found"] is True
    assert result["hash_type"] == "SHA1"
    assert result["risk"] == "High"


def test_sha256():

    result = check_hash_reputation(
        "5d41402abc4b2a76b9719d911017c5926c4c8d0d89e74e8f2f4b3f8b8f8b8f8b"
    )

    assert result["found"] is True
    assert result["hash_type"] == "SHA256"
    assert result["risk"] == "Critical"


def test_unknown_hash():

    result = check_hash_reputation(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )

    assert result["found"] is False
    assert result["risk"] == "Clean"