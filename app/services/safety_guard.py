from app.config import ALLOWED_TEST_HOSTS, ALLOWED_TEST_USERS


def is_allowed_host(hostname: str) -> bool:
    """
    Checks whether a host is approved for sandbox containment testing.
    """

    if not hostname:
        return False

    return hostname in ALLOWED_TEST_HOSTS


def is_allowed_user(username: str) -> bool:
    """
    Checks whether a user is approved for sandbox identity response testing.
    """

    if not username:
        return False

    return username in ALLOWED_TEST_USERS


def validate_sandbox_target(hostname: str, username: str) -> dict:
    """
    Validates both hostname and username before real EDR/IDP actions.
    """

    host_allowed = is_allowed_host(hostname)
    user_allowed = is_allowed_user(username)

    return {
        "hostname": hostname,
        "username": username,
        "host_allowed": host_allowed,
        "user_allowed": user_allowed,
        "approved": host_allowed and user_allowed
    }