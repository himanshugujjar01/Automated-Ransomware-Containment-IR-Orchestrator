from app.integrations.azure_ad import (
    get_graph_status,
    is_graph_configured,
    disable_user_account,
    revoke_user_sessions
)


def test_graph_status_format():
    status = get_graph_status()

    assert status["integration"] == "Microsoft Graph / Azure AD / Entra ID"
    assert "configured" in status
    assert "api_base_url" in status
    assert "auth_url" in status
    assert "scope" in status
    assert status["safe_mode"] is True


def test_graph_configured_returns_boolean():
    result = is_graph_configured()

    assert isinstance(result, bool)


def test_disable_user_account_dry_run():
    result = disable_user_account(
        user_id_or_upn="test.ir.user",
        dry_run=True
    )

    assert result["status"] == "dry_run"
    assert result["action"] == "disable_user_account"
    assert "No real Azure AD user account was disabled" in result["message"]


def test_revoke_user_sessions_dry_run():
    result = revoke_user_sessions(
        user_id_or_upn="test.ir.user",
        dry_run=True
    )

    assert result["status"] == "dry_run"
    assert result["action"] == "revoke_user_sessions"
    assert "No real Azure AD sessions were revoked" in result["message"]


def test_disable_user_account_missing_user():
    result = disable_user_account(
        user_id_or_upn="",
        dry_run=True
    )

    assert result["status"] == "failed"
    assert "missing" in result["message"].lower()


def test_revoke_user_sessions_missing_user():
    result = revoke_user_sessions(
        user_id_or_upn="",
        dry_run=True
    )

    assert result["status"] == "failed"
    assert "missing" in result["message"].lower()