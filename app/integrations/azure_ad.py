import requests

from app.config import (
    GRAPH_TENANT_ID,
    GRAPH_CLIENT_ID,
    GRAPH_CLIENT_SECRET,
    GRAPH_API_BASE_URL,
    GRAPH_AUTHORITY_URL,
    GRAPH_SCOPE
)


def is_graph_configured() -> bool:
    """
    Checks whether Microsoft Graph credentials are configured.
    This does not call Microsoft APIs.
    """

    required_values = [
        GRAPH_TENANT_ID,
        GRAPH_CLIENT_ID,
        GRAPH_CLIENT_SECRET
    ]

    return all(
        value and value != "change_me"
        for value in required_values
    )


def get_graph_status() -> dict:
    """
    Returns Microsoft Graph / Azure AD connector readiness status.
    """

    configured = is_graph_configured()

    return {
        "integration": "Microsoft Graph / Azure AD / Entra ID",
        "configured": configured,
        "api_base_url": GRAPH_API_BASE_URL,
        "auth_url": f"{GRAPH_AUTHORITY_URL}/{GRAPH_TENANT_ID}/oauth2/v2.0/token",
        "scope": GRAPH_SCOPE,
        "safe_mode": True,
        "message": (
            "Microsoft Graph connector is configured."
            if configured
            else "Microsoft Graph connector is not configured. Add real tenant ID, client ID, and client secret in .env."
        )
    }


def get_graph_token() -> str:
    """
    Gets Microsoft Graph access token using OAuth2 client credentials.

    Use this only in your own authorized Azure AD / Entra ID lab tenant.
    """

    if not is_graph_configured():
        raise ValueError(
            "Microsoft Graph credentials are not configured. "
            "Update GRAPH_TENANT_ID, GRAPH_CLIENT_ID, and GRAPH_CLIENT_SECRET in .env."
        )

    token_url = f"{GRAPH_AUTHORITY_URL}/{GRAPH_TENANT_ID}/oauth2/v2.0/token"

    payload = {
        "client_id": GRAPH_CLIENT_ID,
        "client_secret": GRAPH_CLIENT_SECRET,
        "scope": GRAPH_SCOPE,
        "grant_type": "client_credentials"
    }

    response = requests.post(token_url, data=payload, timeout=30)

    if response.status_code != 200:
        raise RuntimeError(
            f"Failed to get Microsoft Graph token. "
            f"Status: {response.status_code}, Response: {response.text}"
        )

    return response.json()["access_token"]


def find_user_by_username(username: str) -> dict:
    """
    Finds a user in Microsoft Graph by userPrincipalName.

    This is read-only.
    """

    if not username:
        return {
            "found": False,
            "user": None,
            "message": "Username is missing."
        }

    if not is_graph_configured():
        return {
            "found": False,
            "user": None,
            "message": "Microsoft Graph credentials are not configured."
        }

    token = get_graph_token()

    url = f"{GRAPH_API_BASE_URL}/users/{username}"

    params = {
        "$select": "id,displayName,userPrincipalName,mail,accountEnabled"
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }

    response = requests.get(url, headers=headers, params=params, timeout=30)

    if response.status_code == 404:
        return {
            "found": False,
            "user": None,
            "message": f"User not found: {username}"
        }

    if response.status_code != 200:
        raise RuntimeError(
            f"Failed to lookup Microsoft Graph user. "
            f"Status: {response.status_code}, Response: {response.text}"
        )

    return {
        "found": True,
        "user": response.json(),
        "message": "User found in Microsoft Graph."
    }


def disable_user_account(
    user_id_or_upn: str,
    dry_run: bool = True
) -> dict:
    """
    Disables a user account using Microsoft Graph.

    dry_run=True means no real account change is made.
    Use dry_run=False only in your authorized lab tenant with a test user.
    """

    if not user_id_or_upn:
        return {
            "status": "failed",
            "message": "User ID or UPN is missing."
        }

    if dry_run:
        return {
            "status": "dry_run",
            "user": user_id_or_upn,
            "action": "disable_user_account",
            "message": "Dry-run only. No real Azure AD user account was disabled."
        }

    token = get_graph_token()

    url = f"{GRAPH_API_BASE_URL}/users/{user_id_or_upn}"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "accountEnabled": False
    }

    response = requests.patch(url, headers=headers, json=payload, timeout=30)

    if response.status_code not in [200, 204]:
        raise RuntimeError(
            f"Failed to disable user account. "
            f"Status: {response.status_code}, Response: {response.text}"
        )

    return {
        "status": "success",
        "user": user_id_or_upn,
        "action": "disable_user_account",
        "message": "User account disabled successfully using Microsoft Graph."
    }


def revoke_user_sessions(
    user_id_or_upn: str,
    dry_run: bool = True
) -> dict:
    """
    Revokes active sign-in sessions using Microsoft Graph.

    dry_run=True means no real token/session revocation is made.
    Use dry_run=False only in your authorized lab tenant with a test user.
    """

    if not user_id_or_upn:
        return {
            "status": "failed",
            "message": "User ID or UPN is missing."
        }

    if dry_run:
        return {
            "status": "dry_run",
            "user": user_id_or_upn,
            "action": "revoke_user_sessions",
            "message": "Dry-run only. No real Azure AD sessions were revoked."
        }

    token = get_graph_token()

    url = f"{GRAPH_API_BASE_URL}/users/{user_id_or_upn}/revokeSignInSessions"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    response = requests.post(url, headers=headers, timeout=30)

    if response.status_code not in [200, 204]:
        raise RuntimeError(
            f"Failed to revoke user sessions. "
            f"Status: {response.status_code}, Response: {response.text}"
        )

    return {
        "status": "success",
        "user": user_id_or_upn,
        "action": "revoke_user_sessions",
        "message": "User sessions revoked successfully using Microsoft Graph."
    }