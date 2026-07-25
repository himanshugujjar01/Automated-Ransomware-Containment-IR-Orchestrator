from app import config


def is_configured(*values) -> bool:
    """
    Checks whether required config values are present and not placeholder values.
    """

    return all(
        value
        and value != "change_me"
        for value in values
    )


def get_production_readiness_report() -> dict:
    """
    Checks readiness for production-level Project 3 integrations.
    """

    defender_ready = is_configured(
        config.MDE_TENANT_ID,
        config.MDE_CLIENT_ID,
        config.MDE_CLIENT_SECRET
    )

    graph_ready = is_configured(
        config.GRAPH_TENANT_ID,
        config.GRAPH_CLIENT_ID,
        config.GRAPH_CLIENT_SECRET
    )

    aws_ready = is_configured(
        config.AWS_ACCESS_KEY_ID,
        config.AWS_SECRET_ACCESS_KEY,
        config.S3_BUCKET_NAME
    )

    jira_ready = is_configured(
        config.JIRA_BASE_URL,
        config.JIRA_EMAIL,
        config.JIRA_API_TOKEN,
        config.JIRA_PROJECT_KEY
    )

    slack_ready = (
        config.NOTIFICATION_PROVIDER == "slack"
        and is_configured(config.SLACK_WEBHOOK_URL)
    )

    teams_ready = (
        config.NOTIFICATION_PROVIDER == "teams"
        and is_configured(config.TEAMS_WEBHOOK_URL)
    )

    return {
        "project": "Automated Ransomware Containment & Incident Response Orchestrator",
        "readiness_scope": "Production integration setup",
        "safety": {
            "use_real_edr": config.USE_REAL_EDR,
            "use_real_idp": config.USE_REAL_IDP,
            "use_real_aws": config.USE_REAL_AWS,
            "use_real_ticketing": config.USE_REAL_TICKETING,
            "use_real_notifications": config.USE_REAL_NOTIFICATIONS,
            "manual_approval_required": config.REQUIRE_MANUAL_APPROVAL,
            "allowed_test_hosts": config.ALLOWED_TEST_HOSTS,
            "allowed_test_users": config.ALLOWED_TEST_USERS
        },
        "integrations": {
            "microsoft_defender_edr": {
                "configured": defender_ready,
                "enabled": config.USE_REAL_EDR,
                "status": "ready" if defender_ready else "credentials_pending"
            },
            "microsoft_graph_azure_ad": {
                "configured": graph_ready,
                "enabled": config.USE_REAL_IDP,
                "status": "ready" if graph_ready else "credentials_pending"
            },
            "aws_s3_evidence_storage": {
                "configured": aws_ready,
                "enabled": config.USE_REAL_AWS,
                "status": "ready" if aws_ready else "credentials_pending"
            },
            "jira_ticketing": {
                "configured": jira_ready,
                "enabled": config.USE_REAL_TICKETING,
                "status": "ready" if jira_ready else "credentials_pending"
            },
            "slack_or_teams_notifications": {
                "slack_configured": slack_ready,
                "teams_configured": teams_ready,
                "enabled": config.USE_REAL_NOTIFICATIONS,
                "provider": config.NOTIFICATION_PROVIDER,
                "status": "ready" if slack_ready or teams_ready else "credentials_pending"
            }
        },
        "day1_status": "completed_safely",
        "important_note": (
            "Real actions must remain disabled until authorized lab credentials, "
            "test hosts, test users, and approval controls are confirmed."
        )
    }