from app.config import (
    USE_REAL_EDR,
    USE_REAL_IDP,
    REQUIRE_MANUAL_APPROVAL,
    ALLOWED_TEST_HOSTS,
    ALLOWED_TEST_USERS
)


def get_week1_week2_validation_report() -> dict:
    """
    Generates validation report for Project 3 Week 1 and Week 2 requirements.
    """

    week1_requirements = [
        {
            "requirement": "Setup orchestration environment",
            "implementation": "FastAPI orchestration backend with Swagger UI",
            "status": "completed"
        },
        {
            "requirement": "Secure EDR API/Webhook integration",
            "implementation": "POST /webhooks/edr with x-webhook-secret",
            "status": "completed"
        },
        {
            "requirement": "Ingest high-severity alerts",
            "implementation": "Mock ransomware EDR alert ingestion and Microsoft Defender alert-fetch connector skeleton",
            "status": "completed_lab_and_real_ready"
        },
        {
            "requirement": "Parse hostname, IP, user, and process hash",
            "implementation": "app/services/alert_parser.py",
            "status": "completed"
        }
    ]

    week2_requirements = [
        {
            "requirement": "Network containment command to EDR",
            "implementation": "Mock EDR host isolation and Microsoft Defender isolation-preview connector",
            "status": "completed_lab_and_real_ready"
        },
        {
            "requirement": "Isolate machine while preserving management safety",
            "implementation": "Approved host isolation workflow with dry_run and sandbox allowlist",
            "status": "completed_safe_mode"
        },
        {
            "requirement": "Identity Provider integration",
            "implementation": "Mock IDP and Microsoft Graph / Azure AD connector skeleton",
            "status": "completed_lab_and_real_ready"
        },
        {
            "requirement": "Suspend compromised user account",
            "implementation": "Approved user suspension workflow with dry_run protection",
            "status": "completed_safe_mode"
        },
        {
            "requirement": "Revoke session tokens",
            "implementation": "Approved session revocation workflow with dry_run protection",
            "status": "completed_safe_mode"
        },
        {
            "requirement": "Test containment workflow in safe sandbox",
            "implementation": "POST /playbooks/{alert_id}/approved-run and pytest validation",
            "status": "completed"
        }
    ]

    return {
        "project": "Automated Ransomware Containment & Incident Response Orchestrator",
        "validation_scope": "Week 1 and Week 2",
        "overall_status": "completed_in_safe_lab_and_real_integration_ready_mode",
        "real_edr_enabled": USE_REAL_EDR,
        "real_idp_enabled": USE_REAL_IDP,
        "manual_approval_required": REQUIRE_MANUAL_APPROVAL,
        "allowed_test_hosts": ALLOWED_TEST_HOSTS,
        "allowed_test_users": ALLOWED_TEST_USERS,
        "week1": {
            "title": "API Integration & Alert Ingestion",
            "status": "completed",
            "requirements": week1_requirements
        },
        "week2": {
            "title": "Zero-Trust Containment Playbooks",
            "status": "completed",
            "requirements": week2_requirements
        },
        "important_note": (
            "Real EDR and real Azure AD actions are protected by dry_run, allowlist, "
            "approval code, and configuration flags. This project is safe for lab demonstration."
        )
    }