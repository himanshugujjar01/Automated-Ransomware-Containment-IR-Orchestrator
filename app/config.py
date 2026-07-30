import os
from dotenv import load_dotenv

load_dotenv()

APP_NAME = os.getenv("APP_NAME", "Ransomware IR Orchestrator")
APP_ENV = os.getenv("APP_ENV", "development")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "supersecret123")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./ir_orchestrator.db")
LOCAL_S3_BUCKET = os.getenv("LOCAL_S3_BUCKET", "local_s3_bucket")

# Safety flags
USE_REAL_EDR = os.getenv("USE_REAL_EDR", "false").lower() == "true"
USE_REAL_IDP = os.getenv("USE_REAL_IDP", "false").lower() == "true"
USE_REAL_AWS = os.getenv("USE_REAL_AWS", "false").lower() == "true"
USE_REAL_TICKETING = os.getenv("USE_REAL_TICKETING", "false").lower() == "true"
USE_REAL_NOTIFICATIONS = os.getenv("USE_REAL_NOTIFICATIONS", "false").lower() == "true"
REQUIRE_MANUAL_APPROVAL = os.getenv("REQUIRE_MANUAL_APPROVAL", "true").lower() == "true"
REAL_ACTION_APPROVAL_CODE = os.getenv("REAL_ACTION_APPROVAL_CODE", "confirm_lab_only")

ALLOWED_TEST_HOSTS = [
    host.strip()
    for host in os.getenv("ALLOWED_TEST_HOSTS", "").split(",")
    if host.strip()
]

ALLOWED_TEST_USERS = [
    user.strip()
    for user in os.getenv("ALLOWED_TEST_USERS", "").split(",")
    if user.strip()
]

# Microsoft Defender EDR
MDE_TENANT_ID = os.getenv("MDE_TENANT_ID", "change_me")
MDE_CLIENT_ID = os.getenv("MDE_CLIENT_ID", "change_me")
MDE_CLIENT_SECRET = os.getenv("MDE_CLIENT_SECRET", "change_me")
MDE_API_BASE_URL = os.getenv("MDE_API_BASE_URL", "https://api.security.microsoft.com")
MDE_AUTHORITY_URL = os.getenv("MDE_AUTHORITY_URL", "https://login.microsoftonline.com")
MDE_SCOPE = os.getenv("MDE_SCOPE", "https://api.securitycenter.microsoft.com/.default")

# Microsoft Graph / Azure AD
GRAPH_TENANT_ID = os.getenv("GRAPH_TENANT_ID", "change_me")
GRAPH_CLIENT_ID = os.getenv("GRAPH_CLIENT_ID", "change_me")
GRAPH_CLIENT_SECRET = os.getenv("GRAPH_CLIENT_SECRET", "change_me")
GRAPH_API_BASE_URL = os.getenv("GRAPH_API_BASE_URL", "https://graph.microsoft.com/v1.0")
GRAPH_AUTHORITY_URL = os.getenv("GRAPH_AUTHORITY_URL", "https://login.microsoftonline.com")
GRAPH_SCOPE = os.getenv("GRAPH_SCOPE", "https://graph.microsoft.com/.default")

# AWS S3
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "change_me")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "change_me")
AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME", "change_me")
S3_EVIDENCE_PREFIX = os.getenv("S3_EVIDENCE_PREFIX", "forensic-evidence")
S3_OBJECT_LOCK_MODE = os.getenv("S3_OBJECT_LOCK_MODE", "GOVERNANCE")
S3_RETENTION_DAYS = int(os.getenv("S3_RETENTION_DAYS", "30"))
S3_LEGAL_HOLD_ENABLED = os.getenv("S3_LEGAL_HOLD_ENABLED", "false").lower() == "true"

# Ticketing
USE_REAL_TICKETING = os.getenv("USE_REAL_TICKETING", "false").lower() == "true"
TICKETING_PROVIDER = os.getenv("TICKETING_PROVIDER", "mock")
JIRA_BASE_URL = os.getenv("JIRA_BASE_URL", "change_me")
JIRA_EMAIL = os.getenv("JIRA_EMAIL", "change_me")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN", "change_me")
JIRA_PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY", "IR")
SERVICENOW_INSTANCE_URL = os.getenv("SERVICENOW_INSTANCE_URL", "change_me")
SERVICENOW_USERNAME = os.getenv("SERVICENOW_USERNAME", "change_me")
SERVICENOW_PASSWORD = os.getenv("SERVICENOW_PASSWORD", "change_me")
SERVICENOW_API_PATH = os.getenv("SERVICENOW_API_PATH", "/api/now/table/incident")

# Notifications
NOTIFICATION_PROVIDER = os.getenv("NOTIFICATION_PROVIDER", "mock")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "change_me")
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL", "change_me")

# Forensic tool configuration
KAPE_ENABLED = os.getenv("KAPE_ENABLED", "false").lower() == "true"
KAPE_PATH = os.getenv("KAPE_PATH", "change_me")
KAPE_OUTPUT_DIR = os.getenv("KAPE_OUTPUT_DIR", "artifacts/kape")

VOLATILITY_ENABLED = os.getenv("VOLATILITY_ENABLED", "false").lower() == "true"
VOLATILITY_PATH = os.getenv("VOLATILITY_PATH", "change_me")
MEMORY_DUMP_DIR = os.getenv("MEMORY_DUMP_DIR", "artifacts/memory")