import os
from dotenv import load_dotenv

load_dotenv()

APP_NAME = os.getenv("APP_NAME", "Ransomware IR Orchestrator")
APP_ENV = os.getenv("APP_ENV", "development")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "supersecret123")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./ir_orchestrator.db")
LOCAL_S3_BUCKET = os.getenv("LOCAL_S3_BUCKET", "local_s3_bucket")

USE_REAL_EDR = os.getenv("USE_REAL_EDR", "false").lower() == "true"
USE_REAL_IDP = os.getenv("USE_REAL_IDP", "false").lower() == "true"
REQUIRE_MANUAL_APPROVAL = os.getenv("REQUIRE_MANUAL_APPROVAL", "true").lower() == "true"

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

MDE_TENANT_ID = os.getenv("MDE_TENANT_ID", "change_me")
MDE_CLIENT_ID = os.getenv("MDE_CLIENT_ID", "change_me")
MDE_CLIENT_SECRET = os.getenv("MDE_CLIENT_SECRET", "change_me")
MDE_API_BASE_URL = os.getenv("MDE_API_BASE_URL", "https://api.security.microsoft.com")
MDE_AUTHORITY_URL = os.getenv("MDE_AUTHORITY_URL", "https://login.microsoftonline.com")
MDE_SCOPE = os.getenv("MDE_SCOPE", "https://api.securitycenter.microsoft.com/.default")

GRAPH_TENANT_ID = os.getenv("GRAPH_TENANT_ID", "change_me")
GRAPH_CLIENT_ID = os.getenv("GRAPH_CLIENT_ID", "change_me")
GRAPH_CLIENT_SECRET = os.getenv("GRAPH_CLIENT_SECRET", "change_me")
GRAPH_API_BASE_URL = os.getenv("GRAPH_API_BASE_URL", "https://graph.microsoft.com/v1.0")
GRAPH_AUTHORITY_URL = os.getenv("GRAPH_AUTHORITY_URL", "https://login.microsoftonline.com")
GRAPH_SCOPE = os.getenv("GRAPH_SCOPE", "https://graph.microsoft.com/.default")

REAL_ACTION_APPROVAL_CODE = os.getenv("REAL_ACTION_APPROVAL_CODE", "confirm_lab_only")