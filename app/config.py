import os
from dotenv import load_dotenv

load_dotenv()

APP_NAME = os.getenv("APP_NAME", "Ransomware IR Orchestrator")
APP_ENV = os.getenv("APP_ENV", "development")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "supersecret123")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./ir_orchestrator.db")
LOCAL_S3_BUCKET = os.getenv("LOCAL_S3_BUCKET", "local_s3_bucket")