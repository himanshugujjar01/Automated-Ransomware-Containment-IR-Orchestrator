from fastapi import FastAPI
from app.config import APP_NAME, APP_ENV
from app.database import Base, engine

from app.models.alert_model import Alert
from app.models.action_model import ActionLog
from app.models.artifact_model import Artifact
from app.models.ticket_model import Ticket

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=APP_NAME,
    description="A safe lab-based SOAR platform for ransomware alert ingestion, containment, forensics, ticketing, and SOC monitoring.",
    version="1.0.0"
)

@app.get("/")
def root():
    return {
        "message": f"{APP_NAME} is running",
        "environment": APP_ENV
    }

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": APP_NAME,
        "environment": APP_ENV
    }