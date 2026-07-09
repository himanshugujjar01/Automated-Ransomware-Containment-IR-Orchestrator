from fastapi import FastAPI
from app.config import APP_NAME, APP_ENV

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