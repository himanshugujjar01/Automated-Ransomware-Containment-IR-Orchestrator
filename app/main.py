from fastapi import FastAPI

app = FastAPI(
    title="Automated Ransomware Containment & IR Orchestrator",
    description="A safe lab-based SOAR platform for ransomware alert ingestion, containment, forensics, ticketing, and SOC monitoring.",
    version="1.0.0"
)

@app.get("/")
def root():
    return {
        "message": "Automated Ransomware Containment & IR Orchestrator is running"
    }

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "ransomware-ir-orchestrator"
    }