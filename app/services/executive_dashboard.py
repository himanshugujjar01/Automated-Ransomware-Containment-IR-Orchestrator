from app.services.security_metrics import build_security_metrics
from app.services.dashboard_service import build_dashboard_timeline
from app.services.incident_summary import build_incident_summary
from app.services.ransomware_simulator import simulator_status


def build_executive_dashboard():

    return {

        "platform": "Ransomware IR Orchestrator",

        "status": "Healthy",

        "security_metrics": build_security_metrics(),

        "timeline": build_dashboard_timeline(),

        "incident_summary": build_incident_summary("SIM-001"),

        "simulation": simulator_status()
    }