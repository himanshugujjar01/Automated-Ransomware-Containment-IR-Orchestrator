from pydantic import BaseModel


class SimulationResponse(BaseModel):

    simulation: str

    alert_id: str

    severity: str

    hostname: str

    username: str

    ticket_created: bool

    notifications_sent: bool

    dry_run: bool