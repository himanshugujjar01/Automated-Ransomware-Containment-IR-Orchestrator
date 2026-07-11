from pydantic import BaseModel


class EDRAlert(BaseModel):
    alert_id: str
    severity: str
    detection_type: str
    hostname: str
    ip_address: str
    username: str
    process_name: str
    process_hash: str
    description: str