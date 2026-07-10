from sqlalchemy import Column, Integer, String, DateTime, Text
from datetime import datetime
from app.database import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String, unique=True, index=True)
    severity = Column(String)
    detection_type = Column(String)
    hostname = Column(String)
    ip_address = Column(String)
    username = Column(String)
    process_name = Column(String)
    process_hash = Column(String)
    description = Column(Text)
    status = Column(String, default="received")
    raw_payload = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)