from sqlalchemy import Column, Integer, String, DateTime, Text
from datetime import datetime
from app.database import Base

class Ticket(Base):
    __tablename__ = "tickets"

    id = Column(Integer, primary_key=True, index=True)
    ticket_id = Column(String, unique=True, index=True)
    alert_id = Column(String, index=True)
    priority = Column(String)
    assigned_team = Column(String)
    status = Column(String)
    summary = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)