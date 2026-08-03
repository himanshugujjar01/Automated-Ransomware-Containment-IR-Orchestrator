from sqlalchemy import Column, Integer, String, DateTime, Text
from app.database import Base, utcnow

class ActionLog(Base):
    __tablename__ = "action_logs"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String, index=True)
    action_type = Column(String)
    target = Column(String)
    status = Column(String)
    details = Column(Text)
    started_at = Column(DateTime, default=utcnow)
    completed_at = Column(DateTime, default=utcnow)