from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from app.database import Base

class Artifact(Base):
    __tablename__ = "artifacts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String, index=True)
    artifact_type = Column(String)
    file_path = Column(String)
    sha256_hash = Column(String)
    storage_path = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)