
from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    Boolean,
)
from sqlalchemy.sql import func

from app.database import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(100), nullable=False, index=True)
    source = Column(String(100), nullable=False)
    source_ip = Column(String(45), nullable=True, index=True)
    username = Column(String(100), nullable=True)
    description = Column(Text, nullable=False)

    severity = Column(String(20), default="LOW", nullable=False, index=True)
    risk_score = Column(Integer, default=0, nullable=False)
    status = Column(String(30), default="NEW", nullable=False)
    is_suspicious = Column(Boolean, default=False, nullable=False)

    # Authentication evidence
    request_id = Column(String(36), nullable=True, index=True)
    user_agent = Column(String(500), nullable=True)
    auth_result = Column(String(20), nullable=True)
    failure_reason = Column(String(100), nullable=True)

    # Endpoint process attribution
    process_name = Column(String(255), nullable=True)
    process_id = Column(Integer, nullable=True)

    # Network connection evidence
    local_ip = Column(String(45), nullable=True)
    local_port = Column(Integer, nullable=True)
    remote_ip = Column(String(45), nullable=True)
    remote_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)

    # Structured Windows Event Log evidence
    windows_event_id = Column(Integer, nullable=True, index=True)
    windows_record_id = Column(Integer, nullable=True)
    windows_channel = Column(String(255), nullable=True)
    windows_status = Column(String(50), nullable=True)
    windows_sub_status = Column(String(50), nullable=True)
    windows_logon_type = Column(Integer, nullable=True)
    windows_event_timestamp = Column(DateTime(timezone=True), nullable=True)

    # NyensungAI database ingestion timestamp
    timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )
