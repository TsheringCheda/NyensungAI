from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, func
from sqlalchemy.orm import relationship
from app.database import Base

class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True, index=True)
    incident_number = Column(String(32), unique=True, nullable=False, index=True)
    security_event_id = Column(Integer, ForeignKey("security_events.id"), nullable=False, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, default="MEDIUM", index=True)
    priority = Column(String(20), nullable=False, default="P2")
    status = Column(String(30), nullable=False, default="NEW", index=True)
    source_ip = Column(String(45), nullable=True)
    assigned_to = Column(String(100), nullable=True)
    resolution = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    notes = relationship("IncidentNote", back_populates="incident", cascade="all, delete-orphan")
    actions = relationship("IncidentAction", back_populates="incident", cascade="all, delete-orphan")

class IncidentNote(Base):
    __tablename__ = "incident_notes"
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    author = Column(String(100), nullable=False)
    note = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    incident = relationship("Incident", back_populates="notes")

class IncidentAction(Base):
    __tablename__ = "incident_actions"
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    actor = Column(String(100), nullable=False)
    action_type = Column(String(80), nullable=False)
    details = Column(Text, nullable=False)
    outcome = Column(String(80), nullable=False, default="RECORDED")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    incident = relationship("Incident", back_populates="actions")
