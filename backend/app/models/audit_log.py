from sqlalchemy import Column, Integer, String, Text, DateTime, func, Index
from app.database import Base


class AuditLog(Base):
    """Append-only record of security-sensitive analyst and administrator actions."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    actor_user_id = Column(Integer, nullable=True, index=True)
    actor_username = Column(String(100), nullable=False, index=True)
    action = Column(String(100), nullable=False, index=True)
    target_type = Column(String(80), nullable=True)
    target_id = Column(String(100), nullable=True, index=True)
    details = Column(Text, nullable=True)
    source_ip = Column(String(45), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    __table_args__ = (
        Index("ix_audit_action_created", "action", "created_at"),
    )
