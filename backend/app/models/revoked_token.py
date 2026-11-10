from sqlalchemy import Column, String, DateTime
from sqlalchemy.sql import func

from app.database import Base


class RevokedToken(Base):

    __tablename__ = "revoked_tokens"

    jti = Column(
        String(100),
        primary_key=True
    )

    revoked_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )