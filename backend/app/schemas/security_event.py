
from datetime import datetime
from typing import Optional, Literal

from pydantic import BaseModel, ConfigDict, Field


class SecurityEventCreate(BaseModel):
    event_type: str = Field(min_length=2, max_length=100)
    source: str = Field(min_length=2, max_length=100)

    source_ip: Optional[str] = Field(default=None, max_length=45)
    username: Optional[str] = Field(default=None, max_length=100)
    description: str = Field(min_length=3)

    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "LOW"
    risk_score: int = Field(default=0, ge=0, le=100)
    status: Literal["NEW", "INVESTIGATING", "RESOLVED"] = "NEW"
    is_suspicious: bool = False

    # Authentication evidence
    request_id: Optional[str] = Field(default=None, max_length=36)
    user_agent: Optional[str] = Field(default=None, max_length=500)
    auth_result: Optional[Literal["SUCCESS", "FAILURE", "BLOCKED"]] = None
    failure_reason: Optional[str] = Field(default=None, max_length=100)

    # Endpoint process attribution
    process_name: Optional[str] = Field(default=None, max_length=255)
    process_id: Optional[int] = Field(default=None, ge=1)

    # Network connection evidence
    local_ip: Optional[str] = Field(default=None, max_length=45)
    local_port: Optional[int] = Field(default=None, ge=1, le=65535)
    remote_ip: Optional[str] = Field(default=None, max_length=45)
    remote_port: Optional[int] = Field(default=None, ge=1, le=65535)
    protocol: Optional[Literal["TCP", "UDP"]] = None

    # Structured Windows Event Log evidence
    windows_event_id: Optional[int] = Field(default=None, ge=0)
    windows_record_id: Optional[int] = Field(default=None, ge=0)
    windows_channel: Optional[str] = Field(default=None, max_length=255)
    windows_status: Optional[str] = Field(default=None, max_length=50)
    windows_sub_status: Optional[str] = Field(default=None, max_length=50)
    windows_logon_type: Optional[int] = Field(default=None, ge=0)
    windows_event_timestamp: Optional[datetime] = None


class SecurityEventUpdate(BaseModel):
    status: Literal["NEW", "INVESTIGATING", "RESOLVED"]


class SecurityEventResponse(BaseModel):
    id: int
    event_type: str
    source: str
    source_ip: Optional[str]
    username: Optional[str]
    description: str
    severity: str
    risk_score: int
    status: str
    is_suspicious: bool

    request_id: Optional[str] = None
    user_agent: Optional[str] = None
    auth_result: Optional[str] = None
    failure_reason: Optional[str] = None

    process_name: Optional[str] = None
    process_id: Optional[int] = None

    local_ip: Optional[str] = None
    local_port: Optional[int] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    protocol: Optional[str] = None

    # Structured Windows evidence
    windows_event_id: Optional[int] = None
    windows_record_id: Optional[int] = None
    windows_channel: Optional[str] = None
    windows_status: Optional[str] = None
    windows_sub_status: Optional[str] = None
    windows_logon_type: Optional[int] = None
    windows_event_timestamp: Optional[datetime] = None

    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)
