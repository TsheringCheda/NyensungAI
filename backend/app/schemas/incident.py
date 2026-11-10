from datetime import datetime
from typing import Optional, Literal
from pydantic import BaseModel, ConfigDict, Field

IncidentStatus = Literal["NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"]
IncidentSeverity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

class IncidentUpdate(BaseModel):
    status: Optional[IncidentStatus] = None
    severity: Optional[IncidentSeverity] = None
    priority: Optional[Literal["P1", "P2", "P3", "P4"]] = None
    assigned_to: Optional[str] = Field(default=None, max_length=100)
    resolution: Optional[str] = Field(default=None, max_length=5000)

class IncidentNoteCreate(BaseModel):
    note: str = Field(min_length=2, max_length=5000)

class IncidentActionCreate(BaseModel):
    action_type: str = Field(min_length=2, max_length=80)
    details: str = Field(min_length=2, max_length=5000)
    outcome: str = Field(default="RECORDED", max_length=80)

class IncidentResponse(BaseModel):
    id: int
    incident_number: str
    security_event_id: int
    title: str
    description: str
    severity: str
    priority: str
    status: str
    source_ip: Optional[str]
    assigned_to: Optional[str]
    resolution: Optional[str]
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)
