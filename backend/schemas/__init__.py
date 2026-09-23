from datetime import datetime
from enum import Enum
from typing import Any, List

from pydantic import BaseModel, EmailStr, Field


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    email: EmailStr | None = None
    role: UserRole = UserRole.VIEWER


class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=100)


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    role: UserRole | None = None
    is_active: bool | None = None
    password: str | None = Field(None, min_length=8, max_length=100)


class UserResponse(UserBase):
    id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime
    last_login: datetime | None = None

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    database: str
    redis: str


class PaginatedResponse(BaseModel):
    items: list[Any]
    total: int
    page: int
    page_size: int
    total_pages: int


class EventBase(BaseModel):
    source_ip: str
    service: str
    event_type: str
    username: str | None = None
    password: str | None = None
    request_path: str | None = None
    payload: str | None = None
    result: str | None = None
    severity: str = "LOW"
    fingerprint: str | None = None
    country: str | None = None
    threat_score: int = 0
    classification: str | None = None
    mitre_techniques: str | None = None
    confidence: str | None = None


class EventCreate(EventBase):
    timestamp: datetime | None = None
    session_id: int | None = None


class EventResponse(EventBase):
    id: int
    timestamp: datetime
    session_id: int | None = None
    event_hash: str | None = None

    class Config:
        from_attributes = True


class SessionBase(BaseModel):
    source_ip: str
    service: str
    risk_level: str = "LOW"
    classification: str | None = None
    threat_score: int = 0
    mitre_techniques: str | None = None


class SessionResponse(SessionBase):
    id: int
    started_at: datetime
    ended_at: datetime | None = None
    event_count: int

    class Config:
        from_attributes = True


class AlertBase(BaseModel):
    alert_type: str
    message: str


class AlertResponse(AlertBase):
    id: int
    event_id: int
    created_at: datetime
    acknowledged: bool
    acknowledged_at: datetime | None = None
    acknowledged_by: int | None = None
    event: EventResponse | None = None

    class Config:
        from_attributes = True


class IPStatsBase(BaseModel):
    source_ip: str
    total_events: int = 0
    failed_logins: int = 0
    services_hit: int = 0
    threat_score: int = 0
    country: str | None = None
    asn: str | None = None
    isp: str | None = None
    reputation_score: int = 0
    is_blocked: bool = False


class IPStatsResponse(IPStatsBase):
    first_seen: datetime
    last_seen: datetime

    class Config:
        from_attributes = True


class IncidentStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentBase(BaseModel):
    title: str | None = None
    risk_level: RiskLevel = RiskLevel.LOW
    threat_score: int = 0
    classification: str
    status: IncidentStatus = IncidentStatus.OPEN
    source_ip: str
    target_service: str | None = None
    mitre_techniques: str | None = None
    tags: str | None = None


class IncidentCreate(IncidentBase):
    pass


class IncidentUpdate(BaseModel):
    title: str | None = None
    risk_level: RiskLevel | None = None
    threat_score: int | None = None
    classification: str | None = None
    status: IncidentStatus | None = None
    target_service: str | None = None
    assignee_id: int | None = None
    mitre_techniques: str | None = None
    tags: str | None = None


class IncidentResponse(IncidentBase):
    id: int
    incident_id: str
    first_seen: datetime
    last_seen: datetime
    duration_seconds: int
    event_count: int
    alert_count: int
    assignee_id: int | None = None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None = None
    closed_by: int | None = None
    assignee: UserResponse | None = None

    class Config:
        from_attributes = True


class IncidentEventResponse(BaseModel):
    id: int
    incident_id: int
    event_id: int
    sequence: int
    behavior_stage: str | None = None
    is_key_event: bool = False
    event: EventResponse | None = None

    class Config:
        from_attributes = True


class IncidentNoteBase(BaseModel):
    content: str
    is_internal: bool = True


class IncidentNoteCreate(IncidentNoteBase):
    pass


class IncidentNoteResponse(IncidentNoteBase):
    id: int
    incident_id: int
    author_id: int | None = None
    created_at: datetime
    updated_at: datetime
    author: UserResponse | None = None

    class Config:
        from_attributes = True


class IncidentEvidenceBase(BaseModel):
    evidence_type: str
    title: str
    description: str | None = None
    file_path: str | None = None
    content: str | None = None
    mime_type: str | None = None
    size_bytes: int = 0


class IncidentEvidenceCreate(IncidentEvidenceBase):
    pass


class IncidentEvidenceResponse(IncidentEvidenceBase):
    id: int
    incident_id: int
    created_at: datetime

    class Config:
        from_attributes = True


class MitreTechniqueResponse(BaseModel):
    id: int
    technique_id: str
    name: str
    description: str | None = None
    tactic: str
    platform: str | None = None
    detection: str | None = None
    mitigation: str | None = None
    references: str | None = None
    sub_techniques: str | None = None
    is_subtechnique: bool = False
    parent_technique: str | None = None

    class Config:
        from_attributes = True


class DashboardStats(BaseModel):
    active_incidents: int
    critical_incidents: int
    high_incidents: int
    medium_incidents: int
    low_incidents: int
    total_incidents: int
    unique_sources: int
    events_last_hour: int
    events_last_24h: int
    avg_threat_score: float
    top_classifications: list[dict]
    attack_trend: list[dict]
    service_heatmap: list[dict]
