from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Any
from datetime import datetime
from enum import Enum


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    email: Optional[EmailStr] = None
    role: UserRole = UserRole.VIEWER


class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=100)


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    password: Optional[str] = Field(None, min_length=8, max_length=100)


class UserResponse(UserBase):
    id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None

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
    items: List[Any]
    total: int
    page: int
    page_size: int
    total_pages: int


class EventBase(BaseModel):
    source_ip: str
    service: str
    event_type: str
    username: Optional[str] = None
    password: Optional[str] = None
    request_path: Optional[str] = None
    payload: Optional[str] = None
    result: Optional[str] = None
    severity: str = "LOW"
    fingerprint: Optional[str] = None
    country: Optional[str] = None
    threat_score: int = 0
    classification: Optional[str] = None
    mitre_techniques: Optional[str] = None
    confidence: Optional[str] = None


class EventCreate(EventBase):
    timestamp: Optional[datetime] = None
    session_id: Optional[int] = None


class EventResponse(EventBase):
    id: int
    timestamp: datetime
    session_id: Optional[int] = None
    event_hash: Optional[str] = None

    class Config:
        from_attributes = True


class SessionBase(BaseModel):
    source_ip: str
    service: str
    risk_level: str = "LOW"
    classification: Optional[str] = None
    threat_score: int = 0
    mitre_techniques: Optional[str] = None


class SessionResponse(SessionBase):
    id: int
    started_at: datetime
    ended_at: Optional[datetime] = None
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
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[int] = None
    event: Optional[EventResponse] = None

    class Config:
        from_attributes = True


class IPStatsBase(BaseModel):
    source_ip: str
    total_events: int = 0
    failed_logins: int = 0
    services_hit: int = 0
    threat_score: int = 0
    country: Optional[str] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
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
    title: Optional[str] = None
    risk_level: RiskLevel = RiskLevel.LOW
    threat_score: int = 0
    classification: str
    status: IncidentStatus = IncidentStatus.OPEN
    source_ip: str
    target_service: Optional[str] = None
    mitre_techniques: Optional[str] = None
    tags: Optional[str] = None


class IncidentCreate(IncidentBase):
    pass


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    risk_level: Optional[RiskLevel] = None
    threat_score: Optional[int] = None
    classification: Optional[str] = None
    status: Optional[IncidentStatus] = None
    target_service: Optional[str] = None
    assignee_id: Optional[int] = None
    mitre_techniques: Optional[str] = None
    tags: Optional[str] = None


class IncidentResponse(IncidentBase):
    id: int
    incident_id: str
    first_seen: datetime
    last_seen: datetime
    duration_seconds: int
    event_count: int
    alert_count: int
    assignee_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime] = None
    closed_by: Optional[int] = None
    assignee: Optional[UserResponse] = None

    class Config:
        from_attributes = True


class IncidentEventResponse(BaseModel):
    id: int
    incident_id: int
    event_id: int
    sequence: int
    behavior_stage: Optional[str] = None
    is_key_event: bool = False
    event: Optional[EventResponse] = None

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
    author_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    author: Optional[UserResponse] = None

    class Config:
        from_attributes = True


class IncidentEvidenceBase(BaseModel):
    evidence_type: str
    title: str
    description: Optional[str] = None
    file_path: Optional[str] = None
    content: Optional[str] = None
    mime_type: Optional[str] = None
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
    description: Optional[str] = None
    tactic: str
    platform: Optional[str] = None
    detection: Optional[str] = None
    mitigation: Optional[str] = None
    references: Optional[str] = None
    sub_techniques: Optional[str] = None
    is_subtechnique: bool = False
    parent_technique: Optional[str] = None

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
    top_classifications: List[dict]
    attack_trend: List[dict]
    service_heatmap: List[dict]