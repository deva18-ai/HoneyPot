from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, ForeignKey, Index, UniqueConstraint
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def utc_now():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=True, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="viewer")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    last_login = Column(DateTime(timezone=True), nullable=True)

    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="assignee", foreign_keys="Incident.assignee_id")
    notes = relationship("IncidentNote", back_populates="author")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(255), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    user_agent = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)

    user = relationship("User", back_populates="refresh_tokens")


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    service = Column(String(50), nullable=False, index=True)
    event_type = Column(String(100), nullable=False, index=True)
    username = Column(String(255), nullable=True)
    password = Column(Text, nullable=True)
    request_path = Column(String(500), nullable=True)
    payload = Column(Text, nullable=True)
    result = Column(String(20), nullable=True)
    severity = Column(String(20), nullable=False, default="LOW", index=True)
    session_id = Column(Integer, ForeignKey("sessions.id", ondelete="SET NULL"), nullable=True, index=True)
    fingerprint = Column(String(100), nullable=True)
    country = Column(String(100), nullable=True)
    threat_score = Column(Integer, default=0, index=True)
    prev_hash = Column(String(64), nullable=True)
    event_hash = Column(String(64), nullable=True, index=True)
    classification = Column(String(200), nullable=True)
    mitre_techniques = Column(Text, nullable=True)
    confidence = Column(String(20), nullable=True)
    enriched_data = Column(Text, nullable=True)

    session = relationship("Session", back_populates="events")
    alerts = relationship("Alert", back_populates="event")

    __table_args__ = (
        Index("ix_events_ip_time", "source_ip", "timestamp"),
        Index("ix_events_severity_time", "severity", "timestamp"),
        Index("ix_events_service_time", "service", "timestamp"),
        Index("ix_events_classification_time", "classification", "timestamp"),
        Index("ix_events_threat_score_time", "threat_score", "timestamp"),
        Index("ix_events_ip_service", "source_ip", "service"),
    )


class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    source_ip = Column(String(45), nullable=False, index=True)
    service = Column(String(50), nullable=False, index=True)
    started_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    ended_at = Column(DateTime(timezone=True), nullable=True)
    event_count = Column(Integer, default=0)
    risk_level = Column(String(20), default="LOW")
    classification = Column(String(200), nullable=True)
    threat_score = Column(Integer, default=0)
    mitre_techniques = Column(Text, nullable=True)

    events = relationship("Event", back_populates="session", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_sessions_ip_time", "source_ip", "started_at"),
        Index("ix_sessions_service_time", "service", "started_at"),
        Index("ix_sessions_risk_time", "risk_level", "started_at"),
    )


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(Integer, ForeignKey("events.id", ondelete="CASCADE"), nullable=False, index=True)
    alert_type = Column(String(100), nullable=False, index=True)
    message = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    acknowledged = Column(Boolean, default=False)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    acknowledged_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    event = relationship("Event", back_populates="alerts")

    __table_args__ = (
        Index("ix_alerts_type_time", "alert_type", "created_at"),
        Index("ix_alerts_ack_time", "acknowledged", "created_at"),
    )


class IPStats(Base):
    __tablename__ = "ip_stats"

    source_ip = Column(String(45), primary_key=True)
    total_events = Column(Integer, default=0)
    failed_logins = Column(Integer, default=0)
    services_hit = Column(Integer, default=0)
    threat_score = Column(Integer, default=0, index=True)
    country = Column(String(100), nullable=True)
    asn = Column(String(100), nullable=True)
    isp = Column(String(255), nullable=True)
    reputation_score = Column(Integer, default=0)
    last_seen = Column(DateTime(timezone=True), default=utc_now, index=True)
    first_seen = Column(DateTime(timezone=True), default=utc_now)
    is_blocked = Column(Boolean, default=False)

    __table_args__ = (
        Index("ix_ip_stats_threat_score", "threat_score"),
        Index("ix_ip_stats_last_seen", "last_seen"),
        Index("ix_ip_stats_country", "country"),
        Index("ix_ip_stats_blocked_score", "is_blocked", "threat_score"),
    )


class Honeytoken(Base):
    __tablename__ = "honeytokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    token_name = Column(String(100), unique=True, nullable=False)
    secret_value = Column(String(500), unique=True, nullable=False)
    token_type = Column(String(50), nullable=False, default="credential")
    created_at = Column(DateTime(timezone=True), default=utc_now)
    triggered_at = Column(DateTime(timezone=True), nullable=True)
    triggered_by_ip = Column(String(45), nullable=True)
    triggered_count = Column(Integer, default=0)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(50), unique=True, nullable=False, index=True)
    title = Column(String(500), nullable=True)
    risk_level = Column(String(20), nullable=False, default="LOW", index=True)
    threat_score = Column(Integer, default=0, index=True)
    classification = Column(String(200), nullable=False, index=True)
    status = Column(String(30), nullable=False, default="open", index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    target_service = Column(String(50), nullable=True)
    first_seen = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    last_seen = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    duration_seconds = Column(Integer, default=0)
    event_count = Column(Integer, default=0)
    alert_count = Column(Integer, default=0)
    assignee_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    mitre_techniques = Column(Text, nullable=True)
    tags = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    closed_at = Column(DateTime(timezone=True), nullable=True)
    closed_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    assignee = relationship("User", back_populates="incidents", foreign_keys=[assignee_id])
    events = relationship("IncidentEvent", back_populates="incident", cascade="all, delete-orphan")
    notes = relationship("IncidentNote", back_populates="incident", cascade="all, delete-orphan")
    evidence = relationship("IncidentEvidence", back_populates="incident", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_incidents_status_risk", "status", "risk_level"),
        Index("ix_incidents_ip_time", "source_ip", "first_seen"),
        Index("ix_incidents_classification_time", "classification", "first_seen"),
        Index("ix_incidents_assignee_time", "assignee_id", "first_seen"),
    )


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    event_id = Column(Integer, ForeignKey("events.id", ondelete="CASCADE"), nullable=False, index=True)
    sequence = Column(Integer, default=0)
    behavior_stage = Column(String(100), nullable=True)
    is_key_event = Column(Boolean, default=False)

    incident = relationship("Incident", back_populates="events")
    event = relationship("Event")


class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    author_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    content = Column(Text, nullable=False)
    is_internal = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    incident = relationship("Incident", back_populates="notes")
    author = relationship("User", back_populates="notes")


class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_type = Column(String(50), nullable=False)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    file_path = Column(String(500), nullable=True)
    content = Column(Text, nullable=True)
    mime_type = Column(String(100), nullable=True)
    size_bytes = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    incident = relationship("Incident", back_populates="evidence")


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    id = Column(Integer, primary_key=True, autoincrement=True)
    technique_id = Column(String(20), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    tactic = Column(String(100), nullable=False, index=True)
    platform = Column(Text, nullable=True)
    detection = Column(Text, nullable=True)
    mitigation = Column(Text, nullable=True)
    references = Column(Text, nullable=True)
    sub_techniques = Column(Text, nullable=True)
    is_subtechnique = Column(Boolean, default=False)
    parent_technique = Column(String(20), nullable=True)


class EnrichmentCache(Base):
    __tablename__ = "enrichment_cache"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cache_key = Column(String(200), unique=True, nullable=False, index=True)
    cache_type = Column(String(50), nullable=False, index=True)
    source = Column(String(50), nullable=False)
    data = Column(Text, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (
        Index("ix_enrichment_cache_type_expires", "cache_type", "expires_at"),
    )


class AttackPattern(Base):
    __tablename__ = "attack_patterns"

    id = Column(Integer, primary_key=True, autoincrement=True)
    pattern_id = Column(String(50), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    classification = Column(String(100), nullable=False, index=True)
    mitre_techniques = Column(Text, nullable=True)
    detection_rules = Column(Text, nullable=True)
    severity = Column(String(20), default="MEDIUM")
    base_score = Column(Integer, default=50)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)