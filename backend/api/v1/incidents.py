from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, and_, or_, update
from sqlalchemy.orm import selectinload
from typing import Optional, List
from datetime import datetime, timezone, timedelta

from backend.db.session import get_db
from backend.models import (
    Incident, IncidentEvent, IncidentNote, IncidentEvidence, Event, User
)
from backend.schemas import (
    IncidentResponse, IncidentCreate, IncidentUpdate, IncidentStatus, RiskLevel,
    IncidentEventResponse, IncidentNoteResponse, IncidentNoteCreate,
    IncidentEvidenceResponse, IncidentEvidenceCreate, PaginatedResponse
)
from backend.api.deps import get_current_active_user, require_admin, require_analyst

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=PaginatedResponse)
async def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[IncidentStatus] = None,
    risk_level: Optional[RiskLevel] = None,
    classification: Optional[str] = None,
    source_ip: Optional[str] = None,
    assignee_id: Optional[int] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    min_score: Optional[int] = None,
    max_score: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    query = select(Incident).options(
        selectinload(Incident.assignee),
        selectinload(Incident.events).selectinload(IncidentEvent.event)
    )
    
    if status:
        query = query.where(Incident.status == status)
    if risk_level:
        query = query.where(Incident.risk_level == risk_level)
    if classification:
        query = query.where(Incident.classification.ilike(f"%{classification}%"))
    if source_ip:
        query = query.where(Incident.source_ip == source_ip)
    if assignee_id:
        query = query.where(Incident.assignee_id == assignee_id)
    if start_time:
        query = query.where(Incident.first_seen >= start_time)
    if end_time:
        query = query.where(Incident.first_seen <= end_time)
    if min_score is not None:
        query = query.where(Incident.threat_score >= min_score)
    if max_score is not None:
        query = query.where(Incident.threat_score <= max_score)
    
    query = query.order_by(desc(Incident.first_seen))
    
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()
    
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    incidents = result.scalars().all()
    
    return PaginatedResponse(
        items=[IncidentResponse.model_validate(i) for i in incidents],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size
    )


@router.get("/stats/summary")
async def get_incident_stats(
    hours: int = Query(24, ge=1, le=720),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
    
    total = await db.execute(
        select(func.count()).where(Incident.first_seen >= start_time)
    )
    
    by_status = await db.execute(
        select(Incident.status, func.count())
        .where(Incident.first_seen >= start_time)
        .group_by(Incident.status)
    )
    
    by_risk = await db.execute(
        select(Incident.risk_level, func.count())
        .where(Incident.first_seen >= start_time)
        .group_by(Incident.risk_level)
    )
    
    by_classification = await db.execute(
        select(Incident.classification, func.count())
        .where(Incident.first_seen >= start_time)
        .group_by(Incident.classification)
    )
    
    avg_score = await db.execute(
        select(func.avg(Incident.threat_score))
        .where(Incident.first_seen >= start_time)
    )
    
    open_critical = await db.execute(
        select(func.count())
        .where(and_(
            Incident.first_seen >= start_time,
            Incident.status == IncidentStatus.OPEN,
            Incident.risk_level == RiskLevel.CRITICAL
        ))
    )
    
    return {
        "total_incidents": total.scalar(),
        "by_status": dict(by_status.all()),
        "by_risk_level": dict(by_risk.all()),
        "by_classification": dict(by_classification.all()),
        "avg_threat_score": round(avg_score.scalar() or 0, 2),
        "open_critical": open_critical.scalar(),
        "time_range_hours": hours,
    }


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    result = await db.execute(
        select(Incident).options(
            selectinload(Incident.assignee),
            selectinload(Incident.events).selectinload(IncidentEvent.event),
            selectinload(Incident.notes).selectinload(IncidentNote.author),
            selectinload(Incident.evidence)
        ).where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.get("/{incident_id}/timeline")
async def get_incident_timeline(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    result = await db.execute(
        select(Incident).options(
            selectinload(Incident.events).selectinload(IncidentEvent.event)
        ).where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    timeline = []
    for ie in sorted(incident.events, key=lambda x: x.sequence):
        e = ie.event
        timeline.append({
            "sequence": ie.sequence,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "event_id": e.id,
            "event_type": e.event_type,
            "service": e.service,
            "source_ip": e.source_ip,
            "severity": e.severity,
            "threat_score": e.threat_score,
            "behavior_stage": ie.behavior_stage,
            "is_key_event": ie.is_key_event,
            "username": e.username,
            "request_path": e.request_path,
            "payload": e.payload,
            "result": e.result,
            "classification": e.classification,
            "mitre_techniques": e.mitre_techniques,
        })
    
    return {
        "incident_id": incident.incident_id,
        "timeline": timeline,
        "duration_seconds": incident.duration_seconds,
    }


@router.get("/{incident_id}/evidence")
async def get_incident_evidence(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    result = await db.execute(
        select(Incident).options(selectinload(Incident.evidence))
        .where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    return {
        "incident_id": incident.incident_id,
        "evidence": [IncidentEvidenceResponse.model_validate(e) for e in incident.evidence]
    }


@router.get("/{incident_id}/mitre")
async def get_incident_mitre(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    techniques = []
    if incident.mitre_techniques:
        technique_ids = incident.mitre_techniques.split(",")
        for tid in technique_ids:
            result = await db.execute(
                select(MitreTechnique).where(MitreTechnique.technique_id == tid.strip())
            )
            technique = result.scalar_one_or_none()
            if technique:
                techniques.append({
                    "technique_id": technique.technique_id,
                    "name": technique.name,
                    "tactic": technique.tactic,
                    "description": technique.description,
                    "detection": technique.detection,
                    "mitigation": technique.mitigation,
                })
    
    return {
        "incident_id": incident.incident_id,
        "techniques": techniques
    }


@router.post("", response_model=IncidentResponse, status_code=201)
async def create_incident(
    incident_data: IncidentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    from backend.services.incident import generate_incident_id
    
    incident = Incident(
        **incident_data.model_dump(),
        incident_id=generate_incident_id(),
        assignee_id=current_user.id if current_user.role != "viewer" else None,
    )
    db.add(incident)
    await db.commit()
    await db.refresh(incident)
    return incident


@router.patch("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: int,
    incident_data: IncidentUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    update_data = incident_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(incident, field, value)
    
    incident.updated_at = datetime.now(timezone.utc)
    
    if incident_data.status in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE]:
        incident.closed_at = datetime.now(timezone.utc)
        incident.closed_by = current_user.id
    
    await db.commit()
    await db.refresh(incident)
    return incident


@router.post("/{incident_id}/notes", response_model=IncidentNoteResponse)
async def add_incident_note(
    incident_id: int,
    note_data: IncidentNoteCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    note = IncidentNote(
        incident_id=incident_id,
        author_id=current_user.id,
        **note_data.model_dump()
    )
    db.add(note)
    incident.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(note)
    return note


@router.post("/{incident_id}/evidence", response_model=IncidentEvidenceResponse)
async def add_incident_evidence(
    incident_id: int,
    evidence_data: IncidentEvidenceCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    evidence = IncidentEvidence(
        incident_id=incident_id,
        **evidence_data.model_dump()
    )
    db.add(evidence)
    incident.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(evidence)
    return evidence


@router.delete("/{incident_id}")
async def delete_incident(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can delete incidents")
    
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    await db.delete(incident)
    await db.commit()
    return {"message": "Incident deleted"}


@router.post("/{incident_id}/link-events")
async def link_events_to_incident(
    incident_id: int,
    event_ids: List[int],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    for idx, event_id in enumerate(event_ids):
        result = await db.execute(select(Event).where(Event.id == event_id))
        event = result.scalar_one_or_none()
        if not event:
            continue
        
        existing = await db.execute(
            select(IncidentEvent).where(
                and_(IncidentEvent.incident_id == incident_id, IncidentEvent.event_id == event_id)
            )
        )
        if existing.scalar_one_or_none():
            continue
        
        ie = IncidentEvent(
            incident_id=incident_id,
            event_id=event_id,
            sequence=idx,
        )
        db.add(ie)
    
    incident.event_count = len(event_ids)
    incident.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return {"message": f"Linked {len(event_ids)} events to incident"}


from backend.models import MitreTechnique