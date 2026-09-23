from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, and_, or_
from sqlalchemy.orm import selectinload
from typing import Optional, List
from datetime import datetime, timezone, timedelta

from backend.db.session import get_db
from backend.models import Event, Session, Alert, User
from backend.schemas import EventResponse, EventCreate, SessionResponse, AlertResponse, PaginatedResponse
from backend.api.deps import get_current_active_user

router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=PaginatedResponse)
async def list_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    source_ip: Optional[str] = None,
    service: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    classification: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    min_score: Optional[int] = None,
    max_score: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    query = select(Event).options(selectinload(Event.alerts))
    
    if source_ip:
        query = query.where(Event.source_ip == source_ip)
    if service:
        query = query.where(Event.service == service)
    if event_type:
        query = query.where(Event.event_type.ilike(f"%{event_type}%"))
    if severity:
        query = query.where(Event.severity == severity)
    if classification:
        query = query.where(Event.classification.ilike(f"%{classification}%"))
    if start_time:
        query = query.where(Event.timestamp >= start_time)
    if end_time:
        query = query.where(Event.timestamp <= end_time)
    if min_score is not None:
        query = query.where(Event.threat_score >= min_score)
    if max_score is not None:
        query = query.where(Event.threat_score <= max_score)
    
    query = query.order_by(desc(Event.timestamp))
    
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()
    
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    events = result.scalars().all()
    
    return PaginatedResponse(
        items=[EventResponse.model_validate(e) for e in events],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size
    )


@router.get("/{event_id}", response_model=EventResponse)
async def get_event(
    event_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    result = await db.execute(
        select(Event).options(selectinload(Event.alerts)).where(Event.id == event_id)
    )
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.get("/stats/summary")
async def get_event_stats(
    hours: int = Query(24, ge=1, le=168),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
    
    total = await db.execute(
        select(func.count()).where(Event.timestamp >= start_time)
    )
    
    by_severity = await db.execute(
        select(Event.severity, func.count())
        .where(Event.timestamp >= start_time)
        .group_by(Event.severity)
    )
    
    by_service = await db.execute(
        select(Event.service, func.count())
        .where(Event.timestamp >= start_time)
        .group_by(Event.service)
    )
    
    by_classification = await db.execute(
        select(Event.classification, func.count())
        .where(Event.timestamp >= start_time)
        .group_by(Event.classification)
    )
    
    top_ips = await db.execute(
        select(Event.source_ip, func.count().label("cnt"))
        .where(Event.timestamp >= start_time)
        .group_by(Event.source_ip)
        .order_by(desc("cnt"))
        .limit(10)
    )
    
    avg_score = await db.execute(
        select(func.avg(Event.threat_score))
        .where(Event.timestamp >= start_time)
    )
    
    return {
        "total_events": total.scalar(),
        "by_severity": dict(by_severity.all()),
        "by_service": dict(by_service.all()),
        "by_classification": dict(by_classification.all()),
        "top_source_ips": [{"ip": ip, "count": cnt} for ip, cnt in top_ips.all()],
        "avg_threat_score": round(avg_score.scalar() or 0, 2),
        "time_range_hours": hours,
    }


@router.get("/stats/trend")
async def get_event_trend(
    hours: int = Query(24, ge=1, le=168),
    interval_minutes: int = Query(60, ge=5, le=1440),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
    
    events = await db.execute(
        select(Event.timestamp, Event.severity, Event.threat_score)
        .where(Event.timestamp >= start_time)
        .order_by(Event.timestamp)
    )
    
    events_data = events.all()
    
    if not events_data:
        return {"trend": [], "interval_minutes": interval_minutes}
    
    from collections import defaultdict
    
    buckets = defaultdict(lambda: {"count": 0, "high": 0, "medium": 0, "low": 0, "total_score": 0})
    
    for ts, severity, score in events_data:
        bucket_ts = ts.replace(
            minute=(ts.minute // interval_minutes) * interval_minutes,
            second=0, microsecond=0
        )
        bucket_key = bucket_ts.isoformat()
        buckets[bucket_key]["count"] += 1
        buckets[bucket_key]["total_score"] += score or 0
        if severity == "HIGH":
            buckets[bucket_key]["high"] += 1
        elif severity == "MEDIUM":
            buckets[bucket_key]["medium"] += 1
        else:
            buckets[bucket_key]["low"] += 1
    
    trend = []
    for bucket_key in sorted(buckets.keys()):
        b = buckets[bucket_key]
        trend.append({
            "timestamp": bucket_key,
            "count": b["count"],
            "high": b["high"],
            "medium": b["medium"],
            "low": b["low"],
            "avg_score": round(b["total_score"] / b["count"], 2) if b["count"] > 0 else 0
        })
    
    return {"trend": trend, "interval_minutes": interval_minutes}


@router.post("", response_model=EventResponse, status_code=201)
async def create_event(
    event_data: EventCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    event = Event(**event_data.model_dump())
    db.add(event)
    await db.commit()
    await db.refresh(event)
    return event