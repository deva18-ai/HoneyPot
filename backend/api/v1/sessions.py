from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, and_
from sqlalchemy.orm import selectinload
from typing import Optional, List
from datetime import datetime, timezone, timedelta

from backend.db.session import get_db
from backend.models import Session, Event
from backend.schemas import SessionResponse, PaginatedResponse
from backend.api.deps import get_current_active_user

router = APIRouter(prefix="/sessions", tags=["sessions"])


@router.get("", response_model=PaginatedResponse)
async def list_sessions(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    source_ip: Optional[str] = None,
    service: Optional[str] = None,
    risk_level: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    query = select(Session)
    
    if source_ip:
        query = query.where(Session.source_ip == source_ip)
    if service:
        query = query.where(Session.service == service)
    if risk_level:
        query = query.where(Session.risk_level == risk_level)
    if start_time:
        query = query.where(Session.started_at >= start_time)
    if end_time:
        query = query.where(Session.started_at <= end_time)
    
    query = query.order_by(desc(Session.started_at))
    
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()
    
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    sessions = result.scalars().all()
    
    return PaginatedResponse(
        items=[SessionResponse.model_validate(s) for s in sessions],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size
    )


@router.get("/stats/summary")
async def get_session_stats(
    hours: int = Query(24, ge=1, le=168),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
    
    total = await db.execute(
        select(func.count()).where(Session.started_at >= start_time)
    )
    
    by_service = await db.execute(
        select(Session.service, func.count())
        .where(Session.started_at >= start_time)
        .group_by(Session.service)
    )
    
    by_risk = await db.execute(
        select(Session.risk_level, func.count())
        .where(Session.started_at >= start_time)
        .group_by(Session.risk_level)
    )
    
    avg_events = await db.execute(
        select(func.avg(Session.event_count))
        .where(Session.started_at >= start_time)
    )
    
    top_ips = await db.execute(
        select(Session.source_ip, func.count().label("cnt"))
        .where(Session.started_at >= start_time)
        .group_by(Session.source_ip)
        .order_by(desc("cnt"))
        .limit(10)
    )
    
    return {
        "total_sessions": total.scalar(),
        "by_service": dict(by_service.all()),
        "by_risk_level": dict(by_risk.all()),
        "avg_events_per_session": round(avg_events.scalar() or 0, 2),
        "top_source_ips": [{"ip": ip, "count": cnt} for ip, cnt in top_ips.all()],
        "time_range_hours": hours,
    }


@router.get("/{session_id}", response_model=SessionResponse)
async def get_session(
    session_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    result = await db.execute(
        select(Session).options(selectinload(Session.events)).where(Session.id == session_id)
    )
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.get("/{session_id}/events")
async def get_session_events(
    session_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    result = await db.execute(
        select(Event)
        .where(Event.session_id == session_id)
        .order_by(Event.timestamp)
    )
    events = result.scalars().all()
    return {"session_id": session_id, "events": events}


from backend.models import User