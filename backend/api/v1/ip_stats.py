from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from typing import Optional, List
from datetime import datetime, timezone, timedelta

from backend.db.session import get_db
from backend.models import IPStats
from backend.schemas import IPStatsResponse, PaginatedResponse
from backend.api.deps import get_current_active_user

router = APIRouter(prefix="/ip-stats", tags=["ip-stats"])


@router.get("", response_model=PaginatedResponse)
async def list_ip_stats(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    min_score: Optional[int] = None,
    is_blocked: Optional[bool] = None,
    country: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    query = select(IPStats)
    
    if min_score is not None:
        query = query.where(IPStats.threat_score >= min_score)
    if is_blocked is not None:
        query = query.where(IPStats.is_blocked == is_blocked)
    if country:
        query = query.where(IPStats.country.ilike(f"%{country}%"))
    
    query = query.order_by(desc(IPStats.threat_score), desc(IPStats.last_seen))
    
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()
    
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    items = result.scalars().all()
    
    return PaginatedResponse(
        items=[IPStatsResponse.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size
    )


@router.get("/{ip}", response_model=IPStatsResponse)
async def get_ip_stats(
    ip: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    result = await db.execute(select(IPStats).where(IPStats.source_ip == ip))
    stats = result.scalar_one_or_none()
    if not stats:
        raise HTTPException(status_code=404, detail="IP stats not found")
    return stats


@router.get("/{ip}/events")
async def get_ip_events(
    ip: str,
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    from backend.models import Event
    result = await db.execute(
        select(Event)
        .where(Event.source_ip == ip)
        .order_by(desc(Event.timestamp))
        .limit(limit)
    )
    events = result.scalars().all()
    return {"source_ip": ip, "events": events}


@router.post("/{ip}/block")
async def block_ip(
    ip: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    result = await db.execute(select(IPStats).where(IPStats.source_ip == ip))
    stats = result.scalar_one_or_none()
    if not stats:
        raise HTTPException(status_code=404, detail="IP stats not found")
    
    stats.is_blocked = True
    await db.commit()
    return {"message": f"IP {ip} blocked"}


@router.post("/{ip}/unblock")
async def unblock_ip(
    ip: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    result = await db.execute(select(IPStats).where(IPStats.source_ip == ip))
    stats = result.scalar_one_or_none()
    if not stats:
        raise HTTPException(status_code=404, detail="IP stats not found")
    
    stats.is_blocked = False
    await db.commit()
    return {"message": f"IP {ip} unblocked"}


from backend.models import User