from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.api.deps import get_current_active_user
from backend.db.session import get_db
from backend.models import Alert, User
from backend.schemas import AlertResponse, PaginatedResponse

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=PaginatedResponse)
async def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    alert_type: str | None = None,
    acknowledged: bool | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    query = select(Alert).options(selectinload(Alert.event))

    if alert_type:
        query = query.where(Alert.alert_type.ilike(f"%{alert_type}%"))
    if acknowledged is not None:
        query = query.where(Alert.acknowledged == acknowledged)
    if start_time:
        query = query.where(Alert.created_at >= start_time)
    if end_time:
        query = query.where(Alert.created_at <= end_time)

    query = query.order_by(desc(Alert.created_at))

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()

    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    alerts = result.scalars().all()

    return PaginatedResponse(
        items=[AlertResponse.model_validate(a) for a in alerts],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get("/stats/summary")
async def get_alert_stats(
    hours: int = Query(24, ge=1, le=168),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    start_time = datetime.now(timezone.utc) - timedelta(hours=hours)

    total = await db.execute(select(func.count()).where(Alert.created_at >= start_time))

    by_type = await db.execute(
        select(Alert.alert_type, func.count())
        .where(Alert.created_at >= start_time)
        .group_by(Alert.alert_type)
    )

    ack_stats = await db.execute(
        select(Alert.acknowledged, func.count())
        .where(Alert.created_at >= start_time)
        .group_by(Alert.acknowledged)
    )

    recent_critical = await db.execute(
        select(Alert)
        .where(
            and_(
                Alert.created_at >= start_time,
                Alert.alert_type.in_(
                    [
                        "BRUTE_FORCE",
                        "MULTI_SERVICE_SCAN",
                        "HONEYTOKEN_TRIGGERED",
                        "EXPLOIT_ATTEMPT",
                    ]
                ),
            )
        )
        .order_by(desc(Alert.created_at))
        .limit(10)
    )

    return {
        "total_alerts": total.scalar(),
        "by_type": dict(by_type.all()),
        "acknowledged_stats": dict(ack_stats.all()),
        "recent_critical": [
            AlertResponse.model_validate(a) for a in recent_critical.scalars().all()
        ],
        "time_range_hours": hours,
    }


@router.patch("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.acknowledged = True
    alert.acknowledged_at = datetime.now(timezone.utc)
    alert.acknowledged_by = current_user.id
    await db.commit()
    return {"message": "Alert acknowledged"}


@router.patch("/{alert_id}/unacknowledge")
async def unacknowledge_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.acknowledged = False
    alert.acknowledged_at = None
    alert.acknowledged_by = None
    await db.commit()
    return {"message": "Alert unacknowledged"}


@router.post("/bulk-acknowledge")
async def bulk_acknowledge_alerts(
    alert_ids: list[int],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    result = await db.execute(select(Alert).where(Alert.id.in_(alert_ids)))
    alerts = result.scalars().all()

    for alert in alerts:
        alert.acknowledged = True
        alert.acknowledged_at = datetime.now(timezone.utc)
        alert.acknowledged_by = current_user.id

    await db.commit()
    return {"message": f"Acknowledged {len(alerts)} alerts"}


from backend.models import User
