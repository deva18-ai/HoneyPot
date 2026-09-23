from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.deps import get_current_active_user
from backend.db.session import get_db
from backend.models import (
    Alert,
    Event,
    Incident,
    User,
)
from backend.schemas import DashboardStats

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    hours: int = Query(24, ge=1, le=720),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
    day_start = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    )

    total_incidents = await db.execute(
        select(func.count()).where(Incident.first_seen >= start_time)
    )

    by_risk = await db.execute(
        select(Incident.risk_level, func.count())
        .where(Incident.first_seen >= start_time)
        .group_by(Incident.risk_level)
    )
    risk_counts = dict(by_risk.all())

    by_status = await db.execute(
        select(Incident.status, func.count())
        .where(Incident.first_seen >= start_time)
        .group_by(Incident.status)
    )
    status_counts = dict(by_status.all())

    unique_sources = await db.execute(
        select(func.count(func.distinct(Incident.source_ip))).where(
            Incident.first_seen >= start_time
        )
    )

    events_last_hour = await db.execute(
        select(func.count()).where(
            Event.timestamp >= datetime.now(timezone.utc) - timedelta(hours=1)
        )
    )

    events_last_24h = await db.execute(
        select(func.count()).where(Event.timestamp >= day_start)
    )

    avg_score = await db.execute(
        select(func.avg(Incident.threat_score)).where(Incident.first_seen >= start_time)
    )

    top_classifications = await db.execute(
        select(Incident.classification, func.count())
        .where(Incident.first_seen >= start_time)
        .group_by(Incident.classification)
        .order_by(desc(func.count()))
        .limit(10)
    )

    attack_trend = []
    for i in range(hours):
        bucket_start = datetime.now(timezone.utc) - timedelta(hours=hours - i)
        bucket_end = bucket_start + timedelta(hours=1)

        count = await db.execute(
            select(func.count()).where(
                and_(Event.timestamp >= bucket_start, Event.timestamp < bucket_end)
            )
        )

        high = await db.execute(
            select(func.count()).where(
                and_(
                    Event.timestamp >= bucket_start,
                    Event.timestamp < bucket_end,
                    Event.severity == "HIGH",
                )
            )
        )

        attack_trend.append(
            {
                "timestamp": bucket_start.isoformat(),
                "count": count.scalar(),
                "high_severity": high.scalar(),
            }
        )

    service_heatmap = []
    for hour in range(24):
        bucket_start = day_start + timedelta(hours=hour)
        bucket_end = bucket_start + timedelta(hours=1)

        by_service = await db.execute(
            select(Event.service, func.count())
            .where(and_(Event.timestamp >= bucket_start, Event.timestamp < bucket_end))
            .group_by(Event.service)
        )

        row = {"hour": hour}
        for service, count in by_service.all():
            row[service.lower()] = count
        service_heatmap.append(row)

    return DashboardStats(
        active_incidents=status_counts.get("open", 0)
        + status_counts.get("in_progress", 0),
        critical_incidents=risk_counts.get("CRITICAL", 0),
        high_incidents=risk_counts.get("HIGH", 0),
        medium_incidents=risk_counts.get("MEDIUM", 0),
        low_incidents=risk_counts.get("LOW", 0),
        total_incidents=total_incidents.scalar(),
        unique_sources=unique_sources.scalar(),
        events_last_hour=events_last_hour.scalar(),
        events_last_24h=events_last_24h.scalar(),
        avg_threat_score=round(avg_score.scalar() or 0, 2),
        top_classifications=[
            {"classification": c, "count": cnt} for c, cnt in top_classifications.all()
        ],
        attack_trend=attack_trend,
        service_heatmap=service_heatmap,
    )


@router.get("/threat-overview")
async def get_threat_overview(
    hours: int = Query(24, ge=1, le=168),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    start_time = datetime.now(timezone.utc) - timedelta(hours=hours)

    kpis = {}

    kpis["total_events"] = (
        await db.execute(select(func.count()).where(Event.timestamp >= start_time))
    ).scalar()

    kpis["high_severity_events"] = (
        await db.execute(
            select(func.count()).where(
                and_(Event.timestamp >= start_time, Event.severity == "HIGH")
            )
        )
    ).scalar()

    kpis["unique_ips"] = (
        await db.execute(
            select(func.count(func.distinct(Event.source_ip))).where(
                Event.timestamp >= start_time
            )
        )
    ).scalar()

    kpis["active_incidents"] = (
        await db.execute(
            select(func.count()).where(
                and_(
                    Incident.first_seen >= start_time,
                    Incident.status.in_(["open", "in_progress"]),
                )
            )
        )
    ).scalar()

    kpis["critical_incidents"] = (
        await db.execute(
            select(func.count()).where(
                and_(
                    Incident.first_seen >= start_time, Incident.risk_level == "CRITICAL"
                )
            )
        )
    ).scalar()

    kpis["alerts_generated"] = (
        await db.execute(select(func.count()).where(Alert.created_at >= start_time))
    ).scalar()

    kpis["honeypot_services_active"] = 5

    top_attackers = await db.execute(
        select(
            Event.source_ip,
            func.count().label("cnt"),
            func.max(Event.threat_score).label("max_score"),
        )
        .where(Event.timestamp >= start_time)
        .group_by(Event.source_ip)
        .order_by(desc("cnt"))
        .limit(10)
    )

    attack_distribution = await db.execute(
        select(Event.classification, func.count())
        .where(Event.timestamp >= start_time)
        .where(Event.classification.isnot(None))
        .group_by(Event.classification)
        .order_by(desc(func.count()))
    )

    recent_incidents = await db.execute(
        select(Incident)
        .where(Incident.first_seen >= start_time)
        .order_by(desc(Incident.first_seen))
        .limit(10)
    )

    return {
        "kpis": kpis,
        "top_attackers": [
            {"ip": ip, "event_count": cnt, "max_threat_score": max_score}
            for ip, cnt, max_score in top_attackers.all()
        ],
        "attack_distribution": dict(attack_distribution.all()),
        "recent_incidents": [
            {
                "incident_id": i.incident_id,
                "classification": i.classification,
                "risk_level": i.risk_level,
                "threat_score": i.threat_score,
                "source_ip": i.source_ip,
                "first_seen": i.first_seen.isoformat(),
                "status": i.status,
            }
            for i in recent_incidents.scalars().all()
        ],
    }


from backend.models import User
