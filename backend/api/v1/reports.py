from fastapi import APIRouter, Depends, Query, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional, List
from datetime import datetime, timezone, timedelta
import os
import csv
import json
from pathlib import Path

from backend.db.session import get_db
from backend.models import Event, Incident, IPStats, User
from backend.schemas import PaginatedResponse
from backend.api.deps import get_current_active_user, require_admin
from backend.core.config import get_settings

settings = get_settings()
router = APIRouter(prefix="/reports", tags=["reports"])

REPORT_DIR = settings.REPORT_DIR
REPORT_DIR.mkdir(parents=True, exist_ok=True)


@router.get("/export/csv")
async def export_events_csv(
    background_tasks: BackgroundTasks,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    source_ip: Optional[str] = None,
    severity: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    query = select(Event).order_by(Event.timestamp)
    
    if start_time:
        query = query.where(Event.timestamp >= start_time)
    if end_time:
        query = query.where(Event.timestamp <= end_time)
    if source_ip:
        query = query.where(Event.source_ip == source_ip)
    if severity:
        query = query.where(Event.severity == severity)
    
    result = await db.execute(query)
    events = result.scalars().all()
    
    filename = f"honeytrap_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    filepath = REPORT_DIR / filename
    
    fields = [
        "id", "timestamp", "source_ip", "service", "event_type", "username",
        "request_path", "result", "severity", "threat_score", "fingerprint",
        "country", "classification", "mitre_techniques", "confidence"
    ]
    
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for e in events:
            writer.writerow({
                "id": e.id,
                "timestamp": e.timestamp.isoformat() if e.timestamp else "",
                "source_ip": e.source_ip,
                "service": e.service,
                "event_type": e.event_type,
                "username": e.username or "",
                "request_path": e.request_path or "",
                "result": e.result or "",
                "severity": e.severity,
                "threat_score": e.threat_score,
                "fingerprint": e.fingerprint or "",
                "country": e.country or "",
                "classification": e.classification or "",
                "mitre_techniques": e.mitre_techniques or "",
                "confidence": e.confidence or "",
            })
    
    background_tasks.add_task(cleanup_file, filepath)
    return FileResponse(
        filepath,
        media_type="text/csv",
        filename=filename
    )


@router.get("/export/incidents/csv")
async def export_incidents_csv(
    background_tasks: BackgroundTasks,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    status: Optional[str] = None,
    risk_level: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    query = select(Incident).order_by(Incident.first_seen)
    
    if start_time:
        query = query.where(Incident.first_seen >= start_time)
    if end_time:
        query = query.where(Incident.first_seen <= end_time)
    if status:
        query = query.where(Incident.status == status)
    if risk_level:
        query = query.where(Incident.risk_level == risk_level)
    
    result = await db.execute(query)
    incidents = result.scalars().all()
    
    filename = f"honeytrap_incidents_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    filepath = REPORT_DIR / filename
    
    fields = [
        "incident_id", "title", "risk_level", "threat_score", "classification",
        "status", "source_ip", "target_service", "first_seen", "last_seen",
        "duration_seconds", "event_count", "alert_count", "mitre_techniques", "tags"
    ]
    
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for i in incidents:
            writer.writerow({
                "incident_id": i.incident_id,
                "title": i.title or "",
                "risk_level": i.risk_level,
                "threat_score": i.threat_score,
                "classification": i.classification,
                "status": i.status,
                "source_ip": i.source_ip,
                "target_service": i.target_service or "",
                "first_seen": i.first_seen.isoformat() if i.first_seen else "",
                "last_seen": i.last_seen.isoformat() if i.last_seen else "",
                "duration_seconds": i.duration_seconds,
                "event_count": i.event_count,
                "alert_count": i.alert_count,
                "mitre_techniques": i.mitre_techniques or "",
                "tags": i.tags or "",
            })
    
    background_tasks.add_task(cleanup_file, filepath)
    return FileResponse(
        filepath,
        media_type="text/csv",
        filename=filename
    )


@router.get("/export/json")
async def export_events_json(
    background_tasks: BackgroundTasks,
    limit: int = Query(1000, ge=1, le=10000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    result = await db.execute(
        select(Event).order_by(desc(Event.timestamp)).limit(limit)
    )
    events = result.scalars().all()
    
    filename = f"honeytrap_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filepath = REPORT_DIR / filename
    
    data = []
    for e in events:
        data.append({
            "id": e.id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "source_ip": e.source_ip,
            "service": e.service,
            "event_type": e.event_type,
            "username": e.username,
            "request_path": e.request_path,
            "result": e.result,
            "severity": e.severity,
            "threat_score": e.threat_score,
            "fingerprint": e.fingerprint,
            "country": e.country,
            "classification": e.classification,
            "mitre_techniques": e.mitre_techniques.split(",") if e.mitre_techniques else [],
            "confidence": e.confidence,
        })
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    
    background_tasks.add_task(cleanup_file, filepath)
    return FileResponse(
        filepath,
        media_type="application/json",
        filename=filename
    )


@router.get("/list")
async def list_reports(
    current_user: User = Depends(require_admin)
):
    files = []
    for f in REPORT_DIR.glob("*"):
        if f.is_file():
            stat = f.stat()
            files.append({
                "filename": f.name,
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
            })
    
    return {"reports": sorted(files, key=lambda x: x["created"], reverse=True)}


def cleanup_file(filepath: Path):
    try:
        if filepath.exists():
            filepath.unlink()
    except Exception:
        pass


from sqlalchemy import desc