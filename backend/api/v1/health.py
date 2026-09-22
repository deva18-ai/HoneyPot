from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from datetime import datetime, timezone

from backend.db.session import get_db, engine
from backend.schemas import HealthResponse
from backend.core.config import get_settings

settings = get_settings()
router = APIRouter(prefix="/health", tags=["health"])


@router.get("", response_model=HealthResponse)
async def health_check(
    db: AsyncSession = Depends(get_db)
):
    db_status = "healthy"
    redis_status = "not_configured"
    
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        db_status = "unhealthy"
    
    try:
        import redis.asyncio as redis
        r = redis.from_url(settings.REDIS_URL)
        await r.ping()
        await r.close()
        redis_status = "healthy"
    except Exception:
        redis_status = "unhealthy"
    
    return HealthResponse(
        status="healthy" if db_status == "healthy" else "degraded",
        service=settings.APP_NAME,
        version=settings.APP_VERSION,
        database=db_status,
        redis=redis_status,
    )


@router.get("/ready")
async def readiness_check(
    db: AsyncSession = Depends(get_db)
):
    try:
        await db.execute(text("SELECT 1"))
        return {"status": "ready"}
    except Exception:
        return {"status": "not_ready"}, 503


@router.get("/live")
async def liveness_check():
    return {"status": "alive"}