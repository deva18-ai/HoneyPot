from fastapi import APIRouter

from backend.api.v1.health import router as health_router
from backend.api.v1.auth import router as auth_router
from backend.api.v1.incidents import router as incidents_router
from backend.api.v1.events import router as events_router
from backend.api.v1.alerts import router as alerts_router
from backend.api.v1.dashboard import router as dashboard_router
from backend.api.v1.mitre import router as mitre_router
from backend.api.v1.reports import router as reports_router
from backend.api.v1.ip_stats import router as ip_stats_router
from backend.api.v1.sessions import router as sessions_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(incidents_router)
api_router.include_router(events_router)
api_router.include_router(alerts_router)
api_router.include_router(dashboard_router)
api_router.include_router(mitre_router)
api_router.include_router(reports_router)
api_router.include_router(ip_stats_router)
api_router.include_router(sessions_router)

__all__ = ["api_router"]