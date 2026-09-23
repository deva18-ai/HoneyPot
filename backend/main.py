from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import structlog
import uuid
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

from backend.api.v1 import api_router
from backend.core.config import get_settings
from backend.db.session import init_db, close_db
from backend.services.websocket import ConnectionManager

settings = get_settings()

limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

# Prometheus metrics
REQUEST_COUNT = Counter(
    "http_requests_total", "Total HTTP requests", ["method", "endpoint", "status"]
)
REQUEST_DURATION = Histogram(
    "http_request_duration_seconds", "HTTP request duration", ["method", "endpoint"]
)
ACTIVE_CONNECTIONS = Gauge("active_websocket_connections", "Active WebSocket connections")
INCIDENTS_TOTAL = Counter("incidents_total", "Total incidents created", ["risk_level"])
ALERTS_TOTAL = Counter("alerts_total", "Total alerts generated", ["alert_type"])
EVENTS_TOTAL = Counter("events_total", "Total events recorded", ["service", "severity"])

structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
)

logger = structlog.get_logger()

manager = ConnectionManager()


def get_correlation_id(request: Request) -> str:
    return request.headers.get("X-Correlation-ID") or str(uuid.uuid4())


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("starting_application", version=settings.APP_VERSION)
    await init_db()
    
    from backend.services.honeypot_manager import HoneypotManager
    honeypot_manager = HoneypotManager()
    await honeypot_manager.start_all()
    app.state.honeypot_manager = honeypot_manager
    
    yield
    
    logger.info("shutting_down_application")
    await honeypot_manager.stop_all()
    await close_db()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="HoneyTrap - Advanced Honeypot Intrusion Detection System",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api/v1")

app.mount("/static", StaticFiles(directory=settings.DASHBOARD_DIR), name="static")


@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = datetime.now(timezone.utc)
    correlation_id = get_correlation_id(request)
    
    # Bind correlation ID to logger context
    request_logger = logger.bind(correlation_id=correlation_id)
    
    response = await call_next(request)
    duration = (datetime.now(timezone.utc) - start_time).total_seconds()

    endpoint = request.url.path
    REQUEST_COUNT.labels(
        method=request.method, endpoint=endpoint, status=response.status_code
    ).inc()
    REQUEST_DURATION.labels(method=request.method, endpoint=endpoint).observe(duration)

    request_logger.info(
        "http_request",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        duration=duration,
        client_ip=request.client.host if request.client else None,
    )
    
    # Add correlation ID to response headers
    response.headers["X-Correlation-ID"] = correlation_id
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("unhandled_exception", path=request.url.path, error=str(exc), exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    token = websocket.query_params.get("token")
    await manager.connect(websocket, channel="event", token=token)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    token = websocket.query_params.get("token")
    await manager.connect(websocket, channel="alert", token=token)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)


def broadcast_event(event_data: dict):
    import asyncio
    asyncio.create_task(manager.broadcast("event", event_data))


def broadcast_alert(alert_data: dict):
    import asyncio
    asyncio.create_task(manager.broadcast("alert", alert_data))


from datetime import datetime, timezone