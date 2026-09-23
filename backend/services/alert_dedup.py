import hashlib
from datetime import datetime, timezone

import structlog

from backend.db.session import async_session_maker
from backend.models import Alert

logger = structlog.get_logger()


class AlertDeduplicationService:
    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        self._cache = {}

    def _generate_dedup_key(
        self, alert_type: str, source_ip: str, classification: str
    ) -> str:
        content = f"{alert_type}:{source_ip}:{classification}"
        return hashlib.md5(content.encode()).hexdigest()

    async def should_alert(
        self, alert_type: str, source_ip: str, classification: str, event_id: int
    ) -> bool:
        dedup_key = self._generate_dedup_key(alert_type, source_ip, classification)
        now = datetime.now(timezone.utc)

        if dedup_key in self._cache:
            last_alert_time, count = self._cache[dedup_key]
            if (now - last_alert_time).total_seconds() < self.window_seconds:
                self._cache[dedup_key] = (last_alert_time, count + 1)
                logger.info(
                    "alert_deduplicated",
                    alert_type=alert_type,
                    source_ip=source_ip,
                    dedup_count=count + 1,
                )
                return False

        self._cache[dedup_key] = (now, 1)
        return True

    async def create_alert(
        self,
        alert_type: str,
        source_ip: str,
        message: str,
        event_id: int,
        classification: str,
    ) -> Alert | None:
        if not await self.should_alert(alert_type, source_ip, classification, event_id):
            return None

        async with async_session_maker() as db:
            alert = Alert(
                event_id=event_id,
                alert_type=alert_type,
                message=message,
            )
            db.add(alert)
            await db.commit()
            await db.refresh(alert)
            return alert


alert_dedup_service = AlertDeduplicationService(window_seconds=300)
