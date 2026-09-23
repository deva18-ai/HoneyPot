import asyncio

from fastapi import WebSocket, WebSocketException, status
from sqlalchemy import select

from backend.core.security import decode_token
from backend.db.session import async_session_maker
from backend.models import User


class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, set[WebSocket]] = {
            "event": set(),
            "alert": set(),
            "incident": set(),
        }
        self._lock = asyncio.Lock()

    async def connect(
        self, websocket: WebSocket, channel: str = "event", token: str | None = None
    ):
        # Validate token if provided
        if token:
            user = await self._validate_token(token)
            if not user:
                raise WebSocketException(
                    code=status.WS_1008_POLICY_VIOLATION, reason="Invalid token"
                )
            websocket.state.user = user

        await websocket.accept()
        async with self._lock:
            if channel not in self.active_connections:
                self.active_connections[channel] = set()
            self.active_connections[channel].add(websocket)

    async def _validate_token(self, token: str) -> User | None:
        try:
            payload = decode_token(token)
            if not payload or payload.get("type") != "access":
                return None
            user_id = payload.get("sub")
            if not user_id:
                return None

            async with async_session_maker() as db:
                result = await db.execute(select(User).where(User.id == int(user_id)))
                user = result.scalar_one_or_none()
                if user and user.is_active:
                    return user
        except Exception:  # noqa: BLE001, S110
            pass
        return None

    async def disconnect(self, websocket: WebSocket, channel: str = "event"):
        async with self._lock:
            if channel in self.active_connections:
                self.active_connections[channel].discard(websocket)

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        try:
            await websocket.send_json(message)
        except Exception:  # noqa: BLE001, S110
            pass

    async def broadcast(self, channel: str, message: dict):
        if channel not in self.active_connections:
            return

        dead_connections = set()
        async with self._lock:
            connections = self.active_connections[channel].copy()

        for connection in connections:
            try:
                await connection.send_json(message)
            except Exception:  # noqa: BLE001
                dead_connections.add(connection)

        if dead_connections:
            async with self._lock:
                for conn in dead_connections:
                    self.active_connections[channel].discard(conn)

    def get_connection_count(self, channel: str = "event") -> int:
        return len(self.active_connections.get(channel, set()))


manager = ConnectionManager()


def broadcast_event(event_data: dict):
    import asyncio

    asyncio.create_task(manager.broadcast("event", event_data))


def broadcast_alert(alert_data: dict):
    import asyncio

    asyncio.create_task(manager.broadcast("alert", alert_data))
