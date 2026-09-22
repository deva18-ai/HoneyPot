from typing import Dict, List, Set
from fastapi import WebSocket
import json
import asyncio


class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {
            "event": set(),
            "alert": set(),
            "incident": set(),
        }
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, channel: str = "event"):
        await websocket.accept()
        async with self._lock:
            if channel not in self.active_connections:
                self.active_connections[channel] = set()
            self.active_connections[channel].add(websocket)

    def disconnect(self, websocket: WebSocket, channel: str = "event"):
        async with self._lock:
            if channel in self.active_connections:
                self.active_connections[channel].discard(websocket)

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        try:
            await websocket.send_json(message)
        except Exception:
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
            except Exception:
                dead_connections.add(connection)
        
        if dead_connections:
            async with self._lock:
                for conn in dead_connections:
                    self.active_connections[channel].discard(conn)

    def get_connection_count(self, channel: str = "event") -> int:
        return len(self.active_connections.get(channel, set()))


manager = ConnectionManager()