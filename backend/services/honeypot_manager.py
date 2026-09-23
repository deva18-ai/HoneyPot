import asyncio
from typing import Dict, List, Optional
from datetime import datetime, timezone
import structlog

from backend.core.config import get_settings
from backend.db.session import async_session_maker
from backend.models import Event, Session
from backend.services.incident import classify_attack, map_to_mitre, calculate_risk_level
from backend.services.websocket import broadcast_event, broadcast_alert
from backend.services.alert_dedup import alert_dedup_service

logger = structlog.get_logger()
settings = get_settings()


class BaseHoneypotService:
    def __init__(self, name: str, port: int):
        self.name = name
        self.port = port
        self.server: Optional[asyncio.Server] = None
        self.running = False

    async def start(self):
        self.server = await asyncio.start_server(
            self._handle_client, settings.HOST, self.port
        )
        self.running = True
        logger.info("honeypot_started", service=self.name, port=self.port)

    async def stop(self):
        self.running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        logger.info("honeypot_stopped", service=self.name)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        ip = addr[0] if addr else "unknown"
        try:
            await self.handle_connection(reader, writer, ip)
        except Exception as e:
            logger.error("client_handler_error", service=self.name, error=str(e))
        finally:
            writer.close()
            await writer.wait_closed()

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ip: str):
        raise NotImplementedError

    async def _create_session(self, service: str, ip: str) -> int:
        async with async_session_maker() as db:
            session = Session(
                source_ip=ip,
                service=service,
                started_at=datetime.now(timezone.utc),
            )
            db.add(session)
            await db.commit()
            await db.refresh(session)
            return session.id

    async def _log_event(self, event_data: dict):
        async with async_session_maker() as db:
            event = Event(**event_data)
            db.add(event)

            if event_data.get("session_id"):
                await db.execute(
                    Session.__table__.update()
                    .where(Session.id == event_data["session_id"])
                    .values(event_count=Session.event_count + 1, risk_level=event_data.get("risk_level", "LOW"))
                )

            await db.commit()
            await db.refresh(event)

            broadcast_event({
                "type": "event",
                "data": {
                    "id": event.id,
                    "timestamp": event.timestamp.isoformat(),
                    "source_ip": event.source_ip,
                    "service": event.service,
                    "event_type": event.event_type,
                    "severity": event.severity,
                    "threat_score": event.threat_score,
                    "classification": event.classification,
                }
            })

            if event_data.get("classification", "").startswith(("BRUTE_FORCE", "EXPLOIT", "SCAN")):
                alert_type = event.classification.split("|")[0]
                await alert_dedup_service.create_alert(
                    alert_type=alert_type,
                    source_ip=event.source_ip,
                    message=f"{alert_type} detected from {event.source_ip}",
                    event_id=event.id,
                    classification=event.classification,
                )


class SSHService(BaseHoneypotService):
    def __init__(self, port: int):
        super().__init__("SSH", port)

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ip: str):
        session_id = await self._create_session("SSH", ip)

        try:
            writer.write(b"SSH-2.0-OpenSSH_8.9-HoneyTrap\r\nlogin: ")
            await writer.drain()
            username = (await reader.read(256)).decode("utf-8", "ignore").strip()

            writer.write(b"password: ")
            await writer.drain()
            password = (await reader.read(256)).decode("utf-8", "ignore").strip()

            event_data = {
                "source_ip": ip,
                "service": "SSH",
                "event_type": "AUTH_ATTEMPT",
                "username": username,
                "password": password,
                "result": "FAIL",
                "session_id": session_id,
                "fingerprint": "unknown-socket-client",
                "country": "LOCAL-LAB",
            }

            classification = classify_attack(event_data, [])
            event_data.update(classification)
            event_data["mitre_techniques"] = ",".join(map_to_mitre(classification["classification"]))

            await self._log_event(event_data)

            writer.write(b"Access denied. This is a defensive honeypot.\r\n")
            await writer.drain()
        except Exception as e:
            await self._log_event({
                "source_ip": ip,
                "service": "SSH",
                "event_type": "CONNECTION",
                "payload": str(e),
                "result": "FAIL",
                "session_id": session_id,
            })


class FTPService(BaseHoneypotService):
    def __init__(self, port: int):
        super().__init__("FTP", port)

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ip: str):
        session_id = await self._create_session("FTP", ip)

        try:
            writer.write(b"220 HoneyTrap FTP Service\r\nUsername: ")
            await writer.drain()
            username = (await reader.read(256)).decode("utf-8", "ignore").strip()

            writer.write(b"Password: ")
            await writer.drain()
            password = (await reader.read(256)).decode("utf-8", "ignore").strip()

            event_data = {
                "source_ip": ip,
                "service": "FTP",
                "event_type": "AUTH_ATTEMPT",
                "username": username,
                "password": password,
                "result": "FAIL",
                "session_id": session_id,
                "fingerprint": "unknown-socket-client",
                "country": "LOCAL-LAB",
            }

            classification = classify_attack(event_data, [])
            event_data.update(classification)
            event_data["mitre_techniques"] = ",".join(map_to_mitre(classification["classification"]))

            await self._log_event(event_data)

            writer.write(b"530 Login incorrect\r\n")
            await writer.drain()
        except Exception as e:
            await self._log_event({
                "source_ip": ip,
                "service": "FTP",
                "event_type": "CONNECTION",
                "payload": str(e),
                "result": "FAIL",
                "session_id": session_id,
            })


class TelnetService(BaseHoneypotService):
    def __init__(self, port: int):
        super().__init__("TELNET", port)

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ip: str):
        session_id = await self._create_session("TELNET", ip)

        try:
            writer.write(b"Welcome to HoneyTrap Telnet\r\nlogin: ")
            await writer.drain()
            username = (await reader.read(256)).decode("utf-8", "ignore").strip()

            writer.write(b"Password: ")
            await writer.drain()
            password = (await reader.read(256)).decode("utf-8", "ignore").strip()

            event_data = {
                "source_ip": ip,
                "service": "TELNET",
                "event_type": "AUTH_ATTEMPT",
                "username": username,
                "password": password,
                "result": "FAIL",
                "session_id": session_id,
                "fingerprint": "unknown-socket-client",
                "country": "LOCAL-LAB",
            }

            classification = classify_attack(event_data, [])
            event_data.update(classification)
            event_data["mitre_techniques"] = ",".join(map_to_mitre(classification["classification"]))

            await self._log_event(event_data)

            writer.write(b"Login failed.\r\n")
            await writer.drain()
        except Exception as e:
            await self._log_event({
                "source_ip": ip,
                "service": "TELNET",
                "event_type": "CONNECTION",
                "payload": str(e),
                "result": "FAIL",
                "session_id": session_id,
            })


class DBService(BaseHoneypotService):
    def __init__(self, port: int):
        super().__init__("DB", port)

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ip: str):
        session_id = await self._create_session("DB", ip)

        try:
            writer.write(b"PostgreSQL 15.2 HoneyTrap Database\r\n")
            await writer.drain()
            data = (await reader.read(512)).decode("utf-8", "ignore").strip()

            event_data = {
                "source_ip": ip,
                "service": "DB",
                "event_type": "BANNER_PROBE",
                "payload": data,
                "result": "SUCCESS",
                "session_id": session_id,
                "fingerprint": "unknown-socket-client",
                "country": "LOCAL-LAB",
            }

            classification = classify_attack(event_data, [])
            event_data.update(classification)
            event_data["mitre_techniques"] = ",".join(map_to_mitre(classification["classification"]))

            await self._log_event(event_data)

            writer.write(b"ERROR: synthetic database endpoint; no real database is exposed.\r\n")
            await writer.drain()
        except Exception as e:
            await self._log_event({
                "source_ip": ip,
                "service": "DB",
                "event_type": "CONNECTION",
                "payload": str(e),
                "result": "FAIL",
                "session_id": session_id,
            })


class HoneypotManager:
    def __init__(self):
        self.services: List[BaseHoneypotService] = []

    async def start_all(self):
        self.services = [
            SSHService(settings.SSH_PORT),
            FTPService(settings.FTP_PORT),
            TelnetService(settings.TELNET_PORT),
            DBService(settings.DB_PORT),
        ]

        for service in self.services:
            await service.start()

        logger.info("all_honeypots_started", count=len(self.services))

    async def stop_all(self):
        for service in self.services:
            await service.stop()
        logger.info("all_honeypots_stopped")