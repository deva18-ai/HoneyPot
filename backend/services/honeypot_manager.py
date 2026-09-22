import socket
import threading
import asyncio
from typing import Dict, List, Optional
from datetime import datetime, timezone
import structlog

from backend.core.config import get_settings
from backend.db.session import async_session_maker
from backend.models import Event, Session
from backend.services.incident import classify_attack, map_to_mitre, calculate_risk_level
from backend.services.websocket import broadcast_event, broadcast_alert
from backend.core.security import hash_password

logger = structlog.get_logger()
settings = get_settings()


class HoneypotService:
    def __init__(self, name: str, port: int, handler):
        self.name = name
        self.port = port
        self.handler = handler
        self.server: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.running = False

    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((settings.HOST, self.port))
        self.server.listen(20)
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        logger.info("honeypot_started", service=self.name, port=self.port)

    def _run(self):
        while self.running:
            try:
                conn, addr = self.server.accept()
                client_thread = threading.Thread(
                    target=self._handle_client, args=(conn, addr), daemon=True
                )
                client_thread.start()
            except OSError:
                break

    def _handle_client(self, conn: socket.socket, addr: tuple):
        try:
            self.handler(conn, addr)
        except Exception as e:
            logger.error("client_handler_error", service=self.name, error=str(e))
        finally:
            conn.close()

    def stop(self):
        self.running = False
        if self.server:
            self.server.close()
        logger.info("honeypot_stopped", service=self.name)


class SSHService:
    @staticmethod
    def handle(conn: socket.socket, addr: tuple):
        ip = addr[0]
        session_id = asyncio.run(SSHService._create_session("SSH", ip))
        
        try:
            conn.sendall(b"SSH-2.0-OpenSSH_8.9-HoneyTrap\r\nlogin: ")
            username = conn.recv(256).decode("utf-8", "ignore").strip()
            conn.sendall(b"password: ")
            password = conn.recv(256).decode("utf-8", "ignore").strip()
            
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
            
            asyncio.run(SSHService._log_event(event_data))
            
            conn.sendall(b"Access denied. This is a defensive honeypot.\r\n")
        except Exception as e:
            asyncio.run(SSHService._log_event({
                "source_ip": ip,
                "service": "SSH",
                "event_type": "CONNECTION",
                "payload": str(e),
                "result": "FAIL",
                "session_id": session_id,
            }))

    @staticmethod
    async def _create_session(service: str, ip: str) -> int:
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

    @staticmethod
    async def _log_event(event_data: dict):
        async with async_session_maker() as db:
            event = Event(**event_data)
            db.add(event)
            
            if event_data.get("session_id"):
                await db.execute(
                    Session.__table__.update()
                    .where(Session.id == event_data["session_id"])
                    .values(event_count=Session.event_count + 1, risk_level=event_data["risk_level"])
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
                broadcast_alert({
                    "type": "alert",
                    "data": {
                        "event_id": event.id,
                        "alert_type": event.classification.split("|")[0],
                        "message": f"{event.classification.split('|')[0]} detected from {event.source_ip}",
                        "created_at": event.timestamp.isoformat(),
                    }
                })


class FTPService:
    @staticmethod
    def handle(conn: socket.socket, addr: tuple):
        ip = addr[0]
        session_id = asyncio.run(FTPService._create_session("FTP", ip))
        
        try:
            conn.sendall(b"220 HoneyTrap FTP Service\r\nUsername: ")
            username = conn.recv(256).decode("utf-8", "ignore").strip()
            conn.sendall(b"Password: ")
            password = conn.recv(256).decode("utf-8", "ignore").strip()
            
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
            
            asyncio.run(FTPService._log_event(event_data))
            
            conn.sendall(b"530 Login incorrect\r\n")
        except Exception as e:
            asyncio.run(FTPService._log_event({
                "source_ip": ip,
                "service": "FTP",
                "event_type": "CONNECTION",
                "payload": str(e),
                "result": "FAIL",
                "session_id": session_id,
            }))

    @staticmethod
    async def _create_session(service: str, ip: str) -> int:
        async with async_session_maker() as db:
            session = Session(source_ip=ip, service=service, started_at=datetime.now(timezone.utc))
            db.add(session)
            await db.commit()
            await db.refresh(session)
            return session.id

    @staticmethod
    async def _log_event(event_data: dict):
        async with async_session_maker() as db:
            event = Event(**event_data)
            db.add(event)
            await db.commit()
            broadcast_event({"type": "event", "data": {"id": event.id, **event_data}})


class TelnetService:
    @staticmethod
    def handle(conn: socket.socket, addr: tuple):
        ip = addr[0]
        session_id = asyncio.run(TelnetService._create_session("TELNET", ip))
        
        try:
            conn.sendall(b"Welcome to HoneyTrap Telnet\r\nlogin: ")
            username = conn.recv(256).decode("utf-8", "ignore").strip()
            conn.sendall(b"Password: ")
            password = conn.recv(256).decode("utf-8", "ignore").strip()
            
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
            
            asyncio.run(TelnetService._log_event(event_data))
            
            conn.sendall(b"Login failed.\r\n")
        except Exception as e:
            asyncio.run(TelnetService._log_event({
                "source_ip": ip,
                "service": "TELNET",
                "event_type": "CONNECTION",
                "payload": str(e),
                "result": "FAIL",
                "session_id": session_id,
            }))

    @staticmethod
    async def _create_session(service: str, ip: str) -> int:
        async with async_session_maker() as db:
            session = Session(source_ip=ip, service=service, started_at=datetime.now(timezone.utc))
            db.add(session)
            await db.commit()
            await db.refresh(session)
            return session.id

    @staticmethod
    async def _log_event(event_data: dict):
        async with async_session_maker() as db:
            event = Event(**event_data)
            db.add(event)
            await db.commit()
            broadcast_event({"type": "event", "data": {"id": event.id, **event_data}})


class DBService:
    @staticmethod
    def handle(conn: socket.socket, addr: tuple):
        ip = addr[0]
        session_id = asyncio.run(DBService._create_session("DB", ip))
        
        try:
            conn.sendall(b"PostgreSQL 15.2 HoneyTrap Database\r\n")
            data = conn.recv(512).decode("utf-8", "ignore").strip()
            
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
            
            asyncio.run(DBService._log_event(event_data))
            
            conn.sendall(b"ERROR: synthetic database endpoint; no real database is exposed.\r\n")
        except Exception as e:
            asyncio.run(DBService._log_event({
                "source_ip": ip,
                "service": "DB",
                "event_type": "CONNECTION",
                "payload": str(e),
                "result": "FAIL",
                "session_id": session_id,
            }))

    @staticmethod
    async def _create_session(service: str, ip: str) -> int:
        async with async_session_maker() as db:
            session = Session(source_ip=ip, service=service, started_at=datetime.now(timezone.utc))
            db.add(session)
            await db.commit()
            await db.refresh(session)
            return session.id

    @staticmethod
    async def _log_event(event_data: dict):
        async with async_session_maker() as db:
            event = Event(**event_data)
            db.add(event)
            await db.commit()
            broadcast_event({"type": "event", "data": {"id": event.id, **event_data}})


class HoneypotManager:
    def __init__(self):
        self.services: List[HoneypotService] = []

    async def start_all(self):
        self.services = [
            HoneypotService("SSH", settings.SSH_PORT, SSHService.handle),
            HoneypotService("FTP", settings.FTP_PORT, FTPService.handle),
            HoneypotService("TELNET", settings.TELNET_PORT, TelnetService.handle),
            HoneypotService("DB", settings.DB_PORT, DBService.handle),
        ]
        
        for service in self.services:
            service.start()
        
        logger.info("all_honeypots_started", count=len(self.services))

    async def stop_all(self):
        for service in self.services:
            service.stop()
        logger.info("all_honeypots_stopped")