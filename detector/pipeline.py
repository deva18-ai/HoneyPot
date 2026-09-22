from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import structlog

from backend.models import Event
from backend.db.session import async_session_maker
from backend.services.incident import classify_attack, map_to_mitre, calculate_risk_level
from backend.services.websocket import broadcast_event, broadcast_alert

logger = structlog.get_logger()


@dataclass
class DetectionContext:
    event_data: Dict[str, Any]
    recent_events: List[Dict[str, Any]] = field(default_factory=list)
    ip_stats: Optional[Dict[str, Any]] = None
    enrichment: Dict[str, Any] = field(default_factory=dict)
    classification: Optional[str] = None
    threat_score: int = 0
    risk_level: str = "LOW"
    mitre_techniques: List[str] = field(default_factory=list)
    alerts: List[Dict[str, Any]] = field(default_factory=list)
    confidence: str = "MEDIUM"


class DetectionStage(ABC):
    @abstractmethod
    async def process(self, context: DetectionContext) -> DetectionContext:
        pass


class EnrichmentStage(DetectionStage):
    async def process(self, context: DetectionContext) -> DetectionContext:
        ip = context.event_data.get("source_ip", "")
        
        if ip:
            context.enrichment["ip"] = ip
            context.enrichment["is_private"] = self._is_private_ip(ip)
            
            if context.enrichment["is_private"]:
                context.enrichment["country"] = "LOCAL-LAB"
                context.enrichment["asn"] = "LOCAL"
            else:
                context.enrichment["country"] = "UNKNOWN"
                context.enrichment["asn"] = "UNKNOWN"
        
        service = context.event_data.get("service", "")
        payload = str(context.event_data.get("payload") or "").lower()
        user_agent = str(context.event_data.get("user_agent") or "").lower()
        
        fingerprint = self._fingerprint(service, payload, user_agent)
        context.enrichment["fingerprint"] = fingerprint
        
        return context
    
    def _is_private_ip(self, ip: str) -> bool:
        try:
            import ipaddress
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return True
    
    def _fingerprint(self, service: str, payload: str, user_agent: str) -> str:
        text = f"{payload} {user_agent}".lower()
        if "curl" in text:
            return "curl"
        if "python" in text:
            return "python-client"
        if "nmap" in text:
            return "nmap-like"
        if "hydra" in text:
            return "hydra-like"
        if "masscan" in text:
            return "masscan-like"
        if "zmap" in text:
            return "zmap-like"
        if "mozilla" in text or "chrome" in text or "safari" in text:
            return "browser"
        if service in {"SSH", "FTP", "TELNET"}:
            return "unknown-socket-client"
        return "unknown"


class ClassificationStage(DetectionStage):
    async def process(self, context: DetectionContext) -> DetectionContext:
        result = classify_attack(context.event_data, context.recent_events)
        context.classification = result["classification"]
        context.threat_score = result["threat_score"]
        context.risk_level = result["risk_level"]
        context.mitre_techniques = map_to_mitre(result["classification"])
        
        if context.threat_score >= 90:
            context.confidence = "HIGH"
        elif context.threat_score >= 50:
            context.confidence = "MEDIUM"
        else:
            context.confidence = "LOW"
        
        return context


class AlertingStage(DetectionStage):
    async def process(self, context: DetectionContext) -> DetectionContext:
        if context.classification:
            for cls in context.classification.split("|"):
                if cls in ["BRUTE_FORCE", "EXPLOIT_ATTEMPT", "SERVICE_SCAN", "PORT_SCAN", "HONEYTOKEN_TRIGGERED", "BRUTE_FORCE_TOOL"]:
                    alert = {
                        "type": cls,
                        "message": f"{cls} detected from {context.event_data.get('source_ip')}: {context.classification}",
                        "event_id": context.event_data.get("id"),
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    }
                    context.alerts.append(alert)
                    
                    broadcast_alert(alert)
        
        return context


class PersistenceStage(DetectionStage):
    async def process(self, context: DetectionContext) -> DetectionContext:
        async with async_session_maker() as db:
            event = Event(
                timestamp=datetime.fromisoformat(context.event_data["timestamp"].replace("Z", "+00:00"))
                    if isinstance(context.event_data.get("timestamp"), str)
                    else context.event_data.get("timestamp", datetime.now(timezone.utc)),
                source_ip=context.event_data.get("source_ip", ""),
                service=context.event_data.get("service", ""),
                event_type=context.event_data.get("event_type", ""),
                username=context.event_data.get("username"),
                password=context.event_data.get("password"),
                request_path=context.event_data.get("request_path"),
                payload=context.event_data.get("payload"),
                result=context.event_data.get("result"),
                severity=context.risk_level,
                session_id=context.event_data.get("session_id"),
                fingerprint=context.enrichment.get("fingerprint"),
                country=context.enrichment.get("country", "LOCAL-LAB"),
                threat_score=context.threat_score,
                classification=context.classification,
                mitre_techniques=",".join(context.mitre_techniques) if context.mitre_techniques else None,
                confidence=context.confidence,
            )
            db.add(event)
            await db.flush()
            
            context.event_data["id"] = event.id
            
            for alert in context.alerts:
                from backend.models import Alert
                alert_obj = Alert(
                    event_id=event.id,
                    alert_type=alert["type"],
                    message=alert["message"],
                    created_at=datetime.fromisoformat(alert["created_at"].replace("Z", "+00:00"))
                        if isinstance(alert.get("created_at"), str)
                        else datetime.now(timezone.utc),
                )
                db.add(alert_obj)
            
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
        
        return context


class DetectionPipeline:
    def __init__(self, stages: List[DetectionStage] = None):
        self.stages = stages or [
            EnrichmentStage(),
            ClassificationStage(),
            AlertingStage(),
            PersistenceStage(),
        ]
    
    async def run(self, event_data: Dict[str, Any], recent_events: List[Dict[str, Any]] = None) -> DetectionContext:
        context = DetectionContext(
            event_data=event_data,
            recent_events=recent_events or [],
        )
        
        for stage in self.stages:
            try:
                context = await stage.process(context)
            except Exception as e:
                logger.error("pipeline_stage_failed", stage=stage.__class__.__name__, error=str(e))
        
        return context


pipeline = DetectionPipeline()


async def process_event(event_data: Dict[str, Any], recent_events: List[Dict[str, Any]] = None) -> DetectionContext:
    return await pipeline.run(event_data, recent_events)