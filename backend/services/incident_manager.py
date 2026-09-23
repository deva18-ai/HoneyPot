from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, desc, func, select
from sqlalchemy.orm import selectinload

from backend.db.session import async_session_maker
from backend.models import Event, Incident, IncidentEvent
from backend.services.incident import generate_incident_id


class IncidentManager:
    def __init__(self):
        self.correlation_window_minutes = 60
        self.max_events_per_incident = 100

    async def create_incident_from_event(
        self,
        event: Event,
        classification: dict[str, Any],
    ) -> Incident:
        async with async_session_maker() as db:
            existing = await self._find_correlated_incident(db, event)

            if existing:
                return await self._add_event_to_incident(
                    db, existing, event, classification
                )

            incident = Incident(
                incident_id=generate_incident_id(),
                title=f"{classification.get('classification', 'Attack')} from {event.source_ip}",
                risk_level=classification.get("risk_level", "LOW"),
                threat_score=classification.get("threat_score", 0),
                classification=classification.get("classification", "UNKNOWN"),
                status="open",
                source_ip=event.source_ip,
                target_service=event.service,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                duration_seconds=0,
                event_count=1,
                alert_count=len(classification.get("alerts", [])),
                mitre_techniques=",".join(classification.get("mitre_techniques", [])),
            )

            db.add(incident)
            await db.flush()

            incident_event = IncidentEvent(
                incident_id=incident.id,
                event_id=event.id,
                sequence=0,
                behavior_stage=self._determine_behavior_stage(event, classification),
                is_key_event=True,
            )
            db.add(incident_event)

            await db.commit()
            await db.refresh(incident)

            return incident

    async def _find_correlated_incident(self, db, event: Event) -> Incident | None:
        window_start = event.timestamp - timedelta(
            minutes=self.correlation_window_minutes
        )

        result = await db.execute(
            select(Incident)
            .where(
                and_(
                    Incident.source_ip == event.source_ip,
                    Incident.status.in_(["open", "in_progress"]),
                    Incident.last_seen >= window_start,
                )
            )
            .order_by(desc(Incident.last_seen))
        )

        return result.scalars().first()

    async def _add_event_to_incident(
        self,
        db,
        incident: Incident,
        event: Event,
        classification: dict[str, Any],
    ) -> Incident:
        existing_events = await db.execute(
            select(IncidentEvent).where(IncidentEvent.incident_id == incident.id)
        )
        seq = len(existing_events.scalars().all())

        incident_event = IncidentEvent(
            incident_id=incident.id,
            event_id=event.id,
            sequence=seq,
            behavior_stage=self._determine_behavior_stage(event, classification),
            is_key_event=self._is_key_event(event, classification),
        )
        db.add(incident_event)

        incident.event_count += 1
        incident.last_seen = event.timestamp
        incident.duration_seconds = int(
            (event.timestamp - incident.first_seen).total_seconds()
        )
        incident.threat_score = max(
            incident.threat_score, classification.get("threat_score", 0)
        )
        incident.risk_level = self._merge_risk_levels(
            incident.risk_level, classification.get("risk_level", "LOW")
        )

        existing_classifications = (
            set(incident.classification.split("|"))
            if incident.classification
            else set()
        )
        new_classifications = set(classification.get("classification", "").split("|"))
        incident.classification = "|".join(
            existing_classifications | new_classifications
        )

        existing_mitre = (
            set(incident.mitre_techniques.split(","))
            if incident.mitre_techniques
            else set()
        )
        new_mitre = set(classification.get("mitre_techniques", []))
        incident.mitre_techniques = ",".join(existing_mitre | new_mitre)

        incident.alert_count += len(classification.get("alerts", []))
        incident.updated_at = datetime.now(timezone.utc)

        await db.commit()
        await db.refresh(incident)

        return incident

    def _determine_behavior_stage(
        self, event: Event, classification: dict[str, Any]
    ) -> str:
        event_type = event.event_type
        classification_str = classification.get("classification", "")

        if "CONNECTION" in event_type:
            return "initial_access"
        elif "AUTH_ATTEMPT" in event_type:
            if "BRUTE_FORCE" in classification_str:
                return "credential_access"
            return "credential_access"
        elif "PATH_REQUEST" in event_type or "HTTP" in event_type:
            if "WEB_RECON" in classification_str:
                return "reconnaissance"
            elif "EXPLOIT_ATTEMPT" in classification_str:
                return "execution"
            return "reconnaissance"
        elif "BANNER_PROBE" in event_type:
            return "reconnaissance"
        elif "COMMAND" in event_type or "PAYLOAD" in event_type:
            return "execution"
        else:
            return "unknown"

    def _is_key_event(self, event: Event, classification: dict[str, Any]) -> bool:
        classification_str = classification.get("classification", "")
        key_indicators = [
            "BRUTE_FORCE",
            "EXPLOIT_ATTEMPT",
            "HONEYTOKEN_TRIGGERED",
            "SERVICE_SCAN",
            "PORT_SCAN",
            "CREDENTIAL_ABUSE",
        ]
        return any(indicator in classification_str for indicator in key_indicators)

    def _merge_risk_levels(self, current: str, new: str) -> str:
        levels = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        return max(current, new, key=lambda x: levels.get(x, 0))

    async def get_incident_with_details(self, incident_id: int) -> Incident | None:
        async with async_session_maker() as db:
            result = await db.execute(
                select(Incident)
                .options(
                    selectinload(Incident.events).selectinload(IncidentEvent.event),
                    selectinload(Incident.notes),
                    selectinload(Incident.evidence),
                    selectinload(Incident.assignee),
                )
                .where(Incident.id == incident_id)
            )
            return result.scalar_one_or_none()

    async def update_incident_status(
        self,
        incident_id: int,
        status: str,
        user_id: int,
    ) -> Incident | None:
        async with async_session_maker() as db:
            result = await db.execute(
                select(Incident).where(Incident.id == incident_id)
            )
            incident = result.scalar_one_or_none()

            if not incident:
                return None

            incident.status = status
            incident.updated_at = datetime.now(timezone.utc)

            if status in ["resolved", "closed", "false_positive"]:
                incident.closed_at = datetime.now(timezone.utc)
                incident.closed_by = user_id

            await db.commit()
            await db.refresh(incident)
            return incident

    async def assign_incident(
        self, incident_id: int, assignee_id: int
    ) -> Incident | None:
        async with async_session_maker() as db:
            result = await db.execute(
                select(Incident).where(Incident.id == incident_id)
            )
            incident = result.scalar_one_or_none()

            if not incident:
                return None

            incident.assignee_id = assignee_id
            incident.updated_at = datetime.now(timezone.utc)

            if incident.status == "open":
                incident.status = "in_progress"

            await db.commit()
            await db.refresh(incident)
            return incident

    async def add_note(
        self,
        incident_id: int,
        author_id: int,
        content: str,
        is_internal: bool = True,
    ):
        async with async_session_maker() as db:
            from backend.models import IncidentNote

            note = IncidentNote(
                incident_id=incident_id,
                author_id=author_id,
                content=content,
                is_internal=is_internal,
            )
            db.add(note)

            result = await db.execute(
                select(Incident).where(Incident.id == incident_id)
            )
            incident = result.scalar_one_or_none()
            if incident:
                incident.updated_at = datetime.now(timezone.utc)

            await db.commit()
            await db.refresh(note)
            return note

    async def add_evidence(
        self,
        incident_id: int,
        evidence_type: str,
        title: str,
        description: str | None = None,
        content: str | None = None,
        file_path: str | None = None,
    ):
        async with async_session_maker() as db:
            from backend.models import IncidentEvidence

            evidence = IncidentEvidence(
                incident_id=incident_id,
                evidence_type=evidence_type,
                title=title,
                description=description,
                content=content,
                file_path=file_path,
                size_bytes=len(content) if content else 0,
            )
            db.add(evidence)

            result = await db.execute(
                select(Incident).where(Incident.id == incident_id)
            )
            incident = result.scalar_one_or_none()
            if incident:
                incident.updated_at = datetime.now(timezone.utc)

            await db.commit()
            await db.refresh(evidence)
            return evidence

    async def search_incidents(
        self,
        filters: dict[str, Any],
        page: int = 1,
        page_size: int = 20,
    ) -> dict[str, Any]:
        async with async_session_maker() as db:
            query = select(Incident)

            if filters.get("status"):
                query = query.where(Incident.status == filters["status"])
            if filters.get("risk_level"):
                query = query.where(Incident.risk_level == filters["risk_level"])
            if filters.get("classification"):
                query = query.where(
                    Incident.classification.ilike(f"%{filters['classification']}%")
                )
            if filters.get("source_ip"):
                query = query.where(Incident.source_ip == filters["source_ip"])
            if filters.get("assignee_id"):
                query = query.where(Incident.assignee_id == filters["assignee_id"])
            if filters.get("start_time"):
                query = query.where(Incident.first_seen >= filters["start_time"])
            if filters.get("end_time"):
                query = query.where(Incident.first_seen <= filters["end_time"])
            if filters.get("min_score"):
                query = query.where(Incident.threat_score >= filters["min_score"])
            if filters.get("max_score"):
                query = query.where(Incident.threat_score <= filters["max_score"])

            query = query.order_by(desc(Incident.first_seen))

            count_query = select(func.count()).select_from(query.subquery())
            total = (await db.execute(count_query)).scalar()

            query = query.offset((page - 1) * page_size).limit(page_size)
            result = await db.execute(query)
            incidents = result.scalars().all()

            return {
                "items": incidents,
                "total": total,
                "page": page,
                "page_size": page_size,
                "total_pages": (total + page_size - 1) // page_size,
            }

    async def get_incident_stats(self, hours: int = 24) -> dict[str, Any]:
        async with async_session_maker() as db:
            start_time = datetime.now(timezone.utc) - timedelta(hours=hours)

            total = await db.execute(
                select(func.count()).where(Incident.first_seen >= start_time)
            )

            by_status = await db.execute(
                select(Incident.status, func.count())
                .where(Incident.first_seen >= start_time)
                .group_by(Incident.status)
            )

            by_risk = await db.execute(
                select(Incident.risk_level, func.count())
                .where(Incident.first_seen >= start_time)
                .group_by(Incident.risk_level)
            )

            by_classification = await db.execute(
                select(Incident.classification, func.count())
                .where(Incident.first_seen >= start_time)
                .group_by(Incident.classification)
            )

            avg_score = await db.execute(
                select(func.avg(Incident.threat_score)).where(
                    Incident.first_seen >= start_time
                )
            )

            return {
                "total_incidents": total.scalar(),
                "by_status": dict(by_status.all()),
                "by_risk_level": dict(by_risk.all()),
                "by_classification": dict(by_classification.all()),
                "avg_threat_score": round(avg_score.scalar() or 0, 2),
                "time_range_hours": hours,
            }


incident_manager = IncidentManager()
