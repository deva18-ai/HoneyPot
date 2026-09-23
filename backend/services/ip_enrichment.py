from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
import structlog

from backend.db.session import async_session_maker
from backend.models import IPStats, EnrichmentCache
from backend.core.config import get_settings
from sqlalchemy import select

logger = structlog.get_logger()
settings = get_settings()


class IPEnrichmentService:
    def __init__(self):
        self.cache_ttl = settings.ENRICHMENT_CACHE_TTL

    async def _get_cached(self, cache_key: str, cache_type: str) -> Optional[Dict[str, Any]]:
        async with async_session_maker() as db:
            result = await db.execute(
                select(EnrichmentCache)
                .where(EnrichmentCache.cache_key == cache_key)
                .where(EnrichmentCache.cache_type == cache_type)
                .where(EnrichmentCache.expires_at > datetime.now(timezone.utc))
            )
            cache = result.scalar_one_or_none()
            if cache:
                import json
                return json.loads(cache.data)
        return None

    async def _set_cache(self, cache_key: str, cache_type: str, data: Dict[str, Any]):
        import json
        async with async_session_maker() as db:
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=self.cache_ttl)
            cache = EnrichmentCache(
                cache_key=cache_key,
                cache_type=cache_type,
                source="enrichment",
                data=json.dumps(data),
                expires_at=expires_at,
            )
            db.add(cache)
            await db.commit()

    async def enrich_ip(self, ip: str) -> Dict[str, Any]:
        cache_key = f"ip:{ip}"
        cached = await self._get_cached(cache_key, "ip_enrichment")
        if cached:
            return cached

        enriched = {
            "ip": ip,
            "country": None,
            "asn": None,
            "isp": None,
            "reputation_score": 0,
        }

        if settings.ABUSEIPDB_API_KEY:
            try:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"https://api.abuseipdb.com/api/v2/check",
                        params={"ipAddress": ip, "maxAgeInDays": 90},
                        headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            enriched["country"] = data.get("data", {}).get("countryCode")
                            enriched["asn"] = data.get("data", {}).get("asn")
                            enriched["isp"] = data.get("data", {}).get("isp")
                            enriched["reputation_score"] = data.get("data", {}).get("abuseConfidenceScore", 0)
            except Exception as e:
                logger.warning("abuseipdb_enrichment_failed", ip=ip, error=str(e))

        await self._set_cache(cache_key, "ip_enrichment", enriched)
        return enriched

    async def update_ip_stats(self, ip: str):
        enriched = await self.enrich_ip(ip)
        
        async with async_session_maker() as db:
            result = await db.execute(select(IPStats).where(IPStats.source_ip == ip))
            stats = result.scalar_one_or_none()
            
            if stats:
                if enriched.get("country"):
                    stats.country = enriched["country"]
                if enriched.get("asn"):
                    stats.asn = str(enriched["asn"])
                if enriched.get("isp"):
                    stats.isp = enriched["isp"]
                stats.reputation_score = enriched.get("reputation_score", 0)
                await db.commit()


ip_enrichment_service = IPEnrichmentService()