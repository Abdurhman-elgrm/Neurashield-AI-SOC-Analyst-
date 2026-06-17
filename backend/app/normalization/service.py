from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.event import Event, EventCategory
from app.normalization.mapper import map_stream_message_to_normalized
from app.normalization.models import NormalizedEvent
from app.threat_intel.service import EnrichmentResult

logger = structlog.get_logger(__name__)


class NormalizationService:

    @staticmethod
    def normalize(message: dict[str, Any]) -> NormalizedEvent:
        return map_stream_message_to_normalized(message)

    @staticmethod
    async def persist_event(
        db: AsyncSession,
        normalized: NormalizedEvent,
        stream_id: str | None = None,
        enrichment: EnrichmentResult | None = None,
    ) -> Event:
        """
        Persists a NormalizedEvent to the events table and returns the ORM object.
        Uses flush() so the ID is available without committing the outer transaction.
        """
        try:
            category = EventCategory(normalized.category)
        except ValueError:
            category = EventCategory.OTHER

        proc_dict = dataclasses.asdict(normalized.process) if normalized.process else None
        net_dict = dataclasses.asdict(normalized.network) if normalized.network else None
        file_dict = dataclasses.asdict(normalized.file) if normalized.file else None
        user_dict = dataclasses.asdict(normalized.user) if normalized.user else None

        enr = enrichment or EnrichmentResult()

        event = Event(
            tenant_id=UUID(normalized.tenant_id),
            agent_id=UUID(normalized.agent_id) if normalized.agent_id else None,
            stream_id=stream_id,
            raw_id=normalized.event_id or None,
            category=category,
            severity=normalized.severity,
            event_timestamp=normalized.timestamp or datetime.now(tz=timezone.utc),
            ingested_at=normalized.ingested_at,
            host_name=normalized.hostname or None,
            source_ip=normalized.source_ip,
            dest_ip=normalized.dest_ip,
            process_name=normalized.process_name,
            username=normalized.username,
            process=proc_dict,
            user=user_dict,
            network=net_dict,
            file=file_dict,
            registry=normalized.registry,
            normalized=normalized.to_dict(),
            raw_payload=normalized.raw,
            tags=normalized.tags,
            # GeoIP
            geo_country=enr.geo_country,
            geo_country_code=enr.geo_country_code,
            geo_city=enr.geo_city,
            geo_latitude=enr.geo_latitude,
            geo_longitude=enr.geo_longitude,
            geo_isp=enr.geo_isp,
            # Threat Intel
            abuse_confidence=enr.abuse_confidence,
            is_threat_ip=enr.is_threat_ip,
            threat_intel_flags=enr.threat_intel_flags,
        )

        db.add(event)
        await db.flush()

        logger.debug(
            "event_persisted",
            event_id=str(event.id),
            category=category.value,
            tenant_id=normalized.tenant_id,
            is_threat_ip=enr.is_threat_ip,
            geo_country=enr.geo_country,
        )

        return event
