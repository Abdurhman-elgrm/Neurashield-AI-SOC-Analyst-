"""
ConnectorService — authenticates via API key, then queues parsed events
into the raw_events Redis stream.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.base import ParsedEvent
from app.core.exceptions import NotFoundError, UnauthorizedError
from app.core.redis import TenantRedisClient
from app.models.api_key import ApiKey
from app.pipeline import stream_names
from app.pipeline.publisher import StreamPublisher

logger = structlog.get_logger(__name__)


class ConnectorService:

    @staticmethod
    async def resolve_tenant(db: AsyncSession, raw_key: str) -> UUID:
        """
        Validate an API key and return the associated tenant_id.
        Raises UnauthorizedError if the key is missing, invalid, or expired.
        """
        if not raw_key:
            raise UnauthorizedError("X-API-Key header is required")

        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

        result = await db.execute(
            select(ApiKey).where(
                ApiKey.key_hash == key_hash,
                ApiKey.revoked_at.is_(None),
            )
        )
        key = result.scalar_one_or_none()
        if key is None:
            raise UnauthorizedError("Invalid or revoked API key")

        if key.expires_at and key.expires_at < datetime.now(tz=timezone.utc):
            raise UnauthorizedError("API key has expired")

        # Touch last_used_at (best-effort, no commit required)
        key.last_used_at = datetime.now(tz=timezone.utc)

        logger.debug(
            "connector_api_key_resolved",
            key_prefix=key.key_prefix,
            tenant_id=str(key.tenant_id),
        )

        return key.tenant_id

    @staticmethod
    async def ingest(
        tenant_id: UUID,
        parsed_events: list[ParsedEvent],
        redis_client: TenantRedisClient,
        source_type: str,
    ) -> dict[str, Any]:
        """Publish parsed events to the raw_events stream."""
        publisher = StreamPublisher(redis_client)
        accepted = 0
        rejected = 0

        for evt in parsed_events:
            try:
                msg = evt.to_stream_message(str(tenant_id))
                await publisher.publish_raw_event(msg)
                accepted += 1
            except Exception as exc:
                rejected += 1
                logger.error(
                    "connector_event_publish_failed",
                    source_type=source_type,
                    error=str(exc),
                )

        logger.info(
            "connector_events_ingested",
            source_type=source_type,
            tenant_id=str(tenant_id),
            accepted=accepted,
            rejected=rejected,
        )

        return {
            "accepted": accepted,
            "rejected": rejected,
            "source_type": source_type,
        }
