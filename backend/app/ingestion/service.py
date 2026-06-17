from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError, UnauthorizedError
from app.core.redis import TenantRedisClient
from app.core.security import hash_password, verify_password
from app.ingestion.idempotency import IdempotencyStore
from app.ingestion.schemas import (
    AgentEnrollRequest,
    AgentEnrollResponse,
    HeartbeatRequest,
    IngestBatchRequest,
    IngestBatchResponse,
    RawEventPayload,
)
from app.ingestion.validators import validate_batch
from app.models.agent import Agent, AgentOsType, AgentStatus
from app.models.heartbeat import Heartbeat
from app.pipeline.publisher import StreamPublisher
from app.pipeline import stream_names

logger = structlog.get_logger(__name__)

_ENROLLMENT_TOKEN_BYTES = 32


class IngestionService:

    @staticmethod
    async def enroll_agent(
        db: AsyncSession,
        tenant_id: UUID,
        payload: AgentEnrollRequest,
        created_by_id: UUID,
    ) -> AgentEnrollResponse:
        raw_token = secrets.token_urlsafe(_ENROLLMENT_TOKEN_BYTES)
        token_hash = hash_password(raw_token)

        agent = Agent(
            tenant_id=tenant_id,
            name=payload.name,
            hostname=payload.hostname,
            os_type=AgentOsType(payload.os_type),
            status=AgentStatus.OFFLINE,
            agent_version=payload.agent_version,
            ip_address=payload.ip_address,
            enrollment_token_hash=token_hash,
            config={},
            tags=payload.tags,
        )
        db.add(agent)
        await db.flush()

        logger.info(
            "agent_enrolled",
            agent_id=str(agent.id),
            tenant_id=str(tenant_id),
            hostname=payload.hostname,
        )

        return AgentEnrollResponse(
            agent_id=agent.id,
            enrollment_token=raw_token,
            config=agent.config,
        )

    @staticmethod
    async def authenticate_agent(
        db: AsyncSession,
        tenant_id: UUID,
        agent_id: UUID,
        enrollment_token: str,
    ) -> Agent:
        """Validates agent credentials, returns Agent or raises UnauthorizedError."""
        result = await db.execute(
            select(Agent).where(
                Agent.id == agent_id,
                Agent.tenant_id == tenant_id,
                Agent.deleted_at.is_(None),
            )
        )
        agent = result.scalar_one_or_none()
        if agent is None:
            raise UnauthorizedError("Agent not found")

        if not verify_password(enrollment_token, agent.enrollment_token_hash):
            raise UnauthorizedError("Invalid agent credentials")

        return agent

    @staticmethod
    async def ingest_batch(
        db: AsyncSession,
        redis_client: TenantRedisClient,
        agent: Agent,
        payload: IngestBatchRequest,
    ) -> IngestBatchResponse:
        validate_batch(payload.events)

        idempotency = IdempotencyStore(redis_client)
        publisher = StreamPublisher(redis_client)

        accepted = 0
        rejected = 0
        duplicates = 0
        stream_ids: list[str] = []

        for event in payload.events:
            if await idempotency.is_duplicate(event.event_id):
                duplicates += 1
                logger.debug("duplicate_event_skipped", event_id=event.event_id)
                continue

            try:
                message = _build_stream_message(agent, event)
                stream_id = await publisher.publish_raw_event(message)
                await idempotency.mark_seen(event.event_id, stream_id)
                stream_ids.append(stream_id)
                accepted += 1
            except Exception as exc:
                rejected += 1
                logger.error(
                    "event_publish_failed",
                    event_id=event.event_id,
                    error=str(exc),
                )

        logger.info(
            "batch_ingested",
            tenant_id=str(agent.tenant_id),
            agent_id=str(agent.id),
            accepted=accepted,
            rejected=rejected,
            duplicates=duplicates,
        )

        return IngestBatchResponse(
            accepted=accepted,
            rejected=rejected,
            duplicate=duplicates,
            stream_ids=stream_ids,
        )

    @staticmethod
    async def record_heartbeat(
        db: AsyncSession,
        agent: Agent,
        payload: HeartbeatRequest,
    ) -> None:
        now = datetime.now(tz=timezone.utc)

        heartbeat = Heartbeat(
            tenant_id=agent.tenant_id,
            agent_id=agent.id,
            received_at=now,
            agent_version=payload.agent_version,
            ip_address=payload.ip_address,
            os_metrics=payload.os_metrics,
        )
        db.add(heartbeat)

        agent.last_seen_at = now
        agent.status = AgentStatus.ONLINE
        if payload.agent_version:
            agent.agent_version = payload.agent_version
        if payload.ip_address:
            agent.ip_address = payload.ip_address

        await db.flush()


def _build_stream_message(agent: Agent, event: RawEventPayload) -> dict[str, Any]:
    # Spread extra fields first (e.g. event_id_windows, Image, CommandLine, TargetUserName
    # sent by the Windows agent) so the normalizer can read them at the top level.
    message: dict[str, Any] = {**(event.model_extra or {})}
    message.update({
        # Authoritative agent metadata — always override what the agent claims
        "agent_id":  str(agent.id),
        "tenant_id": str(agent.tenant_id),
        "hostname":  agent.hostname,
        "os_type":   agent.os_type.value,
        # Named event fields
        "event_id":  event.event_id,
        "timestamp": event.timestamp.isoformat(),
        "category":  event.category,
        "process":   event.process,
        "user":      event.user,
        "network":   event.network,
        "file":      event.file,
        "registry":  event.registry,
        "raw":       event.raw,
    })
    return message
