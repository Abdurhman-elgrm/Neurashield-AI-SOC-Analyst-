from __future__ import annotations

import secrets
from datetime import UTC, datetime
from typing import Any
from uuid import UUID


async def _invalidate_dashboard_cache(tenant_id: str) -> None:
    try:
        from app.api.v1.dashboard import _invalidate_dashboard_cache as _dash_invalidate

        await _dash_invalidate(tenant_id)
    except Exception:
        pass


import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import UnauthorizedError
from app.core.metrics import AGENT_HEARTBEATS_TOTAL, EVENTS_INGESTED_TOTAL
from app.core.redis import TenantRedisClient
from app.core.security import hash_agent_token, verify_agent_token
from app.core.utils import create_task_safe
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

logger = structlog.get_logger(__name__)

_ENROLLMENT_TOKEN_BYTES = 32

# Explicit allowlist of extra fields an agent may send beyond the RawEventPayload schema.
# Windows Event Log structured fields + Sysmon modern channel fields only.
_ALLOWED_EXTRA_FIELDS: frozenset[str] = frozenset(
    {
        "event_id_windows",
        "Image",
        "CommandLine",
        "ParentImage",
        "ParentCommandLine",
        "TargetUserName",
        "SubjectUserName",
        "TargetDomainName",
        "SubjectDomainName",
        "ServiceName",
        "GroupName",
        "MemberName",
        "ProcessId",
        "ParentProcessId",
        "LogonType",
        "PrivilegeList",
        "WorkstationName",
        "CurrentDirectory",
        "IntegrityLevel",
        "TargetObject",
        "Details",
        "EventType",
        "RuleName",
        "DestinationIp",
        "DestinationPort",
        "SourceIp",
        "SourcePort",
        "Protocol",
        "DestinationHostname",
        "source_ip",
    }
)

_VALID_CATEGORIES: frozenset[str] = frozenset(
    {"auth", "process", "network", "file", "dns", "registry", "other"}
)
_MAX_FUTURE_SKEW_SECONDS = 300  # 5 minutes — reject events timestamped too far in future


def _sanitize_event_fields(event: RawEventPayload, now: datetime) -> RawEventPayload:
    """
    Sanitize agent-supplied event fields to prevent injection attacks.
    Returns a new model instance with sanitized fields (Pydantic models are immutable).
    """
    updates: dict[str, Any] = {}

    # Clamp unknown categories to "other"
    if event.category not in _VALID_CATEGORIES:
        updates["category"] = "other"

    # Reject events timestamped more than 5 min in the future (agent clock manipulation)
    if event.timestamp.tzinfo is None:
        ts = event.timestamp.replace(tzinfo=UTC)
    else:
        ts = event.timestamp
    if (ts - now).total_seconds() > _MAX_FUTURE_SKEW_SECONDS:
        updates["timestamp"] = now

    if updates:
        return event.model_copy(update=updates)
    return event


class IngestionService:
    @staticmethod
    async def enroll_agent(
        db: AsyncSession,
        tenant_id: UUID,
        payload: AgentEnrollRequest,
        created_by_id: UUID,
    ) -> AgentEnrollResponse:
        raw_token = secrets.token_urlsafe(_ENROLLMENT_TOKEN_BYTES)
        token_hash = hash_agent_token(raw_token)

        # Re-enrollment: if a non-deleted agent with the same hostname already
        # exists for this tenant, rotate its token and update metadata instead
        # of creating a duplicate record.
        existing = await db.execute(
            select(Agent)
            .where(
                Agent.tenant_id == tenant_id,
                Agent.hostname == payload.hostname,
                Agent.deleted_at.is_(None),
            )
            .limit(1)
        )
        agent = existing.scalar_one_or_none()

        if agent is not None:
            agent.enrollment_token_hash = token_hash
            agent.agent_version = payload.agent_version
            agent.ip_address = payload.ip_address
            agent.os_type = AgentOsType(payload.os_type)
            agent.status = AgentStatus.OFFLINE
            await db.flush()
            logger.info(
                "agent_re_enrolled",
                agent_id=str(agent.id),
                tenant_id=str(tenant_id),
                hostname=payload.hostname,
            )
        else:
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

        if not verify_agent_token(enrollment_token, agent.enrollment_token_hash):
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

        from datetime import datetime

        _now = datetime.now(tz=UTC)
        sanitized_events = [_sanitize_event_fields(e, _now) for e in payload.events]

        idempotency = IdempotencyStore(redis_client)
        publisher = StreamPublisher(redis_client)

        accepted = 0
        rejected = 0
        duplicates = 0
        stream_ids: list[str] = []

        for event in sanitized_events:
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

        if accepted > 0:
            EVENTS_INGESTED_TOTAL.labels(tenant_id=str(agent.tenant_id)).inc(accepted)
            create_task_safe(
                _invalidate_dashboard_cache(str(agent.tenant_id)),
                name=f"invalidate_dashboard_{agent.tenant_id}",
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
        now = datetime.now(tz=UTC)

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

        AGENT_HEARTBEATS_TOTAL.labels(tenant_id=str(agent.tenant_id)).inc()


def _build_stream_message(agent: Agent, event: RawEventPayload) -> dict[str, Any]:
    # Spread allowlisted extra fields (e.g. event_id_windows, Image, CommandLine, TargetUserName
    # sent by the Windows agent) so the normalizer can read them at the top level.
    message: dict[str, Any] = {
        k: v for k, v in (event.model_extra or {}).items() if k in _ALLOWED_EXTRA_FIELDS
    }
    message.update(
        {
            # Authoritative agent metadata — always override what the agent claims
            "agent_id": str(agent.id),
            "tenant_id": str(agent.tenant_id),
            "hostname": agent.hostname,
            "os_type": agent.os_type.value,
            # Named event fields
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "category": event.category,
            "process": event.process,
            "user": event.user,
            "network": event.network,
            "file": event.file,
            "registry": event.registry,
            "raw": event.raw,
        }
    )
    return message
