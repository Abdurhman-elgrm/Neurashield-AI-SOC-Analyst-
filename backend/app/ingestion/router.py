from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import CurrentMember, CurrentUser, require_permission
from app.core.exceptions import LockedError, UnauthorizedError
from app.core.redis import TenantRedisClient, get_redis
from app.models.agent import ContainmentState
from app.ingestion.schemas import (
    AgentEnrollRequest,
    AgentEnrollResponse,
    HeartbeatRequest,
    IngestBatchRequest,
    IngestBatchResponse,
)
from app.ingestion.service import IngestionService
from app.models.agent import Agent
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse, EmptyResponse

router = APIRouter(prefix="/agents", tags=["agents"])


# ─── Agent management (requires tenant member auth) ───────────────────────────

@router.post("/enroll", response_model=APIResponse[AgentEnrollResponse], status_code=201)
async def enroll_agent(
    payload: AgentEnrollRequest,
    member: Annotated[object, require_permission(Permission.AGENTS_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[AgentEnrollResponse]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    result = await IngestionService.enroll_agent(
        db, m.tenant_id, payload, created_by_id=m.user_id
    )
    await db.commit()
    return APIResponse.ok(result)


# ─── Agent self-authentication helpers ────────────────────────────────────────

async def _get_authenticated_agent(
    x_agent_id: Annotated[str | None, Header(alias="X-Agent-ID")] = None,
    x_agent_token: Annotated[str | None, Header(alias="X-Agent-Token")] = None,
    x_tenant_id: Annotated[str | None, Header(alias="X-Tenant-ID")] = None,
    db: AsyncSession = Depends(get_db),
) -> Agent:
    if not x_agent_id or not x_agent_token or not x_tenant_id:
        raise UnauthorizedError("X-Agent-ID, X-Agent-Token, and X-Tenant-ID headers required")
    try:
        agent_id = UUID(x_agent_id)
        tenant_id = UUID(x_tenant_id)
    except ValueError:
        raise UnauthorizedError("Invalid agent or tenant ID format")

    return await IngestionService.authenticate_agent(db, tenant_id, agent_id, x_agent_token)


AuthenticatedAgent = Annotated[Agent, Depends(_get_authenticated_agent)]


# ─── Agent ingestion endpoints ────────────────────────────────────────────────

@router.post("/ingest", response_model=APIResponse[IngestBatchResponse])
async def ingest_batch(
    payload: IngestBatchRequest,
    agent: AuthenticatedAgent,
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated["object", Depends(get_redis)],
) -> APIResponse[IngestBatchResponse]:
    from redis.asyncio import Redis
    from app.pipeline import stream_names

    # Quarantined and isolated agents cannot send telemetry
    if agent.containment_state in (ContainmentState.QUARANTINED, ContainmentState.ISOLATED):
        raise LockedError(
            f"Agent is {agent.containment_state.value} — ingest blocked. "
            f"Reason: {agent.containment_reason or 'Security containment active'}",
        )

    redis_typed: Redis[str] = redis  # type: ignore[assignment]
    tenant_client = TenantRedisClient(
        redis_typed, str(agent.tenant_id), stream_names.SUBSYSTEM
    )

    # Per-tenant ingest rate limit — prevents a single noisy tenant from
    # exhausting pipeline capacity and starving other tenants.
    from app.core.config import settings as _settings
    from app.core.exceptions import RateLimitError as _RateLimitError
    _per_tenant_limit = _settings.RATE_LIMIT_INGEST_EVENTS
    _allowed, _remaining = await tenant_client.check_rate_limit(
        f"ingest_batch:{agent.id}",
        limit=_per_tenant_limit,
        window_secs=60,
    )
    if not _allowed:
        raise _RateLimitError(
            f"Ingest rate limit exceeded — tenant allows {_per_tenant_limit} events/min",
            retry_after=60,
        )

    result = await IngestionService.ingest_batch(db, tenant_client, agent, payload)
    await db.commit()
    return APIResponse.ok(result)


@router.post("/heartbeat", response_model=APIResponse[EmptyResponse])
async def heartbeat(
    payload: HeartbeatRequest,
    agent: AuthenticatedAgent,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[EmptyResponse]:
    # Quarantined agents cannot heartbeat — full lockout
    if agent.containment_state == ContainmentState.QUARANTINED:
        raise LockedError(
            f"Agent is quarantined — heartbeat blocked. "
            f"Reason: {agent.containment_reason or 'Security quarantine active'}",
        )

    await IngestionService.record_heartbeat(db, agent, payload)
    await db.commit()
    return APIResponse.ok(EmptyResponse())


@router.get("/pipeline-status")
async def pipeline_status(
    agent: AuthenticatedAgent,
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated["object", Depends(get_redis)],
) -> APIResponse:
    """Diagnostic endpoint: returns pipeline health for this tenant (agent auth)."""
    from datetime import datetime, timezone, timedelta
    from sqlalchemy import select, func as sqlfunc
    from app.models.event import Event
    from app.pipeline import stream_names

    now = datetime.now(tz=timezone.utc)
    cutoff_24h = now - timedelta(hours=24)
    cutoff_1h  = now - timedelta(hours=1)

    r24 = await db.execute(
        select(sqlfunc.count()).where(
            Event.tenant_id == agent.tenant_id,
            Event.ingested_at >= cutoff_24h,
        )
    )
    r1 = await db.execute(
        select(sqlfunc.count()).where(
            Event.tenant_id == agent.tenant_id,
            Event.ingested_at >= cutoff_1h,
        )
    )
    latest_row = await db.execute(
        select(Event.ingested_at).where(Event.tenant_id == agent.tenant_id)
        .order_by(Event.ingested_at.desc()).limit(1)
    )
    latest_ingested = latest_row.scalar_one_or_none()

    from redis.asyncio import Redis as _Redis
    redis_typed: _Redis[str] = redis  # type: ignore[assignment]
    pipeline_client = TenantRedisClient(redis_typed, str(agent.tenant_id), stream_names.SUBSYSTEM)

    try:
        stream_key = pipeline_client._key(stream_names.RAW_EVENTS)
        stream_len = await redis_typed.xlen(stream_key)
        pending = await pipeline_client.xpending_count(stream_names.RAW_EVENTS, stream_names.GROUP_NORMALIZE)
    except Exception:
        stream_len = -1
        pending = -1

    return APIResponse.ok({
        "tenant_id":          str(agent.tenant_id),
        "agent_id":           str(agent.id),
        "events_last_24h":    r24.scalar() or 0,
        "events_last_1h":     r1.scalar() or 0,
        "latest_ingested_at": latest_ingested.isoformat() if latest_ingested else None,
        "redis_stream_len":   stream_len,
        "pending_normalize":  pending,
        "checked_at":         now.isoformat(),
    })
