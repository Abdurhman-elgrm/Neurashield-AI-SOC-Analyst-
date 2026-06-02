from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import CurrentMember, CurrentUser, require_permission
from app.core.exceptions import UnauthorizedError
from app.core.redis import TenantRedisClient, get_redis
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

    redis_typed: Redis[str] = redis  # type: ignore[assignment]
    tenant_client = TenantRedisClient(
        redis_typed, str(agent.tenant_id), stream_names.SUBSYSTEM
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
    await IngestionService.record_heartbeat(db, agent, payload)
    await db.commit()
    return APIResponse.ok(EmptyResponse())
