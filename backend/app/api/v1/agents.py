from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import CurrentMember, require_permission
from app.rbac.permissions import Permission
from app.schemas.agent import AgentResponse, AgentUpdateRequest
from app.schemas.common import APIResponse, EmptyResponse, PaginatedResponse, PaginationParams
from app.services.agent_service import AgentService
from app.services.audit_service import AuditService

router = APIRouter(prefix="/agents", tags=["agents"])


@router.get("", response_model=PaginatedResponse[AgentResponse])
async def list_agents(
    member: Annotated[object, require_permission(Permission.AGENTS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=25, ge=1, le=100),
) -> PaginatedResponse[AgentResponse]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    agents, total = await AgentService.list_agents(db, m.tenant_id, page=page, limit=limit)
    return PaginatedResponse[AgentResponse].offset(
        data=[AgentResponse.model_validate(a) for a in agents],
        page=page, limit=limit, total=total,
    )


@router.get("/{agent_id}", response_model=APIResponse[AgentResponse])
async def get_agent(
    agent_id: UUID,
    member: Annotated[object, require_permission(Permission.AGENTS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[AgentResponse]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    agent = await AgentService.require_by_id(db, m.tenant_id, agent_id)
    return APIResponse.ok(AgentResponse.model_validate(agent))


@router.patch("/{agent_id}", response_model=APIResponse[AgentResponse])
async def update_agent(
    agent_id: UUID,
    payload: AgentUpdateRequest,
    member: Annotated[object, require_permission(Permission.AGENTS_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[AgentResponse]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    agent = await AgentService.update_agent(db, m.tenant_id, agent_id, payload, m.user_id)
    await AuditService.log(
        db, action="agent.updated", actor_id=m.user_id, actor_role=m.role,
        tenant_id=m.tenant_id, resource_type="agent", resource_id=agent_id,
    )
    await db.commit()
    return APIResponse.ok(AgentResponse.model_validate(agent))


@router.delete("/{agent_id}", response_model=APIResponse[EmptyResponse])
async def delete_agent(
    agent_id: UUID,
    member: Annotated[object, require_permission(Permission.AGENTS_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[EmptyResponse]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    await AgentService.delete_agent(db, m.tenant_id, agent_id)
    await AuditService.log(
        db, action="agent.deleted", actor_id=m.user_id, actor_role=m.role,
        tenant_id=m.tenant_id, resource_type="agent", resource_id=agent_id,
    )
    await db.commit()
    return APIResponse.ok(EmptyResponse())
