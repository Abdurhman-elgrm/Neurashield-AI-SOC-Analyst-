from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.rbac.permissions import Permission
from app.schemas.agent import AgentResponse, AgentUpdateRequest
from app.schemas.common import APIResponse, EmptyResponse, PaginatedResponse
from app.schemas.playbook import (
    ContainmentRequest,
    ContainmentStatusResponse,
    ResponseActionResponse,
)
from app.services.agent_service import AgentService
from app.services.audit_service import AuditService
from app.services.containment_service import ContainmentService

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
        page=page,
        limit=limit,
        total=total,
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
        db,
        action="agent.updated",
        actor_id=m.user_id,
        actor_role=m.role,
        tenant_id=m.tenant_id,
        resource_type="agent",
        resource_id=agent_id,
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
        db,
        action="agent.deleted",
        actor_id=m.user_id,
        actor_role=m.role,
        tenant_id=m.tenant_id,
        resource_type="agent",
        resource_id=agent_id,
    )
    await db.commit()
    return APIResponse.ok(EmptyResponse())


# ── Agent Containment ─────────────────────────────────────────────────────────


@router.get("/{agent_id}/containment", response_model=APIResponse[ContainmentStatusResponse])
async def get_containment_status(
    agent_id: UUID,
    member: Annotated[object, require_permission(Permission.AGENTS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[ContainmentStatusResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    agent = await AgentService.require_by_id(db, m.tenant_id, agent_id)
    return APIResponse.ok(
        ContainmentStatusResponse(
            agent_id=agent.id,
            hostname=agent.hostname,
            containment_state=agent.containment_state.value,
            containment_reason=agent.containment_reason,
            contained_at=agent.contained_at,
            contained_by_id=agent.contained_by_id,
        )
    )


@router.post("/{agent_id}/quarantine", response_model=APIResponse[ContainmentStatusResponse])
async def quarantine_agent(
    agent_id: UUID,
    payload: ContainmentRequest,
    member: Annotated[object, require_permission(Permission.RESPONSE_EXECUTE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[ContainmentStatusResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    agent = await ContainmentService.quarantine(
        db=db,
        tenant_id=m.tenant_id,
        agent_id=agent_id,
        actor_id=m.user_id,
        reason=payload.reason,
        alert_id=payload.alert_id,
    )
    await AuditService.log(
        db,
        action="agent.quarantined",
        actor_id=m.user_id,
        actor_role=m.role,
        tenant_id=m.tenant_id,
        resource_type="agent",
        resource_id=agent_id,
        changes={"reason": payload.reason},
    )
    await db.commit()
    return APIResponse.ok(
        ContainmentStatusResponse(
            agent_id=agent.id,
            hostname=agent.hostname,
            containment_state=agent.containment_state.value,
            containment_reason=agent.containment_reason,
            contained_at=agent.contained_at,
            contained_by_id=agent.contained_by_id,
        )
    )


@router.post("/{agent_id}/isolate", response_model=APIResponse[ContainmentStatusResponse])
async def isolate_agent(
    agent_id: UUID,
    payload: ContainmentRequest,
    member: Annotated[object, require_permission(Permission.RESPONSE_EXECUTE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[ContainmentStatusResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    agent = await ContainmentService.isolate(
        db=db,
        tenant_id=m.tenant_id,
        agent_id=agent_id,
        actor_id=m.user_id,
        reason=payload.reason,
        alert_id=payload.alert_id,
    )
    await AuditService.log(
        db,
        action="agent.isolated",
        actor_id=m.user_id,
        actor_role=m.role,
        tenant_id=m.tenant_id,
        resource_type="agent",
        resource_id=agent_id,
        changes={"reason": payload.reason},
    )
    await db.commit()
    return APIResponse.ok(
        ContainmentStatusResponse(
            agent_id=agent.id,
            hostname=agent.hostname,
            containment_state=agent.containment_state.value,
            containment_reason=agent.containment_reason,
            contained_at=agent.contained_at,
            contained_by_id=agent.contained_by_id,
        )
    )


@router.post("/{agent_id}/release", response_model=APIResponse[ContainmentStatusResponse])
async def release_agent(
    agent_id: UUID,
    payload: ContainmentRequest,
    member: Annotated[object, require_permission(Permission.RESPONSE_EXECUTE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[ContainmentStatusResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    agent = await ContainmentService.release(
        db=db,
        tenant_id=m.tenant_id,
        agent_id=agent_id,
        actor_id=m.user_id,
        reason=payload.reason,
    )
    await AuditService.log(
        db,
        action="agent.released",
        actor_id=m.user_id,
        actor_role=m.role,
        tenant_id=m.tenant_id,
        resource_type="agent",
        resource_id=agent_id,
        changes={"reason": payload.reason},
    )
    await db.commit()
    return APIResponse.ok(
        ContainmentStatusResponse(
            agent_id=agent.id,
            hostname=agent.hostname,
            containment_state=agent.containment_state.value,
            containment_reason=agent.containment_reason,
            contained_at=agent.contained_at,
            contained_by_id=agent.contained_by_id,
        )
    )


@router.get(
    "/{agent_id}/response-actions", response_model=APIResponse[list[ResponseActionResponse]]
)
async def list_agent_response_actions(
    agent_id: UUID,
    member: Annotated[object, require_permission(Permission.AGENTS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[list[ResponseActionResponse]]:
    from app.models.response_action import ResponseAction
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    # Verify agent belongs to tenant
    await AgentService.require_by_id(db, m.tenant_id, agent_id)
    result = await db.execute(
        select(ResponseAction)
        .where(
            ResponseAction.tenant_id == m.tenant_id,
            ResponseAction.agent_id == agent_id,
        )
        .order_by(ResponseAction.created_at.desc())
        .limit(100)
    )
    actions = list(result.scalars().all())
    return APIResponse.ok([ResponseActionResponse.model_validate(a) for a in actions])
