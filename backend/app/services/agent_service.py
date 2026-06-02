from __future__ import annotations

from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.models.agent import Agent
from app.schemas.agent import AgentUpdateRequest

logger = structlog.get_logger(__name__)


class AgentService:

    @staticmethod
    async def get_by_id(
        db: AsyncSession,
        tenant_id: UUID,
        agent_id: UUID,
    ) -> Agent | None:
        result = await db.execute(
            select(Agent).where(
                Agent.id == agent_id,
                Agent.tenant_id == tenant_id,
                Agent.deleted_at.is_(None),
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def require_by_id(
        db: AsyncSession,
        tenant_id: UUID,
        agent_id: UUID,
    ) -> Agent:
        agent = await AgentService.get_by_id(db, tenant_id, agent_id)
        if agent is None:
            raise NotFoundError(f"Agent {agent_id} not found")
        return agent

    @staticmethod
    async def list_agents(
        db: AsyncSession,
        tenant_id: UUID,
        page: int = 1,
        limit: int = 25,
    ) -> tuple[list[Agent], int]:
        offset = (page - 1) * limit

        total_result = await db.execute(
            select(func.count()).where(
                Agent.tenant_id == tenant_id,
                Agent.deleted_at.is_(None),
            )
        )
        total = total_result.scalar_one()

        result = await db.execute(
            select(Agent)
            .where(
                Agent.tenant_id == tenant_id,
                Agent.deleted_at.is_(None),
            )
            .order_by(Agent.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        agents = list(result.scalars().all())
        return agents, total

    @staticmethod
    async def update_agent(
        db: AsyncSession,
        tenant_id: UUID,
        agent_id: UUID,
        payload: AgentUpdateRequest,
        updated_by_id: UUID,
    ) -> Agent:
        agent = await AgentService.require_by_id(db, tenant_id, agent_id)

        if payload.name is not None:
            agent.name = payload.name
        if payload.config is not None:
            agent.config = payload.config
        if payload.tags is not None:
            agent.tags = payload.tags

        await db.flush()
        logger.info("agent_updated", agent_id=str(agent_id), tenant_id=str(tenant_id))
        return agent

    @staticmethod
    async def delete_agent(
        db: AsyncSession,
        tenant_id: UUID,
        agent_id: UUID,
    ) -> None:
        agent = await AgentService.require_by_id(db, tenant_id, agent_id)
        agent.soft_delete()
        await db.flush()
        logger.info("agent_deleted", agent_id=str(agent_id), tenant_id=str(tenant_id))
