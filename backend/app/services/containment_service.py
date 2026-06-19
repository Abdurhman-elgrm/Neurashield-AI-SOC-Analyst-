"""
Agent Containment Service — quarantine, isolate, and release agents.

Containment states:
  none        — normal operation
  quarantined — blocks both heartbeat and ingest (full lockout)
  isolated    — blocks ingest only (agent can still check in but sends no data)
  muted       — ingest continues, but alerts are suppressed

All state transitions are logged to response_actions for full audit trail.
WebSocket broadcast is sent on every state change.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent, ContainmentState
from app.models.response_action import ResponseAction
from app.services.agent_service import AgentService

logger = structlog.get_logger(__name__)


class ContainmentService:

    @staticmethod
    async def quarantine(
        db: AsyncSession,
        tenant_id: UUID,
        agent_id: UUID,
        actor_id: UUID,
        reason: str,
        alert_id: UUID | None = None,
        playbook_step_id: UUID | None = None,
    ) -> Agent:
        return await ContainmentService._set_state(
            db=db,
            tenant_id=tenant_id,
            agent_id=agent_id,
            actor_id=actor_id,
            new_state=ContainmentState.QUARANTINED,
            reason=reason,
            action_type="quarantine",
            alert_id=alert_id,
            playbook_step_id=playbook_step_id,
        )

    @staticmethod
    async def isolate(
        db: AsyncSession,
        tenant_id: UUID,
        agent_id: UUID,
        actor_id: UUID,
        reason: str,
        alert_id: UUID | None = None,
        playbook_step_id: UUID | None = None,
    ) -> Agent:
        return await ContainmentService._set_state(
            db=db,
            tenant_id=tenant_id,
            agent_id=agent_id,
            actor_id=actor_id,
            new_state=ContainmentState.ISOLATED,
            reason=reason,
            action_type="isolate",
            alert_id=alert_id,
            playbook_step_id=playbook_step_id,
        )

    @staticmethod
    async def mute(
        db: AsyncSession,
        tenant_id: UUID,
        agent_id: UUID,
        actor_id: UUID,
        reason: str,
    ) -> Agent:
        return await ContainmentService._set_state(
            db=db,
            tenant_id=tenant_id,
            agent_id=agent_id,
            actor_id=actor_id,
            new_state=ContainmentState.MUTED,
            reason=reason,
            action_type="mute",
        )

    @staticmethod
    async def release(
        db: AsyncSession,
        tenant_id: UUID,
        agent_id: UUID,
        actor_id: UUID,
        reason: str = "Manual release",
    ) -> Agent:
        return await ContainmentService._set_state(
            db=db,
            tenant_id=tenant_id,
            agent_id=agent_id,
            actor_id=actor_id,
            new_state=ContainmentState.NONE,
            reason=reason,
            action_type="release",
        )

    @staticmethod
    async def _set_state(
        db: AsyncSession,
        tenant_id: UUID,
        agent_id: UUID,
        actor_id: UUID,
        new_state: ContainmentState,
        reason: str,
        action_type: str,
        alert_id: UUID | None = None,
        playbook_step_id: UUID | None = None,
    ) -> Agent:
        agent = await AgentService.require_by_id(db, tenant_id, agent_id)

        previous_state = agent.containment_state

        if new_state == ContainmentState.NONE:
            agent.containment_state = ContainmentState.NONE
            agent.containment_reason = None
            agent.contained_at = None
            agent.contained_by_id = None
        else:
            agent.containment_state = new_state
            agent.containment_reason = reason
            agent.contained_at = datetime.now(tz=timezone.utc)
            agent.contained_by_id = actor_id

        action = ResponseAction(
            tenant_id=tenant_id,
            agent_id=agent_id,
            alert_id=alert_id,
            playbook_step_id=playbook_step_id,
            actor_id=actor_id,
            action_type=action_type,
            target_type="agent",
            target_id=str(agent_id),
            target_name=agent.hostname,
            status="success",
            result=f"State changed from {previous_state.value} to {new_state.value}",
            action_metadata={
                "reason": reason,
                "previous_state": previous_state.value,
                "new_state": new_state.value,
            },
        )
        db.add(action)
        await db.flush()

        # Non-blocking WebSocket broadcast
        asyncio.create_task(
            _broadcast_containment_change(tenant_id, agent, new_state, reason)
        )

        logger.info(
            "agent_containment_state_changed",
            agent_id=str(agent_id),
            tenant_id=str(tenant_id),
            previous_state=previous_state.value,
            new_state=new_state.value,
            actor_id=str(actor_id),
        )
        return agent


async def _broadcast_containment_change(
    tenant_id: UUID,
    agent: Agent,
    new_state: ContainmentState,
    reason: str,
) -> None:
    try:
        import json
        from app.core.redis import redis_manager, TenantRedisClient
        from app.pipeline import stream_names

        redis = redis_manager.get_client()
        ws_client = TenantRedisClient(redis, str(tenant_id), "pipeline")
        payload = json.dumps({
            "type": "agent.containment_changed",
            "agent_id": str(agent.id),
            "hostname": agent.hostname,
            "containment_state": new_state.value,
            "reason": reason,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        })
        await ws_client.publish(stream_names.ALERTS_PUBSUB_CHANNEL, payload)
    except Exception:
        logger.warning("containment_ws_broadcast_failed", exc_info=True)
