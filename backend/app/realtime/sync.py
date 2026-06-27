from __future__ import annotations

"""
SyncEngine — bridges the analyst workspace mutation layer with the
realtime broadcast system.

Call these static methods AFTER a mutation succeeds and is committed.
Each method creates the appropriate RealtimeEvent and publishes it to Redis.

No DB calls happen here — all data is passed in as arguments.
The caller (API layer or worker) is responsible for providing the data.
"""


from typing import Any

import structlog

from app.core.redis import TenantRedisClient
from app.realtime import events as ev
from app.realtime.broadcast import RealtimeBroadcaster

logger = structlog.get_logger(__name__)


class SyncEngine:
    @staticmethod
    async def on_investigation_created(
        client: TenantRedisClient,
        tenant_id: str,
        actor_id: str,
        investigation_id: str,
        threat_score: int,
        confidence: str,
        status: str,
    ) -> None:
        event = ev.realtime_investigation_created(
            tenant_id, actor_id, investigation_id, threat_score, confidence, status
        )
        await RealtimeBroadcaster.broadcast_event(client, event)

    @staticmethod
    async def on_investigation_updated(
        client: TenantRedisClient,
        tenant_id: str,
        actor_id: str,
        investigation_id: str,
        changes: dict[str, Any],
    ) -> None:
        event = ev.realtime_investigation_updated(tenant_id, actor_id, investigation_id, changes)
        await RealtimeBroadcaster.broadcast_event(client, event)

    @staticmethod
    async def on_verdict_changed(
        client: TenantRedisClient,
        tenant_id: str,
        actor_id: str,
        investigation_id: str,
        new_verdict: str,
        previous_verdict: str | None = None,
        reasoning: str | None = None,
    ) -> None:
        event = ev.realtime_verdict_changed(
            tenant_id,
            actor_id,
            investigation_id,
            new_verdict,
            previous_verdict,
            reasoning,
        )
        await RealtimeBroadcaster.broadcast_event(client, event)

    @staticmethod
    async def on_assignment_changed(
        client: TenantRedisClient,
        tenant_id: str,
        actor_id: str,
        investigation_id: str,
        assigned_to: str,
        escalated: bool = False,
        escalation_reason: str | None = None,
    ) -> None:
        event = ev.realtime_investigation_assigned(
            tenant_id,
            actor_id,
            investigation_id,
            assigned_to,
            escalated,
            escalation_reason,
        )
        await RealtimeBroadcaster.broadcast_event(client, event)

    @staticmethod
    async def on_status_changed(
        client: TenantRedisClient,
        tenant_id: str,
        actor_id: str,
        investigation_id: str,
        new_status: str,
        reason: str | None = None,
    ) -> None:
        event = ev.realtime_investigation_updated(
            tenant_id,
            actor_id,
            investigation_id,
            {"new_status": new_status, "reason": reason},
        )
        await RealtimeBroadcaster.broadcast_event(client, event)

    @staticmethod
    async def on_note_added(
        client: TenantRedisClient,
        tenant_id: str,
        actor_id: str,
        investigation_id: str,
        note_id: str,
        content_preview: str,
        pinned: bool = False,
    ) -> None:
        event = ev.realtime_note_created(
            tenant_id, actor_id, investigation_id, note_id, content_preview, pinned
        )
        await RealtimeBroadcaster.broadcast_event(client, event)

    @staticmethod
    async def on_note_updated(
        client: TenantRedisClient,
        tenant_id: str,
        actor_id: str,
        investigation_id: str,
        note_id: str,
    ) -> None:
        event = ev.realtime_note_updated(tenant_id, actor_id, investigation_id, note_id)
        await RealtimeBroadcaster.broadcast_event(client, event)

    @staticmethod
    async def on_evidence_added(
        client: TenantRedisClient,
        tenant_id: str,
        actor_id: str,
        investigation_id: str,
        evidence_id: str,
        title: str,
        evidence_type: str,
    ) -> None:
        event = ev.realtime_evidence_added(
            tenant_id, actor_id, investigation_id, evidence_id, title, evidence_type
        )
        await RealtimeBroadcaster.broadcast_event(client, event)

    @staticmethod
    async def on_case_merged(
        client: TenantRedisClient,
        tenant_id: str,
        actor_id: str,
        primary_id: str,
        secondary_ids: list[str],
        reason: str | None = None,
    ) -> None:
        event = ev.realtime_case_merged(tenant_id, actor_id, primary_id, secondary_ids, reason)
        await RealtimeBroadcaster.broadcast_event(client, event)

    @staticmethod
    async def on_case_closed(
        client: TenantRedisClient,
        tenant_id: str,
        actor_id: str,
        investigation_id: str,
        verdict: str | None = None,
    ) -> None:
        event = ev.realtime_case_closed(tenant_id, actor_id, investigation_id, verdict)
        await RealtimeBroadcaster.broadcast_event(client, event)

    @staticmethod
    async def on_hunt_completed(
        client: TenantRedisClient,
        tenant_id: str,
        actor_id: str,
        result_count: int,
        hunt_id: str | None = None,
        query_summary: str = "",
    ) -> None:
        event = ev.realtime_hunt_completed(
            tenant_id, actor_id, hunt_id, result_count, query_summary
        )
        await RealtimeBroadcaster.broadcast_event(client, event)

    @staticmethod
    async def on_analyst_joined(
        client: TenantRedisClient,
        tenant_id: str,
        analyst_id: str,
        display_name: str,
        workspace: str,
    ) -> None:
        event = ev.realtime_analyst_joined(tenant_id, analyst_id, display_name, workspace)
        await RealtimeBroadcaster.broadcast_event(client, event)

    @staticmethod
    async def on_analyst_left(
        client: TenantRedisClient,
        tenant_id: str,
        analyst_id: str,
    ) -> None:
        event = ev.realtime_analyst_left(tenant_id, analyst_id)
        await RealtimeBroadcaster.broadcast_event(client, event)

    @staticmethod
    async def on_analyst_typing(
        client: TenantRedisClient,
        tenant_id: str,
        analyst_id: str,
        investigation_id: str,
    ) -> None:
        event = ev.realtime_analyst_typing(tenant_id, analyst_id, investigation_id)
        await RealtimeBroadcaster.broadcast_event(client, event)
