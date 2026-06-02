from __future__ import annotations

"""
Typed event constructors for the realtime system.

Two parallel APIs live here:
  1. Legacy WSMessage constructors (Phase 2) — kept for backward compatibility.
  2. RealtimeEvent constructors (Phase 3.5) — strongly typed, channel-aware.

All Phase 3.5 callers should use the realtime_* helpers below.
"""

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import orjson
from pydantic import BaseModel, ConfigDict

from app.realtime import channels as ch
from app.realtime.schemas import RealtimeEvent, RealtimeEventType


# ─── Phase 2 legacy envelope (kept for /ws backward compat) ──────────────────

class WSMessage(BaseModel):
    model_config = ConfigDict(frozen=True)

    v:         int = 1
    type:      str
    tenant_id: str
    payload:   dict[str, Any]
    ts:        str = ""

    def model_post_init(self, __context: Any) -> None:
        object.__setattr__(self, "ts", datetime.now(tz=timezone.utc).isoformat())

    def to_json(self) -> str:
        return orjson.dumps(self.model_dump()).decode()


# ─── Phase 2 constructors ─────────────────────────────────────────────────────

def alert_created_msg(tenant_id: str, alert: dict[str, Any]) -> WSMessage:
    return WSMessage(type="alert.created", tenant_id=tenant_id, payload=alert)


def alert_updated_msg(tenant_id: str, alert: dict[str, Any]) -> WSMessage:
    return WSMessage(type="alert.updated", tenant_id=tenant_id, payload=alert)


def event_ingested_msg(tenant_id: str, event_summary: dict[str, Any]) -> WSMessage:
    return WSMessage(type="event.ingested", tenant_id=tenant_id, payload=event_summary)


def agent_status_msg(tenant_id: str, agent: dict[str, Any]) -> WSMessage:
    return WSMessage(type="agent.status_changed", tenant_id=tenant_id, payload=agent)


def pipeline_stats_msg(tenant_id: str, stats: dict[str, Any]) -> WSMessage:
    return WSMessage(type="pipeline.stats", tenant_id=tenant_id, payload=stats)


def error_msg(tenant_id: str, code: str, message: str) -> WSMessage:
    return WSMessage(
        type="error",
        tenant_id=tenant_id,
        payload={"code": code, "message": message},
    )


# ─── Phase 3.5 realtime event constructors ────────────────────────────────────

_SYSTEM_ACTOR = "system"


def _rt(
    event_type: str,
    tenant_id: str,
    channel: str,
    actor_id: str,
    payload: dict[str, Any],
) -> RealtimeEvent:
    return RealtimeEvent.create(
        event_type=event_type,
        tenant_id=tenant_id,
        actor_id=actor_id,
        channel=channel,
        payload=payload,
    )


# ── Alerts ────────────────────────────────────────────────────────────────────

def realtime_alert_created(
    tenant_id: str,
    actor_id: str,
    alert: dict[str, Any],
) -> RealtimeEvent:
    return _rt(
        RealtimeEventType.ALERT_CREATED,
        tenant_id,
        ch.ALERTS,
        actor_id,
        alert,
    )


def realtime_alert_updated(
    tenant_id: str,
    actor_id: str,
    alert: dict[str, Any],
) -> RealtimeEvent:
    return _rt(
        RealtimeEventType.ALERT_UPDATED,
        tenant_id,
        ch.ALERTS,
        actor_id,
        alert,
    )


# ── Investigations ────────────────────────────────────────────────────────────

def realtime_investigation_created(
    tenant_id: str,
    actor_id: str,
    investigation_id: str,
    threat_score: int,
    confidence: str,
    status: str,
) -> RealtimeEvent:
    return _rt(
        RealtimeEventType.INVESTIGATION_CREATED,
        tenant_id,
        ch.INVESTIGATIONS,
        actor_id,
        {
            "investigation_id": investigation_id,
            "threat_score":     threat_score,
            "confidence":       confidence,
            "status":           status,
        },
    )


def realtime_investigation_updated(
    tenant_id: str,
    actor_id: str,
    investigation_id: str,
    changes: dict[str, Any],
) -> RealtimeEvent:
    return _rt(
        RealtimeEventType.INVESTIGATION_UPDATED,
        tenant_id,
        ch.INVESTIGATIONS,
        actor_id,
        {"investigation_id": investigation_id, **changes},
    )


def realtime_investigation_assigned(
    tenant_id: str,
    actor_id: str,
    investigation_id: str,
    assigned_to: str,
    escalated: bool,
    escalation_reason: str | None,
) -> RealtimeEvent:
    return _rt(
        RealtimeEventType.INVESTIGATION_ASSIGNED,
        tenant_id,
        ch.INVESTIGATIONS,
        actor_id,
        {
            "investigation_id":  investigation_id,
            "assigned_to":       assigned_to,
            "escalated":         escalated,
            "escalation_reason": escalation_reason,
        },
    )


def realtime_verdict_changed(
    tenant_id: str,
    actor_id: str,
    investigation_id: str,
    new_verdict: str,
    previous_verdict: str | None,
    reasoning: str | None,
) -> RealtimeEvent:
    return _rt(
        RealtimeEventType.INVESTIGATION_VERDICT_CHANGED,
        tenant_id,
        ch.INVESTIGATIONS,
        actor_id,
        {
            "investigation_id": investigation_id,
            "new_verdict":      new_verdict,
            "previous_verdict": previous_verdict,
            "reasoning":        reasoning,
        },
    )


# ── Notes ─────────────────────────────────────────────────────────────────────

def realtime_note_created(
    tenant_id: str,
    actor_id: str,
    investigation_id: str,
    note_id: str,
    content_preview: str,
    pinned: bool,
) -> RealtimeEvent:
    return _rt(
        RealtimeEventType.NOTE_CREATED,
        tenant_id,
        ch.ACTIVITY,
        actor_id,
        {
            "investigation_id": investigation_id,
            "note_id":          note_id,
            "content_preview":  content_preview[:200],
            "pinned":           pinned,
        },
    )


def realtime_note_updated(
    tenant_id: str,
    actor_id: str,
    investigation_id: str,
    note_id: str,
) -> RealtimeEvent:
    return _rt(
        RealtimeEventType.NOTE_UPDATED,
        tenant_id,
        ch.ACTIVITY,
        actor_id,
        {"investigation_id": investigation_id, "note_id": note_id},
    )


# ── Evidence ──────────────────────────────────────────────────────────────────

def realtime_evidence_added(
    tenant_id: str,
    actor_id: str,
    investigation_id: str,
    evidence_id: str,
    title: str,
    evidence_type: str,
) -> RealtimeEvent:
    return _rt(
        RealtimeEventType.EVIDENCE_ADDED,
        tenant_id,
        ch.ACTIVITY,
        actor_id,
        {
            "investigation_id": investigation_id,
            "evidence_id":      evidence_id,
            "title":            title,
            "evidence_type":    evidence_type,
        },
    )


# ── Cases ─────────────────────────────────────────────────────────────────────

def realtime_case_merged(
    tenant_id: str,
    actor_id: str,
    primary_id: str,
    secondary_ids: list[str],
    reason: str | None,
) -> RealtimeEvent:
    return _rt(
        RealtimeEventType.CASE_MERGED,
        tenant_id,
        ch.CASES,
        actor_id,
        {
            "primary_investigation_id":    primary_id,
            "secondary_investigation_ids": secondary_ids,
            "reason":                      reason,
        },
    )


def realtime_case_closed(
    tenant_id: str,
    actor_id: str,
    investigation_id: str,
    verdict: str | None,
) -> RealtimeEvent:
    return _rt(
        RealtimeEventType.CASE_CLOSED,
        tenant_id,
        ch.CASES,
        actor_id,
        {"investigation_id": investigation_id, "verdict": verdict},
    )


# ── Presence ──────────────────────────────────────────────────────────────────

def realtime_analyst_joined(
    tenant_id: str,
    analyst_id: str,
    display_name: str,
    workspace: str,
) -> RealtimeEvent:
    return _rt(
        RealtimeEventType.ANALYST_JOINED,
        tenant_id,
        ch.PRESENCE,
        analyst_id,
        {
            "analyst_id":   analyst_id,
            "display_name": display_name,
            "workspace":    workspace,
        },
    )


def realtime_analyst_left(
    tenant_id: str,
    analyst_id: str,
) -> RealtimeEvent:
    return _rt(
        RealtimeEventType.ANALYST_LEFT,
        tenant_id,
        ch.PRESENCE,
        analyst_id,
        {"analyst_id": analyst_id},
    )


def realtime_analyst_typing(
    tenant_id: str,
    analyst_id: str,
    investigation_id: str,
) -> RealtimeEvent:
    return _rt(
        RealtimeEventType.ANALYST_TYPING,
        tenant_id,
        ch.PRESENCE,
        analyst_id,
        {"analyst_id": analyst_id, "investigation_id": investigation_id},
    )


# ── Events (Phase 3.6) ────────────────────────────────────────────────────────

def realtime_event_created(
    tenant_id: str,
    actor_id: str,
    event_id: str,
    category: str,
    severity: int,
    host_name: str | None,
    source_ip: str | None,
    username: str | None,
    event_timestamp: str,
) -> RealtimeEvent:
    return _rt(
        RealtimeEventType.EVENT_CREATED,
        tenant_id,
        ch.EVENTS,
        actor_id,
        {
            "event_id":        event_id,
            "category":        category,
            "severity":        severity,
            "host_name":       host_name,
            "source_ip":       source_ip,
            "username":        username,
            "event_timestamp": event_timestamp,
        },
    )


def realtime_event_updated(
    tenant_id: str,
    actor_id: str,
    event_id: str,
    changes: dict[str, Any],
) -> RealtimeEvent:
    return _rt(
        RealtimeEventType.EVENT_UPDATED,
        tenant_id,
        ch.EVENTS,
        actor_id,
        {"event_id": event_id, **changes},
    )


def realtime_event_deleted(
    tenant_id: str,
    actor_id: str,
    event_id: str,
    reason: str | None = None,
) -> RealtimeEvent:
    return _rt(
        RealtimeEventType.EVENT_DELETED,
        tenant_id,
        ch.EVENTS,
        actor_id,
        {"event_id": event_id, "reason": reason},
    )


def realtime_events_bulk_ingested(
    tenant_id: str,
    actor_id: str,
    count: int,
    agent_id: str | None,
    categories: list[str],
) -> RealtimeEvent:
    return _rt(
        RealtimeEventType.EVENTS_BULK_INGESTED,
        tenant_id,
        ch.EVENTS,
        actor_id,
        {
            "count":      count,
            "agent_id":   agent_id,
            "categories": categories,
        },
    )


# ── Hunt ──────────────────────────────────────────────────────────────────────

def realtime_hunt_completed(
    tenant_id: str,
    actor_id: str,
    hunt_id: str | None,
    result_count: int,
    query_summary: str,
) -> RealtimeEvent:
    return _rt(
        RealtimeEventType.HUNT_COMPLETED,
        tenant_id,
        ch.HUNTS,
        actor_id,
        {
            "hunt_id":       hunt_id,
            "result_count":  result_count,
            "query_summary": query_summary,
        },
    )


# ── System ────────────────────────────────────────────────────────────────────

def realtime_error(tenant_id: str, code: str, message: str) -> RealtimeEvent:
    return _rt(
        RealtimeEventType.ERROR,
        tenant_id,
        ch.PRESENCE,
        _SYSTEM_ACTOR,
        {"code": code, "message": message},
    )
