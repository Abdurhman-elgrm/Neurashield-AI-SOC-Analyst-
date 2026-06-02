from __future__ import annotations

"""
Pydantic schemas for the Phase 3.5 realtime SOC operations layer.

All events flowing through WebSocket connections use RealtimeEvent.
Client-to-server messages use ClientMessage.
"""

import enum
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

import orjson
from pydantic import BaseModel, ConfigDict, Field


# ─── Event types ─────────────────────────────────────────────────────────────

class RealtimeEventType(str, enum.Enum):
    # Alert events
    ALERT_CREATED            = "alert.created"
    ALERT_UPDATED            = "alert.updated"

    # Investigation events
    INVESTIGATION_CREATED    = "investigation.created"
    INVESTIGATION_UPDATED    = "investigation.updated"
    INVESTIGATION_ASSIGNED   = "investigation.assigned"
    INVESTIGATION_VERDICT_CHANGED = "investigation.verdict_changed"
    INVESTIGATION_NOTE_ADDED = "investigation.note_added"
    INVESTIGATION_STATUS_UPDATED = "investigation.status_updated"

    # Note events
    NOTE_CREATED             = "note.created"
    NOTE_UPDATED             = "note.updated"

    # Evidence events
    EVIDENCE_ADDED           = "evidence.added"

    # Case events
    CASE_MERGED              = "case.merged"
    CASE_CLOSED              = "case.closed"

    # Analyst presence
    ANALYST_JOINED           = "analyst.joined"
    ANALYST_LEFT             = "analyst.left"
    ANALYST_TYPING           = "analyst.typing"

    # Hunt events
    HUNT_COMPLETED           = "hunt.completed"

    # Event stream events (Phase 3.6)
    EVENT_CREATED            = "event.created"
    EVENT_UPDATED            = "event.updated"
    EVENT_DELETED            = "event.deleted"
    EVENTS_BULK_INGESTED     = "events.bulk_ingested"

    # System
    PING                     = "ping"
    PONG                     = "pong"
    ERROR                    = "error"
    SUBSCRIBED               = "subscribed"
    UNSUBSCRIBED             = "unsubscribed"
    WELCOME                  = "welcome"


# ─── Channel names ────────────────────────────────────────────────────────────

class ChannelName(str, enum.Enum):
    ALERTS          = "alerts"
    INVESTIGATIONS  = "investigations"
    CASES           = "cases"
    ACTIVITY        = "activity"
    HUNTS           = "hunts"
    PRESENCE        = "presence"


# ─── Core event envelope ─────────────────────────────────────────────────────

class RealtimeEvent(BaseModel):
    """
    Canonical realtime event envelope. All events flowing to WS clients
    use this structure. The v=2 field distinguishes from Phase 2 WSMessage.
    """
    model_config = ConfigDict(frozen=True)

    v:          int = 2
    event_id:   str = Field(default_factory=lambda: str(uuid4()))
    event_type: str
    tenant_id:  str
    actor_id:   str
    channel:    str
    timestamp:  str = Field(default="")
    payload:    dict[str, Any]

    def model_post_init(self, __context: Any) -> None:
        if not self.timestamp:
            object.__setattr__(
                self, "timestamp",
                datetime.now(tz=timezone.utc).isoformat(),
            )

    def to_json(self) -> str:
        return orjson.dumps(self.model_dump()).decode()

    @classmethod
    def create(
        cls,
        event_type: str,
        tenant_id: str,
        actor_id: str,
        channel: str,
        payload: dict[str, Any],
    ) -> "RealtimeEvent":
        return cls(
            event_type=event_type,
            tenant_id=tenant_id,
            actor_id=actor_id,
            channel=channel,
            payload=payload,
        )


# ─── Presence ─────────────────────────────────────────────────────────────────

class PresenceState(BaseModel):
    """Current state of an online analyst."""
    analyst_id:       str
    tenant_id:        str
    display_name:     str = ""
    workspace:        str = "dashboard"
    investigation_id: str | None = None
    idle:             bool = False
    last_seen:        str = Field(default_factory=lambda: datetime.now(tz=timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()

    @classmethod
    def from_redis(cls, data: dict[str, str]) -> "PresenceState":
        return cls(
            analyst_id=data.get("analyst_id", ""),
            tenant_id=data.get("tenant_id", ""),
            display_name=data.get("display_name", ""),
            workspace=data.get("workspace", "dashboard"),
            investigation_id=data.get("investigation_id") or None,
            idle=data.get("idle", "false") == "true",
            last_seen=data.get("last_seen", ""),
        )


# ─── Locks ────────────────────────────────────────────────────────────────────

class LockInfo(BaseModel):
    """Information about an investigation edit lock."""
    investigation_id: str
    tenant_id:        str
    owner_id:         str
    locked_at:        str
    expires_at:       str
    lock_key:         str = ""

    @classmethod
    def from_redis(cls, data: dict[str, Any]) -> "LockInfo":
        return cls(
            investigation_id=data["investigation_id"],
            tenant_id=data["tenant_id"],
            owner_id=data["owner_id"],
            locked_at=data["locked_at"],
            expires_at=data["expires_at"],
        )


# ─── Client messages ──────────────────────────────────────────────────────────

class ClientMessageType(str, enum.Enum):
    SUBSCRIBE         = "subscribe"
    UNSUBSCRIBE       = "unsubscribe"
    HEARTBEAT         = "heartbeat"
    TYPING            = "typing"
    SET_INVESTIGATION = "set_investigation"
    ACQUIRE_LOCK      = "acquire_lock"
    RELEASE_LOCK      = "release_lock"
    PONG              = "pong"


class ClientMessage(BaseModel):
    """Message sent from WebSocket client to server."""
    type:             str
    channel:          str | None = None
    investigation_id: str | None = None
    workspace:        str | None = None
    lock_id:          str | None = None
    data:             dict[str, Any] = Field(default_factory=dict)


# ─── Subscription state ───────────────────────────────────────────────────────

class SubscriptionInfo(BaseModel):
    ws_id:      str
    tenant_id:  str
    channels:   list[str]
    analyst_id: str


# ─── Welcome handshake ────────────────────────────────────────────────────────

class WelcomePayload(BaseModel):
    analyst_id:        str
    tenant_id:         str
    available_channels: list[str]
    online_analysts:   int = 0
    server_time:       str = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )
