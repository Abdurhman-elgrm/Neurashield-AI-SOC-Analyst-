from __future__ import annotations

"""Tests for realtime Pydantic schemas."""

import json
from datetime import datetime, timezone

import pytest

from app.realtime.schemas import (
    ChannelName,
    ClientMessage,
    ClientMessageType,
    LockInfo,
    PresenceState,
    RealtimeEvent,
    RealtimeEventType,
    SubscriptionInfo,
    WelcomePayload,
)

TENANT_ID  = "aaa00000-0000-0000-0000-000000000001"
ANALYST_ID = "ccc00000-0000-0000-0000-000000000001"


# ─── RealtimeEventType ────────────────────────────────────────────────────────

def test_event_type_alert_values():
    assert RealtimeEventType.ALERT_CREATED == "alert.created"
    assert RealtimeEventType.ALERT_UPDATED == "alert.updated"


def test_event_type_investigation_values():
    assert RealtimeEventType.INVESTIGATION_CREATED == "investigation.created"
    assert RealtimeEventType.INVESTIGATION_UPDATED == "investigation.updated"
    assert RealtimeEventType.INVESTIGATION_ASSIGNED == "investigation.assigned"
    assert RealtimeEventType.INVESTIGATION_VERDICT_CHANGED == "investigation.verdict_changed"


def test_event_type_presence_values():
    assert RealtimeEventType.ANALYST_JOINED == "analyst.joined"
    assert RealtimeEventType.ANALYST_LEFT == "analyst.left"
    assert RealtimeEventType.ANALYST_TYPING == "analyst.typing"


def test_event_type_system_values():
    assert RealtimeEventType.WELCOME == "welcome"
    assert RealtimeEventType.PING == "ping"
    assert RealtimeEventType.PONG == "pong"
    assert RealtimeEventType.ERROR == "error"
    assert RealtimeEventType.SUBSCRIBED == "subscribed"
    assert RealtimeEventType.UNSUBSCRIBED == "unsubscribed"


# ─── RealtimeEvent ────────────────────────────────────────────────────────────

def test_realtime_event_create_fields():
    event = RealtimeEvent.create(
        event_type=RealtimeEventType.ALERT_CREATED,
        tenant_id=TENANT_ID,
        actor_id="system",
        channel="alerts",
        payload={"alert_id": "123"},
    )
    assert event.v == 2
    assert event.event_type == "alert.created"
    assert event.tenant_id == TENANT_ID
    assert event.actor_id == "system"
    assert event.channel == "alerts"
    assert event.payload == {"alert_id": "123"}
    assert event.event_id != ""
    assert event.timestamp != ""


def test_realtime_event_auto_timestamp():
    event = RealtimeEvent.create(
        event_type=RealtimeEventType.PING,
        tenant_id=TENANT_ID,
        actor_id="system",
        channel="presence",
        payload={},
    )
    ts = datetime.fromisoformat(event.timestamp)
    assert ts.tzinfo is not None


def test_realtime_event_unique_ids():
    ev1 = RealtimeEvent.create("alert.created", TENANT_ID, "system", "alerts", {})
    ev2 = RealtimeEvent.create("alert.created", TENANT_ID, "system", "alerts", {})
    assert ev1.event_id != ev2.event_id


def test_realtime_event_to_json():
    event = RealtimeEvent.create(
        event_type=RealtimeEventType.ALERT_CREATED,
        tenant_id=TENANT_ID,
        actor_id=ANALYST_ID,
        channel="alerts",
        payload={"severity": "high"},
    )
    raw = event.to_json()
    data = json.loads(raw)
    assert data["v"] == 2
    assert data["event_type"] == "alert.created"
    assert data["tenant_id"] == TENANT_ID
    assert data["payload"] == {"severity": "high"}


def test_realtime_event_is_frozen():
    event = RealtimeEvent.create("ping", TENANT_ID, "system", "presence", {})
    with pytest.raises(Exception):
        event.event_type = "tampered"  # type: ignore[misc]


# ─── PresenceState ────────────────────────────────────────────────────────────

def test_presence_state_from_redis_full():
    state = PresenceState.from_redis({
        "analyst_id": ANALYST_ID,
        "tenant_id": TENANT_ID,
        "display_name": "Alice",
        "workspace": "investigations",
        "investigation_id": "inv-1",
        "idle": "false",
        "last_seen": "2026-01-01T00:00:00+00:00",
    })
    assert state.analyst_id == ANALYST_ID
    assert state.workspace == "investigations"
    assert state.investigation_id == "inv-1"
    assert state.idle is False


def test_presence_state_from_redis_idle_flag():
    state = PresenceState.from_redis({
        "analyst_id": ANALYST_ID,
        "tenant_id": TENANT_ID,
        "idle": "true",
        "last_seen": "",
    })
    assert state.idle is True


def test_presence_state_from_redis_empty_investigation_becomes_none():
    state = PresenceState.from_redis({
        "analyst_id": ANALYST_ID,
        "tenant_id": TENANT_ID,
        "investigation_id": "",
        "idle": "false",
        "last_seen": "",
    })
    assert state.investigation_id is None


# ─── LockInfo ─────────────────────────────────────────────────────────────────

def test_lock_info_from_redis():
    data = {
        "investigation_id": "inv-1",
        "tenant_id": TENANT_ID,
        "owner_id": ANALYST_ID,
        "locked_at": "2026-01-01T00:00:00+00:00",
        "expires_at": "2026-01-01T00:01:00+00:00",
    }
    lock = LockInfo.from_redis(data)
    assert lock.investigation_id == "inv-1"
    assert lock.owner_id == ANALYST_ID
    assert lock.tenant_id == TENANT_ID


def test_lock_info_model_dump_roundtrip():
    data = {
        "investigation_id": "inv-99",
        "tenant_id": TENANT_ID,
        "owner_id": ANALYST_ID,
        "locked_at": "2026-01-01T00:00:00+00:00",
        "expires_at": "2026-01-01T00:01:00+00:00",
    }
    lock = LockInfo.from_redis(data)
    dumped = lock.model_dump()
    assert dumped["investigation_id"] == "inv-99"
    assert dumped["owner_id"] == ANALYST_ID


# ─── ClientMessage ────────────────────────────────────────────────────────────

def test_client_message_subscribe():
    msg = ClientMessage(type="subscribe", channel="alerts")
    assert msg.type == "subscribe"
    assert msg.channel == "alerts"
    assert msg.investigation_id is None


def test_client_message_heartbeat_with_workspace():
    msg = ClientMessage(type="heartbeat", workspace="investigations")
    assert msg.workspace == "investigations"


def test_client_message_acquire_lock():
    msg = ClientMessage(type="acquire_lock", investigation_id="inv-1")
    assert msg.investigation_id == "inv-1"


def test_client_message_defaults():
    msg = ClientMessage(type="pong")
    assert msg.channel is None
    assert msg.investigation_id is None
    assert msg.data == {}


# ─── WelcomePayload ───────────────────────────────────────────────────────────

def test_welcome_payload_model_dump():
    wp = WelcomePayload(
        analyst_id=ANALYST_ID,
        tenant_id=TENANT_ID,
        available_channels=["alerts", "investigations"],
        online_analysts=3,
    )
    d = wp.model_dump()
    assert d["analyst_id"] == ANALYST_ID
    assert d["online_analysts"] == 3
    assert "server_time" in d
