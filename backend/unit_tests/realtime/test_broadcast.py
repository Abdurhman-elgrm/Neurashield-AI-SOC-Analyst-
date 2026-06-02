from __future__ import annotations

"""Tests for RealtimeBroadcaster and per-connection send queues."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.realtime import channels as ch
from app.realtime.broadcast import (
    RealtimeBroadcaster,
    active_queue_count,
    deregister_connection_queue,
    get_connection_queue,
    register_connection_queue,
    QUEUE_MAX_SIZE,
)
from app.realtime.schemas import RealtimeEvent, RealtimeEventType

from unit_tests.realtime.conftest import TENANT_ID, ANALYST_ID, WS_ID, WS_ID_2


def make_event(channel: str = ch.ALERTS) -> RealtimeEvent:
    return RealtimeEvent.create(
        event_type=RealtimeEventType.ALERT_CREATED,
        tenant_id=TENANT_ID,
        actor_id="system",
        channel=channel,
        payload={"alert_id": "test"},
    )


# ─── Connection queue lifecycle ───────────────────────────────────────────────

def test_register_queue_creates_bounded_queue():
    q = register_connection_queue(f"reg-{WS_ID}")
    try:
        assert q.maxsize == QUEUE_MAX_SIZE
    finally:
        deregister_connection_queue(f"reg-{WS_ID}")


def test_get_queue_returns_registered_queue():
    ws = f"get-{WS_ID}"
    q = register_connection_queue(ws)
    try:
        assert get_connection_queue(ws) is q
    finally:
        deregister_connection_queue(ws)


def test_get_queue_returns_none_for_unknown_ws():
    assert get_connection_queue("ws-does-not-exist-xyz") is None


def test_deregister_removes_queue():
    ws = f"deregister-{WS_ID}"
    register_connection_queue(ws)
    deregister_connection_queue(ws)
    assert get_connection_queue(ws) is None


def test_deregister_idempotent():
    ws = f"deregister2-{WS_ID}"
    register_connection_queue(ws)
    deregister_connection_queue(ws)
    deregister_connection_queue(ws)  # should not raise


def test_active_queue_count_tracks_correctly():
    ws_a = f"aqc-a-{WS_ID}"
    ws_b = f"aqc-b-{WS_ID}"
    before = active_queue_count()
    register_connection_queue(ws_a)
    register_connection_queue(ws_b)
    assert active_queue_count() == before + 2
    deregister_connection_queue(ws_a)
    deregister_connection_queue(ws_b)
    assert active_queue_count() == before


# ─── deliver_local ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_deliver_local_puts_message_in_subscribed_queue():
    from app.realtime.subscriptions import SubscriptionManager
    mgr = SubscriptionManager()
    ws = f"deliver-{WS_ID}"
    await mgr.subscribe(ws, TENANT_ID, ch.ALERTS)
    q = register_connection_queue(ws)

    with patch("app.realtime.broadcast.subscription_manager", mgr):
        count = await RealtimeBroadcaster.deliver_local(TENANT_ID, ch.ALERTS, '{"test":1}')

    assert count == 1
    assert not q.empty()
    msg = q.get_nowait()
    assert msg == '{"test":1}'
    deregister_connection_queue(ws)


@pytest.mark.asyncio
async def test_deliver_local_returns_zero_when_no_subscribers():
    from app.realtime.subscriptions import SubscriptionManager
    mgr = SubscriptionManager()

    with patch("app.realtime.broadcast.subscription_manager", mgr):
        count = await RealtimeBroadcaster.deliver_local(TENANT_ID, ch.ALERTS, '{}')
    assert count == 0


@pytest.mark.asyncio
async def test_deliver_local_skips_ws_with_no_queue():
    from app.realtime.subscriptions import SubscriptionManager
    mgr = SubscriptionManager()
    ws = f"skip-{WS_ID}"
    await mgr.subscribe(ws, TENANT_ID, ch.ALERTS)
    # No queue registered for this ws_id

    with patch("app.realtime.broadcast.subscription_manager", mgr):
        count = await RealtimeBroadcaster.deliver_local(TENANT_ID, ch.ALERTS, '{}')
    assert count == 0


@pytest.mark.asyncio
async def test_deliver_local_drops_on_full_queue(caplog):
    from app.realtime.subscriptions import SubscriptionManager
    import logging

    mgr = SubscriptionManager()
    ws = f"full-{WS_ID}"
    await mgr.subscribe(ws, TENANT_ID, ch.ALERTS)
    q = register_connection_queue(ws)

    # Fill the queue to capacity
    for _ in range(QUEUE_MAX_SIZE):
        q.put_nowait("x")

    with patch("app.realtime.broadcast.subscription_manager", mgr):
        count = await RealtimeBroadcaster.deliver_local(TENANT_ID, ch.ALERTS, '{"dropped":true}')

    assert count == 0  # nothing delivered
    deregister_connection_queue(ws)


@pytest.mark.asyncio
async def test_deliver_local_delivers_to_multiple_connections():
    from app.realtime.subscriptions import SubscriptionManager
    mgr = SubscriptionManager()
    ws_a = f"multi-a-{WS_ID}"
    ws_b = f"multi-b-{WS_ID}"
    await mgr.subscribe(ws_a, TENANT_ID, ch.ALERTS)
    await mgr.subscribe(ws_b, TENANT_ID, ch.ALERTS)
    q_a = register_connection_queue(ws_a)
    q_b = register_connection_queue(ws_b)

    with patch("app.realtime.broadcast.subscription_manager", mgr):
        count = await RealtimeBroadcaster.deliver_local(TENANT_ID, ch.ALERTS, '{"msg":1}')

    assert count == 2
    assert not q_a.empty()
    assert not q_b.empty()
    deregister_connection_queue(ws_a)
    deregister_connection_queue(ws_b)


@pytest.mark.asyncio
async def test_deliver_local_tenant_isolation():
    from app.realtime.subscriptions import SubscriptionManager
    mgr = SubscriptionManager()
    ws_t1 = f"iso-t1-{WS_ID}"
    ws_t2 = f"iso-t2-{WS_ID}"
    TENANT2 = "bbb00000-0000-0000-0000-000000000002"
    await mgr.subscribe(ws_t1, TENANT_ID, ch.ALERTS)
    await mgr.subscribe(ws_t2, TENANT2, ch.ALERTS)
    q_t1 = register_connection_queue(ws_t1)
    q_t2 = register_connection_queue(ws_t2)

    with patch("app.realtime.broadcast.subscription_manager", mgr):
        # Deliver only to TENANT_ID
        count = await RealtimeBroadcaster.deliver_local(TENANT_ID, ch.ALERTS, '{"t":1}')

    assert count == 1
    assert not q_t1.empty()
    assert q_t2.empty()  # tenant 2 must NOT receive tenant 1's messages
    deregister_connection_queue(ws_t1)
    deregister_connection_queue(ws_t2)


# ─── broadcast_event ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_broadcast_event_calls_redis_publish(rt_client):
    event = make_event()
    await RealtimeBroadcaster.broadcast_event(rt_client, event)
    rt_client.publish.assert_called_once()
    suffix_arg = rt_client.publish.call_args[0][0]
    assert "realtime:alerts" in suffix_arg or suffix_arg == "realtime:alerts"


@pytest.mark.asyncio
async def test_broadcast_event_publishes_json(rt_client):
    event = make_event()
    await RealtimeBroadcaster.broadcast_event(rt_client, event)
    json_arg = rt_client.publish.call_args[0][1]
    import json
    data = json.loads(json_arg)
    assert data["v"] == 2
    assert data["channel"] == ch.ALERTS


@pytest.mark.asyncio
async def test_broadcast_event_handles_publish_failure(rt_client):
    rt_client.publish.side_effect = Exception("Redis down")
    event = make_event()
    # Should not raise — errors are swallowed
    await RealtimeBroadcaster.broadcast_event(rt_client, event)


# ─── broadcast_to_tenant ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_broadcast_to_tenant_delegates_to_broadcast_event(rt_client):
    event = make_event()
    await RealtimeBroadcaster.broadcast_to_tenant(rt_client, TENANT_ID, event)
    rt_client.publish.assert_called_once()
