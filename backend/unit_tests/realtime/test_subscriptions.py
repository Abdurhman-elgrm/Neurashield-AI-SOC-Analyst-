from __future__ import annotations

"""Tests for SubscriptionManager."""

import asyncio

import pytest

from app.realtime import channels as ch
from app.realtime.subscriptions import SubscriptionManager

from unit_tests.realtime.conftest import (
    ANALYST_ID,
    TENANT_ID,
    TENANT2_ID,
    WS_ID,
    WS_ID_2,
)


@pytest.fixture
def mgr() -> SubscriptionManager:
    return SubscriptionManager()


# ─── subscribe ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_subscribe_returns_true_for_new(mgr):
    added = await mgr.subscribe(WS_ID, TENANT_ID, ch.ALERTS)
    assert added is True


@pytest.mark.asyncio
async def test_subscribe_returns_false_for_duplicate(mgr):
    await mgr.subscribe(WS_ID, TENANT_ID, ch.ALERTS)
    added = await mgr.subscribe(WS_ID, TENANT_ID, ch.ALERTS)
    assert added is False


@pytest.mark.asyncio
async def test_subscribe_rejects_unknown_channel(mgr):
    added = await mgr.subscribe(WS_ID, TENANT_ID, "nonexistent_channel")
    assert added is False


@pytest.mark.asyncio
async def test_subscribe_accepts_all_known_channels(mgr):
    for channel in ch.ALL_CHANNELS:
        added = await mgr.subscribe(WS_ID, TENANT_ID, channel)
        assert added is True, f"Failed to subscribe to {channel}"


@pytest.mark.asyncio
async def test_subscribe_tracks_tenant_mapping(mgr):
    await mgr.subscribe(WS_ID, TENANT_ID, ch.ALERTS)
    assert mgr._tenant_map[WS_ID] == TENANT_ID


# ─── unsubscribe ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_unsubscribe_returns_true_when_subscribed(mgr):
    await mgr.subscribe(WS_ID, TENANT_ID, ch.ALERTS)
    result = await mgr.unsubscribe(WS_ID, ch.ALERTS)
    assert result is True


@pytest.mark.asyncio
async def test_unsubscribe_returns_false_when_not_subscribed(mgr):
    result = await mgr.unsubscribe(WS_ID, ch.ALERTS)
    assert result is False


@pytest.mark.asyncio
async def test_unsubscribe_removes_from_channel_index(mgr):
    await mgr.subscribe(WS_ID, TENANT_ID, ch.ALERTS)
    await mgr.unsubscribe(WS_ID, ch.ALERTS)
    subs = mgr.subscribers_for_channel(TENANT_ID, ch.ALERTS)
    assert WS_ID not in subs


@pytest.mark.asyncio
async def test_unsubscribe_does_not_affect_other_channels(mgr):
    await mgr.subscribe(WS_ID, TENANT_ID, ch.ALERTS)
    await mgr.subscribe(WS_ID, TENANT_ID, ch.INVESTIGATIONS)
    await mgr.unsubscribe(WS_ID, ch.ALERTS)
    assert mgr.is_subscribed(WS_ID, ch.INVESTIGATIONS) is True


# ─── subscribe_all ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_subscribe_all_subscribes_to_every_channel(mgr):
    await mgr.subscribe_all(WS_ID, TENANT_ID)
    for channel in ch.ALL_CHANNELS:
        assert mgr.is_subscribed(WS_ID, channel), f"Not subscribed to {channel}"


# ─── cleanup ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cleanup_removes_all_subscriptions(mgr):
    await mgr.subscribe(WS_ID, TENANT_ID, ch.ALERTS)
    await mgr.subscribe(WS_ID, TENANT_ID, ch.INVESTIGATIONS)
    channels = await mgr.cleanup(WS_ID)
    assert ch.ALERTS in channels
    assert ch.INVESTIGATIONS in channels
    assert not mgr.is_subscribed(WS_ID, ch.ALERTS)


@pytest.mark.asyncio
async def test_cleanup_removes_from_channel_index(mgr):
    await mgr.subscribe(WS_ID, TENANT_ID, ch.ALERTS)
    await mgr.cleanup(WS_ID)
    subs = mgr.subscribers_for_channel(TENANT_ID, ch.ALERTS)
    assert WS_ID not in subs


@pytest.mark.asyncio
async def test_cleanup_removes_tenant_mapping(mgr):
    await mgr.subscribe(WS_ID, TENANT_ID, ch.PRESENCE)
    await mgr.cleanup(WS_ID)
    assert WS_ID not in mgr._tenant_map


@pytest.mark.asyncio
async def test_cleanup_returns_empty_for_unknown_ws(mgr):
    channels = await mgr.cleanup("ws-does-not-exist")
    assert channels == set()


# ─── is_subscribed ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_is_subscribed_true(mgr):
    await mgr.subscribe(WS_ID, TENANT_ID, ch.PRESENCE)
    assert mgr.is_subscribed(WS_ID, ch.PRESENCE) is True


@pytest.mark.asyncio
async def test_is_subscribed_false(mgr):
    assert mgr.is_subscribed(WS_ID, ch.PRESENCE) is False


# ─── get_subscriptions ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_subscriptions_returns_copy(mgr):
    await mgr.subscribe(WS_ID, TENANT_ID, ch.ALERTS)
    await mgr.subscribe(WS_ID, TENANT_ID, ch.HUNTS)
    subs = mgr.get_subscriptions(WS_ID)
    assert ch.ALERTS in subs
    assert ch.HUNTS in subs
    # Mutation of the returned set should not affect internal state
    subs.add("evil_channel")
    assert not mgr.is_subscribed(WS_ID, "evil_channel")


# ─── subscribers_for_channel ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_subscribers_for_channel_multiple_connections(mgr):
    await mgr.subscribe(WS_ID, TENANT_ID, ch.ALERTS)
    await mgr.subscribe(WS_ID_2, TENANT_ID, ch.ALERTS)
    subs = mgr.subscribers_for_channel(TENANT_ID, ch.ALERTS)
    assert WS_ID in subs
    assert WS_ID_2 in subs


@pytest.mark.asyncio
async def test_subscribers_for_channel_tenant_isolation(mgr):
    await mgr.subscribe(WS_ID, TENANT_ID, ch.ALERTS)
    await mgr.subscribe(WS_ID_2, TENANT2_ID, ch.ALERTS)
    # Tenant 1 sees only its own subscriber
    subs_t1 = mgr.subscribers_for_channel(TENANT_ID, ch.ALERTS)
    subs_t2 = mgr.subscribers_for_channel(TENANT2_ID, ch.ALERTS)
    assert WS_ID in subs_t1
    assert WS_ID_2 not in subs_t1
    assert WS_ID_2 in subs_t2
    assert WS_ID not in subs_t2


@pytest.mark.asyncio
async def test_subscribers_for_channel_empty_when_none(mgr):
    subs = mgr.subscribers_for_channel(TENANT_ID, ch.CASES)
    assert subs == set()


# ─── connection_count / channel_subscriber_count ──────────────────────────────

@pytest.mark.asyncio
async def test_connection_count(mgr):
    assert mgr.connection_count() == 0
    await mgr.subscribe(WS_ID, TENANT_ID, ch.ALERTS)
    assert mgr.connection_count() == 1
    await mgr.subscribe(WS_ID_2, TENANT_ID, ch.ALERTS)
    assert mgr.connection_count() == 2


@pytest.mark.asyncio
async def test_channel_subscriber_count(mgr):
    assert mgr.channel_subscriber_count(TENANT_ID, ch.ALERTS) == 0
    await mgr.subscribe(WS_ID, TENANT_ID, ch.ALERTS)
    assert mgr.channel_subscriber_count(TENANT_ID, ch.ALERTS) == 1


# ─── Async safety ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_concurrent_subscriptions_are_safe(mgr):
    async def sub(ws: str, channel: str) -> None:
        await mgr.subscribe(ws, TENANT_ID, channel)

    ws_ids = [f"ws-{i}" for i in range(20)]
    await asyncio.gather(*(sub(ws, ch.ALERTS) for ws in ws_ids))
    count = mgr.channel_subscriber_count(TENANT_ID, ch.ALERTS)
    assert count == 20
