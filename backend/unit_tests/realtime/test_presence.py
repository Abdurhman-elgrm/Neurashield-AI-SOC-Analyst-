from __future__ import annotations

"""Tests for PresenceService."""

import pytest
from unittest.mock import AsyncMock, call

from app.realtime import channels as ch
from app.realtime.presence import PresenceService, PRESENCE_TTL_SECS
from app.realtime.schemas import PresenceState

from unit_tests.realtime.conftest import (
    ANALYST_ID,
    ANALYST2_ID,
    TENANT_ID,
    NOW,
    make_presence_hash,
)


# ─── join ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_join_returns_presence_state(rt_client):
    state = await PresenceService.join(rt_client, ANALYST_ID, TENANT_ID, "Alice", "dashboard")
    assert isinstance(state, PresenceState)
    assert state.analyst_id == ANALYST_ID
    assert state.display_name == "Alice"
    assert state.workspace == "dashboard"
    assert state.idle is False


@pytest.mark.asyncio
async def test_join_calls_hset_and_expire(rt_client):
    await PresenceService.join(rt_client, ANALYST_ID, TENANT_ID, "Alice")
    rt_client.hset.assert_called_once()
    key_used = rt_client.hset.call_args[0][0]
    assert ANALYST_ID in key_used
    rt_client.expire.assert_called_once_with(key_used, PRESENCE_TTL_SECS)


@pytest.mark.asyncio
async def test_join_adds_to_presence_set(rt_client):
    await PresenceService.join(rt_client, ANALYST_ID, TENANT_ID)
    rt_client.sadd.assert_called_once_with(ch.presence_set_key(), ANALYST_ID)


@pytest.mark.asyncio
async def test_join_with_investigation_id(rt_client):
    state = await PresenceService.join(
        rt_client, ANALYST_ID, TENANT_ID, investigation_id="inv-99"
    )
    assert state.investigation_id == "inv-99"


@pytest.mark.asyncio
async def test_join_idempotent_on_reconnect(rt_client):
    await PresenceService.join(rt_client, ANALYST_ID, TENANT_ID)
    await PresenceService.join(rt_client, ANALYST_ID, TENANT_ID)
    assert rt_client.hset.call_count == 2  # called each time, that's fine


# ─── leave ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_leave_deletes_key(rt_client):
    await PresenceService.leave(rt_client, ANALYST_ID)
    key = ch.presence_key(ANALYST_ID)
    rt_client.delete.assert_called_once_with(key)


@pytest.mark.asyncio
async def test_leave_removes_from_set(rt_client):
    await PresenceService.leave(rt_client, ANALYST_ID)
    rt_client.srem.assert_called_once_with(ch.presence_set_key(), ANALYST_ID)


# ─── heartbeat ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_heartbeat_returns_true_when_online(rt_client):
    rt_client.exists.return_value = True
    result = await PresenceService.heartbeat(rt_client, ANALYST_ID)
    assert result is True


@pytest.mark.asyncio
async def test_heartbeat_returns_false_when_offline(rt_client):
    rt_client.exists.return_value = False
    result = await PresenceService.heartbeat(rt_client, ANALYST_ID)
    assert result is False
    rt_client.hset.assert_not_called()


@pytest.mark.asyncio
async def test_heartbeat_refreshes_ttl(rt_client):
    rt_client.exists.return_value = True
    await PresenceService.heartbeat(rt_client, ANALYST_ID)
    key = ch.presence_key(ANALYST_ID)
    rt_client.expire.assert_called_once_with(key, PRESENCE_TTL_SECS)


@pytest.mark.asyncio
async def test_heartbeat_updates_workspace(rt_client):
    rt_client.exists.return_value = True
    await PresenceService.heartbeat(rt_client, ANALYST_ID, workspace="investigations")
    mapping_arg = rt_client.hset.call_args[0][1]
    assert mapping_arg["workspace"] == "investigations"


@pytest.mark.asyncio
async def test_heartbeat_updates_investigation_id(rt_client):
    rt_client.exists.return_value = True
    await PresenceService.heartbeat(rt_client, ANALYST_ID, investigation_id="inv-5")
    mapping_arg = rt_client.hset.call_args[0][1]
    assert mapping_arg["investigation_id"] == "inv-5"


@pytest.mark.asyncio
async def test_heartbeat_no_workspace_update_if_not_provided(rt_client):
    rt_client.exists.return_value = True
    await PresenceService.heartbeat(rt_client, ANALYST_ID)
    mapping_arg = rt_client.hset.call_args[0][1]
    assert "workspace" not in mapping_arg


# ─── set_active_investigation ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_set_active_investigation_returns_true_when_online(rt_client):
    rt_client.exists.return_value = True
    result = await PresenceService.set_active_investigation(rt_client, ANALYST_ID, "inv-7")
    assert result is True
    mapping = rt_client.hset.call_args[0][1]
    assert mapping["investigation_id"] == "inv-7"


@pytest.mark.asyncio
async def test_set_active_investigation_returns_false_when_offline(rt_client):
    rt_client.exists.return_value = False
    result = await PresenceService.set_active_investigation(rt_client, ANALYST_ID, "inv-7")
    assert result is False


@pytest.mark.asyncio
async def test_set_active_investigation_clears_with_none(rt_client):
    rt_client.exists.return_value = True
    await PresenceService.set_active_investigation(rt_client, ANALYST_ID, None)
    mapping = rt_client.hset.call_args[0][1]
    assert mapping["investigation_id"] == ""


# ─── get ──────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_returns_state_when_present(rt_client):
    rt_client.hgetall.return_value = make_presence_hash()
    state = await PresenceService.get(rt_client, ANALYST_ID)
    assert state is not None
    assert state.analyst_id == ANALYST_ID


@pytest.mark.asyncio
async def test_get_returns_none_when_missing(rt_client):
    rt_client.hgetall.return_value = {}
    state = await PresenceService.get(rt_client, ANALYST_ID)
    assert state is None


# ─── list_online ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_online_returns_all_online(rt_client):
    rt_client.smembers.return_value = {ANALYST_ID, ANALYST2_ID}
    rt_client.hgetall.return_value = make_presence_hash()
    online = await PresenceService.list_online(rt_client)
    assert len(online) == 2


@pytest.mark.asyncio
async def test_list_online_prunes_stale_entries(rt_client):
    rt_client.smembers.return_value = {ANALYST_ID, ANALYST2_ID}
    # ANALYST_ID has state, ANALYST2_ID is stale (empty hash)
    rt_client.hgetall.side_effect = [make_presence_hash(), {}]
    online = await PresenceService.list_online(rt_client)
    assert len(online) == 1
    # Should have called srem to prune the stale one
    rt_client.srem.assert_called_once()
    stale_arg = rt_client.srem.call_args[0][1]
    assert stale_arg == ANALYST2_ID


@pytest.mark.asyncio
async def test_list_online_empty_set(rt_client):
    rt_client.smembers.return_value = set()
    online = await PresenceService.list_online(rt_client)
    assert online == []
    rt_client.srem.assert_not_called()


# ─── count_online ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_count_online_delegates_to_scard(rt_client):
    rt_client.scard.return_value = 7
    count = await PresenceService.count_online(rt_client)
    assert count == 7
    rt_client.scard.assert_called_once_with(ch.presence_set_key())
