from __future__ import annotations

"""Tests for InvestigationLockService."""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from app.realtime import channels as ch
from app.realtime.locks import InvestigationLockService, LOCK_TTL_SECS
from app.realtime.schemas import LockInfo

from unit_tests.realtime.conftest import (
    ANALYST_ID,
    ANALYST2_ID,
    TENANT_ID,
    INV_ID,
    make_lock_json,
)


# ─── acquire ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_acquire_returns_lock_info_on_success(rt_client):
    rt_client.set.return_value = True  # NX succeeded
    lock = await InvestigationLockService.acquire(rt_client, INV_ID, TENANT_ID, ANALYST_ID)
    assert lock is not None
    assert isinstance(lock, LockInfo)
    assert lock.owner_id == ANALYST_ID
    assert lock.investigation_id == INV_ID
    assert lock.tenant_id == TENANT_ID


@pytest.mark.asyncio
async def test_acquire_returns_none_when_already_locked(rt_client):
    rt_client.set.return_value = False  # NX failed — key exists
    lock = await InvestigationLockService.acquire(rt_client, INV_ID, TENANT_ID, ANALYST_ID)
    assert lock is None


@pytest.mark.asyncio
async def test_acquire_calls_set_with_nx_and_ttl(rt_client):
    rt_client.set.return_value = True
    await InvestigationLockService.acquire(rt_client, INV_ID, TENANT_ID, ANALYST_ID)
    rt_client.set.assert_called_once()
    call_kwargs = rt_client.set.call_args[1]
    assert call_kwargs.get("nx") is True
    assert call_kwargs.get("ex") == LOCK_TTL_SECS


@pytest.mark.asyncio
async def test_acquire_stores_valid_json(rt_client):
    rt_client.set.return_value = True
    await InvestigationLockService.acquire(rt_client, INV_ID, TENANT_ID, ANALYST_ID)
    json_arg = rt_client.set.call_args[0][1]
    data = json.loads(json_arg)
    assert data["investigation_id"] == INV_ID
    assert data["owner_id"] == ANALYST_ID
    assert "expires_at" in data
    assert "locked_at" in data


@pytest.mark.asyncio
async def test_acquire_uses_correct_key(rt_client):
    rt_client.set.return_value = True
    await InvestigationLockService.acquire(rt_client, INV_ID, TENANT_ID, ANALYST_ID)
    key_arg = rt_client.set.call_args[0][0]
    assert INV_ID in key_arg
    assert "lock" in key_arg


@pytest.mark.asyncio
async def test_acquire_custom_ttl(rt_client):
    rt_client.set.return_value = True
    await InvestigationLockService.acquire(rt_client, INV_ID, TENANT_ID, ANALYST_ID, ttl=30)
    call_kwargs = rt_client.set.call_args[1]
    assert call_kwargs.get("ex") == 30


# ─── get ──────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_returns_lock_info_when_locked(rt_client):
    rt_client.get.return_value = make_lock_json()
    lock = await InvestigationLockService.get(rt_client, INV_ID)
    assert lock is not None
    assert lock.owner_id == ANALYST_ID


@pytest.mark.asyncio
async def test_get_returns_none_when_not_locked(rt_client):
    rt_client.get.return_value = None
    lock = await InvestigationLockService.get(rt_client, INV_ID)
    assert lock is None


@pytest.mark.asyncio
async def test_get_returns_none_on_corrupt_json(rt_client):
    rt_client.get.return_value = "not-valid-json{{{"
    lock = await InvestigationLockService.get(rt_client, INV_ID)
    assert lock is None


# ─── release ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_release_returns_true_for_owner(rt_client):
    rt_client.get.return_value = make_lock_json(owner_id=ANALYST_ID)
    released = await InvestigationLockService.release(rt_client, INV_ID, ANALYST_ID)
    assert released is True
    rt_client.delete.assert_called_once()


@pytest.mark.asyncio
async def test_release_returns_false_for_non_owner(rt_client):
    rt_client.get.return_value = make_lock_json(owner_id=ANALYST_ID)
    released = await InvestigationLockService.release(rt_client, INV_ID, ANALYST2_ID)
    assert released is False
    rt_client.delete.assert_not_called()


@pytest.mark.asyncio
async def test_release_returns_false_when_not_locked(rt_client):
    rt_client.get.return_value = None
    released = await InvestigationLockService.release(rt_client, INV_ID, ANALYST_ID)
    assert released is False


# ─── refresh ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_refresh_returns_true_for_owner(rt_client):
    rt_client.get.return_value = make_lock_json(owner_id=ANALYST_ID)
    rt_client.set.return_value = True  # XX succeeded
    result = await InvestigationLockService.refresh(rt_client, INV_ID, ANALYST_ID)
    assert result is True


@pytest.mark.asyncio
async def test_refresh_returns_false_for_non_owner(rt_client):
    rt_client.get.return_value = make_lock_json(owner_id=ANALYST_ID)
    result = await InvestigationLockService.refresh(rt_client, INV_ID, ANALYST2_ID)
    assert result is False
    rt_client.set.assert_not_called()


@pytest.mark.asyncio
async def test_refresh_returns_false_when_not_locked(rt_client):
    rt_client.get.return_value = None
    result = await InvestigationLockService.refresh(rt_client, INV_ID, ANALYST_ID)
    assert result is False


@pytest.mark.asyncio
async def test_refresh_uses_xx_flag(rt_client):
    rt_client.get.return_value = make_lock_json(owner_id=ANALYST_ID)
    rt_client.set.return_value = True
    await InvestigationLockService.refresh(rt_client, INV_ID, ANALYST_ID)
    call_kwargs = rt_client.set.call_args[1]
    assert call_kwargs.get("xx") is True


@pytest.mark.asyncio
async def test_refresh_returns_false_if_set_xx_fails(rt_client):
    rt_client.get.return_value = make_lock_json(owner_id=ANALYST_ID)
    rt_client.set.return_value = None  # XX failed — key expired between get+set
    result = await InvestigationLockService.refresh(rt_client, INV_ID, ANALYST_ID)
    assert result is False


# ─── transfer ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_transfer_success(rt_client):
    rt_client.get.return_value = make_lock_json(owner_id=ANALYST_ID)
    rt_client.set.return_value = True
    lock = await InvestigationLockService.transfer(
        rt_client, INV_ID, TENANT_ID, ANALYST_ID, ANALYST2_ID
    )
    assert lock is not None
    assert lock.owner_id == ANALYST2_ID


@pytest.mark.asyncio
async def test_transfer_fails_if_not_owner(rt_client):
    rt_client.get.return_value = make_lock_json(owner_id=ANALYST2_ID)
    lock = await InvestigationLockService.transfer(
        rt_client, INV_ID, TENANT_ID, ANALYST_ID, ANALYST2_ID
    )
    assert lock is None


# ─── force_release ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_force_release_returns_true_when_lock_exists(rt_client):
    rt_client.exists.return_value = True
    result = await InvestigationLockService.force_release(rt_client, INV_ID)
    assert result is True
    rt_client.delete.assert_called_once()


@pytest.mark.asyncio
async def test_force_release_returns_false_when_no_lock(rt_client):
    rt_client.exists.return_value = False
    result = await InvestigationLockService.force_release(rt_client, INV_ID)
    assert result is False
    rt_client.delete.assert_not_called()


@pytest.mark.asyncio
async def test_force_release_does_not_check_owner(rt_client):
    rt_client.exists.return_value = True
    # Even with ANALYST2 owning, admin can force release
    rt_client.get.return_value = make_lock_json(owner_id=ANALYST2_ID)
    result = await InvestigationLockService.force_release(rt_client, INV_ID)
    assert result is True


# ─── is_locked / is_locked_by ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_is_locked_true(rt_client):
    rt_client.exists.return_value = True
    assert await InvestigationLockService.is_locked(rt_client, INV_ID) is True


@pytest.mark.asyncio
async def test_is_locked_false(rt_client):
    rt_client.exists.return_value = False
    assert await InvestigationLockService.is_locked(rt_client, INV_ID) is False


@pytest.mark.asyncio
async def test_is_locked_by_correct_owner(rt_client):
    rt_client.get.return_value = make_lock_json(owner_id=ANALYST_ID)
    assert await InvestigationLockService.is_locked_by(rt_client, INV_ID, ANALYST_ID) is True


@pytest.mark.asyncio
async def test_is_locked_by_wrong_owner(rt_client):
    rt_client.get.return_value = make_lock_json(owner_id=ANALYST_ID)
    assert await InvestigationLockService.is_locked_by(rt_client, INV_ID, ANALYST2_ID) is False


@pytest.mark.asyncio
async def test_is_locked_by_no_lock(rt_client):
    rt_client.get.return_value = None
    assert await InvestigationLockService.is_locked_by(rt_client, INV_ID, ANALYST_ID) is False
