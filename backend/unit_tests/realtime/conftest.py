from __future__ import annotations

"""Shared fixtures for realtime unit tests."""

import asyncio
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.core.redis import TenantRedisClient

TENANT_ID  = "aaa00000-0000-0000-0000-000000000001"
TENANT2_ID = "bbb00000-0000-0000-0000-000000000002"
ANALYST_ID = "ccc00000-0000-0000-0000-000000000001"
ANALYST2_ID = "ccc00000-0000-0000-0000-000000000002"
INV_ID     = "ddd00000-0000-0000-0000-000000000001"
INV_ID_2   = "ddd00000-0000-0000-0000-000000000002"
WS_ID      = str(uuid4())
WS_ID_2    = str(uuid4())
NOW        = datetime.now(tz=timezone.utc).isoformat()


@pytest.fixture
def rt_client() -> AsyncMock:
    """Mocked TenantRedisClient for the realtime subsystem."""
    client = AsyncMock(spec=TenantRedisClient)
    client.hset.return_value = 0
    client.hget.return_value = None
    client.hgetall.return_value = {}
    client.hdel.return_value = 1
    client.delete.return_value = 1
    client.expire.return_value = True
    client.exists.return_value = True
    client.sadd.return_value = 1
    client.srem.return_value = 1
    client.smembers.return_value = set()
    client.scard.return_value = 0
    client.sismember.return_value = False
    client.set.return_value = True
    client.get.return_value = None
    client.publish.return_value = 1
    return client


@pytest.fixture
def rt_client2() -> AsyncMock:
    """Second mocked TenantRedisClient for tenant isolation tests."""
    client = AsyncMock(spec=TenantRedisClient)
    client.hset.return_value = 0
    client.hget.return_value = None
    client.hgetall.return_value = {}
    client.delete.return_value = 1
    client.expire.return_value = True
    client.exists.return_value = False
    client.sadd.return_value = 1
    client.srem.return_value = 1
    client.smembers.return_value = set()
    client.scard.return_value = 0
    client.set.return_value = None
    client.get.return_value = None
    return client


def make_presence_hash(
    analyst_id: str = ANALYST_ID,
    tenant_id: str = TENANT_ID,
    display_name: str = "Alice",
    workspace: str = "dashboard",
    investigation_id: str = "",
    idle: str = "false",
    last_seen: str = NOW,
) -> dict[str, str]:
    return {
        "analyst_id": analyst_id,
        "tenant_id": tenant_id,
        "display_name": display_name,
        "workspace": workspace,
        "investigation_id": investigation_id,
        "idle": idle,
        "last_seen": last_seen,
    }


def make_lock_json(
    investigation_id: str = INV_ID,
    tenant_id: str = TENANT_ID,
    owner_id: str = ANALYST_ID,
) -> str:
    import json
    from datetime import timedelta

    now = datetime.now(tz=timezone.utc)
    return json.dumps({
        "investigation_id": investigation_id,
        "tenant_id": tenant_id,
        "owner_id": owner_id,
        "locked_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=60)).isoformat(),
    })
