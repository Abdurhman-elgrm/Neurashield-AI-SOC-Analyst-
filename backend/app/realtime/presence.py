from __future__ import annotations

"""
Analyst presence system — tracks who is online, what they are viewing,
and when they were last seen.

Redis data model (all keys scoped via TenantRedisClient):
  presence:{analyst_id}   — Hash with PresenceState fields, TTL = PRESENCE_TTL_SECS
  presence_online         — Set of analyst_id strings currently online

Flow:
  join()        → HSET + SADD + EXPIRE
  heartbeat()   → HSET updated fields + EXPIRE (refresh TTL)
  leave()       → DEL + SREM
  list_online() → SMEMBERS → filter by key existence
"""

from datetime import UTC, datetime

import structlog

from app.core.redis import TenantRedisClient
from app.realtime import channels as ch
from app.realtime.schemas import PresenceState

logger = structlog.get_logger(__name__)

PRESENCE_TTL_SECS = 30  # clients must heartbeat faster than this
IDLE_THRESHOLD_SECS = 120


class PresenceService:
    """
    Stateless service — all state lives in Redis.
    Every method takes a TenantRedisClient scoped to the realtime subsystem.
    """

    @staticmethod
    async def join(
        client: TenantRedisClient,
        analyst_id: str,
        tenant_id: str,
        display_name: str = "",
        workspace: str = "dashboard",
        investigation_id: str | None = None,
    ) -> PresenceState:
        """Register an analyst as online. Idempotent — safe to call on reconnect."""
        now = datetime.now(tz=UTC).isoformat()
        mapping: dict[str, str] = {
            "analyst_id": analyst_id,
            "tenant_id": tenant_id,
            "display_name": display_name,
            "workspace": workspace,
            "investigation_id": investigation_id or "",
            "idle": "false",
            "last_seen": now,
        }
        key = ch.presence_key(analyst_id)
        await client.hset(key, mapping)
        await client.expire(key, PRESENCE_TTL_SECS)
        await client.sadd(ch.presence_set_key(), analyst_id)

        logger.debug("analyst_presence_joined", analyst_id=analyst_id, workspace=workspace)
        return PresenceState(
            analyst_id=analyst_id,
            tenant_id=tenant_id,
            display_name=display_name,
            workspace=workspace,
            investigation_id=investigation_id,
            idle=False,
            last_seen=now,
        )

    @staticmethod
    async def leave(
        client: TenantRedisClient,
        analyst_id: str,
    ) -> None:
        """Remove analyst from presence tracking."""
        await client.delete(ch.presence_key(analyst_id))
        await client.srem(ch.presence_set_key(), analyst_id)
        logger.debug("analyst_presence_left", analyst_id=analyst_id)

    @staticmethod
    async def heartbeat(
        client: TenantRedisClient,
        analyst_id: str,
        workspace: str | None = None,
        investigation_id: str | None = None,
        idle: bool = False,
    ) -> bool:
        """
        Refresh presence TTL and optionally update state fields.
        Returns True if the analyst was already online.
        """
        key = ch.presence_key(analyst_id)
        if not await client.exists(key):
            return False

        now = datetime.now(tz=UTC).isoformat()
        update: dict[str, str] = {
            "last_seen": now,
            "idle": "true" if idle else "false",
        }
        if workspace is not None:
            update["workspace"] = workspace
        if investigation_id is not None:
            update["investigation_id"] = investigation_id

        await client.hset(key, update)
        await client.expire(key, PRESENCE_TTL_SECS)
        return True

    @staticmethod
    async def set_active_investigation(
        client: TenantRedisClient,
        analyst_id: str,
        investigation_id: str | None,
    ) -> bool:
        """Update which investigation the analyst is currently viewing."""
        key = ch.presence_key(analyst_id)
        if not await client.exists(key):
            return False
        await client.hset(key, {"investigation_id": investigation_id or ""})
        await client.expire(key, PRESENCE_TTL_SECS)
        return True

    @staticmethod
    async def get(
        client: TenantRedisClient,
        analyst_id: str,
    ) -> PresenceState | None:
        """Return current presence state for one analyst, or None if offline."""
        data = await client.hgetall(ch.presence_key(analyst_id))
        if not data:
            return None
        return PresenceState.from_redis(data)

    @staticmethod
    async def list_online(
        client: TenantRedisClient,
    ) -> list[PresenceState]:
        """
        Return presence states for all currently online analysts.
        Prunes stale entries from the online set.
        """
        analyst_ids = await client.smembers(ch.presence_set_key())
        online: list[PresenceState] = []
        stale: list[str] = []

        for aid in analyst_ids:
            state = await PresenceService.get(client, aid)
            if state is not None:
                online.append(state)
            else:
                stale.append(aid)

        if stale:
            await client.srem(ch.presence_set_key(), *stale)

        return online

    @staticmethod
    async def count_online(client: TenantRedisClient) -> int:
        """Approximate count of online analysts."""
        return await client.scard(ch.presence_set_key())
