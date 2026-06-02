from __future__ import annotations

"""
Investigation edit-lock service.

Uses Redis SET NX EX for atomic, TTL-bounded exclusive locks.
Lock state is JSON stored in a string key (not a hash) for atomic NX semantics.

Key schema (within TenantRedisClient):
  lock:inv:{investigation_id}  →  JSON string with LockInfo fields

Lock lifecycle:
  acquire → SET NX EX lock_ttl_secs
  refresh → SET XX EX lock_ttl_secs (only by current owner)
  release → DEL (only by current owner, or admin force-release)
  transfer → release + acquire atomically (best-effort)
"""


import json
from datetime import datetime, timezone, timedelta

import structlog

from app.core.redis import TenantRedisClient
from app.realtime import channels as ch
from app.realtime.schemas import LockInfo

logger = structlog.get_logger(__name__)

LOCK_TTL_SECS     = 60   # 1-minute edit lock
LOCK_REFRESH_SECS = 45   # refresh before expiry


class InvestigationLockService:
    """
    All methods take a TenantRedisClient scoped to the realtime subsystem.
    Tenant isolation is enforced by the client's key prefix.
    """

    @staticmethod
    async def acquire(
        client: TenantRedisClient,
        investigation_id: str,
        tenant_id: str,
        analyst_id: str,
        ttl: int = LOCK_TTL_SECS,
    ) -> LockInfo | None:
        """
        Attempt to acquire an exclusive edit lock.
        Returns LockInfo if acquired; None if already locked by someone else.
        """
        now = datetime.now(tz=timezone.utc)
        expires_at = (now + timedelta(seconds=ttl)).isoformat()
        info = {
            "investigation_id": investigation_id,
            "tenant_id":        tenant_id,
            "owner_id":         analyst_id,
            "locked_at":        now.isoformat(),
            "expires_at":       expires_at,
        }
        key = ch.lock_key(investigation_id)
        acquired = await client.set(key, json.dumps(info), ex=ttl, nx=True)
        if not acquired:
            logger.debug(
                "lock_acquire_failed",
                investigation_id=investigation_id,
                analyst_id=analyst_id,
            )
            return None

        logger.info(
            "lock_acquired",
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            ttl=ttl,
        )
        return LockInfo(**info)

    @staticmethod
    async def get(
        client: TenantRedisClient,
        investigation_id: str,
    ) -> LockInfo | None:
        """Return current lock info, or None if not locked."""
        raw = await client.get(ch.lock_key(investigation_id))
        if raw is None:
            return None
        try:
            return LockInfo.from_redis(json.loads(raw))
        except Exception:
            return None

    @staticmethod
    async def release(
        client: TenantRedisClient,
        investigation_id: str,
        analyst_id: str,
    ) -> bool:
        """
        Release the lock if the caller is the owner.
        Returns True on success; False if not the owner or lock doesn't exist.
        """
        lock = await InvestigationLockService.get(client, investigation_id)
        if lock is None:
            return False
        if lock.owner_id != analyst_id:
            logger.debug(
                "lock_release_denied",
                investigation_id=investigation_id,
                requester=analyst_id,
                owner=lock.owner_id,
            )
            return False
        await client.delete(ch.lock_key(investigation_id))
        logger.info("lock_released", investigation_id=investigation_id, analyst_id=analyst_id)
        return True

    @staticmethod
    async def refresh(
        client: TenantRedisClient,
        investigation_id: str,
        analyst_id: str,
        ttl: int = LOCK_TTL_SECS,
    ) -> bool:
        """
        Extend the lock TTL if the caller is the current owner.
        Returns True on success.
        """
        lock = await InvestigationLockService.get(client, investigation_id)
        if lock is None or lock.owner_id != analyst_id:
            return False

        now = datetime.now(tz=timezone.utc)
        expires_at = (now + timedelta(seconds=ttl)).isoformat()
        updated = {
            "investigation_id": lock.investigation_id,
            "tenant_id":        lock.tenant_id,
            "owner_id":         analyst_id,
            "locked_at":        lock.locked_at,
            "expires_at":       expires_at,
        }
        # XX = only update if key exists (avoids race where lock expired between get+set)
        ok = await client.set(ch.lock_key(investigation_id), json.dumps(updated), ex=ttl, xx=True)
        return bool(ok)

    @staticmethod
    async def transfer(
        client: TenantRedisClient,
        investigation_id: str,
        tenant_id: str,
        from_analyst: str,
        to_analyst: str,
        ttl: int = LOCK_TTL_SECS,
    ) -> LockInfo | None:
        """
        Transfer the lock from one analyst to another.
        Only succeeds if from_analyst currently holds the lock.
        Returns the new LockInfo on success, None on failure.
        """
        released = await InvestigationLockService.release(
            client, investigation_id, from_analyst
        )
        if not released:
            return None
        return await InvestigationLockService.acquire(
            client, investigation_id, tenant_id, to_analyst, ttl
        )

    @staticmethod
    async def force_release(
        client: TenantRedisClient,
        investigation_id: str,
    ) -> bool:
        """
        Force-release a lock regardless of owner (admin operation).
        Returns True if a lock existed and was removed.
        """
        exists = await client.exists(ch.lock_key(investigation_id))
        if not exists:
            return False
        await client.delete(ch.lock_key(investigation_id))
        logger.info("lock_force_released", investigation_id=investigation_id)
        return True

    @staticmethod
    async def is_locked(
        client: TenantRedisClient,
        investigation_id: str,
    ) -> bool:
        return await client.exists(ch.lock_key(investigation_id))

    @staticmethod
    async def is_locked_by(
        client: TenantRedisClient,
        investigation_id: str,
        analyst_id: str,
    ) -> bool:
        lock = await InvestigationLockService.get(client, investigation_id)
        return lock is not None and lock.owner_id == analyst_id
