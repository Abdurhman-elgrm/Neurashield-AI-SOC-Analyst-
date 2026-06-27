"""
UEBA baseline persistence — snapshot Redis sets to DB and restore on startup.

Redis holds the live baseline (30-day TTL sets of seen IPs / seen processes).
After a pod restart those sets are gone, causing false positives for 24-48 hours
while the baseline re-learns.  This module bridges the gap:

  * snapshot(): dumps current Redis sets to the `ueba_baseline_snapshots` table.
  * restore():  on first UEBA startup, pre-populates Redis sets from the last
                snapshot so the baseline is warm immediately.
"""

from __future__ import annotations

import json
import os
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis import TenantRedisClient

logger = structlog.get_logger(__name__)

# How many entries to cap per set when snapshotting (avoid storing unbounded data).
_MAX_ENTRIES_PER_SET = int(os.getenv("UEBA_BASELINE_SNAPSHOT_MAX", "2000"))
_TTL_30D = 86400 * 30


class BaselinePersistenceService:
    """
    Snapshots the Redis UEBA baseline to the DB and restores it on startup.
    Operates on a single tenant at a time.
    """

    def __init__(self, tenant_id: str, redis_client: Any) -> None:
        self._tenant_id = tenant_id
        self._client = TenantRedisClient(redis_client, tenant_id, "ueba")

    # ── Snapshot ──────────────────────────────────────────────────────────────

    async def snapshot(self, db: AsyncSession) -> int:
        """
        Dump all seen_ips and seen_procs sets to DB.
        Returns the number of rows upserted.
        """
        from sqlalchemy import text

        rows_written = 0

        # Scan for all known pattern keys in the UEBA subsystem.
        # TenantRedisClient.scan_iter returns unprefixed keys.
        try:
            async for raw_key in self._client.scan_iter("user:*:seen_ips"):
                values = await self._client.smembers(raw_key)
                if values:
                    entries = list(values)[:_MAX_ENTRIES_PER_SET]
                    await db.execute(
                        text("""
                        INSERT INTO ueba_baseline_snapshots
                            (tenant_id, key_type, entity_key, values_json, snapshot_at)
                        VALUES
                            (CAST(:tid AS uuid), 'seen_ips', :ekey, CAST(:vals AS jsonb), NOW())
                        ON CONFLICT (tenant_id, key_type, entity_key)
                        DO UPDATE SET values_json = CAST(:vals AS jsonb), snapshot_at = NOW()
                    """),
                        {
                            "tid": self._tenant_id,
                            "ekey": raw_key,
                            "vals": json.dumps(entries),
                        },
                    )
                    rows_written += 1

            async for raw_key in self._client.scan_iter("host:*:seen_procs"):
                values = await self._client.smembers(raw_key)
                if values:
                    entries = list(values)[:_MAX_ENTRIES_PER_SET]
                    await db.execute(
                        text("""
                        INSERT INTO ueba_baseline_snapshots
                            (tenant_id, key_type, entity_key, values_json, snapshot_at)
                        VALUES
                            (CAST(:tid AS uuid), 'seen_procs', :ekey, CAST(:vals AS jsonb), NOW())
                        ON CONFLICT (tenant_id, key_type, entity_key)
                        DO UPDATE SET values_json = CAST(:vals AS jsonb), snapshot_at = NOW()
                    """),
                        {
                            "tid": self._tenant_id,
                            "ekey": raw_key,
                            "vals": json.dumps(entries),
                        },
                    )
                    rows_written += 1

            await db.commit()
            logger.info(
                "ueba_baseline_snapshot_complete",
                tenant_id=self._tenant_id,
                rows=rows_written,
            )
        except Exception as exc:
            logger.error("ueba_baseline_snapshot_failed", tenant_id=self._tenant_id, error=str(exc))

        return rows_written

    # ── Restore ───────────────────────────────────────────────────────────────

    async def restore(self, db: AsyncSession) -> int:
        """
        Pre-populate Redis baseline sets from the last DB snapshot.
        Skips any key that already has live Redis data.
        Returns the number of Redis keys restored.
        """
        from sqlalchemy import text

        restored = 0
        try:
            rows = await db.execute(
                text("""
                SELECT key_type, entity_key, values_json
                FROM ueba_baseline_snapshots
                WHERE tenant_id = CAST(:tid AS uuid)
            """),
                {"tid": self._tenant_id},
            )

            for row in rows.fetchall():
                values: list[str] = row.values_json or []
                if not values:
                    continue
                redis_key = row.entity_key  # already in the unprefixed form
                # Only restore if the key doesn't exist (e.g. after a pod restart)
                if not await self._client.exists(redis_key):
                    await self._client.sadd(redis_key, *values)
                    await self._client.expire(redis_key, _TTL_30D)
                    restored += 1

            logger.info(
                "ueba_baseline_restore_complete",
                tenant_id=self._tenant_id,
                keys_restored=restored,
            )
        except Exception as exc:
            logger.error("ueba_baseline_restore_failed", tenant_id=self._tenant_id, error=str(exc))

        return restored
