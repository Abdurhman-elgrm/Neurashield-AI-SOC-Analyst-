from __future__ import annotations

import time
from typing import Any

import structlog

from app.core.redis import TenantRedisClient
from app.detection.patterns import _get_field, evaluate_conditions
from app.normalization.models import NormalizedEvent

logger = structlog.get_logger(__name__)


class ThresholdEvaluator:
    """
    Evaluates threshold-type detection rules using a Redis ZSET sliding window.

    Each distinct (rule_id, group_value) pair maintains an independent ZSET where:
      - member = unique event marker (event_id or high-res timestamp)
      - score  = unix timestamp (float)

    On every call we atomically: add the new member, prune expired members, count,
    and refresh the key TTL — all via a Redis pipeline.  This eliminates the
    INCR/EXPIRE race condition that the original counter-based approach had.

    Rule conditions schema:
    {
      "field": "network.dst_ip",      -- value to group/count occurrences of
      "group_by": "hostname",          -- optional dimension key
      "threshold": 5,                  -- fire when count >= this
      "window_secs": 300,              -- sliding window in seconds
      "filters": [...]                 -- pre-conditions: event must match ALL of these
    }
    """

    def __init__(self, client: TenantRedisClient) -> None:
        self._client = client

    async def evaluate(
        self,
        rule_id: str,
        conditions: dict[str, Any],
        event: NormalizedEvent,
    ) -> tuple[bool, int, list[str]]:
        """
        Returns (fired, current_count, window_event_ids).
        fired=True means the sliding-window count crossed the threshold after this event.
        window_event_ids contains the members (event IDs or timestamps) currently in the
        window — gives analysts full context of all contributing events, not just the last.
        """
        filters: list[dict[str, Any]] = conditions.get("filters", [])
        if filters and not evaluate_conditions(filters, event):
            return False, 0, []

        field_path: str = conditions.get("field", "hostname")
        group_by: str | None = conditions.get("group_by")
        threshold: int = int(conditions.get("threshold", 5))
        window_secs: int = int(conditions.get("window_secs", 300))

        field_value = _get_field(event, field_path)
        if field_value is None:
            return False, 0, []

        group_value = _get_field(event, group_by) if group_by else "global"
        zset_key = f"threshold:{rule_id}:{group_value or 'global'}"

        now = time.time()
        cutoff = now - window_secs
        # Use event_id for deduplication if available, otherwise high-res timestamp
        member = str(event.event_id) if event.event_id else f"{now:.9f}"

        # Atomic pipeline: add → prune expired → count → fetch members → refresh TTL.
        # No race condition possible — all ops are sequential in a single pipeline.
        pipe = self._client.pipeline()
        full_key = self._client._key(zset_key)
        pipe.zadd(full_key, {member: now})
        pipe.zremrangebyscore(full_key, "-inf", cutoff)
        pipe.zcount(full_key, cutoff, "+inf")
        pipe.zrangebyscore(full_key, cutoff, "+inf")  # retrieve members for evidence
        pipe.expire(full_key, window_secs + 60)        # TTL slightly longer than window
        results = await pipe.execute()
        count = int(results[2])
        # Members are event IDs (or high-res timestamps) — cap at 25 for evidence
        window_members: list[str] = list(results[3])[:25]

        fired = count >= threshold

        if fired:
            logger.info(
                "threshold_rule_fired",
                rule_id=rule_id,
                count=count,
                threshold=threshold,
                window_secs=window_secs,
                group_value=str(group_value),
            )

        return fired, count, window_members

    async def get_count(self, rule_id: str, group_value: str = "global") -> int:
        """Returns current sliding-window count without incrementing."""
        now = time.time()
        # We need the window_secs to compute cutoff, but we don't have it here.
        # Return the total ZSET count as a best-effort approximation.
        zset_key = f"threshold:{rule_id}:{group_value}"
        return await self._client.zcount(zset_key, "-inf", "+inf")
