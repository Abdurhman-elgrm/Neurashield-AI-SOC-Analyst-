from __future__ import annotations

from typing import Any

import structlog

from app.core.redis import TenantRedisClient
from app.detection.patterns import _get_field, evaluate_conditions
from app.normalization.models import NormalizedEvent

logger = structlog.get_logger(__name__)


class ThresholdEvaluator:
    """
    Evaluates threshold-type detection rules.

    Rule conditions schema:
    {
      "field": "network.dst_ip",      -- value to count occurrences of
      "group_by": "hostname",          -- optional dimension key
      "threshold": 5,                  -- fire when count >= this
      "window_secs": 300,              -- sliding window in seconds
      "filters": [...]                 -- pre-conditions: event must match ALL of these
    }

    Counter key pattern:
      threshold:{rule_id}:{group_value}
    (TenantRedisClient prefix: tenant:{id}:detect:)
    """

    def __init__(self, client: TenantRedisClient) -> None:
        self._client = client

    async def evaluate(
        self,
        rule_id: str,
        conditions: dict[str, Any],
        event: NormalizedEvent,
    ) -> tuple[bool, int]:
        """
        Returns (fired, current_count).
        fired=True means count crossed the threshold after this event.
        """
        filters: list[dict[str, Any]] = conditions.get("filters", [])
        if filters and not evaluate_conditions(filters, event):
            return False, 0

        field_path: str = conditions.get("field", "hostname")
        group_by: str | None = conditions.get("group_by")
        threshold: int = int(conditions.get("threshold", 5))
        window_secs: int = int(conditions.get("window_secs", 300))

        field_value = _get_field(event, field_path)
        if field_value is None:
            return False, 0

        group_value = _get_field(event, group_by) if group_by else "global"
        counter_key = f"threshold:{rule_id}:{group_value or 'global'}"

        count = await self._client.incr(counter_key)
        if count == 1:
            await self._client.expire(counter_key, window_secs)

        fired = count >= threshold

        if fired:
            logger.info(
                "threshold_rule_fired",
                rule_id=rule_id,
                count=count,
                threshold=threshold,
                group_value=str(group_value),
            )

        return fired, count

    async def get_count(self, rule_id: str, group_value: str = "global") -> int:
        """Returns current counter without incrementing."""
        val = await self._client.get(f"threshold:{rule_id}:{group_value}")
        return int(val) if val else 0
