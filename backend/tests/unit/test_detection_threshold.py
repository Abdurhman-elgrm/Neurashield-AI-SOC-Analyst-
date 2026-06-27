"""Unit tests for threshold-based detection rules."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.detection.threshold import ThresholdEvaluator
from app.normalization.models import NormalizedEvent, NormalizedNetwork


def _make_event(**kwargs) -> NormalizedEvent:
    defaults = {
        "event_id": "test",
        "timestamp": datetime.now(tz=UTC),
        "category": "network",
        "severity": 1,
        "hostname": "WIN-TEST",
        "os_type": "windows",
        "agent_id": "agent1",
        "tenant_id": "tenant1",
    }
    defaults.update(kwargs)
    return NormalizedEvent(**defaults)


def _make_tenant_client(counter_val: int) -> MagicMock:
    client = MagicMock()
    client.incr = AsyncMock(return_value=counter_val)
    client.expire = AsyncMock(return_value=True)
    client.get = AsyncMock(return_value=str(counter_val))
    return client


@pytest.mark.asyncio
class TestThresholdEvaluator:
    async def test_fires_when_threshold_reached(self):
        client = _make_tenant_client(5)
        evaluator = ThresholdEvaluator(client)
        conditions = {"field": "network.dst_ip", "threshold": 5, "window_secs": 60}
        event = _make_event(network=NormalizedNetwork(dst_ip="8.8.8.8"))
        fired, count = await evaluator.evaluate("rule-1", conditions, event)
        assert fired is True
        assert count == 5

    async def test_does_not_fire_below_threshold(self):
        client = _make_tenant_client(3)
        evaluator = ThresholdEvaluator(client)
        conditions = {"field": "network.dst_ip", "threshold": 5, "window_secs": 60}
        event = _make_event(network=NormalizedNetwork(dst_ip="8.8.8.8"))
        fired, count = await evaluator.evaluate("rule-1", conditions, event)
        assert fired is False
        assert count == 3

    async def test_filters_applied_before_counting(self):
        client = _make_tenant_client(10)
        evaluator = ThresholdEvaluator(client)
        conditions = {
            "field": "network.dst_ip",
            "threshold": 5,
            "window_secs": 60,
            "filters": [{"field": "category", "op": "eq", "value": "process"}],
        }
        # event category is "network", filter requires "process" — should not fire
        event = _make_event(category="network")
        fired, count = await evaluator.evaluate("rule-1", conditions, event)
        assert fired is False
        assert count == 0
        # incr should NOT have been called because filter didn't match
        client.incr.assert_not_called()

    async def test_missing_field_skips_count(self):
        client = _make_tenant_client(10)
        evaluator = ThresholdEvaluator(client)
        conditions = {"field": "network.dst_ip", "threshold": 5, "window_secs": 60}
        event = _make_event(network=None)
        fired, count = await evaluator.evaluate("rule-1", conditions, event)
        assert fired is False
        assert count == 0

    async def test_expire_called_on_first_increment(self):
        client = _make_tenant_client(1)
        evaluator = ThresholdEvaluator(client)
        conditions = {"field": "hostname", "threshold": 1, "window_secs": 300}
        event = _make_event()
        await evaluator.evaluate("rule-1", conditions, event)
        client.expire.assert_called_once()
