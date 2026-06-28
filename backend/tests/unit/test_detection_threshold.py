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


def _make_pipeline(count_val: int) -> MagicMock:
    """Build a mock Redis pipeline whose execute() returns results for the ZSET ops."""
    pipe = MagicMock()
    pipe.zadd = MagicMock()
    pipe.zremrangebyscore = MagicMock()
    pipe.zcount = MagicMock()
    pipe.zrangebyscore = MagicMock()
    pipe.expire = MagicMock()
    # execute() returns: [zadd_result, zremrange_result, count, members_list, expire_result]
    pipe.execute = AsyncMock(
        return_value=[1, 0, count_val, [f"evt-{i}" for i in range(count_val)], True]
    )
    return pipe


def _make_tenant_client(count_val: int) -> MagicMock:
    """Build a mock TenantRedisClient backed by a ZSET pipeline mock."""
    pipe = _make_pipeline(count_val)
    client = MagicMock()
    client.pipeline = MagicMock(return_value=pipe)
    client._key = MagicMock(side_effect=lambda k: f"tenant:test:{k}")
    # Expose pipe so tests can assert on individual commands
    client._pipe = pipe
    return client


@pytest.mark.asyncio
class TestThresholdEvaluator:
    async def test_fires_when_threshold_reached(self):
        client = _make_tenant_client(5)
        evaluator = ThresholdEvaluator(client)
        conditions = {"field": "network.dst_ip", "threshold": 5, "window_secs": 60}
        event = _make_event(network=NormalizedNetwork(dst_ip="8.8.8.8"))
        fired, count, members = await evaluator.evaluate("rule-1", conditions, event)
        assert fired is True
        assert count == 5
        assert len(members) == 5

    async def test_does_not_fire_below_threshold(self):
        client = _make_tenant_client(3)
        evaluator = ThresholdEvaluator(client)
        conditions = {"field": "network.dst_ip", "threshold": 5, "window_secs": 60}
        event = _make_event(network=NormalizedNetwork(dst_ip="8.8.8.8"))
        fired, count, _ = await evaluator.evaluate("rule-1", conditions, event)
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
        # event category is "network", filter requires "process" — pipeline must not run
        event = _make_event(category="network")
        fired, count, members = await evaluator.evaluate("rule-1", conditions, event)
        assert fired is False
        assert count == 0
        assert members == []
        # pipeline should NOT have been executed because filter didn't match
        client._pipe.execute.assert_not_called()

    async def test_missing_field_skips_count(self):
        client = _make_tenant_client(10)
        evaluator = ThresholdEvaluator(client)
        conditions = {"field": "network.dst_ip", "threshold": 5, "window_secs": 60}
        event = _make_event(network=None)
        fired, count, members = await evaluator.evaluate("rule-1", conditions, event)
        assert fired is False
        assert count == 0
        assert members == []

    async def test_expire_called_on_first_increment(self):
        client = _make_tenant_client(1)
        evaluator = ThresholdEvaluator(client)
        conditions = {"field": "hostname", "threshold": 1, "window_secs": 300}
        event = _make_event()
        await evaluator.evaluate("rule-1", conditions, event)
        # expire is set as part of the pipeline — verify execute was called
        client._pipe.execute.assert_called_once()
        client._pipe.expire.assert_called_once()
