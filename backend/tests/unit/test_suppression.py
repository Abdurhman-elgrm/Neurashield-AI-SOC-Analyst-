"""Unit tests for alert suppression."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.detection.suppression import SuppressionStore, build_suppression_key


def _make_client(set_nx_result=True) -> MagicMock:
    client = MagicMock()
    client.set = AsyncMock(return_value=None if not set_nx_result else True)
    client.exists = AsyncMock(return_value=set_nx_result)
    return client


class TestBuildSuppressionKey:
    def test_same_inputs_same_key(self):
        k1 = build_suppression_key("rule-1", "HOST1")
        k2 = build_suppression_key("rule-1", "HOST1")
        assert k1 == k2

    def test_different_rule_different_key(self):
        k1 = build_suppression_key("rule-1", "HOST1")
        k2 = build_suppression_key("rule-2", "HOST1")
        assert k1 != k2

    def test_different_host_different_key(self):
        k1 = build_suppression_key("rule-1", "HOST1")
        k2 = build_suppression_key("rule-1", "HOST2")
        assert k1 != k2

    def test_none_host_handled(self):
        k = build_suppression_key("rule-1", None)
        assert isinstance(k, str)
        assert k.startswith("suppress:")


@pytest.mark.asyncio
class TestSuppressionStore:
    async def test_check_and_suppress_first_time_returns_not_suppressed(self):
        client = MagicMock()
        # SET NX returns a truthy value (True) on first call = key was set
        client.set = AsyncMock(return_value=True)
        store = SuppressionStore(client)
        suppressed = await store.check_and_suppress("key1", 300)
        assert suppressed is False  # Not suppressed — was new

    async def test_check_and_suppress_second_time_returns_suppressed(self):
        client = MagicMock()
        # SET NX returns None = key already existed = suppressed
        client.set = AsyncMock(return_value=None)
        # expire is called to slide the window when key already exists
        client.expire = AsyncMock(return_value=True)
        store = SuppressionStore(client)
        suppressed = await store.check_and_suppress("key1", 300)
        assert suppressed is True
