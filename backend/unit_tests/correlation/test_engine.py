from __future__ import annotations

"""
Unit tests for the CorrelationEngine orchestration layer.

Uses an in-memory stub for TenantRedisClient so no Redis instance is needed.
"""

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.correlation.engine import CorrelationEngine, CorrelationResult

TENANT_ID = "tenant-test-0000-1111-2222-333344445555"

# ─── Stub TenantRedisClient ───────────────────────────────────────────────────


class _FakeRedis:
    """Minimal in-memory Redis stub sufficient for engine tests."""

    def __init__(self) -> None:
        self._store: dict[str, Any] = {}
        self._zsets: dict[str, dict[str, float]] = {}
        self._hashes: dict[str, dict[str, str]] = {}

    # STRING
    async def get(self, key: str) -> str | None:
        return self._store.get(key)

    async def set(self, key: str, value: Any, **_: Any) -> bool:
        self._store[key] = str(value)
        return True

    async def expire(self, key: str, seconds: int) -> bool:
        return True

    # ZSET
    async def zadd(self, key: str, mapping: dict[str, float]) -> int:
        zs = self._zsets.setdefault(key, {})
        zs.update(mapping)
        return len(mapping)

    async def zrangebyscore(self, key: str, min: Any, max: Any) -> list[str]:
        zs = self._zsets.get(key, {})
        lo = float("-inf") if min in ("-inf", float("-inf")) else float(min)
        hi = float("inf") if max in ("+inf", float("inf")) else float(max)
        return [m for m, s in zs.items() if lo <= s <= hi]

    async def zremrangebyscore(self, key: str, min: Any, max: Any) -> int:
        zs = self._zsets.get(key, {})
        lo = float("-inf") if min in ("-inf", float("-inf")) else float(min)
        hi = float("inf") if max in ("+inf", float("inf")) else float(max)
        to_remove = [m for m, s in list(zs.items()) if lo <= s <= hi]
        for m in to_remove:
            del zs[m]
        return len(to_remove)

    async def zremrangebyrank(self, key: str, start: int, stop: int) -> int:
        zs = self._zsets.get(key, {})
        sorted_members = sorted(zs.items(), key=lambda x: x[1])
        to_remove = sorted_members[start : stop + 1]
        for m, _ in to_remove:
            del zs[m]
        return len(to_remove)

    async def zcount(self, key: str, min: Any, max: Any) -> int:
        zs = self._zsets.get(key, {})
        lo = float("-inf") if min in ("-inf", float("-inf")) else float(min)
        hi = float("inf") if max in ("+inf", float("inf")) else float(max)
        return sum(1 for s in zs.values() if lo <= s <= hi)

    # HASH
    async def hset(self, name: str, mapping: dict[str, str]) -> int:
        h = self._hashes.setdefault(name, {})
        h.update(mapping)
        return len(mapping)

    async def hgetall(self, name: str) -> dict[str, str]:
        return dict(self._hashes.get(name, {}))


class _FakeTenantClient:
    """Delegates to _FakeRedis with a tenant prefix on all keys."""

    def __init__(self, tenant_id: str) -> None:
        self._redis = _FakeRedis()
        self._prefix = f"tenant:{tenant_id}:corr:"

    def _key(self, key: str) -> str:
        return f"{self._prefix}{key}"

    async def get(self, key: str) -> str | None:
        return await self._redis.get(self._key(key))

    async def set(self, key: str, value: Any, **kwargs: Any) -> bool:
        return await self._redis.set(self._key(key), value)

    async def expire(self, key: str, seconds: int) -> bool:
        return await self._redis.expire(self._key(key), seconds)

    async def zadd(self, key: str, mapping: dict[str, float]) -> int:
        return await self._redis.zadd(self._key(key), mapping)

    async def zrangebyscore(self, key: str, min: Any, max: Any) -> list[str]:
        return await self._redis.zrangebyscore(self._key(key), min, max)

    async def zremrangebyscore(self, key: str, min: Any, max: Any) -> int:
        return await self._redis.zremrangebyscore(self._key(key), min, max)

    async def zremrangebyrank(self, key: str, start: int, stop: int) -> int:
        return await self._redis.zremrangebyrank(self._key(key), start, stop)

    async def zcount(self, key: str, min: Any, max: Any) -> int:
        return await self._redis.zcount(self._key(key), min, max)

    async def hset(self, name: str, mapping: dict[str, str]) -> int:
        return await self._redis.hset(self._key(name), mapping)

    async def hgetall(self, name: str) -> dict[str, str]:
        return await self._redis.hgetall(self._key(name))


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def fake_client() -> _FakeTenantClient:
    return _FakeTenantClient(TENANT_ID)


@pytest.fixture
def engine(fake_client: _FakeTenantClient) -> CorrelationEngine:
    return CorrelationEngine(TENANT_ID, fake_client)  # type: ignore[arg-type]


# ─── Minimal payload helpers ──────────────────────────────────────────────────

def _payload(
    *,
    event_id: str = "evt-001",
    correlation_id: str | None = "cid-aaa",
    session_id: str | None = "sid-bbb",
    process_tree_id: str | None = "ptid-ccc",
    event_chain_id: str | None = "ecid-ddd",
    timestamp: float = 1_700_000_000.0,
    entities: list[dict] | None = None,
    tenant_id: str = TENANT_ID,
) -> dict:
    p: dict = {
        "event_id": event_id,
        "tenant_id": tenant_id,
        "timestamp": timestamp,
        "entities": entities or [],
    }
    if correlation_id:
        p["correlation_id"] = correlation_id
    if session_id:
        p["session_id"] = session_id
    if process_tree_id:
        p["process_tree_id"] = process_tree_id
    if event_chain_id:
        p["event_chain_id"] = event_chain_id
    return p


# ─── Tests ────────────────────────────────────────────────────────────────────

class TestEngineBasic:
    @pytest.mark.asyncio
    async def test_returns_correlation_result(self, engine: CorrelationEngine) -> None:
        result = await engine.process_event(_payload())
        assert isinstance(result, CorrelationResult)

    @pytest.mark.asyncio
    async def test_tenant_id_propagated(self, engine: CorrelationEngine) -> None:
        result = await engine.process_event(_payload())
        assert result.tenant_id == TENANT_ID

    @pytest.mark.asyncio
    async def test_event_id_propagated(self, engine: CorrelationEngine) -> None:
        result = await engine.process_event(_payload(event_id="evt-xyz"))
        assert result.event_id == "evt-xyz"

    @pytest.mark.asyncio
    async def test_first_event_no_match(self, engine: CorrelationEngine) -> None:
        result = await engine.process_event(_payload())
        assert not result.is_significant
        assert result.investigation_id is None
        assert result.score == 0

    @pytest.mark.asyncio
    async def test_to_dict_has_required_fields(self, engine: CorrelationEngine) -> None:
        result = await engine.process_event(_payload())
        d = result.to_dict()
        for field in ("event_id", "tenant_id", "investigation_id", "score", "confidence",
                      "matched_rules", "reasons", "group_keys", "is_significant"):
            assert field in d


class TestEngineScoresAccumulate:
    @pytest.mark.asyncio
    async def test_burst_fires_after_threshold_events(self, engine: CorrelationEngine) -> None:
        ts = 1_700_000_000.0
        cid = "cid-burst"
        # First 3 events: should not be significant individually (no prior counts)
        for i in range(3):
            await engine.process_event(_payload(
                event_id=f"evt-{i}", correlation_id=cid,
                session_id=None, process_tree_id=None, event_chain_id=None,
                timestamp=ts + i,
            ))
        # 4th event — window now has 3 prior events, burst threshold met
        result = await engine.process_event(_payload(
            event_id="evt-3", correlation_id=cid,
            session_id=None, process_tree_id=None, event_chain_id=None,
            timestamp=ts + 3,
        ))
        assert "same_host_burst" in result.matched_rules

    @pytest.mark.asyncio
    async def test_investigation_id_created_when_significant(
        self, engine: CorrelationEngine
    ) -> None:
        ts = 1_700_000_000.0
        cid = "cid-invest"
        # Feed enough events to trigger significance.
        results = []
        for i in range(4):
            r = await engine.process_event(_payload(
                event_id=f"e{i}", correlation_id=cid,
                session_id=None, process_tree_id=None, event_chain_id=None,
                timestamp=ts + i,
            ))
            results.append(r)
        significant = [r for r in results if r.is_significant]
        assert significant, "Expected at least one significant result"
        for r in significant:
            assert r.investigation_id is not None

    @pytest.mark.asyncio
    async def test_same_correlation_id_groups_together(
        self, engine: CorrelationEngine
    ) -> None:
        ts = 1_700_000_000.0
        cid = "cid-same"
        inv_ids: set[str] = set()
        for i in range(6):
            r = await engine.process_event(_payload(
                event_id=f"ev{i}", correlation_id=cid,
                session_id=None, process_tree_id=None, event_chain_id=None,
                timestamp=ts + i,
            ))
            if r.investigation_id:
                inv_ids.add(r.investigation_id)
        assert len(inv_ids) == 1, "All events should resolve to the same investigation"


class TestEngineTenantIsolation:
    @pytest.mark.asyncio
    async def test_different_tenants_different_engines_no_shared_state(self) -> None:
        client_a = _FakeTenantClient("tenant-aaa")
        client_b = _FakeTenantClient("tenant-bbb")
        engine_a = CorrelationEngine("tenant-aaa", client_a)  # type: ignore[arg-type]
        engine_b = CorrelationEngine("tenant-bbb", client_b)  # type: ignore[arg-type]

        ts = 1_700_000_000.0
        cid = "cid-shared-name"  # same name, different tenants
        for i in range(5):
            await engine_a.process_event(_payload(
                event_id=f"a{i}", correlation_id=cid,
                session_id=None, process_tree_id=None, event_chain_id=None,
                timestamp=ts + i, tenant_id="tenant-aaa",
            ))

        # B has seen no events — first event should have zero score
        result_b = await engine_b.process_event(_payload(
            event_id="b0", correlation_id=cid,
            session_id=None, process_tree_id=None, event_chain_id=None,
            timestamp=ts, tenant_id="tenant-bbb",
        ))
        assert result_b.score == 0
        assert not result_b.is_significant


class TestEngineTimestampHandling:
    @pytest.mark.asyncio
    async def test_uses_event_timestamp_not_wall_clock(
        self, engine: CorrelationEngine
    ) -> None:
        # Events with ts in the past — engine should still process them
        old_ts = 1_000_000.0
        result = await engine.process_event(_payload(timestamp=old_ts))
        assert isinstance(result, CorrelationResult)

    @pytest.mark.asyncio
    async def test_missing_timestamp_falls_back_gracefully(
        self, engine: CorrelationEngine
    ) -> None:
        p = _payload()
        del p["timestamp"]
        result = await engine.process_event(p)
        assert isinstance(result, CorrelationResult)

    @pytest.mark.asyncio
    async def test_iso_string_timestamp_accepted(
        self, engine: CorrelationEngine
    ) -> None:
        p = _payload()
        p["timestamp"] = "1700000000.0"
        result = await engine.process_event(p)
        assert isinstance(result, CorrelationResult)
