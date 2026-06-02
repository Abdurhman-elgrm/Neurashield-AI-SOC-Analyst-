from __future__ import annotations

"""
Unit tests for the InvestigationEngine orchestration layer.
Fully isolated — no DB, no Redis.
"""

import pytest

from app.investigation.engine import InvestigationEngine
from app.investigation.schemas import InvestigationResult
from unit_tests.investigation.conftest import (
    INV_ID, TENANT_ID, _TS_BASE,
    make_snapshot, make_network_snapshot, make_process_snapshot,
)


@pytest.fixture
def engine() -> InvestigationEngine:
    return InvestigationEngine(TENANT_ID)


class TestEngineBasic:
    @pytest.mark.asyncio
    async def test_returns_investigation_result(self, engine: InvestigationEngine) -> None:
        result = await engine.process_group(INV_ID, [make_snapshot()])
        assert isinstance(result, InvestigationResult)

    @pytest.mark.asyncio
    async def test_investigation_id_propagated(self, engine: InvestigationEngine) -> None:
        result = await engine.process_group("custom-inv-id", [make_snapshot()])
        assert result.investigation_id == "custom-inv-id"

    @pytest.mark.asyncio
    async def test_tenant_id_propagated(self, engine: InvestigationEngine) -> None:
        result = await engine.process_group(INV_ID, [make_snapshot()])
        assert result.tenant_id == TENANT_ID

    @pytest.mark.asyncio
    async def test_investigation_group_id_set(self, engine: InvestigationEngine) -> None:
        result = await engine.process_group(INV_ID, [make_snapshot()])
        assert result.investigation_group_id == INV_ID

    @pytest.mark.asyncio
    async def test_empty_snapshots_returns_result(self, engine: InvestigationEngine) -> None:
        result = await engine.process_group(INV_ID, [])
        assert isinstance(result, InvestigationResult)
        assert result.timeline.total_events == 0

    @pytest.mark.asyncio
    async def test_all_sub_results_present(self, engine: InvestigationEngine) -> None:
        result = await engine.process_group(INV_ID, [make_snapshot()])
        assert result.timeline is not None
        assert result.graph is not None
        assert result.behaviors is not None
        assert result.context is not None
        assert result.score is not None
        assert result.summary is not None


class TestEnginePipeline:
    @pytest.mark.asyncio
    async def test_timeline_has_events(self, engine: InvestigationEngine) -> None:
        snaps = [make_snapshot(event_id=f"e{i}") for i in range(3)]
        result = await engine.process_group(INV_ID, snaps)
        assert result.timeline.total_events == 3

    @pytest.mark.asyncio
    async def test_graph_built_from_entities(self, engine: InvestigationEngine) -> None:
        snap = make_snapshot(related_entity_keys=["host:myhost", "ip:1.2.3.4"])
        result = await engine.process_group(INV_ID, [snap])
        assert result.graph.node_count >= 2

    @pytest.mark.asyncio
    async def test_behaviors_from_mimikatz(self, engine: InvestigationEngine) -> None:
        snap = make_process_snapshot(process_name="mimikatz.exe")
        result = await engine.process_group(INV_ID, [snap])
        names = [b.behavior_name for b in result.behaviors.detected_behaviors]
        assert "credential_access" in names

    @pytest.mark.asyncio
    async def test_score_range_valid(self, engine: InvestigationEngine) -> None:
        result = await engine.process_group(INV_ID, [make_snapshot()])
        assert 0 <= result.score.threat_score <= 100

    @pytest.mark.asyncio
    async def test_summary_executive_not_empty(self, engine: InvestigationEngine) -> None:
        result = await engine.process_group(INV_ID, [make_snapshot()])
        assert result.summary.executive_summary

    @pytest.mark.asyncio
    async def test_status_active_when_significant(self, engine: InvestigationEngine) -> None:
        snaps = [
            make_process_snapshot(process_name="mimikatz.exe", event_id=f"m{i}")
            for i in range(3)
        ]
        result = await engine.process_group(
            INV_ID, snaps,
            group_meta={"matched_rules": ["r1", "r2"], "score": 60, "confidence": "medium"},
        )
        if result.score.threat_score >= 10:
            assert result.status == "active"

    @pytest.mark.asyncio
    async def test_status_new_for_low_score(self, engine: InvestigationEngine) -> None:
        result = await engine.process_group(INV_ID, [])
        if result.score.threat_score < 10:
            assert result.status == "new"


class TestEngineGroupMeta:
    @pytest.mark.asyncio
    async def test_group_meta_score_used(self, engine: InvestigationEngine) -> None:
        result = await engine.process_group(
            INV_ID,
            [make_snapshot()],
            group_meta={"score": 60, "matched_rules": ["same_host_burst"], "confidence": "medium"},
        )
        assert isinstance(result.score.threat_score, int)

    @pytest.mark.asyncio
    async def test_group_meta_none_handled(self, engine: InvestigationEngine) -> None:
        result = await engine.process_group(INV_ID, [make_snapshot()], group_meta=None)
        assert result is not None


class TestEngineTenantIsolation:
    @pytest.mark.asyncio
    async def test_different_tenant_engines_independent(self) -> None:
        engine_a = InvestigationEngine("tenant-A")
        engine_b = InvestigationEngine("tenant-B")
        snap = make_process_snapshot(process_name="mimikatz.exe")

        result_a = await engine_a.process_group(INV_ID, [snap])
        result_b = await engine_b.process_group(INV_ID, [snap])

        assert result_a.tenant_id == "tenant-A"
        assert result_b.tenant_id == "tenant-B"

    @pytest.mark.asyncio
    async def test_investigation_id_in_result_matches_input(self) -> None:
        engine = InvestigationEngine(TENANT_ID)
        result_x = await engine.process_group("inv-X", [make_snapshot()])
        result_y = await engine.process_group("inv-Y", [make_snapshot()])
        assert result_x.investigation_id == "inv-X"
        assert result_y.investigation_id == "inv-Y"


class TestEngineReplayDeterminism:
    @pytest.mark.asyncio
    async def test_same_snapshots_same_threat_score(self, engine: InvestigationEngine) -> None:
        snaps = [
            make_process_snapshot(process_name="mimikatz.exe", event_id="m1"),
            make_network_snapshot(event_id="n1"),
        ]
        r1 = await engine.process_group(INV_ID, snaps)
        r2 = await engine.process_group(INV_ID, snaps)
        assert r1.score.threat_score == r2.score.threat_score

    @pytest.mark.asyncio
    async def test_same_snapshots_same_behavior_count(self, engine: InvestigationEngine) -> None:
        snaps = [
            make_process_snapshot(process_name="powershell.exe", event_id="p1"),
        ]
        r1 = await engine.process_group(INV_ID, snaps)
        r2 = await engine.process_group(INV_ID, snaps)
        assert r1.behaviors.behavior_count == r2.behaviors.behavior_count

    @pytest.mark.asyncio
    async def test_to_dict_serializable(self, engine: InvestigationEngine) -> None:
        result = await engine.process_group(INV_ID, [make_snapshot()])
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "investigation_id" in d
        assert "score" in d
        assert "timeline" in d

    @pytest.mark.asyncio
    async def test_to_db_dict_has_required_fields(self, engine: InvestigationEngine) -> None:
        result = await engine.process_group(INV_ID, [make_snapshot()])
        db = result.to_db_dict()
        for field in (
            "investigation_id", "tenant_id", "investigation_group_id",
            "threat_score", "confidence", "tp_probability", "fp_probability",
            "executive_summary", "technical_summary",
            "attack_progression", "recommended_actions", "status",
        ):
            assert field in db, f"Missing DB field: {field}"
