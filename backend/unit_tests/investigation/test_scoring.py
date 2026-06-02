from __future__ import annotations

import pytest

from app.investigation.behavior import analyze_behaviors
from app.investigation.context import build_context
from app.investigation.graph import build_attack_graph
from app.investigation.scoring import InvestigationScorer, score_investigation
from app.investigation.timeline import build_timeline
from unit_tests.investigation.conftest import (
    INV_ID, TENANT_ID, _TS_BASE,
    make_snapshot, make_network_snapshot, make_process_snapshot,
)


def _full(snaps: list, matched_rules: list | None = None):
    tl  = build_timeline(INV_ID, TENANT_ID, snaps)
    g   = build_attack_graph(INV_ID, snaps)
    ba  = analyze_behaviors(INV_ID, tl, snaps)
    ctx = build_context(INV_ID, TENANT_ID, tl, g, ba, snaps)
    sc  = score_investigation(tl, ba, ctx, matched_rules=matched_rules)
    return tl, ba, ctx, sc


class TestScorerBasic:
    def test_empty_returns_zero_score(self):
        _, _, _, sc = _full([])
        assert sc.threat_score == 0
        assert sc.confidence == "low"

    def test_score_is_int(self):
        _, _, _, sc = _full([make_snapshot()])
        assert isinstance(sc.threat_score, int)

    def test_score_capped_at_100(self):
        snaps = [
            make_process_snapshot(process_name="mimikatz.exe", event_id=f"m{i}")
            for i in range(20)
        ] + [
            make_process_snapshot(process_name="psexec.exe", event_id=f"p{i}")
            for i in range(20)
        ]
        _, _, _, sc = _full(snaps, matched_rules=["r1", "r2", "r3", "r4", "r5"])
        assert sc.threat_score <= 100

    def test_tp_fp_sum_to_one(self):
        _, _, _, sc = _full([make_snapshot()])
        assert abs(sc.tp_probability + sc.fp_probability - 1.0) < 0.01

    def test_confidence_bands(self):
        scorer = InvestigationScorer()
        assert scorer._band(0) == "low"
        assert scorer._band(39) == "low"
        assert scorer._band(40) == "medium"
        assert scorer._band(74) == "medium"
        assert scorer._band(75) == "high"
        assert scorer._band(100) == "high"


class TestScorerFactors:
    def test_correlation_rules_add_score(self):
        snaps = [make_snapshot()]
        tl  = build_timeline(INV_ID, TENANT_ID, snaps)
        g   = build_attack_graph(INV_ID, snaps)
        ba  = analyze_behaviors(INV_ID, tl, snaps)
        ctx = build_context(INV_ID, TENANT_ID, tl, g, ba, snaps)
        sc_no_rules  = score_investigation(tl, ba, ctx, matched_rules=[])
        sc_with_rules = score_investigation(tl, ba, ctx, matched_rules=["r1", "r2"])
        assert sc_with_rules.threat_score >= sc_no_rules.threat_score

    def test_behaviors_increase_score(self):
        no_beh = _full([make_snapshot()])
        with_beh = _full([make_process_snapshot(process_name="mimikatz.exe")])
        assert with_beh[3].threat_score >= no_beh[3].threat_score

    def test_cross_host_increases_score(self):
        single_host = _full([make_snapshot(hostname="H1")])
        multi_host  = _full([
            make_snapshot(event_id="e1", hostname="H1"),
            make_snapshot(event_id="e2", hostname="H2"),
        ])
        assert multi_host[3].threat_score >= single_host[3].threat_score

    def test_suspicious_processes_add_score(self):
        no_susp = _full([make_snapshot()])
        with_susp = _full([
            make_snapshot(
                related_entity_keys=["host:h1"],
                process={"name": "mimikatz.exe", "executable": "C:\\temp\\mimikatz.exe", "command_line": "mimikatz.exe"},
            )
        ])
        assert with_susp[3].threat_score >= no_susp[3].threat_score

    def test_high_score_high_tp_probability(self):
        snaps = [
            make_process_snapshot(process_name="mimikatz.exe", event_id=f"m{i}", severity=9)
            for i in range(5)
        ] + [
            make_process_snapshot(process_name="psexec.exe", event_id=f"p{i}")
            for i in range(3)
        ]
        _, _, _, sc = _full(snaps, matched_rules=["r1", "r2", "r3"])
        if sc.threat_score >= 50:
            assert sc.tp_probability > 0.5

    def test_zero_score_high_fp_probability(self):
        _, _, _, sc = _full([])
        assert sc.fp_probability > sc.tp_probability

    def test_score_breakdown_not_empty_when_factors_exist(self):
        _, _, _, sc = _full(
            [make_process_snapshot(process_name="mimikatz.exe")],
            matched_rules=["rule1"],
        )
        # If there are factors, breakdown should be non-empty
        if sc.scoring_factors:
            assert len(sc.score_breakdown) > 0

    def test_scoring_factors_dict_has_float_values(self):
        _, _, _, sc = _full([make_snapshot()], matched_rules=["r1"])
        for v in sc.scoring_factors.values():
            assert isinstance(v, float)
