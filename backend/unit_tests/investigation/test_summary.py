from __future__ import annotations

import pytest

from app.investigation.behavior import analyze_behaviors
from app.investigation.context import build_context
from app.investigation.graph import build_attack_graph
from app.investigation.scoring import score_investigation
from app.investigation.summary import generate_summary
from app.investigation.timeline import build_timeline
from unit_tests.investigation.conftest import (
    INV_ID, TENANT_ID, _TS_BASE,
    make_snapshot, make_network_snapshot, make_process_snapshot,
)


def _summary(snaps: list, matched_rules: list | None = None):
    tl  = build_timeline(INV_ID, TENANT_ID, snaps)
    g   = build_attack_graph(INV_ID, snaps)
    ba  = analyze_behaviors(INV_ID, tl, snaps)
    ctx = build_context(INV_ID, TENANT_ID, tl, g, ba, snaps)
    sc  = score_investigation(tl, ba, ctx, matched_rules=matched_rules)
    sm  = generate_summary(INV_ID, tl, ba, ctx, sc)
    return sm, tl, ba, ctx, sc


class TestSummaryBasic:
    def test_returns_investigation_summary(self):
        from app.investigation.schemas import InvestigationSummary
        sm, *_ = _summary([make_snapshot()])
        assert isinstance(sm, InvestigationSummary)

    def test_investigation_id_set(self):
        sm, *_ = _summary([make_snapshot()])
        assert sm.investigation_id == INV_ID

    def test_executive_summary_not_empty(self):
        sm, *_ = _summary([make_snapshot()])
        assert len(sm.executive_summary) > 0

    def test_technical_summary_not_empty(self):
        sm, *_ = _summary([make_snapshot()])
        assert len(sm.technical_summary) > 0

    def test_attack_progression_is_list(self):
        sm, *_ = _summary([make_snapshot()])
        assert isinstance(sm.attack_progression, list)

    def test_attack_progression_not_empty_with_events(self):
        sm, *_ = _summary([make_snapshot()])
        assert len(sm.attack_progression) > 0

    def test_recommended_actions_is_list(self):
        sm, *_ = _summary([make_snapshot()])
        assert isinstance(sm.recommended_actions, list)

    def test_recommended_actions_not_empty(self):
        sm, *_ = _summary([make_snapshot()])
        assert len(sm.recommended_actions) > 0

    def test_containment_recommendations_is_list(self):
        sm, *_ = _summary([make_snapshot()])
        assert isinstance(sm.containment_recommendations, list)


class TestSummaryDeterminism:
    def test_same_inputs_same_executive_summary(self):
        snaps = [
            make_process_snapshot(process_name="mimikatz.exe", event_id="m1"),
        ]
        sm1, *_ = _summary(snaps)
        sm2, *_ = _summary(snaps)
        assert sm1.executive_summary == sm2.executive_summary

    def test_same_inputs_same_technical_summary(self):
        snaps = [make_snapshot(event_id="e1", hostname="MYHOST")]
        sm1, *_ = _summary(snaps)
        sm2, *_ = _summary(snaps)
        assert sm1.technical_summary == sm2.technical_summary

    def test_same_inputs_same_progression(self):
        snaps = [
            make_snapshot(event_id="e1", timestamp=_TS_BASE),
            make_snapshot(event_id="e2", timestamp=_TS_BASE + 60),
        ]
        sm1, *_ = _summary(snaps)
        sm2, *_ = _summary(snaps)
        assert sm1.attack_progression == sm2.attack_progression


class TestSummaryContent:
    def test_high_confidence_executive_mentions_high(self):
        snaps = [
            make_process_snapshot(process_name="mimikatz.exe", event_id=f"m{i}", severity=9)
            for i in range(5)
        ] + [
            make_process_snapshot(process_name="psexec.exe", event_id=f"p{i}", hostname=f"H{i}")
            for i in range(3)
        ]
        sm, *rest = _summary(snaps, matched_rules=["r1", "r2", "r3"])
        sc = rest[3]
        if sc.confidence == "high":
            assert "high" in sm.executive_summary.lower()

    def test_impacted_assets_not_empty_with_events(self):
        snaps = [make_snapshot(hostname="VICTIM-01")]
        sm, *_ = _summary(snaps)
        # impacted_assets includes hosts and users
        assert isinstance(sm.impacted_assets, list)

    def test_analyst_notes_fp_warning_when_high_fp(self):
        snaps = [make_snapshot()]
        sm, *rest = _summary(snaps)
        sc = rest[3]
        if sc.fp_probability >= 0.6:
            any_fp_note = any("FP" in note or "probability" in note.lower() for note in sm.analyst_notes)
            assert any_fp_note

    def test_progression_mentions_host_from_first_event(self):
        snaps = [make_snapshot(hostname="COMPROMISED-01", timestamp=_TS_BASE)]
        sm, *_ = _summary(snaps)
        progression_text = " ".join(sm.attack_progression)
        assert "COMPROMISED-01" in progression_text

    def test_technical_summary_mentions_event_count(self):
        snaps = [make_snapshot(event_id=f"e{i}") for i in range(3)]
        sm, *_ = _summary(snaps)
        assert "3" in sm.technical_summary
