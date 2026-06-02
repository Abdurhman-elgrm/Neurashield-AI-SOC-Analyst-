from __future__ import annotations

import pytest

from app.correlation.matcher import GroupContext, MatchResult, RuleMatch
from app.correlation.rules import (
    SAME_HOST_BURST,
    SAME_PROCESS_TREE,
    SHARED_FILE_HASH,
    SHARED_SOURCE_IP,
)
from app.correlation.scoring import CorrelationScore, CorrelationScorer, score_match


def _make_match(*rules_with_counts: tuple) -> MatchResult:
    """Helper: make a MatchResult from (rule, window_key, count) triples."""
    result = MatchResult()
    for rule, wk, count in rules_with_counts:
        result.matched_rules.append(RuleMatch(rule=rule, window_key=wk, event_count=count))
    return result


class TestScorerBands:
    def test_empty_match_gives_zero(self):
        s = CorrelationScorer()
        cs = s.score(MatchResult())
        assert cs.score == 0
        assert cs.confidence == "low"

    def test_single_low_weight_rule_is_low(self):
        m = _make_match((SHARED_SOURCE_IP, "ip:1.2.3.4", 3))
        cs = score_match(m)
        assert cs.score == SHARED_SOURCE_IP.weight
        assert cs.confidence == "low"

    def test_medium_band_threshold(self):
        # SAME_HOST_BURST(10) + SHARED_SOURCE_IP(8) + SHARED_FILE_HASH(18) = 36 → still low
        # Add SAME_PROCESS_TREE(20) → 56 → medium
        m = _make_match(
            (SAME_HOST_BURST, "cid:x", 5),
            (SHARED_SOURCE_IP, "ip:a", 3),
            (SHARED_FILE_HASH, "hash:md5:abc", 2),
            (SAME_PROCESS_TREE, "ptid:y", 3),
        )
        cs = score_match(m)
        assert cs.score == 56
        assert cs.confidence == "medium"

    def test_high_band_threshold(self):
        # SAME_PROCESS_TREE(20) + SHARED_FILE_HASH(18) + SAME_LOGON_SESSION(15) + ... = ≥75
        from app.correlation.rules import SAME_LOGON_SESSION, SAME_USER_MULTI_HOST
        m = _make_match(
            (SAME_PROCESS_TREE, "ptid:z", 4),
            (SHARED_FILE_HASH, "hash:sha256:ff", 2),
            (SAME_LOGON_SESSION, "sid:q", 3),
            (SAME_USER_MULTI_HOST, "user:corp\\alice", 2),
            (SAME_HOST_BURST, "cid:c", 5),
        )
        cs = score_match(m)
        assert cs.score == 20 + 18 + 15 + 15 + 10
        assert cs.confidence == "high"

    def test_score_capped_at_100(self):
        from app.correlation.rules import ALL_RULES
        m = _make_match(*[(r, "k", 5) for r in ALL_RULES])
        cs = score_match(m)
        assert cs.score == 100

    def test_is_significant_above_threshold(self):
        m = _make_match((SAME_HOST_BURST, "cid:x", 5))
        cs = score_match(m)
        assert cs.is_significant  # score=10 >= 10

    def test_is_not_significant_at_zero(self):
        cs = score_match(MatchResult())
        assert not cs.is_significant


class TestScorerOrdering:
    def test_matched_rules_sorted_by_weight_desc(self):
        m = _make_match(
            (SAME_HOST_BURST, "k1", 3),       # weight 10
            (SAME_PROCESS_TREE, "k2", 2),     # weight 20
            (SHARED_SOURCE_IP, "k3", 2),      # weight 8
        )
        cs = score_match(m)
        weights = [r.rule.weight for r in cs.matched_rules]
        assert weights == sorted(weights, reverse=True)

    def test_reasons_not_empty_when_rules_matched(self):
        m = _make_match((SAME_HOST_BURST, "cid:x", 3))
        cs = score_match(m)
        assert len(cs.reasons) == 1
        assert "same_host_burst" in cs.reasons[0]

    def test_reasons_empty_when_no_match(self):
        cs = score_match(MatchResult())
        assert cs.reasons == []
