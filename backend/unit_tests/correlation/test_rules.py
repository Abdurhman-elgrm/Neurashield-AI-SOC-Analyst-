from __future__ import annotations

import pytest

from app.correlation.rules import (
    ALL_RULES,
    RULES_BY_NAME,
    CorrelationRule,
    HIGH_FREQUENCY_SOURCE,
    SAME_EVENT_CHAIN,
    SAME_HOST_BURST,
    SAME_LOGON_SESSION,
    SAME_PROCESS_TREE,
    SAME_USER_MULTI_HOST,
    SHARED_DEST_IP,
    SHARED_DOMAIN,
    SHARED_FILE_HASH,
    SHARED_SOURCE_IP,
)


class TestRuleStructure:
    def test_all_rules_is_tuple(self):
        assert isinstance(ALL_RULES, tuple)

    def test_all_rules_has_ten_entries(self):
        assert len(ALL_RULES) == 10

    def test_each_rule_is_frozen_dataclass(self):
        for rule in ALL_RULES:
            assert isinstance(rule, CorrelationRule)
            with pytest.raises((AttributeError, TypeError)):
                rule.name = "mutated"  # type: ignore[misc]

    def test_rules_by_name_covers_all(self):
        assert set(RULES_BY_NAME.keys()) == {r.name for r in ALL_RULES}

    def test_no_duplicate_names(self):
        names = [r.name for r in ALL_RULES]
        assert len(names) == len(set(names))

    def test_weights_in_range(self):
        for rule in ALL_RULES:
            assert 1 <= rule.weight <= 25, f"{rule.name} weight={rule.weight} out of range"

    def test_window_seconds_positive(self):
        for rule in ALL_RULES:
            assert rule.window_seconds > 0

    def test_tags_are_tuples(self):
        for rule in ALL_RULES:
            assert isinstance(rule.tags, tuple)


class TestSpecificRules:
    def test_same_host_burst_short_window(self):
        assert SAME_HOST_BURST.window_seconds == 300

    def test_same_process_tree_highest_weight(self):
        assert SAME_PROCESS_TREE.weight >= max(
            r.weight for r in ALL_RULES if r.name != SAME_PROCESS_TREE.name
        ) or SAME_PROCESS_TREE.weight == SHARED_FILE_HASH.weight

    def test_shared_file_hash_weight_high(self):
        assert SHARED_FILE_HASH.weight >= 15

    def test_same_logon_session_medium_window(self):
        assert SAME_LOGON_SESSION.window_seconds == 900

    def test_same_process_tree_long_window(self):
        assert SAME_PROCESS_TREE.window_seconds == 3600

    def test_high_frequency_source_short_window(self):
        assert HIGH_FREQUENCY_SOURCE.window_seconds == 300

    def test_lookup_by_name(self):
        assert RULES_BY_NAME["same_host_burst"] is SAME_HOST_BURST
        assert RULES_BY_NAME["shared_file_hash"] is SHARED_FILE_HASH

    def test_missing_name_raises(self):
        assert RULES_BY_NAME.get("nonexistent") is None

    def test_total_possible_score_exceeds_100(self):
        total = sum(r.weight for r in ALL_RULES)
        assert total > 100, "Score cap at 100 should be meaningful"
