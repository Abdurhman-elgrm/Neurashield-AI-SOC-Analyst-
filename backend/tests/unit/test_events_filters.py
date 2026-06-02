"""Unit tests for the Events Explorer filter engine."""
from __future__ import annotations

import pytest
from sqlalchemy import and_, not_, or_
from sqlalchemy.sql.elements import BooleanClauseList, UnaryExpression

from app.events.filters import (
    FilterValidationError,
    build_condition,
    build_filter_group,
    build_filter_groups,
)
from app.events.schemas import FilterCondition, FilterGroup


# ─── FilterCondition ──────────────────────────────────────────────────────────

class TestFilterCondition:
    def test_eq_operator(self):
        cond = FilterCondition(field="host_name", op="eq", value="dc01")
        clause = build_condition(cond)
        assert clause is not None

    def test_ne_operator(self):
        clause = build_condition(FilterCondition(field="severity", op="ne", value=1))
        assert clause is not None

    def test_gte_operator(self):
        clause = build_condition(FilterCondition(field="severity", op="gte", value=2))
        assert clause is not None

    def test_in_operator(self):
        clause = build_condition(
            FilterCondition(field="category", op="in", value=["process", "network"])
        )
        assert clause is not None

    def test_not_in_operator(self):
        clause = build_condition(
            FilterCondition(field="host_name", op="not_in", value=["dc01", "dc02"])
        )
        assert clause is not None

    def test_contains_operator(self):
        clause = build_condition(FilterCondition(field="process_name", op="contains", value="powershell"))
        assert clause is not None

    def test_icontains_operator(self):
        clause = build_condition(FilterCondition(field="username", op="icontains", value="admin"))
        assert clause is not None

    def test_starts_with_operator(self):
        clause = build_condition(FilterCondition(field="host_name", op="starts_with", value="dc"))
        assert clause is not None

    def test_is_null(self):
        clause = build_condition(FilterCondition(field="username", op="is_null"))
        assert clause is not None

    def test_is_not_null(self):
        clause = build_condition(FilterCondition(field="source_ip", op="is_not_null"))
        assert clause is not None

    def test_invalid_field_raises(self):
        with pytest.raises(FilterValidationError, match="not filterable"):
            build_condition(FilterCondition(field="raw_payload", op="eq", value="{}"))

    def test_sql_injection_field_raises(self):
        with pytest.raises(FilterValidationError):
            build_condition(FilterCondition(field="id; DROP TABLE events--", op="eq", value="1"))

    def test_correlation_id_field(self):
        # New Phase 3.6 fields should be filterable
        clause = build_condition(FilterCondition(field="correlation_id", op="eq", value="corr-123"))
        assert clause is not None

    def test_session_id_field(self):
        clause = build_condition(FilterCondition(field="session_id", op="eq", value="sess-abc"))
        assert clause is not None

    def test_process_tree_id_field(self):
        clause = build_condition(FilterCondition(field="process_tree_id", op="eq", value="tree-xyz"))
        assert clause is not None

    def test_event_chain_id_field(self):
        clause = build_condition(FilterCondition(field="event_chain_id", op="eq", value="chain-001"))
        assert clause is not None


# ─── FilterGroup ──────────────────────────────────────────────────────────────

class TestFilterGroup:
    def test_empty_group_returns_none(self):
        group = FilterGroup(logic="AND")
        result = build_filter_group(group)
        assert result is None

    def test_and_group_with_one_condition(self):
        group = FilterGroup(
            logic="AND",
            conditions=[FilterCondition(field="severity", op="gte", value=3)],
        )
        clause = build_filter_group(group)
        assert clause is not None

    def test_and_group_with_multiple_conditions(self):
        group = FilterGroup(
            logic="AND",
            conditions=[
                FilterCondition(field="severity", op="gte", value=3),
                FilterCondition(field="host_name", op="eq", value="dc01"),
            ],
        )
        clause = build_filter_group(group)
        assert clause is not None
        # AND with multiple conditions should be an AND clause
        assert "AND" in str(clause).upper() or hasattr(clause, "clauses")

    def test_or_group(self):
        group = FilterGroup(
            logic="OR",
            conditions=[
                FilterCondition(field="source_ip", op="eq", value="1.2.3.4"),
                FilterCondition(field="dest_ip", op="eq", value="1.2.3.4"),
            ],
        )
        clause = build_filter_group(group)
        assert clause is not None

    def test_not_group(self):
        group = FilterGroup(
            logic="NOT",
            conditions=[FilterCondition(field="category", op="eq", value="process")],
        )
        clause = build_filter_group(group)
        assert clause is not None

    def test_nested_groups(self):
        inner = FilterGroup(
            logic="OR",
            conditions=[
                FilterCondition(field="source_ip", op="eq", value="1.1.1.1"),
                FilterCondition(field="dest_ip", op="eq", value="1.1.1.1"),
            ],
        )
        outer = FilterGroup(
            logic="AND",
            conditions=[FilterCondition(field="severity", op="gte", value=3)],
            groups=[inner],
        )
        clause = build_filter_group(outer)
        assert clause is not None

    def test_deeply_nested_groups(self):
        lvl3 = FilterGroup(
            logic="NOT",
            conditions=[FilterCondition(field="category", op="eq", value="registry")],
        )
        lvl2 = FilterGroup(
            logic="OR",
            conditions=[FilterCondition(field="severity", op="eq", value=4)],
            groups=[lvl3],
        )
        lvl1 = FilterGroup(
            logic="AND",
            conditions=[FilterCondition(field="host_name", op="is_not_null")],
            groups=[lvl2],
        )
        clause = build_filter_group(lvl1)
        assert clause is not None

    def test_invalid_logic_raises(self):
        from pydantic import ValidationError as PydanticValidationError
        with pytest.raises(PydanticValidationError):
            FilterGroup(logic="XOR", conditions=[])  # type: ignore[arg-type]


# ─── build_filter_groups ──────────────────────────────────────────────────────

class TestBuildFilterGroups:
    def test_none_returns_empty_list(self):
        result = build_filter_groups(None)
        assert result == []

    def test_empty_list_returns_empty_list(self):
        result = build_filter_groups([])
        assert result == []

    def test_single_group(self):
        groups = [
            FilterGroup(
                logic="AND",
                conditions=[FilterCondition(field="severity", op="gte", value=2)],
            )
        ]
        result = build_filter_groups(groups)
        assert len(result) == 1

    def test_multiple_groups(self):
        groups = [
            FilterGroup(logic="AND", conditions=[FilterCondition(field="severity", op="gte", value=2)]),
            FilterGroup(logic="OR", conditions=[
                FilterCondition(field="source_ip", op="eq", value="1.2.3.4"),
                FilterCondition(field="dest_ip", op="eq", value="1.2.3.4"),
            ]),
        ]
        result = build_filter_groups(groups)
        assert len(result) == 2

    def test_empty_groups_skipped(self):
        groups = [
            FilterGroup(logic="AND"),  # empty
            FilterGroup(logic="AND", conditions=[FilterCondition(field="severity", op="gte", value=2)]),
        ]
        result = build_filter_groups(groups)
        assert len(result) == 1
