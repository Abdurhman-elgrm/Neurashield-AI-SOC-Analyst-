from __future__ import annotations

"""
Advanced filter engine for the Events Explorer.

Translates a nested FilterGroup (AND/OR/NOT) tree into a safe SQLAlchemy
ClauseElement.  No raw SQL is constructed — every value is passed through
SQLAlchemy's parameter binding.

Allowed fields are explicitly whitelisted to prevent injection of arbitrary
column names.
"""

from typing import Any
from uuid import UUID

from sqlalchemy import Column, and_, not_, or_
from sqlalchemy.sql.expression import ColumnElement

from app.events.schemas import FilterCondition, FilterGroup, FilterOperator
from app.models.event import Event

# ─── Whitelist of filterable fields ──────────────────────────────────────────

_COLUMN_MAP: dict[str, Column] = {  # type: ignore[type-arg]
    "host_name": Event.host_name,
    "username": Event.username,
    "source_ip": Event.source_ip,
    "dest_ip": Event.dest_ip,
    "process_name": Event.process_name,
    "category": Event.category,
    "severity": Event.severity,
    "event_timestamp": Event.event_timestamp,
    "ingested_at": Event.ingested_at,
    "agent_id": Event.agent_id,
    "raw_id": Event.raw_id,
    "correlation_id": Event.correlation_id,  # type: ignore[attr-defined]
    "session_id": Event.session_id,  # type: ignore[attr-defined]
    "process_tree_id": Event.process_tree_id,  # type: ignore[attr-defined]
    "event_chain_id": Event.event_chain_id,  # type: ignore[attr-defined]
}


class FilterValidationError(ValueError):
    pass


def _coerce(value: Any, col: Column) -> Any:  # type: ignore[type-arg]
    """Best-effort type coercion so string values work for UUID/int columns."""
    col_type = type(col.type).__name__
    if col_type in ("UUID",) and isinstance(value, str):
        return UUID(value)
    if col_type in ("Integer",) and isinstance(value, str):
        return int(value)
    return value


def _apply_op(col: Column, op: FilterOperator, value: Any) -> ColumnElement:  # type: ignore[type-arg]
    if op == "is_null":
        return col.is_(None)
    if op == "is_not_null":
        return col.isnot(None)

    v = _coerce(value, col)

    if op == "eq":
        return col == v
    if op == "ne":
        return col != v
    if op == "gt":
        return col > v
    if op == "gte":
        return col >= v
    if op == "lt":
        return col < v
    if op == "lte":
        return col <= v
    if op == "in":
        items = [_coerce(i, col) for i in (v if isinstance(v, list) else [v])]
        return col.in_(items)
    if op == "not_in":
        items = [_coerce(i, col) for i in (v if isinstance(v, list) else [v])]
        return col.not_in(items)
    if op == "contains":
        return col.contains(str(v))
    if op == "icontains":
        return col.ilike(f"%{v}%")
    if op == "starts_with":
        return col.startswith(str(v))

    raise FilterValidationError(f"Unsupported operator: {op}")


def build_condition(cond: FilterCondition) -> ColumnElement:  # type: ignore[type-arg]
    col = _COLUMN_MAP.get(cond.field)
    if col is None:
        raise FilterValidationError(
            f"Field '{cond.field}' is not filterable. Allowed: {sorted(_COLUMN_MAP)}"
        )
    return _apply_op(col, cond.op, cond.value)


def build_filter_group(group: FilterGroup) -> ColumnElement | None:  # type: ignore[type-arg]
    """
    Recursively converts a FilterGroup tree to a SQLAlchemy expression.
    Returns None when the group is empty (caller should skip it).
    """
    clauses: list[ColumnElement] = []  # type: ignore[type-arg]

    for cond in group.conditions:
        clauses.append(build_condition(cond))

    for sub in group.groups:
        sub_clause = build_filter_group(sub)
        if sub_clause is not None:
            clauses.append(sub_clause)

    if not clauses:
        return None

    if group.logic == "AND":
        return and_(*clauses)
    if group.logic == "OR":
        return or_(*clauses)
    if group.logic == "NOT":
        # NOT wraps the AND of all conditions/groups
        return not_(and_(*clauses))

    raise FilterValidationError(f"Unknown logic: {group.logic}")


def build_filter_groups(
    groups: list[FilterGroup] | None,
) -> list[ColumnElement]:  # type: ignore[type-arg]
    """
    Converts a list of top-level FilterGroups to SQLAlchemy clauses (applied as AND).
    Silently skips empty groups.
    """
    if not groups:
        return []
    clauses = []
    for g in groups:
        clause = build_filter_group(g)
        if clause is not None:
            clauses.append(clause)
    return clauses
