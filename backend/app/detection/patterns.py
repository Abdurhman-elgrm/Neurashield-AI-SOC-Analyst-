from __future__ import annotations

import re
from typing import Any

from app.normalization.models import NormalizedEvent


_OP_EQ = "eq"
_OP_NE = "ne"
_OP_CONTAINS = "contains"
_OP_STARTSWITH = "startswith"
_OP_ENDSWITH = "endswith"
_OP_REGEX = "regex"
_OP_IN = "in"
_OP_NOT_IN = "not_in"
_OP_GT = "gt"
_OP_LT = "lt"
_OP_GTE = "gte"
_OP_LTE = "lte"
_OP_EXISTS = "exists"


def evaluate_condition(condition: dict[str, Any], event: NormalizedEvent) -> bool:
    """
    Evaluates a single condition dict against a normalized event.
    condition = {"field": "process.name", "op": "eq", "value": "cmd.exe"}
    """
    field_path: str = condition.get("field", "")
    op: str = condition.get("op", _OP_EQ)
    expected: Any = condition.get("value")

    actual = _get_field(event, field_path)

    return _apply_op(op, actual, expected)


def evaluate_conditions(conditions: list[dict[str, Any]], event: NormalizedEvent) -> bool:
    """
    All conditions must match (logical AND).
    """
    return all(evaluate_condition(c, event) for c in conditions)


def _get_field(event: NormalizedEvent, path: str) -> Any:
    """
    Dot-notation field access.  Supports first-level sub-objects.
    e.g. "process.name", "network.dst_port", "hostname", "severity"
    """
    parts = path.split(".", 1)
    top = parts[0]
    sub = parts[1] if len(parts) > 1 else None

    # Top-level event attributes
    if sub is None:
        return getattr(event, top, None)

    # Sub-object access
    obj = getattr(event, top, None)
    if obj is None:
        return None

    if hasattr(obj, sub):
        return getattr(obj, sub, None)

    # JSONB dict-like sub-objects (registry, raw)
    if isinstance(obj, dict):
        return obj.get(sub)

    return None


def _apply_op(op: str, actual: Any, expected: Any) -> bool:
    if op == _OP_EXISTS:
        return actual is not None

    if actual is None:
        return False

    actual_str = str(actual).lower() if not isinstance(actual, (int, float, bool)) else actual
    expected_str = str(expected).lower() if isinstance(expected, str) else expected

    if op == _OP_EQ:
        return actual_str == expected_str
    if op == _OP_NE:
        return actual_str != expected_str
    if op == _OP_CONTAINS:
        return isinstance(actual_str, str) and str(expected_str) in actual_str
    if op == _OP_STARTSWITH:
        return isinstance(actual_str, str) and actual_str.startswith(str(expected_str))
    if op == _OP_ENDSWITH:
        return isinstance(actual_str, str) and actual_str.endswith(str(expected_str))
    if op == _OP_REGEX:
        try:
            return bool(re.search(str(expected), str(actual), re.IGNORECASE))
        except re.error:
            return False
    if op == _OP_IN:
        if not isinstance(expected, (list, tuple)):
            return False
        return actual_str in [str(v).lower() for v in expected]
    if op == _OP_NOT_IN:
        if not isinstance(expected, (list, tuple)):
            return True
        return actual_str not in [str(v).lower() for v in expected]
    if op == _OP_GT:
        return float(actual) > float(expected)
    if op == _OP_LT:
        return float(actual) < float(expected)
    if op == _OP_GTE:
        return float(actual) >= float(expected)
    if op == _OP_LTE:
        return float(actual) <= float(expected)

    return False
