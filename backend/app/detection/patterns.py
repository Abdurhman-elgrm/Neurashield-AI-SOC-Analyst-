from __future__ import annotations

import re
import threading
from typing import Any

import structlog

from app.normalization.models import NormalizedEvent

logger = structlog.get_logger(__name__)

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

# ─── Regex cache + ReDoS protection ──────────────────────────────────────────

_REGEX_CACHE: dict[str, re.Pattern[str]] = {}
_REGEX_CACHE_LOCK = threading.Lock()
_REGEX_TIMEOUT_SECS = 2.0  # max seconds allowed for a single regex match


def _get_compiled_regex(pattern: str) -> re.Pattern[str] | None:
    """Compile and cache a regex pattern; return None if invalid."""
    with _REGEX_CACHE_LOCK:
        if pattern not in _REGEX_CACHE:
            try:
                _REGEX_CACHE[pattern] = re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                logger.warning("invalid_regex_pattern", pattern=pattern[:100], error=str(exc))
                _REGEX_CACHE[pattern] = None  # type: ignore[assignment]
        return _REGEX_CACHE.get(pattern)


def _safe_regex_match(pattern: str, text: str) -> bool:
    """
    Thread-based timeout to guard against catastrophically backtracking (ReDoS)
    regular expressions.  If the match doesn't complete within _REGEX_TIMEOUT_SECS
    the function returns False and logs a warning.

    Note: The thread continues running in the background but its result is
    discarded.  Pattern validation on rule creation is the first line of defense;
    this is the last-resort safety net.
    """
    compiled = _get_compiled_regex(pattern)
    if compiled is None:
        return False

    result: list[bool] = [False]

    def _run() -> None:
        try:
            result[0] = bool(compiled.search(text))
        except Exception:
            pass

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=_REGEX_TIMEOUT_SECS)

    if t.is_alive():
        logger.warning(
            "regex_timeout_possible_redos",
            pattern=pattern[:100],
            text_length=len(text),
        )
        return False

    return result[0]


# ─── Field access ─────────────────────────────────────────────────────────────


def _get_field(event: NormalizedEvent, path: str) -> Any:
    """
    Dot-notation field access with unlimited nesting depth.

    Examples:
      "hostname"                → event.hostname
      "process.name"            → event.process.name
      "raw.windows_event_id"    → event.raw["windows_event_id"]
      "network.dst_port"        → event.network.dst_port
      "registry.key"            → event.registry["key"]
    """
    if not path:
        return None

    parts = path.split(".")
    obj: Any = event

    for part in parts:
        if obj is None:
            return None

        # Try attribute access first (dataclass / object fields)
        attr = getattr(obj, part, _MISSING := object())
        if attr is not _MISSING:
            obj = attr
            continue

        # Fall back to dict key access (JSONB sub-objects: raw, registry, etc.)
        if isinstance(obj, dict):
            obj = obj.get(part)
            continue

        return None

    return obj


# ─── Condition evaluation ─────────────────────────────────────────────────────

_OP_ANY_OF = "any_of"
_OP_ANY_OF_GROUPS = "any_of_groups"
_OP_NONE_OF = "none_of"
_OP_LIST_CONTAINS = "list_contains"


def evaluate_condition(condition: dict[str, Any], event: NormalizedEvent) -> bool:
    """
    Evaluates a single condition dict against a normalized event.

    Standard:  {"field": "process.name", "op": "eq", "value": "cmd.exe"}

    Group/logical (no field — recursive):
      {"op": "any_of",        "conditions": [...]}        — OR of sub-conditions
      {"op": "any_of_groups", "groups": [[...], [...]]}   — OR of AND-groups (Sigma 1-of)
      {"op": "none_of",       "conditions": [...]}        — NOT of any sub-condition

    List membership (field value is a Python list):
      {"field": "ueba_flags", "op": "list_contains", "value": "impossible_travel"}
    """
    op: str = condition.get("op", _OP_EQ)

    if op == _OP_ANY_OF:
        return any(evaluate_condition(c, event) for c in condition.get("conditions", []))

    if op == _OP_ANY_OF_GROUPS:
        return any(
            all(evaluate_condition(c, event) for c in grp) for grp in condition.get("groups", [])
        )

    if op == _OP_NONE_OF:
        return not any(evaluate_condition(c, event) for c in condition.get("conditions", []))

    field_path: str = condition.get("field", "")
    expected: Any = condition.get("value")
    actual = _get_field(event, field_path)

    if op == _OP_LIST_CONTAINS:
        if isinstance(actual, list):
            exp_lower = str(expected).lower()
            return any(str(v).lower() == exp_lower for v in actual)
        return False

    return _apply_op(op, actual, expected)


def evaluate_conditions(conditions: list[dict[str, Any]], event: NormalizedEvent) -> bool:
    """All conditions must match (logical AND)."""
    return all(evaluate_condition(c, event) for c in conditions)


# ─── Operator dispatch ────────────────────────────────────────────────────────


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
        return _safe_regex_match(str(expected), str(actual))
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
