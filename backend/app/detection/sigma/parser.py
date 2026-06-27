from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import yaml

from .field_map import (
    SIGMA_FIELD_TO_NORMALIZED,
    SIGMA_LEVEL_TO_SEVERITY,
    SIGMA_LOGSOURCE_TO_CATEGORY,
    SIGMA_MODIFIER_TO_OP,
)


@dataclass
class SigmaParseResult:
    title: str
    description: str
    severity: str
    category: str | None
    mitre_techniques: list[str]
    mitre_tactics: list[str]
    conditions: list[dict[str, Any]]
    error: str | None = None


# ─── Field + modifier parsing ──────────────────────────────────────────────────


def _resolve_field(sigma_field: str) -> tuple[str, list[str]]:
    """'Image|endswith' → ('process.executable', ['endswith'])"""
    parts = sigma_field.split("|")
    raw = parts[0]
    modifiers = [p.lower() for p in parts[1:]]
    normalized = SIGMA_FIELD_TO_NORMALIZED.get(raw, f"raw.{raw.lower()}")
    return normalized, modifiers


def _field_conditions(field_path: str, modifiers: list[str], values: Any) -> list[dict[str, Any]]:
    """
    Translate one Sigma field+modifier+value(s) into our condition dicts.

    - Single value → one condition
    - Multiple values + no 'all' → any_of (OR)
    - Multiple values + 'all'   → list of AND conditions (all must match)
    """
    if not isinstance(values, list):
        values = [values]
    values = [v for v in values if v is not None]
    if not values:
        return []

    op_mods = [m for m in modifiers if m in SIGMA_MODIFIER_TO_OP]
    op = SIGMA_MODIFIER_TO_OP[op_mods[0]] if op_mods else "eq"
    want_all = "all" in modifiers

    if want_all:
        # Each value must match individually (AND)
        return [{"field": field_path, "op": op, "value": str(v)} for v in values]

    if len(values) == 1:
        return [{"field": field_path, "op": op, "value": str(values[0])}]

    # Multiple values for same field — OR logic
    return [
        {
            "op": "any_of",
            "conditions": [{"field": field_path, "op": op, "value": str(v)} for v in values],
        }
    ]


# ─── Selection block parsing ───────────────────────────────────────────────────


def _parse_selection_block(block: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert a Sigma selection dict into a flat AND-list of our conditions."""
    result: list[dict[str, Any]] = []
    for sigma_field, values in block.items():
        if sigma_field.startswith("_") or not isinstance(sigma_field, str):
            continue
        fp, mods = _resolve_field(sigma_field)
        result.extend(_field_conditions(fp, mods, values))
    return result


# ─── Condition expression parser ───────────────────────────────────────────────


def _parse_condition_expr(
    expr: str,
    selections: dict[str, list[dict[str, Any]]],
    filters: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """
    Parse the Sigma `condition:` string into our conditions format.

    Supported patterns:
      selection                  → use the single selection
      1 of selection*            → OR of all matching selections
      all of them                → AND of all selections
      selection and not filter   → selection minus filter exclusions
      sel1 or sel2               → named OR
      sel1 and sel2              → named AND
    """
    expr = expr.strip().lower()
    result: list[dict[str, Any]] = []

    # Extract trailing "and not <filter>" clauses
    not_filter_names: list[str] = []
    while True:
        m = re.search(r"\band\s+not\s+(\w+)", expr)
        if not m:
            break
        not_filter_names.append(m.group(1))
        expr = (expr[: m.start()] + expr[m.end() :]).strip()

    # "1 of selection*" or "1 of them"
    m1 = re.match(r"^1\s+of\s+(\w+?)(\*?)$", expr)
    if m1:
        prefix = m1.group(1)
        wildcard = bool(m1.group(2))
        if prefix == "them":
            groups = list(selections.values())
        elif wildcard:
            groups = [v for k, v in selections.items() if k.startswith(prefix)]
        else:
            groups = [selections[prefix]] if prefix in selections else []

        if len(groups) == 1:
            result = list(groups[0])
        elif groups:
            result = [{"op": "any_of_groups", "groups": [list(g) for g in groups]}]
        return _apply_not_filters(result, not_filter_names, filters)

    # "all of them" / "all of selection*"
    ma = re.match(r"^all\s+of\s+(\w+?)(\*?)$", expr)
    if ma:
        prefix = ma.group(1)
        wildcard = bool(ma.group(2))
        if prefix == "them":
            matched = list(selections.values())
        elif wildcard:
            matched = [v for k, v in selections.items() if k.startswith(prefix)]
        else:
            matched = [selections[prefix]] if prefix in selections else []

        for g in matched:
            result.extend(g)
        return _apply_not_filters(result, not_filter_names, filters)

    # "sel1 or sel2 or sel3" — named OR
    or_parts = [p.strip() for p in re.split(r"\bor\b", expr)]
    if len(or_parts) > 1:
        groups = [selections[p] for p in or_parts if p in selections]
        if groups:
            result = (
                [{"op": "any_of_groups", "groups": [list(g) for g in groups]}]
                if len(groups) > 1
                else list(groups[0])
            )
            return _apply_not_filters(result, not_filter_names, filters)

    # "sel1 and sel2" — named AND
    and_parts = [p.strip() for p in re.split(r"\band\b", expr)]
    if len(and_parts) > 1:
        for part in and_parts:
            if part in selections:
                result.extend(selections[part])
        if result:
            return _apply_not_filters(result, not_filter_names, filters)

    # Fallback: single named selection or first available
    if expr in selections:
        result = list(selections[expr])
    elif selections:
        result = list(next(iter(selections.values())))

    return _apply_not_filters(result, not_filter_names, filters)


def _apply_not_filters(
    conditions: list[dict[str, Any]],
    filter_names: list[str],
    filters: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    for name in filter_names:
        if name in filters and filters[name]:
            conditions.append({"op": "none_of", "conditions": list(filters[name])})
    return conditions


# ─── Public entrypoint ─────────────────────────────────────────────────────────


def parse_sigma_yaml(yaml_text: str) -> SigmaParseResult:
    """Parse a Sigma YAML rule into our internal detection condition format."""
    try:
        rule = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        return SigmaParseResult(
            title="",
            description="",
            severity="medium",
            category=None,
            mitre_techniques=[],
            mitre_tactics=[],
            conditions=[],
            error=f"YAML parse error: {exc}",
        )

    if not isinstance(rule, dict):
        return SigmaParseResult(
            title="",
            description="",
            severity="medium",
            category=None,
            mitre_techniques=[],
            mitre_tactics=[],
            conditions=[],
            error="Rule must be a YAML mapping",
        )

    title = str(rule.get("title") or "Unnamed Sigma Rule")
    description = str(rule.get("description") or "")
    level = str(rule.get("level") or "medium").lower()
    severity = SIGMA_LEVEL_TO_SEVERITY.get(level, "medium")

    # Logsource → category
    logsource = rule.get("logsource") or {}
    ls_cat = str(logsource.get("category") or "").lower()
    category = SIGMA_LOGSOURCE_TO_CATEGORY.get(ls_cat)

    # MITRE ATT&CK tags
    tags: list[str] = list(rule.get("tags") or [])
    techniques = [t.split(".")[-1].upper() for t in tags if re.match(r"^attack\.t\d+", t.lower())]
    tactics = [
        t[len("attack.") :].replace("_", "-")
        for t in tags
        if t.lower().startswith("attack.") and not re.match(r"^attack\.t\d+", t.lower())
    ]

    # Detection block
    detection: dict[str, Any] = rule.get("detection") or {}
    condition_expr = str(detection.get("condition") or "selection")

    selections: dict[str, list[dict[str, Any]]] = {}
    filters: dict[str, list[dict[str, Any]]] = {}

    for key, val in detection.items():
        if key == "condition" or not isinstance(val, dict):
            continue
        parsed = _parse_selection_block(val)
        if key.startswith("filter"):
            filters[key] = parsed
        else:
            selections[key] = parsed

    conditions = _parse_condition_expr(condition_expr, selections, filters)

    # Prepend category constraint so rules only fire on relevant event types
    if category and conditions:
        conditions.insert(0, {"field": "category", "op": "eq", "value": category})

    return SigmaParseResult(
        title=title,
        description=description,
        severity=severity,
        category=category,
        mitre_techniques=techniques,
        mitre_tactics=tactics,
        conditions=conditions,
    )
