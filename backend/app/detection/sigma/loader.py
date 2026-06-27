from __future__ import annotations

import hashlib
import json
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection_rule import DetectionRule, RuleSeverity, RuleType

from .builtin_rules import BUILTIN_SIGMA_YAML, BUILTIN_UEBA_RULES
from .parser import SigmaParseResult, parse_sigma_yaml

logger = structlog.get_logger(__name__)

_SIGMA_NAME_PREFIX = "[Sigma] "
_UEBA_NAME_PREFIX = "[UEBA] "
_SUPPRESSION_SECS = 300  # 5 minutes per host


def _fingerprint(title: str, conditions: list[dict[str, Any]]) -> str:
    key = f"{title}|{json.dumps(conditions, sort_keys=True)}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


async def _rule_exists(db: AsyncSession, tenant_id: UUID, name: str) -> bool:
    result = await db.scalar(
        select(DetectionRule.id).where(
            DetectionRule.tenant_id == tenant_id,
            DetectionRule.name == name,
            DetectionRule.deleted_at.is_(None),
        )
    )
    return result is not None


async def save_sigma_rule(
    db: AsyncSession,
    tenant_id: UUID,
    parsed: SigmaParseResult,
    created_by: UUID | None = None,
) -> tuple[DetectionRule, bool]:
    """
    Insert a parsed Sigma rule as a DetectionRule for the given tenant.
    Returns (rule, created=True) or (existing, created=False) if already imported.
    """
    name = f"{_SIGMA_NAME_PREFIX}{parsed.title}"
    if await _rule_exists(db, tenant_id, name):
        existing = await db.scalar(
            select(DetectionRule).where(
                DetectionRule.tenant_id == tenant_id,
                DetectionRule.name == name,
            )
        )
        return existing, False  # type: ignore[return-value]

    fp = _fingerprint(parsed.title, parsed.conditions)
    rule = DetectionRule(
        tenant_id=tenant_id,
        name=name,
        description=(parsed.description or f"Sigma rule. Fingerprint: {fp}").strip(),
        rule_type=RuleType.PATTERN,
        severity=RuleSeverity(parsed.severity),
        enabled=True,
        conditions=parsed.conditions,
        mitre_techniques=parsed.mitre_techniques,
        mitre_tactics=parsed.mitre_tactics,
        suppression_window_secs=_SUPPRESSION_SECS,
        created_by_id=created_by,
    )
    db.add(rule)
    await db.flush()
    logger.info("sigma_rule_imported", name=name, tenant_id=str(tenant_id))
    return rule, True


async def _save_ueba_rule(
    db: AsyncSession,
    tenant_id: UUID,
    spec: dict[str, Any],
    created_by: UUID | None = None,
) -> tuple[DetectionRule, bool]:
    name = f"{_UEBA_NAME_PREFIX}{spec['title']}"
    if await _rule_exists(db, tenant_id, name):
        existing = await db.scalar(
            select(DetectionRule).where(
                DetectionRule.tenant_id == tenant_id,
                DetectionRule.name == name,
            )
        )
        return existing, False  # type: ignore[return-value]

    rule = DetectionRule(
        tenant_id=tenant_id,
        name=name,
        description=spec.get("description", ""),
        rule_type=RuleType.PATTERN,
        severity=RuleSeverity(spec["severity"]),
        enabled=True,
        conditions=spec["conditions"],
        mitre_techniques=spec.get("mitre_techniques", []),
        mitre_tactics=spec.get("mitre_tactics", []),
        suppression_window_secs=_SUPPRESSION_SECS,
        created_by_id=created_by,
    )
    db.add(rule)
    await db.flush()
    logger.info("ueba_rule_imported", name=name, tenant_id=str(tenant_id))
    return rule, True


async def bulk_import_defaults(
    db: AsyncSession,
    tenant_id: UUID,
    created_by: UUID | None = None,
) -> dict[str, int]:
    """
    Import all builtin Sigma + UEBA rules for a tenant.
    Skips rules that already exist (idempotent).
    Returns {"created": N, "skipped": M, "errors": K}.
    """
    created = skipped = errors = 0

    # Sigma YAML rules
    for yaml_text in BUILTIN_SIGMA_YAML:
        parsed = parse_sigma_yaml(yaml_text.strip())
        if parsed.error:
            logger.warning("sigma_builtin_parse_error", error=parsed.error, title=parsed.title)
            errors += 1
            continue
        if not parsed.conditions:
            logger.warning("sigma_builtin_no_conditions", title=parsed.title)
            errors += 1
            continue
        _, was_created = await save_sigma_rule(db, tenant_id, parsed, created_by)
        if was_created:
            created += 1
        else:
            skipped += 1

    # UEBA native rules
    for spec in BUILTIN_UEBA_RULES:
        _, was_created = await _save_ueba_rule(db, tenant_id, spec, created_by)
        if was_created:
            created += 1
        else:
            skipped += 1

    logger.info(
        "sigma_bulk_import_complete",
        tenant_id=str(tenant_id),
        created=created,
        skipped=skipped,
        errors=errors,
    )
    return {"created": created, "skipped": skipped, "errors": errors}
