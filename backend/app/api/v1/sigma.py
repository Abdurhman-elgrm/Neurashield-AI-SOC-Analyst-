from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse
from app.detection.sigma import parse_sigma_yaml, save_sigma_rule, bulk_import_defaults

router = APIRouter(prefix="/sigma", tags=["sigma-rules"])


class SigmaImportRequest(BaseModel):
    yaml_text: str = Field(..., description="Raw Sigma YAML rule content")


class SigmaImportResult(BaseModel):
    rule_id: str | None
    title: str
    severity: str
    category: str | None
    mitre_techniques: list[str]
    mitre_tactics: list[str]
    conditions_count: int
    created: bool
    error: str | None = None


class BulkImportResult(BaseModel):
    created: int
    skipped: int
    errors: int
    message: str


class SigmaPreviewResult(BaseModel):
    title: str
    severity: str
    category: str | None
    mitre_techniques: list[str]
    mitre_tactics: list[str]
    conditions: list[dict[str, Any]]
    error: str | None = None


@router.post("/preview", response_model=APIResponse[SigmaPreviewResult])
async def preview_sigma_rule(
    payload: SigmaImportRequest,
    member: Annotated[object, require_permission(Permission.RULES_READ)],
) -> APIResponse[SigmaPreviewResult]:
    """
    Parse a Sigma YAML rule and return the translated conditions without saving.
    Useful for validating rules before importing.
    """
    parsed = parse_sigma_yaml(payload.yaml_text)
    return APIResponse.ok(SigmaPreviewResult(
        title=parsed.title,
        severity=parsed.severity,
        category=parsed.category,
        mitre_techniques=parsed.mitre_techniques,
        mitre_tactics=parsed.mitre_tactics,
        conditions=parsed.conditions,
        error=parsed.error,
    ))


@router.post("/import", response_model=APIResponse[SigmaImportResult])
async def import_sigma_rule(
    payload: SigmaImportRequest,
    member: Annotated[object, require_permission(Permission.RULES_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[SigmaImportResult]:
    """
    Parse and import a single Sigma YAML rule for the current tenant.
    Idempotent — re-importing the same rule title returns the existing rule.
    """
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]

    parsed = parse_sigma_yaml(payload.yaml_text)

    if parsed.error:
        return APIResponse.ok(SigmaImportResult(
            rule_id=None, title=parsed.title, severity=parsed.severity,
            category=parsed.category, mitre_techniques=[], mitre_tactics=[],
            conditions_count=0, created=False, error=parsed.error,
        ))

    if not parsed.conditions:
        return APIResponse.ok(SigmaImportResult(
            rule_id=None, title=parsed.title, severity=parsed.severity,
            category=parsed.category, mitre_techniques=parsed.mitre_techniques,
            mitre_tactics=parsed.mitre_tactics, conditions_count=0, created=False,
            error="Rule produced no usable conditions — check logsource and detection block",
        ))

    rule, created = await save_sigma_rule(db, m.tenant_id, parsed, m.user_id)
    await db.commit()

    return APIResponse.ok(SigmaImportResult(
        rule_id=str(rule.id),
        title=parsed.title,
        severity=parsed.severity,
        category=parsed.category,
        mitre_techniques=parsed.mitre_techniques,
        mitre_tactics=parsed.mitre_tactics,
        conditions_count=len(parsed.conditions),
        created=created,
    ))


@router.post("/import-defaults", response_model=APIResponse[BulkImportResult])
async def import_default_rules(
    member: Annotated[object, require_permission(Permission.RULES_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[BulkImportResult]:
    """
    Import all builtin Sigma + UEBA catch-all rules for the current tenant.
    Idempotent — already-imported rules are skipped.

    Imports:
    - Windows: Mimikatz, PowerShell encoded, CertUtil, MSHTA, Rundll32, Regsvr32,
               PsExec, WMI remote, Net.exe recon, Scheduled tasks, Run key persistence
    - Linux: Reverse shells, /tmp execution, Crontab persistence
    - DNS: Tunneling detection
    - UEBA: Strong anomaly, impossible travel, brute force success, lateral movement,
            off-hours access, threat IP + anomaly compound
    """
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]

    result = await bulk_import_defaults(db, m.tenant_id, m.user_id)
    await db.commit()

    total = result["created"] + result["skipped"]
    return APIResponse.ok(BulkImportResult(
        created=result["created"],
        skipped=result["skipped"],
        errors=result["errors"],
        message=(
            f"Import complete: {result['created']} new rules created, "
            f"{result['skipped']} already existed, "
            f"{result['errors']} parse errors."
        ),
    ))
