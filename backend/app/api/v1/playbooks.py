from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.core.exceptions import NotFoundError, ValidationError
from app.models.alert import Alert
from app.models.playbook import Playbook, PlaybookAutoConfig, PlaybookRun, PlaybookStep, PlaybookTemplate, PlaybookTemplateStep
from app.models.tenant_member import TenantMember
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse, EmptyResponse, PaginatedResponse
from app.schemas.playbook import (
    CompleteStepRequest,
    CreateTemplateRequest,
    GeneratePlaybookRequest,
    PlaybookResponse,
    PlaybookRunResponse,
    PlaybookStepResponse,
    PlaybookTemplateResponse,
    PlaybookTemplateStepResponse,
)
from app.services.audit_service import AuditService
from app.services.playbook_service import PlaybookGeneratorService

router = APIRouter(prefix="/playbooks", tags=["playbooks"])


# ── Templates ─────────────────────────────────────────────────────────────────

@router.get("/templates", response_model=PaginatedResponse[PlaybookTemplateResponse])
async def list_templates(
    member: Annotated[object, require_permission(Permission.PLAYBOOKS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=25, ge=1, le=100),
) -> PaginatedResponse[PlaybookTemplateResponse]:
    m: TenantMember = member  # type: ignore[assignment]

    base_where = [
        PlaybookTemplate.deleted_at.is_(None),
        PlaybookTemplate.enabled.is_(True),
        (PlaybookTemplate.tenant_id == m.tenant_id) | (PlaybookTemplate.is_system.is_(True)),
    ]

    total_result = await db.execute(select(func.count()).where(*base_where))
    total = total_result.scalar_one()

    result = await db.execute(
        select(PlaybookTemplate)
        .where(*base_where)
        .order_by(PlaybookTemplate.is_system.asc(), PlaybookTemplate.created_at.desc())
        .offset((page - 1) * limit)
        .limit(limit)
    )
    templates = list(result.scalars().all())

    # Eager load steps for each template
    template_responses = []
    for t in templates:
        steps_result = await db.execute(
            select(PlaybookTemplateStep)
            .where(PlaybookTemplateStep.template_id == t.id)
            .order_by(PlaybookTemplateStep.step_order)
        )
        steps = list(steps_result.scalars().all())
        t_dict = PlaybookTemplateResponse.model_validate(t)
        t_dict = t_dict.model_copy(update={"steps": [
            PlaybookTemplateStepResponse.model_validate(s) for s in steps
        ]})
        template_responses.append(t_dict)

    return PaginatedResponse[PlaybookTemplateResponse].offset(
        data=template_responses, page=page, limit=limit, total=total
    )


@router.post("/templates", response_model=APIResponse[PlaybookTemplateResponse], status_code=201)
async def create_template(
    payload: CreateTemplateRequest,
    member: Annotated[object, require_permission(Permission.PLAYBOOKS_ADMIN)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[PlaybookTemplateResponse]:
    m: TenantMember = member  # type: ignore[assignment]

    template = PlaybookTemplate(
        tenant_id=m.tenant_id,
        name=payload.name,
        description=payload.description,
        tactic=payload.tactic,
        technique=payload.technique,
        category=payload.category,
        created_by_id=m.user_id,
    )
    db.add(template)
    await db.flush()

    for i, step_data in enumerate(payload.steps, 1):
        step = PlaybookTemplateStep(
            template_id=template.id,
            step_order=step_data.get("step_order", i),
            category=step_data.get("category", "investigation"),
            title=step_data["title"],
            description_template=step_data.get("description_template"),
            command_windows=step_data.get("command_windows"),
            command_linux=step_data.get("command_linux"),
            expected_result=step_data.get("expected_result"),
            can_run_parallel=step_data.get("can_run_parallel", False),
            requires_human_approval=step_data.get("requires_human_approval", True),
            is_critical=step_data.get("is_critical", False),
            hint=step_data.get("hint"),
            mitre_reference=step_data.get("mitre_reference"),
            action_type=step_data.get("action_type"),
            step_order_dependencies=step_data.get("step_order_dependencies", []),
        )
        db.add(step)

    await db.flush()
    await AuditService.log(
        db, action="playbook_template.created", actor_id=m.user_id, actor_role=m.role,
        tenant_id=m.tenant_id, resource_type="playbook_template", resource_id=template.id,
    )
    await db.commit()

    steps_result = await db.execute(
        select(PlaybookTemplateStep)
        .where(PlaybookTemplateStep.template_id == template.id)
        .order_by(PlaybookTemplateStep.step_order)
    )
    steps = list(steps_result.scalars().all())
    resp = PlaybookTemplateResponse.model_validate(template).model_copy(
        update={"steps": [PlaybookTemplateStepResponse.model_validate(s) for s in steps]}
    )
    return APIResponse.ok(resp)


# ── Playbooks ─────────────────────────────────────────────────────────────────

@router.post("/generate", response_model=APIResponse[PlaybookResponse], status_code=201)
async def generate_playbook(
    payload: GeneratePlaybookRequest,
    member: Annotated[object, require_permission(Permission.PLAYBOOKS_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[PlaybookResponse]:
    m: TenantMember = member  # type: ignore[assignment]

    from app.models.tenant import Tenant
    tenant_result = await db.execute(
        select(Tenant.name).where(Tenant.id == m.tenant_id)
    )
    company_name = tenant_result.scalar_one_or_none() or "Your Organization"

    if payload.alert_id is not None:
        # Alert-based generation: pull all context from the alert
        alert_result = await db.execute(
            select(Alert).where(
                Alert.id == payload.alert_id,
                Alert.tenant_id == m.tenant_id,
                Alert.deleted_at.is_(None),
            )
        )
        alert = alert_result.scalar_one_or_none()
        if alert is None:
            raise NotFoundError(f"Alert {payload.alert_id} not found")

        alert_title   = alert.title
        severity      = alert.severity.value
        source_host   = alert.source_host
        mitre_techniques = list(alert.mitre_techniques or [])
        mitre_tactics    = list(alert.mitre_tactics or [])
        evidence         = dict(alert.evidence or {})
    else:
        # Manual generation: use the fields supplied in the request
        from app.services.playbook_service import _technique_name as _tname, _TACTIC_NAMES as _tnames
        technique = (payload.technique or "").strip().upper()
        tactic    = (payload.tactic or "").strip().upper()
        tech_label  = _tname(technique) if technique else ""
        tactic_label = _tnames.get(tactic, tactic)
        if tech_label and tech_label != "Unknown Technique":
            alert_title = f"{tech_label} ({technique})"
        elif tactic_label:
            alert_title = f"{tactic_label} Attack"
        else:
            alert_title = payload.source_host or "Manual Playbook"
        if payload.source_host:
            alert_title = f"{alert_title} — {payload.source_host}"
        severity         = payload.severity
        source_host      = payload.source_host
        mitre_techniques = [technique] if technique else []
        mitre_tactics    = [tactic]    if tactic    else []
        evidence         = {}

    playbook = await PlaybookGeneratorService.generate(
        db=db,
        tenant_id=m.tenant_id,
        alert_id=payload.alert_id,
        alert_title=alert_title,
        severity=severity,
        source_host=source_host,
        mitre_techniques=mitre_techniques,
        mitre_tactics=mitre_tactics,
        evidence=evidence,
        company_name=company_name,
        investigation_id=payload.investigation_id,
        created_by_id=m.user_id,
    )
    await db.commit()

    return APIResponse.ok(await _load_playbook_response(db, playbook.id))


@router.get("", response_model=PaginatedResponse[PlaybookResponse])
async def list_playbooks(
    member: Annotated[object, require_permission(Permission.PLAYBOOKS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=25, ge=1, le=100),
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    investigation_id: UUID | None = Query(default=None),
) -> PaginatedResponse[PlaybookResponse]:
    m: TenantMember = member  # type: ignore[assignment]

    where = [
        Playbook.tenant_id == m.tenant_id,
        Playbook.deleted_at.is_(None),
    ]
    if status:
        where.append(Playbook.status == status)
    if severity:
        where.append(Playbook.severity == severity)
    if investigation_id:
        where.append(Playbook.investigation_id == investigation_id)

    total_result = await db.execute(select(func.count()).where(*where))
    total = total_result.scalar_one()

    result = await db.execute(
        select(Playbook)
        .where(*where)
        .order_by(Playbook.created_at.desc())
        .offset((page - 1) * limit)
        .limit(limit)
    )
    playbooks = list(result.scalars().all())
    data = [PlaybookResponse.model_validate(p) for p in playbooks]

    return PaginatedResponse[PlaybookResponse].offset(
        data=data, page=page, limit=limit, total=total
    )


@router.get("/{playbook_id}", response_model=APIResponse[PlaybookResponse])
async def get_playbook(
    playbook_id: UUID,
    member: Annotated[object, require_permission(Permission.PLAYBOOKS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[PlaybookResponse]:
    m: TenantMember = member  # type: ignore[assignment]
    return APIResponse.ok(await _require_playbook_response(db, m.tenant_id, playbook_id))


@router.post("/{playbook_id}/execute", response_model=APIResponse[PlaybookRunResponse])
async def execute_playbook(
    playbook_id: UUID,
    member: Annotated[object, require_permission(Permission.PLAYBOOKS_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[PlaybookRunResponse]:
    m: TenantMember = member  # type: ignore[assignment]
    run = await PlaybookGeneratorService.execute_playbook(
        db=db,
        tenant_id=m.tenant_id,
        playbook_id=playbook_id,
        actor_id=m.user_id,
        mode="manual",
    )
    await AuditService.log(
        db, action="playbook.executed", actor_id=m.user_id, actor_role=m.role,
        tenant_id=m.tenant_id, resource_type="playbook", resource_id=playbook_id,
    )
    await db.commit()
    return APIResponse.ok(PlaybookRunResponse.model_validate(run))


@router.patch("/{playbook_id}/steps/{step_id}", response_model=APIResponse[PlaybookStepResponse])
async def complete_step(
    playbook_id: UUID,
    step_id: UUID,
    payload: CompleteStepRequest,
    member: Annotated[object, require_permission(Permission.PLAYBOOKS_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[PlaybookStepResponse]:
    m: TenantMember = member  # type: ignore[assignment]
    step = await PlaybookGeneratorService.complete_step(
        db=db,
        tenant_id=m.tenant_id,
        playbook_id=playbook_id,
        step_id=step_id,
        actor_id=m.user_id,
        notes=payload.notes,
        result_text=payload.result,
    )
    await db.commit()
    return APIResponse.ok(PlaybookStepResponse.model_validate(step))


@router.delete("/{playbook_id}", response_model=APIResponse[EmptyResponse])
async def delete_playbook(
    playbook_id: UUID,
    member: Annotated[object, require_permission(Permission.PLAYBOOKS_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[EmptyResponse]:
    m: TenantMember = member  # type: ignore[assignment]
    result = await db.execute(
        select(Playbook).where(
            Playbook.id == playbook_id,
            Playbook.tenant_id == m.tenant_id,
            Playbook.deleted_at.is_(None),
        )
    )
    playbook = result.scalar_one_or_none()
    if playbook is None:
        raise NotFoundError(f"Playbook {playbook_id} not found")
    playbook.soft_delete()
    await AuditService.log(
        db, action="playbook.deleted", actor_id=m.user_id, actor_role=m.role,
        tenant_id=m.tenant_id, resource_type="playbook", resource_id=playbook_id,
    )
    await db.commit()
    return APIResponse.ok(EmptyResponse())


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _require_playbook_response(
    db: AsyncSession, tenant_id: UUID, playbook_id: UUID
) -> PlaybookResponse:
    result = await db.execute(
        select(Playbook).where(
            Playbook.id == playbook_id,
            Playbook.tenant_id == tenant_id,
            Playbook.deleted_at.is_(None),
        )
    )
    playbook = result.scalar_one_or_none()
    if playbook is None:
        raise NotFoundError(f"Playbook {playbook_id} not found")
    return await _load_playbook_response(db, playbook_id)


async def _load_playbook_response(db: AsyncSession, playbook_id: UUID) -> PlaybookResponse:
    result = await db.execute(
        select(Playbook).where(Playbook.id == playbook_id)
    )
    playbook = result.scalar_one()
    steps_result = await db.execute(
        select(PlaybookStep)
        .where(PlaybookStep.playbook_id == playbook_id)
        .order_by(PlaybookStep.step_order)
    )
    steps = list(steps_result.scalars().all())
    resp = PlaybookResponse.model_validate(playbook)
    resp = resp.model_copy(update={"steps": [PlaybookStepResponse.model_validate(s) for s in steps]})
    return resp


# ── Auto-config ───────────────────────────────────────────────────────────────

from pydantic import BaseModel as _BaseModel

class AutoConfigResponse(_BaseModel):
    enabled: bool
    min_severity: str

class AutoConfigUpdateRequest(_BaseModel):
    enabled: bool
    min_severity: str = "critical"


@router.get("/auto-config", response_model=APIResponse[AutoConfigResponse])
async def get_auto_config(
    member: Annotated[object, require_permission(Permission.TENANT_SETTINGS)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[AutoConfigResponse]:
    m: TenantMember = member  # type: ignore[assignment]
    result = await db.execute(
        select(PlaybookAutoConfig).where(PlaybookAutoConfig.tenant_id == m.tenant_id)
    )
    cfg = result.scalar_one_or_none()
    if cfg is None:
        return APIResponse.ok(AutoConfigResponse(enabled=False, min_severity="critical"))
    return APIResponse.ok(AutoConfigResponse(enabled=cfg.enabled, min_severity=cfg.min_severity))


@router.put("/auto-config", response_model=APIResponse[AutoConfigResponse])
async def update_auto_config(
    payload: AutoConfigUpdateRequest,
    member: Annotated[object, require_permission(Permission.TENANT_SETTINGS)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[AutoConfigResponse]:
    m: TenantMember = member  # type: ignore[assignment]

    valid_severities = {"critical", "high", "medium", "low"}
    if payload.min_severity not in valid_severities:
        from app.core.exceptions import ValidationError
        raise ValidationError(f"min_severity must be one of {sorted(valid_severities)}")

    result = await db.execute(
        select(PlaybookAutoConfig).where(PlaybookAutoConfig.tenant_id == m.tenant_id)
    )
    cfg = result.scalar_one_or_none()
    if cfg is None:
        cfg = PlaybookAutoConfig(
            tenant_id=m.tenant_id,
            enabled=payload.enabled,
            min_severity=payload.min_severity,
            updated_by_id=m.user_id,
        )
        db.add(cfg)
    else:
        cfg.enabled = payload.enabled
        cfg.min_severity = payload.min_severity
        cfg.updated_by_id = m.user_id

    await AuditService.log(
        db, action="playbook_auto_config.updated", actor_id=m.user_id, actor_role=m.role,
        tenant_id=m.tenant_id, resource_type="playbook_auto_config",
        resource_id=cfg.id if cfg.id else None,
    )
    await db.commit()
    return APIResponse.ok(AutoConfigResponse(enabled=cfg.enabled, min_severity=cfg.min_severity))
