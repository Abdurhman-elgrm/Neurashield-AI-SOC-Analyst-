from __future__ import annotations

"""
Investigations API — Tier 2 analyst workspace endpoints.

All routes require authentication + X-Tenant-ID header.
Tenant isolation is enforced at the service layer.

Routes:
  GET    /investigations                      list investigations
  GET    /investigations/{id}                 investigation detail
  GET    /investigations/{id}/timeline        attack timeline
  GET    /investigations/{id}/graph           attack graph
  GET    /investigations/{id}/activity        analyst activity log
  GET    /investigations/{id}/evidence        attached evidence
  GET    /investigations/{id}/notes           investigation notes
  POST   /investigations/{id}/notes           add note
  PATCH  /investigations/{id}/notes/{note_id} edit note
  DELETE /investigations/{id}/notes/{note_id} delete note
  PATCH  /investigations/{id}/status          change status
  PATCH  /investigations/{id}/verdict         set verdict
  PATCH  /investigations/{id}/assign          assign/escalate
  POST   /investigations/{id}/evidence        attach evidence
  POST   /investigations/hunt                 threat hunt query
  POST   /investigations/hunt/saved           save hunt
  GET    /investigations/hunt/saved           list saved hunts
  POST   /investigations/merge                merge investigations
  POST   /investigations/{id}/pivot           entity pivot
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.rbac.permissions import Permission
from app.rbac.roles import has_minimum_role, Role
from app.schemas.common import APIResponse, EmptyResponse, PaginatedResponse
from app.analyst.schemas import (
    AssignmentCreate,
    EvidenceCreate,
    GraphFilter,
    HuntQuery,
    InvestigationDetail,
    InvestigationFilterParams,
    InvestigationListItem,
    MergeRequest,
    NoteCreate,
    NoteUpdate,
    NoteOut,
    ReopenRequest,
    SavedHuntCreate,
    SavedHuntOut,
    StatusUpdate,
    TimelineFilter,
    TimelineResponse,
    GraphResponse,
    HuntResult,
    PivotResult,
    VerdictCreate,
    ActivityOut,
    EvidenceOut,
    AssignmentOut,
    VerdictOut,
)
from app.analyst.service import AnalystWorkspaceService
from app.analyst.activity import ActivityService
from app.analyst.assignment import AssignmentService
from app.analyst.evidence import EvidenceService
from app.analyst.hunt import HuntEngine
from app.analyst.notes import NoteService
from app.analyst.verdicts import VerdictService
from app.analyst.cases import CaseService
from app.services.audit_service import AuditService

router = APIRouter(prefix="/investigations", tags=["investigations"])


# ─── List / detail ────────────────────────────────────────────────────────────

@router.get("", response_model=PaginatedResponse[InvestigationListItem])
async def list_investigations(
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    status:      str | None  = Query(default=None),
    verdict:     str | None  = Query(default=None),
    assigned_to: UUID | None = Query(default=None),
    min_score:   int | None  = Query(default=None, ge=0, le=100),
    max_score:   int | None  = Query(default=None, ge=0, le=100),
    cursor:      str | None  = Query(default=None),
    limit:       int         = Query(default=50, ge=1, le=200),
    sort:        str         = Query(default="desc", pattern="^(asc|desc)$"),
) -> PaginatedResponse[InvestigationListItem]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]

    params = InvestigationFilterParams(
        status=status, verdict=verdict, assigned_to=assigned_to,
        min_score=min_score, max_score=max_score,
        cursor=cursor, limit=limit, sort=sort,
    )
    items, next_cursor = await AnalystWorkspaceService.list_investigations(
        db, m.tenant_id, params
    )
    return PaginatedResponse[InvestigationListItem].cursor(
        data=items,
        next_cursor=next_cursor,
        prev_cursor=None,
        has_more=next_cursor is not None,
        limit=limit,
    )


@router.get("/{investigation_id}", response_model=APIResponse[InvestigationDetail])
async def get_investigation(
    investigation_id: str,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[InvestigationDetail]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    detail = await AnalystWorkspaceService.get_investigation_detail(
        db, m.tenant_id, investigation_id, m.user_id
    )
    await db.commit()
    return APIResponse.ok(detail)


# ─── Timeline ─────────────────────────────────────────────────────────────────

@router.get("/{investigation_id}/timeline", response_model=APIResponse[TimelineResponse])
async def get_timeline(
    investigation_id: str,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    severity_min:  int | None  = Query(default=None, ge=1, le=10),
    entity_filter: str | None  = Query(default=None),
    category:      str | None  = Query(default=None),
    sort:          str         = Query(default="asc", pattern="^(asc|desc)$"),
    cursor:        str | None  = Query(default=None),
    limit:         int         = Query(default=50, ge=1, le=200),
) -> APIResponse[TimelineResponse]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    filters = TimelineFilter(
        severity_min=severity_min, entity_filter=entity_filter,
        category=category, sort=sort, cursor=cursor, limit=limit,
    )
    result = await AnalystWorkspaceService.get_timeline(
        db, m.tenant_id, investigation_id, m.user_id, filters
    )
    await db.commit()
    return APIResponse.ok(result)


# ─── Graph ────────────────────────────────────────────────────────────────────

@router.get("/{investigation_id}/graph", response_model=APIResponse[GraphResponse])
async def get_graph(
    investigation_id: str,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    depth:        int  = Query(default=3, ge=1, le=10),
    collapse_ips: bool = Query(default=False),
) -> APIResponse[GraphResponse]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    filters = GraphFilter(depth=depth, collapse_ips=collapse_ips)
    result = await AnalystWorkspaceService.get_graph(
        db, m.tenant_id, investigation_id, m.user_id, filters
    )
    await db.commit()
    return APIResponse.ok(result)


# ─── Activity ─────────────────────────────────────────────────────────────────

@router.get("/{investigation_id}/activity", response_model=PaginatedResponse[ActivityOut])
async def get_activity(
    investigation_id: str,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    cursor: str | None = Query(default=None),
    limit:  int        = Query(default=50, ge=1, le=200),
) -> PaginatedResponse[ActivityOut]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    rows, next_cursor = await ActivityService.list_activity(
        db, m.tenant_id, investigation_id, cursor, limit
    )
    data = [
        ActivityOut(
            activity_id=str(r.id),
            investigation_id=investigation_id,
            tenant_id=str(m.tenant_id),
            analyst_id=r.analyst_id,
            action=r.action,
            target_id=r.target_id,
            action_data=r.action_data,
            created_at=r.created_at,
        )
        for r in rows
    ]
    return PaginatedResponse[ActivityOut].cursor(
        data=data,
        next_cursor=next_cursor,
        prev_cursor=None,
        has_more=next_cursor is not None,
        limit=limit,
    )


# ─── Evidence ─────────────────────────────────────────────────────────────────

@router.get("/{investigation_id}/evidence", response_model=APIResponse[list[EvidenceOut]])
async def list_evidence(
    investigation_id: str,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    evidence_type: str | None = Query(default=None),
) -> APIResponse[list[EvidenceOut]]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    rows = await EvidenceService.list_for_investigation(
        db, m.tenant_id, investigation_id, evidence_type
    )
    data = [
        EvidenceOut(
            evidence_id=str(r.id),
            investigation_id=investigation_id,
            tenant_id=str(m.tenant_id),
            analyst_id=r.analyst_id,
            evidence_type=r.evidence_type,
            reference_id=r.reference_id,
            title=r.title,
            description=r.description,
            extra_data=r.extra_data,
            created_at=r.created_at,
        )
        for r in rows
    ]
    return APIResponse.ok(data)


@router.post("/{investigation_id}/evidence", response_model=APIResponse[EvidenceOut])
async def attach_evidence(
    investigation_id: str,
    payload: EvidenceCreate,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_UPDATE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[EvidenceOut]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    ev = await AnalystWorkspaceService.attach_evidence(
        db, m.tenant_id, investigation_id, m.user_id, payload
    )
    await db.commit()
    return APIResponse.ok(
        EvidenceOut(
            evidence_id=str(ev.id),
            investigation_id=investigation_id,
            tenant_id=str(m.tenant_id),
            analyst_id=ev.analyst_id,
            evidence_type=ev.evidence_type,
            reference_id=ev.reference_id,
            title=ev.title,
            description=ev.description,
            extra_data=ev.extra_data,
            created_at=ev.created_at,
        )
    )


# ─── Notes ────────────────────────────────────────────────────────────────────

@router.get("/{investigation_id}/notes", response_model=PaginatedResponse[NoteOut])
async def list_notes(
    investigation_id: str,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    page:  int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
) -> PaginatedResponse[NoteOut]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    rows, total = await NoteService.list_for_investigation(
        db, m.tenant_id, investigation_id, page, limit
    )
    data = [
        NoteOut(
            note_id=str(r.id),
            investigation_id=investigation_id,
            tenant_id=str(m.tenant_id),
            analyst_id=r.analyst_id,
            content=r.content,
            pinned=r.pinned,
            created_at=r.created_at,
            updated_at=r.updated_at,
        )
        for r in rows
    ]
    return PaginatedResponse[NoteOut].offset(data=data, page=page, limit=limit, total=total)


@router.post("/{investigation_id}/notes", response_model=APIResponse[NoteOut])
async def add_note(
    investigation_id: str,
    payload: NoteCreate,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_UPDATE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[NoteOut]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    note = await AnalystWorkspaceService.add_note(
        db, m.tenant_id, investigation_id, m.user_id, payload
    )
    await db.commit()
    return APIResponse.ok(
        NoteOut(
            note_id=str(note.id),
            investigation_id=investigation_id,
            tenant_id=str(m.tenant_id),
            analyst_id=note.analyst_id,
            content=note.content,
            pinned=note.pinned,
            created_at=note.created_at,
            updated_at=note.updated_at,
        )
    )


@router.patch("/{investigation_id}/notes/{note_id}", response_model=APIResponse[NoteOut])
async def update_note(
    investigation_id: str,
    note_id: UUID,
    payload: NoteUpdate,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_UPDATE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[NoteOut]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    is_admin = has_minimum_role(m.role, Role.ADMIN)
    note = await AnalystWorkspaceService.edit_note(
        db, m.tenant_id, note_id, m.user_id, payload, investigation_id, is_admin
    )
    await db.commit()
    return APIResponse.ok(
        NoteOut(
            note_id=str(note.id),
            investigation_id=investigation_id,
            tenant_id=str(m.tenant_id),
            analyst_id=note.analyst_id,
            content=note.content,
            pinned=note.pinned,
            created_at=note.created_at,
            updated_at=note.updated_at,
        )
    )


@router.delete("/{investigation_id}/notes/{note_id}", response_model=APIResponse[EmptyResponse])
async def delete_note(
    investigation_id: str,
    note_id: UUID,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_UPDATE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[EmptyResponse]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    is_admin = has_minimum_role(m.role, Role.ADMIN)
    await AnalystWorkspaceService.delete_note(
        db, m.tenant_id, note_id, m.user_id, investigation_id, is_admin
    )
    await db.commit()
    return APIResponse.ok(EmptyResponse())


# ─── Status ───────────────────────────────────────────────────────────────────

@router.patch("/{investigation_id}/status", response_model=APIResponse[InvestigationDetail])
async def update_status(
    investigation_id: str,
    payload: StatusUpdate,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_UPDATE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[InvestigationDetail]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    await AnalystWorkspaceService.update_status(
        db, m.tenant_id, investigation_id, m.user_id, payload
    )
    detail = await AnalystWorkspaceService.get_investigation_detail(
        db, m.tenant_id, investigation_id, m.user_id
    )
    await db.commit()
    return APIResponse.ok(detail)


# ─── Verdict ──────────────────────────────────────────────────────────────────

@router.patch("/{investigation_id}/verdict", response_model=APIResponse[VerdictOut])
async def set_verdict(
    investigation_id: str,
    payload: VerdictCreate,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_UPDATE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[VerdictOut]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    verdict = await AnalystWorkspaceService.set_verdict(
        db, m.tenant_id, investigation_id, m.user_id, payload
    )
    await db.commit()
    return APIResponse.ok(
        VerdictOut(
            verdict_id=str(verdict.id),
            investigation_id=investigation_id,
            tenant_id=str(m.tenant_id),
            analyst_id=verdict.analyst_id,
            previous_verdict=verdict.previous_verdict,
            new_verdict=verdict.new_verdict,
            reasoning=verdict.reasoning,
            containment_status=verdict.containment_status,
            created_at=verdict.created_at,
        )
    )


# ─── Assignment ───────────────────────────────────────────────────────────────

@router.patch("/{investigation_id}/assign", response_model=APIResponse[AssignmentOut])
async def assign_investigation(
    investigation_id: str,
    payload: AssignmentCreate,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_UPDATE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[AssignmentOut]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    assignment = await AnalystWorkspaceService.assign(
        db, m.tenant_id, investigation_id, m.user_id, payload
    )
    await db.commit()
    return APIResponse.ok(
        AssignmentOut(
            assignment_id=str(assignment.id),
            investigation_id=investigation_id,
            tenant_id=str(m.tenant_id),
            assigned_to=assignment.assigned_to,
            assigned_by=assignment.assigned_by,
            assigned_at=assignment.assigned_at,
            escalated=assignment.escalated,
            escalation_reason=assignment.escalation_reason,
            severity=assignment.severity,
            is_active=assignment.is_active,
        )
    )


# ─── Threat hunt ──────────────────────────────────────────────────────────────

@router.post("/hunt", response_model=APIResponse[HuntResult])
async def run_hunt(
    payload: HuntQuery,
    member: Annotated[object, require_permission(Permission.HUNT_QUERY)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[HuntResult]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    result = await AnalystWorkspaceService.run_hunt(db, m.tenant_id, m.user_id, payload)
    await db.commit()
    return APIResponse.ok(result)


@router.post("/hunt/saved", response_model=APIResponse[SavedHuntOut])
async def save_hunt(
    payload: SavedHuntCreate,
    member: Annotated[object, require_permission(Permission.HUNT_QUERY)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[SavedHuntOut]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    hunt = await HuntEngine.save_hunt(db, m.tenant_id, m.user_id, payload)
    await db.commit()
    return APIResponse.ok(
        SavedHuntOut(
            hunt_id=str(hunt.id),
            tenant_id=str(hunt.tenant_id),
            analyst_id=hunt.analyst_id,
            name=hunt.name,
            description=hunt.description,
            query_params=hunt.query_params,
            run_count=hunt.run_count,
            created_at=hunt.created_at,
            updated_at=hunt.updated_at,
        )
    )


@router.get("/hunt/saved", response_model=APIResponse[list[SavedHuntOut]])
async def list_saved_hunts(
    member: Annotated[object, require_permission(Permission.HUNT_QUERY)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[list[SavedHuntOut]]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    hunts = await HuntEngine.list_saved_hunts(db, m.tenant_id, m.user_id)
    return APIResponse.ok([
        SavedHuntOut(
            hunt_id=str(h.id),
            tenant_id=str(h.tenant_id),
            analyst_id=h.analyst_id,
            name=h.name,
            description=h.description,
            query_params=h.query_params,
            run_count=h.run_count,
            created_at=h.created_at,
            updated_at=h.updated_at,
        )
        for h in hunts
    ])


# ─── Merge investigations ─────────────────────────────────────────────────────

@router.post("/merge", response_model=APIResponse[InvestigationDetail])
async def merge_investigations(
    payload: MergeRequest,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[InvestigationDetail]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    await AnalystWorkspaceService.merge_investigations(db, m.tenant_id, m.user_id, payload)
    detail = await AnalystWorkspaceService.get_investigation_detail(
        db, m.tenant_id, payload.primary_investigation_id, m.user_id
    )
    await db.commit()
    return APIResponse.ok(detail)


# ─── Entity pivot ─────────────────────────────────────────────────────────────

@router.post("/{investigation_id}/pivot", response_model=APIResponse[PivotResult])
async def entity_pivot(
    investigation_id: str,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    entity_type: str = Query(...),
    entity_value: str = Query(...),
) -> APIResponse[PivotResult]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    result = await AnalystWorkspaceService.pivot(
        db, m.tenant_id, m.user_id, entity_type, entity_value
    )
    await db.commit()
    return APIResponse.ok(result)
