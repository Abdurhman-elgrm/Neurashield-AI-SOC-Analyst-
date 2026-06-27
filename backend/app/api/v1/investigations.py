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
  POST   /investigations/hunt                 investigation-level hunt query
  POST   /investigations/hunt/events          raw event-level threat hunt
  POST   /investigations/hunt/saved           save hunt
  GET    /investigations/hunt/saved           list saved hunts
  POST   /investigations/merge                merge investigations
  POST   /investigations/{id}/pivot           entity pivot
"""

import csv
import io
import json
from datetime import UTC
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analyst.activity import ActivityService
from app.analyst.cases import CaseService
from app.analyst.evidence import EvidenceService
from app.analyst.hunt import HuntEngine
from app.analyst.notes import NoteService
from app.analyst.schemas import (
    ActivityOut,
    AssignmentCreate,
    AssignmentOut,
    EventHuntQuery,
    EventHuntResult,
    EvidenceCreate,
    EvidenceOut,
    GraphFilter,
    GraphResponse,
    HuntQuery,
    HuntResult,
    InvestigationCreate,
    InvestigationDetail,
    InvestigationFilterParams,
    InvestigationListItem,
    MergeRequest,
    NoteCreate,
    NoteOut,
    NoteUpdate,
    PivotResult,
    SavedHuntCreate,
    SavedHuntOut,
    StatusUpdate,
    TimelineFilter,
    TimelineResponse,
    VerdictCreate,
    VerdictOut,
)
from app.analyst.service import AnalystWorkspaceService
from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models.user import User
from app.rbac.permissions import Permission
from app.rbac.roles import Role, has_minimum_role
from app.schemas.common import APIResponse, EmptyResponse, PaginatedResponse

router = APIRouter(prefix="/investigations", tags=["investigations"])


# ─── Create (manual) ─────────────────────────────────────────────────────────


@router.post("", response_model=APIResponse[InvestigationDetail])
async def create_investigation(
    body: InvestigationCreate,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[InvestigationDetail]:
    """Manually create a new investigation case."""
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    investigation = await CaseService.create_manual(
        db=db,
        tenant_id=m.tenant_id,
        created_by=m.user_id,
        title=body.title,
        description=body.description,
        severity=body.severity,
        assigned_to=body.assigned_to,
        alert_ids=body.alert_ids,
    )

    detail = InvestigationDetail(
        investigation_id=investigation.investigation_group_id,
        tenant_id=str(investigation.tenant_id),
        investigation_group_id=investigation.investigation_group_id,
        threat_score=investigation.threat_score,
        confidence=investigation.confidence,
        tp_probability=investigation.tp_probability,
        fp_probability=investigation.fp_probability,
        status=investigation.status,
        verdict=investigation.verdict,
        assigned_to=investigation.assigned_to,
        executive_summary=investigation.executive_summary,
        title=investigation.title,
        source=investigation.source,
        created_at=investigation.created_at,
        updated_at=investigation.updated_at,
        technical_summary=investigation.technical_summary,
        attack_progression=investigation.attack_progression,
        recommended_actions=investigation.recommended_actions,
        note_count=0,
        evidence_count=0,
    )
    return APIResponse.ok(detail)


# ─── List / detail ────────────────────────────────────────────────────────────


@router.get("", response_model=PaginatedResponse[InvestigationListItem])
async def list_investigations(
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    status: str | None = Query(default=None),
    verdict: str | None = Query(default=None),
    assigned_to: UUID | None = Query(default=None),
    title_search: str | None = Query(default=None),
    min_score: int | None = Query(default=None, ge=0, le=100),
    max_score: int | None = Query(default=None, ge=0, le=100),
    assigned_to_me: bool = Query(default=False),
    from_ts: str | None = Query(default=None),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    sort: str = Query(default="desc", pattern="^(asc|desc)$"),
) -> PaginatedResponse[InvestigationListItem]:
    from datetime import datetime

    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    from_ts_dt: datetime | None = None
    if from_ts:
        try:
            from_ts_dt = datetime.fromisoformat(from_ts.replace("Z", "+00:00"))
        except ValueError:
            pass

    effective_assigned_to = m.user_id if assigned_to_me else assigned_to

    params = InvestigationFilterParams(
        status=status,
        verdict=verdict,
        assigned_to=effective_assigned_to,
        title_search=title_search,
        min_score=min_score,
        max_score=max_score,
        from_ts=from_ts_dt,
        cursor=cursor,
        limit=limit,
        sort=sort,
    )
    items, next_cursor = await AnalystWorkspaceService.list_investigations(db, m.tenant_id, params)

    # Resolve assigned_to UUIDs → full names in a single batch query
    assigned_ids = {item.assigned_to for item in items if item.assigned_to}
    if assigned_ids:
        result = await db.execute(select(User.id, User.full_name).where(User.id.in_(assigned_ids)))
        name_map: dict = {row.id: row.full_name for row in result.all()}
        for item in items:
            if item.assigned_to:
                item.assigned_to_name = name_map.get(item.assigned_to)

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
    return APIResponse.ok(detail)


# ─── Related alerts ──────────────────────────────────────────────────────────


@router.get("/{investigation_id}/related-alerts", response_model=APIResponse[dict])
async def get_related_alerts(
    investigation_id: str,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> APIResponse[dict]:
    """
    Return alerts linked to an investigation via triggering_alert_ids.
    Includes soft-deleted alerts (they show in investigation context but not in alerts list).
    """

    from app.models.alert import Alert
    from app.models.investigation import Investigation
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    inv_result = await db.execute(
        select(Investigation).where(
            Investigation.investigation_group_id == investigation_id,
            Investigation.tenant_id == m.tenant_id,
        )
    )
    inv = inv_result.scalar_one_or_none()
    if inv is None:
        from app.core.exceptions import NotFoundError

        raise NotFoundError(f"Investigation {investigation_id} not found")

    alert_ids: list[str] = inv.triggering_alert_ids or []
    if not alert_ids:
        return APIResponse.ok(
            {"alerts": [], "total": 0, "offset": offset, "limit": limit, "has_more": False}
        )

    try:
        alert_uuids = [UUID(aid) for aid in alert_ids]
    except ValueError:
        return APIResponse.ok(
            {"alerts": [], "total": 0, "offset": offset, "limit": limit, "has_more": False}
        )

    total_count = len(alert_uuids)
    paged_uuids = alert_uuids[offset : offset + limit]
    if not paged_uuids:
        return APIResponse.ok(
            {
                "alerts": [],
                "total": total_count,
                "offset": offset,
                "limit": limit,
                "has_more": False,
            }
        )

    result = await db.execute(
        select(Alert).where(
            Alert.id.in_(paged_uuids),
            Alert.tenant_id == m.tenant_id,
        )
    )
    alerts = list(result.scalars().all())

    def _serialize(a: Alert) -> dict:
        ev = a.evidence or {}
        process = ev.get("process") or {}
        return {
            "id": str(a.id),
            "tenant_id": str(a.tenant_id),
            "rule_id": str(a.rule_id or ""),
            "rule_name": a.rule_name or "",
            "title": a.title,
            "description": a.description or "",
            "severity": a.severity.value if hasattr(a.severity, "value") else str(a.severity),
            "status": a.status.value if hasattr(a.status, "value") else str(a.status),
            "source_host": a.source_host,
            "source_ip": a.source_ip,
            "username": a.username,
            "process_name": process.get("name"),
            "mitre_tactics": a.mitre_tactics or [],
            "mitre_techniques": a.mitre_techniques or [],
            "ai_analysis": a.ai_analysis,
            "evidence": ev,
            "tags": getattr(a, "tags", []) or [],
            "raw_event_count": a.raw_event_count,
            "first_seen_at": a.first_seen_at.isoformat() if a.first_seen_at else None,
            "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "updated_at": a.updated_at.isoformat() if a.updated_at else None,
            "archived": a.deleted_at is not None,
        }

    return APIResponse.ok(
        {
            "alerts": [_serialize(a) for a in alerts],
            "total": total_count,
            "offset": offset,
            "limit": limit,
            "has_more": offset + limit < total_count,
        }
    )


# ─── AI Analysis ─────────────────────────────────────────────────────────────


@router.post("/{investigation_id}/analyze", response_model=APIResponse[InvestigationDetail])
async def run_ai_analysis(
    investigation_id: str,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_UPDATE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[InvestigationDetail]:
    """Manually trigger AI analysis for any investigation."""
    from datetime import datetime

    from app.ai.investigation_analyzer import get_investigation_analyzer
    from app.analyst.cases import CaseService
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    inv = await CaseService.get_investigation(db, m.tenant_id, investigation_id)

    investigation_data = {
        "id": str(inv.id),
        "title": inv.title or inv.executive_summary[:200],
        "threat_score": inv.threat_score,
        "confidence": inv.confidence,
        "behaviors_json": inv.behaviors_json or {},
        "timeline_json": inv.timeline_json or {},
        "context_json": inv.context_json or {},
        "graph_json": inv.graph_json or {},
    }

    analyzer = get_investigation_analyzer()
    analysis = await analyzer.analyze(db, investigation_data)
    inv.ai_analysis_json = analysis.to_dict()
    inv.updated_at = datetime.now(tz=UTC)
    await db.flush()

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
    severity_min: int | None = Query(default=None, ge=1, le=10),
    entity_filter: str | None = Query(default=None),
    category: str | None = Query(default=None),
    sort: str = Query(default="asc", pattern="^(asc|desc)$"),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
) -> APIResponse[TimelineResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    filters = TimelineFilter(
        severity_min=severity_min,
        entity_filter=entity_filter,
        category=category,
        sort=sort,
        cursor=cursor,
        limit=limit,
    )
    result = await AnalystWorkspaceService.get_timeline(
        db, m.tenant_id, investigation_id, m.user_id, filters
    )
    return APIResponse.ok(result)


# ─── Forensic timeline export ─────────────────────────────────────────────────


@router.get("/{investigation_id}/export/timeline")
async def export_timeline(
    investigation_id: str,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    format: str = Query(default="json", pattern="^(json|csv)$"),
) -> StreamingResponse:
    """
    Export the full investigation timeline as JSON or CSV.
    Useful for forensic handoff, SIEM ingestion, or compliance evidence packages.
    """
    from app.analyst.cases import CaseService
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    inv = await CaseService.get_investigation(db, m.tenant_id, investigation_id)

    timeline_data: list[dict] = []
    if inv.timeline_json:
        raw_timeline = inv.timeline_json
        entries = raw_timeline.get("entries", []) if isinstance(raw_timeline, dict) else []
        for entry in entries:
            timeline_data.append(
                {
                    "event_id": entry.get("event_id", ""),
                    "timestamp": entry.get("timestamp", ""),
                    "hostname": entry.get("hostname", ""),
                    "username": entry.get("username", ""),
                    "category": entry.get("category", ""),
                    "process": entry.get("process", ""),
                    "action": entry.get("action", ""),
                    "outcome": entry.get("outcome", ""),
                    "severity": entry.get("severity", ""),
                    "rule_match": ", ".join(entry.get("rule_match", [])),
                }
            )

    filename_base = f"investigation_{investigation_id[:8]}_timeline"

    if format == "csv":
        output = io.StringIO()
        if timeline_data:
            writer = csv.DictWriter(output, fieldnames=list(timeline_data[0].keys()))
            writer.writeheader()
            writer.writerows(timeline_data)
        else:
            output.write("no_events\n")
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename_base}.csv"'},
        )

    # JSON format
    payload = {
        "investigation_id": investigation_id,
        "exported_by": str(m.user_id),
        "entry_count": len(timeline_data),
        "entries": timeline_data,
        "behaviors": inv.behaviors_json or {},
        "score": {
            "threat_score": inv.threat_score,
            "confidence": inv.confidence,
            "tp_probability": inv.tp_probability,
            "fp_probability": inv.fp_probability,
        },
    }
    return StreamingResponse(
        iter([json.dumps(payload, indent=2, default=str)]),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename_base}.json"'},
    )


# ─── Graph ────────────────────────────────────────────────────────────────────


@router.get("/{investigation_id}/graph", response_model=APIResponse[GraphResponse])
async def get_graph(
    investigation_id: str,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    depth: int = Query(default=3, ge=1, le=10),
    collapse_ips: bool = Query(default=False),
) -> APIResponse[GraphResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    filters = GraphFilter(depth=depth, collapse_ips=collapse_ips)
    result = await AnalystWorkspaceService.get_graph(
        db, m.tenant_id, investigation_id, m.user_id, filters
    )
    return APIResponse.ok(result)


# ─── Activity ─────────────────────────────────────────────────────────────────


@router.get("/{investigation_id}/activity", response_model=PaginatedResponse[ActivityOut])
async def get_activity(
    investigation_id: str,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
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
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
) -> PaginatedResponse[NoteOut]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    rows, total = await NoteService.list_for_investigation(
        db, m.tenant_id, investigation_id, page, limit
    )

    # Bulk-resolve analyst names
    analyst_ids = {r.analyst_id for r in rows}
    name_map: dict = {}
    if analyst_ids:
        res = await db.execute(select(User.id, User.full_name).where(User.id.in_(analyst_ids)))
        name_map = {row.id: row.full_name for row in res.all()}

    data = [
        NoteOut(
            note_id=str(r.id),
            investigation_id=investigation_id,
            tenant_id=str(m.tenant_id),
            analyst_id=r.analyst_id,
            analyst_name=name_map.get(r.analyst_id),
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
    # Resolve name for immediate response
    user_res = await db.execute(select(User.full_name).where(User.id == m.user_id))
    author_name = user_res.scalar_one_or_none()
    return APIResponse.ok(
        NoteOut(
            note_id=str(note.id),
            investigation_id=investigation_id,
            tenant_id=str(m.tenant_id),
            analyst_id=note.analyst_id,
            analyst_name=author_name,
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
    user_res = await db.execute(select(User.full_name).where(User.id == note.analyst_id))
    author_name = user_res.scalar_one_or_none()
    return APIResponse.ok(
        NoteOut(
            note_id=str(note.id),
            investigation_id=investigation_id,
            tenant_id=str(m.tenant_id),
            analyst_id=note.analyst_id,
            analyst_name=author_name,
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

    # Store analyst feedback in ai_analysis_json for AI improvement tracking
    try:
        from datetime import datetime

        from app.analyst.cases import CaseService

        inv = await CaseService.get_investigation(db, m.tenant_id, investigation_id)
        if inv.ai_analysis_json is not None:
            updated = dict(inv.ai_analysis_json)
            verdict_str = (
                payload.verdict.value if hasattr(payload.verdict, "value") else str(payload.verdict)
            )
            updated["analyst_feedback"] = {
                "verdict": verdict_str,
                "timestamp": datetime.now(tz=UTC).isoformat(),
                "agreed_with_ai": updated.get("verdict_suggestion") == verdict_str,
            }
            inv.ai_analysis_json = updated
            await db.flush()
    except Exception:
        pass  # Never block verdict setting

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


@router.post("/hunt/events", response_model=APIResponse[EventHuntResult])
async def run_event_hunt(
    payload: EventHuntQuery,
    member: Annotated[object, require_permission(Permission.HUNT_QUERY)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[EventHuntResult]:
    """
    True threat hunting on raw normalized events.

    Queries the indexed events table directly — hunt by hostname, username,
    process name, source/dest IP, category, severity, UEBA flags, and tags.
    Returns paginated event results with a page-level entity summary.
    """
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    result = await AnalystWorkspaceService.run_event_hunt(db, m.tenant_id, m.user_id, payload)
    await db.commit()
    return APIResponse.ok(result)


@router.delete("/hunt/saved/{hunt_id}", response_model=APIResponse[EmptyResponse])
async def delete_saved_hunt(
    hunt_id: str,
    member: Annotated[object, require_permission(Permission.HUNT_QUERY)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[EmptyResponse]:
    from uuid import UUID as _UUID

    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    await HuntEngine.delete_saved_hunt(db, m.tenant_id, _UUID(hunt_id))
    await db.commit()
    return APIResponse.ok(EmptyResponse())


@router.get("/hunt/saved", response_model=APIResponse[list[SavedHuntOut]])
async def list_saved_hunts(
    member: Annotated[object, require_permission(Permission.HUNT_QUERY)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[list[SavedHuntOut]]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    hunts = await HuntEngine.list_saved_hunts(db, m.tenant_id, m.user_id)
    return APIResponse.ok(
        [
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
        ]
    )


# ─── Process tree (built from linked alert evidence) ─────────────────────────


@router.get("/{investigation_id}/process-tree", response_model=APIResponse[dict])
async def get_process_tree(
    investigation_id: str,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[dict]:
    import uuid as _uuid_mod
    from uuid import UUID as _UUID

    from app.models.alert import Alert
    from app.models.investigation import Investigation
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    inv = await db.scalar(
        select(Investigation).where(
            Investigation.investigation_group_id == investigation_id,
            Investigation.tenant_id == m.tenant_id,
        )
    )
    if not inv:
        return APIResponse.ok({"roots": []})

    alert_ids: list[str] = inv.triggering_alert_ids or []
    if not alert_ids:
        return APIResponse.ok({"roots": []})

    parsed_ids: list[_UUID] = []
    for aid in alert_ids:
        try:
            parsed_ids.append(_uuid_mod.UUID(str(aid)))
        except (ValueError, AttributeError):
            pass

    if not parsed_ids:
        return APIResponse.ok({"roots": []})

    result = await db.execute(
        select(Alert).where(Alert.id.in_(parsed_ids), Alert.tenant_id == m.tenant_id)
    )
    alerts = result.scalars().all()

    roots: list[dict] = []
    for alert in alerts:
        ev = alert.evidence or {}
        proc = ev.get("process") or {}
        if not proc.get("name"):
            continue
        node: dict = {
            "guid": str(alert.id),
            "pid": 0,
            "name": proc.get("name", "unknown"),
            "commandLine": proc.get("command_line") or None,
            "signer": proc.get("signer") or None,
            "imageHash": proc.get("hash") or None,
            "user": (ev.get("user") or {}).get("name") or None,
            "hostname": ev.get("hostname") or alert.source_host or None,
            "suspicious": alert.severity.value not in ("informational", "low")
            if hasattr(alert.severity, "value")
            else True,
            "children": [],
        }
        roots.append(node)

    return APIResponse.ok({"roots": roots})


# ─── Network flows (built from linked alert evidence) ─────────────────────────


@router.get("/{investigation_id}/network-flows", response_model=APIResponse[dict])
async def get_network_flows(
    investigation_id: str,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[dict]:
    import uuid as _uuid_mod

    from app.models.alert import Alert
    from app.models.investigation import Investigation
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    inv = await db.scalar(
        select(Investigation).where(
            Investigation.investigation_group_id == investigation_id,
            Investigation.tenant_id == m.tenant_id,
        )
    )
    if not inv:
        return APIResponse.ok({"flows": [], "start_time": None, "end_time": None})

    alert_ids: list[str] = inv.triggering_alert_ids or []
    parsed_ids = []
    for aid in alert_ids:
        try:
            parsed_ids.append(_uuid_mod.UUID(str(aid)))
        except (ValueError, AttributeError):
            pass

    if not parsed_ids:
        return APIResponse.ok({"flows": [], "start_time": None, "end_time": None})

    result = await db.execute(
        select(Alert).where(Alert.id.in_(parsed_ids), Alert.tenant_id == m.tenant_id)
    )
    alerts = result.scalars().all()

    flows = []
    timestamps = []
    seen = set()

    for alert in alerts:
        ev = alert.evidence or {}
        net = ev.get("network") or {}
        src_ip = net.get("src_ip")
        dst_ip = net.get("dst_ip")
        if not src_ip or not dst_ip:
            continue

        src_host = ev.get("hostname") or alert.source_host or src_ip
        flow_key = (f"{src_ip}({src_host})", dst_ip)
        if flow_key in seen:
            continue
        seen.add(flow_key)

        is_exfil = dst_ip and not (
            dst_ip.startswith("10.") or dst_ip.startswith("192.168.") or dst_ip.startswith("172.")
        )
        is_lateral = not is_exfil and src_ip != dst_ip

        flows.append(
            {
                "source": f"{src_ip} ({src_host})",
                "target": dst_ip,
                "bytes": net.get("bytes_sent") or net.get("bytes") or 0,
                "packets": net.get("packets") or 0,
                "proto": str(net.get("protocol") or "TCP").upper(),
                "is_lateral": is_lateral,
                "is_exfil": is_exfil,
            }
        )

        if alert.created_at:
            timestamps.append(alert.created_at)

    start_time = min(timestamps).isoformat() if timestamps else None
    end_time = max(timestamps).isoformat() if timestamps else None

    return APIResponse.ok({"flows": flows, "start_time": start_time, "end_time": end_time})


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
