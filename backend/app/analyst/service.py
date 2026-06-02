from __future__ import annotations

"""
AnalystWorkspaceService — orchestrator for the Tier 2 analyst workspace.

This is the public entry point called by the API layer.
It delegates to the specialist services and handles cross-cutting concerns:
  - Strict tenant isolation enforcement
  - Activity logging on every mutation
  - Note / evidence count enrichment for detail views
"""

from datetime import datetime
from uuid import UUID

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.analyst.activity import ActivityService, AnalystAction
from app.analyst.assignment import AssignmentService
from app.analyst.cases import CaseService
from app.analyst.evidence import EvidenceService
from app.analyst.graph_api import GraphService
from app.analyst.hunt import HuntEngine
from app.analyst.notes import NoteService
from app.analyst.search import PivotEngine
from app.analyst.timeline_api import TimelineService
from app.analyst.verdicts import VerdictService
from app.analyst.schemas import (
    AssignmentCreate,
    EvidenceCreate,
    GraphFilter,
    GraphResponse,
    HuntQuery,
    HuntResult,
    InvestigationDetail,
    InvestigationFilterParams,
    InvestigationListItem,
    MergeRequest,
    NoteCreate,
    NoteUpdate,
    PivotResult,
    ReopenRequest,
    SavedHuntCreate,
    StatusUpdate,
    TimelineFilter,
    TimelineResponse,
    VerdictCreate,
)
from app.models.investigation import Investigation

logger = structlog.get_logger(__name__)


class AnalystWorkspaceService:

    # ── List / detail ──────────────────────────────────────────────────────────

    @staticmethod
    async def list_investigations(
        db: AsyncSession,
        tenant_id: UUID,
        params: InvestigationFilterParams,
    ) -> tuple[list[InvestigationListItem], str | None]:
        rows, next_cursor = await CaseService.list_investigations(
            db, tenant_id,
            status=params.status,
            verdict=params.verdict,
            assigned_to=params.assigned_to,
            min_score=params.min_score,
            max_score=params.max_score,
            from_ts=params.from_ts,
            to_ts=params.to_ts,
            cursor=params.cursor,
            limit=params.limit,
            sort=params.sort,
        )
        items = [_to_list_item(r) for r in rows]
        return items, next_cursor

    @staticmethod
    async def get_investigation_detail(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        analyst_id: UUID,
    ) -> InvestigationDetail:
        inv = await CaseService.get_investigation(db, tenant_id, investigation_id)

        note_count     = await NoteService.count_for_investigation(db, tenant_id, investigation_id)
        evidence_count = await EvidenceService.count_for_investigation(db, tenant_id, investigation_id)

        await ActivityService.log(
            db,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            action=AnalystAction.OPENED_INVESTIGATION,
        )

        return InvestigationDetail(
            investigation_id=str(inv.investigation_group_id),
            tenant_id=str(inv.tenant_id),
            investigation_group_id=str(inv.investigation_group_id),
            threat_score=inv.threat_score,
            confidence=inv.confidence,
            tp_probability=inv.tp_probability,
            fp_probability=inv.fp_probability,
            status=inv.status,
            verdict=inv.verdict,
            assigned_to=inv.assigned_to,
            executive_summary=inv.executive_summary,
            technical_summary=inv.technical_summary,
            attack_progression=inv.attack_progression or [],
            recommended_actions=inv.recommended_actions or [],
            created_at=inv.created_at,
            updated_at=inv.updated_at,
            note_count=note_count,
            evidence_count=evidence_count,
        )

    # ── Status / case management ───────────────────────────────────────────────

    @staticmethod
    async def update_status(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        analyst_id: UUID,
        payload: StatusUpdate,
    ) -> Investigation:
        inv = await CaseService.change_status(
            db, tenant_id, investigation_id, analyst_id,
            payload.status, payload.reason,
        )
        await ActivityService.log(
            db,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            action=AnalystAction.STATUS_CHANGED,
            metadata={"new_status": payload.status, "reason": payload.reason},
        )
        return inv

    @staticmethod
    async def merge_investigations(
        db: AsyncSession,
        tenant_id: UUID,
        analyst_id: UUID,
        payload: MergeRequest,
    ) -> Investigation:
        inv = await CaseService.merge(db, tenant_id, analyst_id, payload)
        await ActivityService.log(
            db,
            tenant_id=tenant_id,
            investigation_id=payload.primary_investigation_id,
            analyst_id=analyst_id,
            action=AnalystAction.MERGED,
            metadata={
                "secondary_ids": payload.secondary_investigation_ids,
                "reason": payload.reason,
            },
        )
        return inv

    # ── Verdict ────────────────────────────────────────────────────────────────

    @staticmethod
    async def set_verdict(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        analyst_id: UUID,
        payload: VerdictCreate,
    ) -> object:
        verdict = await VerdictService.set_verdict(
            db, tenant_id, investigation_id, analyst_id, payload
        )
        await ActivityService.log(
            db,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            action=AnalystAction.VERDICT_SET,
            metadata={
                "verdict": payload.verdict.value,
                "reasoning": payload.reasoning,
            },
        )
        return verdict

    # ── Assignment ─────────────────────────────────────────────────────────────

    @staticmethod
    async def assign(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        assigned_by: UUID,
        payload: AssignmentCreate,
    ) -> object:
        assignment = await AssignmentService.assign(
            db, tenant_id, investigation_id, assigned_by, payload
        )
        action = AnalystAction.ESCALATED if payload.escalated else AnalystAction.ASSIGNED
        await ActivityService.log(
            db,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            analyst_id=assigned_by,
            action=action,
            metadata={
                "assigned_to": str(payload.assigned_to),
                "escalated": payload.escalated,
                "escalation_reason": payload.escalation_reason,
            },
        )
        return assignment

    # ── Notes ──────────────────────────────────────────────────────────────────

    @staticmethod
    async def add_note(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        analyst_id: UUID,
        payload: NoteCreate,
    ) -> object:
        note = await NoteService.create(
            db, tenant_id, investigation_id, analyst_id, payload
        )
        await ActivityService.log(
            db,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            action=AnalystAction.NOTE_ADDED,
            target_id=str(note.id),
        )
        return note

    @staticmethod
    async def edit_note(
        db: AsyncSession,
        tenant_id: UUID,
        note_id: UUID,
        analyst_id: UUID,
        payload: NoteUpdate,
        investigation_id: str,
        is_admin: bool = False,
    ) -> object:
        note = await NoteService.update(
            db, tenant_id, note_id, analyst_id, payload, is_admin
        )
        await ActivityService.log(
            db,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            action=AnalystAction.NOTE_EDITED,
            target_id=str(note_id),
        )
        return note

    @staticmethod
    async def delete_note(
        db: AsyncSession,
        tenant_id: UUID,
        note_id: UUID,
        analyst_id: UUID,
        investigation_id: str,
        is_admin: bool = False,
    ) -> None:
        await NoteService.delete(db, tenant_id, note_id, analyst_id, is_admin)
        await ActivityService.log(
            db,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            action=AnalystAction.NOTE_DELETED,
            target_id=str(note_id),
        )

    # ── Evidence ───────────────────────────────────────────────────────────────

    @staticmethod
    async def attach_evidence(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        analyst_id: UUID,
        payload: EvidenceCreate,
    ) -> object:
        ev = await EvidenceService.attach(
            db, tenant_id, investigation_id, analyst_id, payload
        )
        await ActivityService.log(
            db,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            action=AnalystAction.EVIDENCE_ATTACHED,
            target_id=str(ev.id),
            metadata={"evidence_type": payload.evidence_type.value, "title": payload.title},
        )
        return ev

    # ── Timeline / Graph ───────────────────────────────────────────────────────

    @staticmethod
    async def get_timeline(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        analyst_id: UUID,
        filters: TimelineFilter,
    ) -> TimelineResponse:
        result = await TimelineService.get_timeline(db, tenant_id, investigation_id, filters)
        await ActivityService.log(
            db,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            action=AnalystAction.TIMELINE_VIEWED,
            metadata={"filter_count": len(result.entries)},
        )
        return result

    @staticmethod
    async def get_graph(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        analyst_id: UUID,
        filters: GraphFilter,
    ) -> GraphResponse:
        result = await GraphService.get_graph(db, tenant_id, investigation_id, filters)
        await ActivityService.log(
            db,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            action=AnalystAction.GRAPH_VIEWED,
            metadata={"node_count": result.node_count, "edge_count": result.edge_count},
        )
        return result

    # ── Hunt ───────────────────────────────────────────────────────────────────

    @staticmethod
    async def run_hunt(
        db: AsyncSession,
        tenant_id: UUID,
        analyst_id: UUID,
        query: HuntQuery,
    ) -> HuntResult:
        result = await HuntEngine.run_query(db, tenant_id, query)
        await ActivityService.log(
            db,
            tenant_id=tenant_id,
            investigation_id="__hunt__",
            analyst_id=analyst_id,
            action=AnalystAction.HUNT_RUN,
            metadata={"filter_count": len(query.filters), "result_count": result.total},
        )
        return result

    # ── Pivot ──────────────────────────────────────────────────────────────────

    @staticmethod
    async def pivot(
        db: AsyncSession,
        tenant_id: UUID,
        analyst_id: UUID,
        entity_type: str,
        entity_value: str,
    ) -> PivotResult:
        result = await PivotEngine.pivot(db, tenant_id, entity_type, entity_value)
        await ActivityService.log(
            db,
            tenant_id=tenant_id,
            investigation_id="__pivot__",
            analyst_id=analyst_id,
            action=AnalystAction.PIVOT_QUERY,
            metadata={
                "entity_type": entity_type,
                "entity_value": entity_value,
                "result_count": result.total,
            },
        )
        return result


# ─── Conversion helpers ───────────────────────────────────────────────────────

def _to_list_item(inv: Investigation) -> InvestigationListItem:
    return InvestigationListItem(
        investigation_id=str(inv.investigation_group_id),
        tenant_id=str(inv.tenant_id),
        investigation_group_id=str(inv.investigation_group_id),
        threat_score=inv.threat_score,
        confidence=inv.confidence,
        tp_probability=inv.tp_probability,
        fp_probability=inv.fp_probability,
        status=inv.status,
        verdict=inv.verdict,
        assigned_to=inv.assigned_to,
        executive_summary=inv.executive_summary,
        created_at=inv.created_at,
        updated_at=inv.updated_at,
    )
