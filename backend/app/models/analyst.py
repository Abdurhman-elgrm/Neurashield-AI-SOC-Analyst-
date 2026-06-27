from __future__ import annotations

"""
SQLAlchemy ORM models for the Tier 2 analyst workspace.

Tables:
  investigation_notes       — analyst notes (markdown, pinnable, soft-deletable)
  investigation_assignments — assignment / escalation records
  investigation_activity    — append-only audit trail for every analyst action
  investigation_evidence    — attached evidence artefacts
  investigation_verdicts    — ordered verdict history
  saved_hunts               — saved threat-hunt queries
"""

import enum
from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, SoftDeleteMixin, TimestampMixin, utcnow

# ─── Enumerations ─────────────────────────────────────────────────────────────


class EvidenceTypeEnum(str, enum.Enum):
    RAW_EVENT = "raw_event"
    CORRELATED_GROUP = "correlated_group"
    SCREENSHOT_META = "screenshot_meta"
    FILE_REF = "file_ref"
    IOC_REF = "ioc_ref"
    NOTE_REF = "note_ref"


# ─── Notes ────────────────────────────────────────────────────────────────────


class InvestigationNote(Base, TimestampMixin, SoftDeleteMixin):
    """Analyst notes on an investigation. Supports markdown, pinning, soft-delete."""

    __tablename__ = "investigation_notes"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    investigation_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    analyst_id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    pinned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    __table_args__ = (Index("idx_note_tenant_inv", "tenant_id", "investigation_id"),)

    def __repr__(self) -> str:
        return f"<InvestigationNote id={self.id} pinned={self.pinned}>"


# ─── Assignments ──────────────────────────────────────────────────────────────


class InvestigationAssignment(Base, TimestampMixin):
    """One record per assignment action. `is_active=True` is the current owner."""

    __tablename__ = "investigation_assignments"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    investigation_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    assigned_to: Mapped[UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    assigned_by: Mapped[UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    unassigned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    escalated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    escalation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)

    __table_args__ = (
        Index("idx_assign_tenant_inv_active", "tenant_id", "investigation_id", "is_active"),
    )

    def __repr__(self) -> str:
        return (
            f"<InvestigationAssignment id={self.id} "
            f"assigned_to={self.assigned_to} active={self.is_active}>"
        )


# ─── Activity (audit trail) ───────────────────────────────────────────────────


class InvestigationActivity(Base):
    """
    Immutable append-only audit trail for all analyst actions.
    Never updated or deleted.
    """

    __tablename__ = "investigation_activity"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    investigation_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    analyst_id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action_data: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )

    __table_args__ = (
        Index("idx_activity_tenant_inv", "tenant_id", "investigation_id"),
        Index("idx_activity_tenant_ts", "tenant_id", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<InvestigationActivity id={self.id} action={self.action}>"


# ─── Evidence ─────────────────────────────────────────────────────────────────


class InvestigationEvidence(Base, TimestampMixin):
    """Evidence artefacts attached to an investigation."""

    __tablename__ = "investigation_evidence"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    investigation_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    analyst_id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(32), nullable=False)
    reference_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    extra_data: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict)

    __table_args__ = (Index("idx_evidence_tenant_inv", "tenant_id", "investigation_id"),)

    def __repr__(self) -> str:
        return f"<InvestigationEvidence id={self.id} type={self.evidence_type}>"


# ─── Verdicts ─────────────────────────────────────────────────────────────────


class InvestigationVerdict(Base):
    """
    Ordered verdict history.  Most recent record is the current verdict.
    Immutable — never updated, new record on change.
    """

    __tablename__ = "investigation_verdicts"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    investigation_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    analyst_id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    previous_verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    new_verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)
    containment_status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )

    __table_args__ = (Index("idx_verdict_tenant_inv", "tenant_id", "investigation_id"),)

    def __repr__(self) -> str:
        return f"<InvestigationVerdict id={self.id} verdict={self.new_verdict}>"


# ─── Saved Hunts ──────────────────────────────────────────────────────────────


class SavedHunt(Base, TimestampMixin):
    """Analyst-saved threat hunt query templates."""

    __tablename__ = "saved_hunts"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    analyst_id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    query_params: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    run_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (Index("idx_saved_hunt_tenant_analyst", "tenant_id", "analyst_id"),)

    def __repr__(self) -> str:
        return f"<SavedHunt id={self.id} name={self.name!r}>"
