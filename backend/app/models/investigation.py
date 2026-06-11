from __future__ import annotations

import enum
from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Float, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class InvestigationStatus(str, enum.Enum):
    NEW           = "new"
    ACTIVE        = "active"
    TRIAGED       = "triaged"
    INVESTIGATING = "investigating"
    CONTAINED     = "contained"
    RESOLVED      = "resolved"
    CLOSED        = "closed"
    FALSE_POSITIVE = "false_positive"


class Investigation(Base, TimestampMixin):
    """
    Persisted record of an AI investigation group.

    Phase 3.3 fields: summary scores, status, summaries.
    Phase 3.4 additions: assignment, verdict, full result JSON for analyst APIs.
    """

    __tablename__ = "investigations"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    tenant_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )
    investigation_group_id: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    threat_score: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, index=True
    )
    confidence: Mapped[str] = mapped_column(
        String(16), nullable=False, default="low"
    )
    tp_probability: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.0
    )
    fp_probability: Mapped[float] = mapped_column(
        Float, nullable=False, default=1.0
    )
    executive_summary: Mapped[str] = mapped_column(
        Text, nullable=False, default=""
    )
    technical_summary: Mapped[str] = mapped_column(
        Text, nullable=False, default=""
    )
    attack_progression: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list
    )
    recommended_actions: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=InvestigationStatus.NEW.value, index=True
    )

    # ── Manual investigation fields ───────────────────────────────────────────
    title:      Mapped[str | None] = mapped_column(String(500), nullable=True)
    source:     Mapped[str | None] = mapped_column(String(32),  nullable=True, default="auto")
    created_by: Mapped[UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)

    # ── Phase 3.4 analyst workspace fields ────────────────────────────────────
    assigned_to: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )
    verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    verdict_set_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    verdict_set_by: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    # Full investigation result JSON for timeline/graph retrieval by analysts.
    timeline_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    graph_json:    Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    behaviors_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    context_json:  Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # AI analysis enrichment (Phase 2)
    ai_analysis_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True, default=None)

    __table_args__ = (
        Index("idx_investigation_tenant_score",   "tenant_id", "threat_score"),
        Index("idx_investigation_tenant_created",  "tenant_id", "created_at"),
        Index("idx_investigation_tenant_status",   "tenant_id", "status"),
        Index("idx_investigation_group",           "investigation_group_id"),
        Index("idx_investigation_tenant_assigned", "tenant_id", "assigned_to"),
    )

    def __repr__(self) -> str:
        return (
            f"<Investigation id={self.id} "
            f"score={self.threat_score} confidence={self.confidence}>"
        )
