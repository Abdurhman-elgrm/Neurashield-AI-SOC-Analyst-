from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, SoftDeleteMixin, utcnow


class PlaybookTemplate(Base, TimestampMixin, SoftDeleteMixin):
    """
    Reusable IR playbook template — can be system-wide (is_system=True, tenant_id=NULL)
    or tenant-specific.  Matched by MITRE technique, tactic, or category.
    """

    __tablename__ = "playbook_templates"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    tactic: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    technique: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    category: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by_id: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    steps: Mapped[list["PlaybookTemplateStep"]] = relationship(
        "PlaybookTemplateStep",
        back_populates="template",
        lazy="noload",
        order_by="PlaybookTemplateStep.step_order",
    )

    __table_args__ = (
        Index("idx_pt_system_enabled", "is_system", "enabled"),
    )


class PlaybookTemplateStep(Base):
    """A single step within a PlaybookTemplate.  description_template may contain {variables}."""

    __tablename__ = "playbook_template_steps"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    template_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("playbook_templates.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    step_order: Mapped[int] = mapped_column(Integer, nullable=False)
    category: Mapped[str] = mapped_column(String(128), nullable=False, default="investigation")
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description_template: Mapped[str | None] = mapped_column(Text, nullable=True)
    command_windows: Mapped[str | None] = mapped_column(Text, nullable=True)
    command_linux: Mapped[str | None] = mapped_column(Text, nullable=True)
    expected_result: Mapped[str | None] = mapped_column(Text, nullable=True)
    can_run_parallel: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    requires_human_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_critical: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    hint: Mapped[str | None] = mapped_column(Text, nullable=True)
    mitre_reference: Mapped[str | None] = mapped_column(String(128), nullable=True)
    action_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    step_order_dependencies: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default="NOW()", nullable=False
    )

    template: Mapped["PlaybookTemplate"] = relationship(
        "PlaybookTemplate", back_populates="steps", lazy="noload"
    )


class Playbook(Base, TimestampMixin, SoftDeleteMixin):
    """
    An instantiated playbook for a specific alert or investigation.
    Variables are substituted from alert context at generation time.
    """

    __tablename__ = "playbooks"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    template_id: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("playbook_templates.id", ondelete="SET NULL"), nullable=True
    )
    alert_id: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True, index=True
    )
    investigation_id: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="SET NULL"), nullable=True
    )
    incident_id: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, default="medium")
    source_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    variables: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    generated_by: Mapped[str] = mapped_column(String(64), nullable=False, default="fallback")
    assigned_to_id: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_by_id: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    steps: Mapped[list["PlaybookStep"]] = relationship(
        "PlaybookStep",
        back_populates="playbook",
        lazy="noload",
        order_by="PlaybookStep.step_order",
    )
    runs: Mapped[list["PlaybookRun"]] = relationship(
        "PlaybookRun", back_populates="playbook", lazy="noload"
    )

    __table_args__ = (
        Index("idx_pb_tenant_status", "tenant_id", "status"),
        Index("idx_pb_tenant_incident", "tenant_id", "incident_id"),
    )


class PlaybookStep(Base):
    """Instantiated step with substituted descriptions, ready for execution."""

    __tablename__ = "playbook_steps"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    playbook_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("playbooks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    step_order: Mapped[int] = mapped_column(Integer, nullable=False)
    category: Mapped[str] = mapped_column(String(128), nullable=False, default="investigation")
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    command_windows: Mapped[str | None] = mapped_column(Text, nullable=True)
    command_linux: Mapped[str | None] = mapped_column(Text, nullable=True)
    expected_result: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    requires_human_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_critical: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    can_run_parallel: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    action_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action_target_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_by_id: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default="NOW()", nullable=False
    )

    playbook: Mapped["Playbook"] = relationship(
        "Playbook", back_populates="steps", lazy="noload"
    )


class PlaybookRun(Base):
    """Execution audit record for a playbook invocation."""

    __tablename__ = "playbook_runs"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    playbook_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("playbooks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="manual")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="running")
    steps_completed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    steps_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    actor_id: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default="NOW()", nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    playbook: Mapped["Playbook"] = relationship(
        "Playbook", back_populates="runs", lazy="noload"
    )


class PlaybookAutoConfig(Base, TimestampMixin):
    """Per-tenant configuration for automatic playbook generation when an alert is created."""

    __tablename__ = "playbook_auto_config"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    min_severity: Mapped[str] = mapped_column(
        String(32), nullable=False, default="critical"
    )  # critical | high | medium
    updated_by_id: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

