from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID

from app.models.base import Base, utcnow


class AuditLog(Base):
    """
    Immutable append-only audit trail for all mutating actions.
    No updated_at or deleted_at — audit records are permanent by design.
    Provides accountability for every security-relevant action in the platform.
    """

    __tablename__ = "audit_logs"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    # NULL for platform-level actions (e.g. global user management)
    tenant_id: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="SET NULL"),
        nullable=True,
    )
    actor_id: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Role/permissions the actor held at time of action (denormalized for auditability)
    actor_role: Mapped[str | None] = mapped_column(String(50), nullable=True)
    # The permission exercised, e.g. "alerts:update"
    permission_used: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # Human-readable action key, e.g. "alert.acknowledged", "member.removed"
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    resource_id: Mapped[UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    # JSON snapshot: { "before": {...}, "after": {...} }
    changes: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Correlates to the HTTP request_id for full traceability
    request_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
    )

    __table_args__ = (
        Index("idx_audit_log_tenant_id", "tenant_id"),
        Index("idx_audit_log_actor_id", "actor_id"),
        Index("idx_audit_log_created_at", "created_at"),
        Index("idx_audit_log_action", "action"),
    )

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} action={self.action} actor={self.actor_id}>"
