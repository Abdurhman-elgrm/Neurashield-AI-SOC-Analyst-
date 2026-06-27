from __future__ import annotations

import hashlib
import json
from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utcnow


class AuditLog(Base):
    """
    Immutable append-only audit trail for all mutating actions.
    No updated_at or deleted_at — audit records are permanent by design.

    Hash chaining: each entry stores the SHA-256 of the previous entry's
    `entry_hash` (per-tenant chain) as `prev_hash`, and its own canonical
    SHA-256 as `entry_hash`. This allows offline forensic verification that
    no rows were inserted, modified, or deleted between two known checkpoints.
    """

    __tablename__ = "audit_logs"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
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
    # Hash chain — NULL on the first entry per tenant; populated by AuditService.
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entry_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("idx_audit_log_tenant_id", "tenant_id"),
        Index("idx_audit_log_actor_id", "actor_id"),
        Index("idx_audit_log_created_at", "created_at"),
        Index("idx_audit_log_action", "action"),
        Index("idx_audit_log_tenant_created", "tenant_id", "created_at"),
    )

    def compute_entry_hash(self, prev_hash: str | None) -> str:
        """
        Compute the canonical SHA-256 for this entry.
        All fields are included; prev_hash links to the previous entry in the chain.
        """
        canonical = json.dumps(
            {
                "id": str(self.id),
                "tenant_id": str(self.tenant_id) if self.tenant_id else None,
                "actor_id": str(self.actor_id) if self.actor_id else None,
                "action": self.action,
                "resource_type": self.resource_type,
                "resource_id": str(self.resource_id) if self.resource_id else None,
                "changes": self.changes,
                "ip_address": self.ip_address,
                "request_id": self.request_id,
                "created_at": self.created_at.isoformat() if self.created_at else None,
                "prev_hash": prev_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} action={self.action} actor={self.actor_id}>"
