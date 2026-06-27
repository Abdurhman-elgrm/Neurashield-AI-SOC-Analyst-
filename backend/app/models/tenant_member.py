from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Enum, ForeignKey, Index, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, SoftDeleteMixin, TimestampMixin


class TenantMember(Base, TimestampMixin, SoftDeleteMixin):
    """
    Junction table linking a User to a Tenant with a role.
    A user can have exactly one active membership per tenant.
    Removing a member soft-deletes this record; the User global account is preserved.
    """

    __tablename__ = "tenant_members"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
    )
    user_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    role: Mapped[str] = mapped_column(
        Enum("owner", "admin", "analyst", "viewer", name="member_role_enum"),
        nullable=False,
    )
    invited_by: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    joined_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    custom_permissions: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=lambda: {"grant": [], "revoke": []},
        server_default=text('\'{"grant":[],"revoke":[]}\'::jsonb'),
    )
    notification_preferences: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=lambda: {
            "email_high_critical_alerts": True,
            "email_agent_offline": True,
            "email_new_investigation": False,
        },
        server_default=text(
            '\'{"email_high_critical_alerts":true,"email_agent_offline":true,"email_new_investigation":false}\'::jsonb'
        ),
    )

    # ─── Constraints ──────────────────────────────────────────────────────────
    __table_args__ = (
        # Only one active membership per (tenant, user) — enforced at DB level.
        # Soft-deleted rows are excluded so a user can be re-invited.
        Index(
            "idx_tenant_member_tenant_user",
            "tenant_id",
            "user_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("idx_tenant_member_tenant_id", "tenant_id"),
        Index("idx_tenant_member_user_id", "user_id"),
    )

    # ─── Relationships ────────────────────────────────────────────────────────
    tenant: Mapped[Tenant] = relationship(  # type: ignore[name-defined]
        "Tenant",
        back_populates="members",
        lazy="noload",
    )
    user: Mapped[User] = relationship(  # type: ignore[name-defined]
        "User",
        back_populates="memberships",
        foreign_keys=[user_id],
        lazy="noload",
    )

    def __repr__(self) -> str:
        return f"<TenantMember tenant={self.tenant_id} user={self.user_id} role={self.role}>"
