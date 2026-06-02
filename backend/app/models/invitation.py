from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Enum, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.models.base import Base, TimestampMixin


class Invitation(Base, TimestampMixin):
    """
    Pending invitation for a user to join a tenant.
    Token is a one-time use credential with an expiry.
    """

    __tablename__ = "invitations"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    tenant_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    invited_by: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        Enum("owner", "admin", "analyst", "viewer", name="member_role_enum"),
        nullable=False,
    )
    # SHA-256 hash of the plaintext invitation token
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("idx_invitation_tenant_id", "tenant_id"),
        Index("idx_invitation_email", "email"),
    )

    # ─── Relationships ────────────────────────────────────────────────────────
    tenant: Mapped["Tenant"] = relationship(  # type: ignore[name-defined]
        "Tenant",
        back_populates="invitations",
        lazy="noload",
    )

    @property
    def is_valid(self) -> bool:
        from datetime import timezone
        now = datetime.now(tz=timezone.utc)
        return (
            self.accepted_at is None
            and self.revoked_at is None
            and self.expires_at > now
        )

    def __repr__(self) -> str:
        return f"<Invitation id={self.id} email={self.email} tenant={self.tenant_id}>"
