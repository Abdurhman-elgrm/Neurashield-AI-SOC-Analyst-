from __future__ import annotations

from uuid import uuid4

from sqlalchemy import Boolean, String, Text, TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.models.base import Base, TimestampMixin, SoftDeleteMixin


class User(Base, TimestampMixin, SoftDeleteMixin):
    """
    Global user account. NOT tenant-scoped.
    A user can be a member of multiple tenants simultaneously.
    Deleting a user is soft-delete only — security audit data must be preserved.
    """

    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    email: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True, index=True
    )
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    timezone: Mapped[str] = mapped_column(String(64), nullable=False, default="UTC")

    # ─── Email verification ───────────────────────────────────────────────────
    email_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    email_verification_token: Mapped[str | None] = mapped_column(String(128), nullable=True)
    email_verification_sent_at: Mapped[str | None] = mapped_column(nullable=True)

    # ─── Password reset ───────────────────────────────────────────────────────
    password_reset_token: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    password_reset_sent_at: Mapped[str | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)

    # ─── Extended profile ─────────────────────────────────────────────────────
    avatar_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    job_title: Mapped[str | None] = mapped_column(String(128), nullable=True)
    bio: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ─── Relationships ────────────────────────────────────────────────────────
    memberships: Mapped[list["TenantMember"]] = relationship(  # type: ignore[name-defined]
        "TenantMember",
        back_populates="user",
        foreign_keys="TenantMember.user_id",
        lazy="noload",
    )
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(  # type: ignore[name-defined]
        "RefreshToken",
        back_populates="user",
        lazy="noload",
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email}>"
