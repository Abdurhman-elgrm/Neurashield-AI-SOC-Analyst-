from __future__ import annotations

from uuid import uuid4

from sqlalchemy import Boolean, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.models.base import Base, TimestampMixin, SoftDeleteMixin


class Tenant(Base, TimestampMixin, SoftDeleteMixin):
    """
    A tenant represents one customer organization.
    All security data (events, alerts, agents) is scoped to a tenant.
    """

    __tablename__ = "tenants"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    timezone: Mapped[str] = mapped_column(String(64), nullable=False, default="UTC")
    logo_url: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)

    # ─── Data retention policies ───────────────────────────────────────────────
    event_retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=90)
    alert_retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=365)

    # ─── Relationships ────────────────────────────────────────────────────────
    members: Mapped[list["TenantMember"]] = relationship(  # type: ignore[name-defined]
        "TenantMember",
        back_populates="tenant",
        lazy="noload",
    )
    invitations: Mapped[list["Invitation"]] = relationship(  # type: ignore[name-defined]
        "Invitation",
        back_populates="tenant",
        lazy="noload",
    )
    agents: Mapped[list["Agent"]] = relationship(  # type: ignore[name-defined]
        "Agent",
        back_populates="tenant",
        lazy="noload",
    )

    def __repr__(self) -> str:
        return f"<Tenant id={self.id} slug={self.slug}>"
