from __future__ import annotations

import enum
from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Enum, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class InstallerTokenStatus(str, enum.Enum):
    PENDING = "pending"
    INSTALLING = "installing"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    FAILED = "failed"


class InstallerToken(Base, TimestampMixin):
    """
    Single-use, time-limited token for the Forwarder Installer Hub.

    Lifecycle:
      pending    — generated, waiting for installer to claim it
      installing — claimed by installer, installation in progress
      active     — installation completed successfully
      expired    — TTL elapsed before use
      revoked    — manually cancelled by an admin
      failed     — installer reported a failure

    Security invariants:
      - Raw token is NEVER persisted; only the Argon2id hash is stored.
      - token_preview (first 8 chars) is safe to display in the UI.
      - status must be PENDING to transition to INSTALLING (enforced with SELECT FOR UPDATE).
      - No soft-delete: rows are never removed — they are terminal (expired/revoked).
    """

    __tablename__ = "installer_tokens"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    token_preview: Mapped[str] = mapped_column(String(16), nullable=False)
    organization: Mapped[str] = mapped_column(String(255), nullable=False)
    machine_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    status: Mapped[InstallerTokenStatus] = mapped_column(
        Enum(
            InstallerTokenStatus,
            name="installer_token_status_enum",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
        default=InstallerTokenStatus.PENDING,
        index=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    installed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    device_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    token_metadata: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict)
    created_by_id: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    revoked_by_id: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    __table_args__ = (
        Index("idx_installer_token_tenant_status", "tenant_id", "status"),
        Index("idx_installer_token_tenant_expires", "tenant_id", "expires_at"),
        # Partial index: only PENDING tokens need the fast expiry sweep
        Index(
            "idx_installer_token_pending_expires",
            "expires_at",
            postgresql_where="status = 'pending'",
        ),
    )

    @property
    def is_expired(self) -> bool:
        from app.models.base import utcnow

        return self.expires_at < utcnow()

    @property
    def is_usable(self) -> bool:
        return self.status == InstallerTokenStatus.PENDING and not self.is_expired

    def __repr__(self) -> str:
        return f"<InstallerToken id={self.id} preview={self.token_preview} status={self.status}>"
