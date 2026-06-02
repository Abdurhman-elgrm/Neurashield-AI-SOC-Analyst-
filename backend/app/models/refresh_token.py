from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.models.base import Base, TimestampMixin


class RefreshToken(Base, TimestampMixin):
    """
    Persisted refresh token record enabling server-side revocation.
    The JTI (JWT ID) is the canonical identifier — used to revoke a token
    without knowing the plaintext value.
    """

    __tablename__ = "refresh_tokens"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    user_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    # JWT ID claim — used for revocation lookup
    jti: Mapped[str] = mapped_column(String(36), nullable=False, unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("idx_refresh_token_user_id", "user_id"),
    )

    # ─── Relationships ────────────────────────────────────────────────────────
    user: Mapped["User"] = relationship(  # type: ignore[name-defined]
        "User",
        back_populates="refresh_tokens",
        lazy="noload",
    )

    @property
    def is_valid(self) -> bool:
        from datetime import timezone
        now = datetime.now(tz=timezone.utc)
        return self.revoked_at is None and self.expires_at > now

    def revoke(self) -> None:
        from datetime import timezone
        self.revoked_at = datetime.now(tz=timezone.utc)

    def __repr__(self) -> str:
        return f"<RefreshToken id={self.id} user={self.user_id} jti={self.jti}>"
