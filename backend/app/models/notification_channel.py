from __future__ import annotations

from uuid import uuid4

from sqlalchemy import Boolean, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, SoftDeleteMixin


class NotificationChannel(Base, TimestampMixin, SoftDeleteMixin):
    """
    Outbound notification channel for a tenant.
    Supported types: slack, teams, webhook, pagerduty, email
    Config is type-specific JSON:
      slack/teams: {"webhook_url": "https://..."}
      webhook:     {"url": "https://...", "secret": "...", "headers": {}}
      pagerduty:   {"integration_key": "..."}
      email:       {"recipients": ["a@b.com", ...]}
    """

    __tablename__ = "notification_channels"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    min_severity: Mapped[str] = mapped_column(String(16), nullable=False, default="high")
    created_by_id: Mapped[UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)

    def __repr__(self) -> str:
        return f"<NotificationChannel id={self.id} type={self.type} tenant={self.tenant_id}>"
