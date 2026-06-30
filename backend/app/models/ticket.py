from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Index, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utcnow


class Ticket(Base):
    """
    External ticket record (Jira / ServiceNow / PagerDuty).
    Created when an analyst links an investigation to an external ticketing system.
    Immutable — never soft-deleted so the audit trail is preserved.
    """

    __tablename__ = "tickets"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    investigation_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    ticket_key: Mapped[str] = mapped_column(String(128), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default="NOW()", nullable=False
    )

    __table_args__ = (
        Index("idx_ticket_tenant_inv", "tenant_id", "investigation_id"),
    )

    def __repr__(self) -> str:
        return f"<Ticket id={self.id} provider={self.provider} key={self.ticket_key}>"
