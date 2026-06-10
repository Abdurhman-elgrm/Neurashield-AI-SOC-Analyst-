from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, utcnow


class Heartbeat(Base):
    """
    Point-in-time health record from an agent.  Append-only — never updated.
    Retention policy trims old rows; the latest heartbeat is the agent's health.
    """

    __tablename__ = "heartbeats"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )
    agent_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    os_metrics: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # ─── Relationships ────────────────────────────────────────────────────────
    agent: Mapped["Agent"] = relationship("Agent", back_populates="heartbeats", lazy="noload")  # type: ignore[name-defined]

    __table_args__ = (
        Index("idx_heartbeat_agent_received", "agent_id", "received_at"),
    )

    def __repr__(self) -> str:
        return f"<Heartbeat agent_id={self.agent_id} received_at={self.received_at}>"
