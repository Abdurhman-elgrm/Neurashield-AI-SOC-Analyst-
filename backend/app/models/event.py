from __future__ import annotations

import enum
from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Enum, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, utcnow


class EventCategory(str, enum.Enum):
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    AUTH = "auth"
    REGISTRY = "registry"
    DNS = "dns"
    OTHER = "other"


class Event(Base):
    """
    Normalized security event.  Append-only — never updated or hard-deleted.
    hot_until controls tiered storage eligibility (future ClickHouse migration).

    stream_id: Redis Streams message-ID for pipeline traceability.
    raw_id:    Idempotency key supplied by the agent (deduplication).
    """

    __tablename__ = "events"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_id: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    stream_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)

    category: Mapped[EventCategory] = mapped_column(
        Enum(EventCategory, name="event_category_enum",
             values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        index=True,
    )
    severity: Mapped[int] = mapped_column(Integer, nullable=False, default=1, index=True)
    event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )

    # Denormalized top-level fields for fast querying
    host_name: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dest_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Correlation / session / chain fields (added Phase 3.6)
    correlation_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    process_tree_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    event_chain_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Structured normalized payload (ECS-inspired)
    process: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    user: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    network: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    file: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    registry: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    normalized: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    raw_payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    tags: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    __table_args__ = (
        Index("idx_event_tenant_ts", "tenant_id", "event_timestamp"),
        Index("idx_event_tenant_category", "tenant_id", "category"),
        Index("idx_event_tenant_raw_id", "tenant_id", "raw_id"),
        # Phase 3.6 indexes
        Index("idx_event_tenant_severity", "tenant_id", "severity"),
        Index("idx_event_tenant_username", "tenant_id", "username"),
        Index("idx_event_tenant_source_ip", "tenant_id", "source_ip"),
        Index("idx_event_tenant_dest_ip", "tenant_id", "dest_ip"),
        Index("idx_event_tenant_process_name", "tenant_id", "process_name"),
        Index("idx_event_tenant_correlation_id", "tenant_id", "correlation_id"),
        Index("idx_event_tenant_session_id", "tenant_id", "session_id"),
        Index("idx_event_tenant_process_tree_id", "tenant_id", "process_tree_id"),
        Index("idx_event_tenant_event_chain_id", "tenant_id", "event_chain_id"),
    )

    def __repr__(self) -> str:
        return f"<Event id={self.id} category={self.category} tenant_id={self.tenant_id}>"
