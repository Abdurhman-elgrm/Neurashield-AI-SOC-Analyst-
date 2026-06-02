from __future__ import annotations

import enum
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, SoftDeleteMixin, utcnow


class AgentOsType(str, enum.Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


class AgentStatus(str, enum.Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"


class Agent(Base, TimestampMixin, SoftDeleteMixin):
    """
    A deployed SOC agent instance.  One agent = one host endpoint.
    Tenant-scoped.  Enrollment token is stored as a one-way hash.
    """

    __tablename__ = "agents"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    os_type: Mapped[AgentOsType] = mapped_column(
        Enum(AgentOsType, name="agent_os_type_enum"),
        nullable=False,
    )
    status: Mapped[AgentStatus] = mapped_column(
        Enum(AgentStatus, name="agent_status_enum"),
        nullable=False,
        default=AgentStatus.OFFLINE,
        index=True,
    )
    agent_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    enrollment_token_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    last_seen_at: Mapped[None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    tags: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    # ─── Relationships ────────────────────────────────────────────────────────
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="agents", lazy="noload")  # type: ignore[name-defined]
    heartbeats: Mapped[list["Heartbeat"]] = relationship(  # type: ignore[name-defined]
        "Heartbeat", back_populates="agent", lazy="noload"
    )

    __table_args__ = (
        Index("idx_agent_tenant_hostname", "tenant_id", "hostname"),
    )

    def __repr__(self) -> str:
        return f"<Agent id={self.id} hostname={self.hostname} status={self.status}>"
