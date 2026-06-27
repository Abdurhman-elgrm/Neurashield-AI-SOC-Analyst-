from __future__ import annotations

import enum
from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Enum, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, SoftDeleteMixin, TimestampMixin


class FeedType(str, enum.Enum):
    STIX_TAXII = "stix_taxii"
    CSV = "csv"
    OPENCTI = "opencti"
    MISP = "misp"
    MANUAL = "manual"


class FeedStatus(str, enum.Enum):
    ACTIVE = "active"
    ERROR = "error"
    SYNCING = "syncing"


class IOCType(str, enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"
    EMAIL = "email"


class ThreatFeed(Base, TimestampMixin, SoftDeleteMixin):
    """
    User-managed threat intelligence feed.  One row per configured feed source.
    api_key_encrypted stores the feed API key encrypted at rest (via app-level AES).
    """

    __tablename__ = "threat_feeds"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[FeedType] = mapped_column(
        Enum(
            FeedType, name="threat_feed_type_enum", values_callable=lambda x: [e.value for e in x]
        ),
        nullable=False,
    )
    endpoint_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    api_key_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ioc_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[FeedStatus] = mapped_column(
        Enum(
            FeedStatus,
            name="threat_feed_status_enum",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
        default=FeedStatus.ACTIVE,
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    sync_interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=1440)

    iocs: Mapped[list[ThreatIOC]] = relationship("ThreatIOC", back_populates="feed", lazy="noload")

    __table_args__ = (Index("idx_threat_feed_tenant", "tenant_id"),)


class ThreatIOC(Base, TimestampMixin):
    """
    Individual indicator of compromise belonging to a threat feed.
    hit_count is incremented each time this IOC matches an event or alert.
    """

    __tablename__ = "threat_iocs"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    feed_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_feeds.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    indicator: Mapped[str] = mapped_column(String(2048), nullable=False)
    type: Mapped[IOCType] = mapped_column(
        Enum(IOCType, name="threat_ioc_type_enum", values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        index=True,
    )
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tags: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    feed: Mapped[ThreatFeed] = relationship("ThreatFeed", back_populates="iocs", lazy="noload")

    __table_args__ = (
        Index("idx_threat_ioc_tenant_type", "tenant_id", "type"),
        Index("idx_threat_ioc_tenant_indicator", "tenant_id", "indicator"),
        Index("idx_threat_ioc_feed", "feed_id"),
    )
