from __future__ import annotations

import enum
from uuid import uuid4

from sqlalchemy import Boolean, Enum, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, SoftDeleteMixin, TimestampMixin


class RuleType(str, enum.Enum):
    PATTERN = "pattern"
    THRESHOLD = "threshold"


class RuleSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionRule(Base, TimestampMixin, SoftDeleteMixin):
    """
    Tenant-scoped detection rule.

    Pattern rules: match fields on individual normalized events.
    Threshold rules: fire when a field value appears >= N times within a sliding window.

    conditions schema for PATTERN:
      [{"field": "process.name", "op": "eq|contains|regex|in|ne", "value": "..."}]

    conditions schema for THRESHOLD:
      {
        "field": "source.ip",          -- the field to count unique values of
        "group_by": "host.name",       -- optional grouping dimension
        "threshold": 5,
        "window_secs": 300,
        "filters": [...]               -- pre-conditions that must match the event
      }
    """

    __tablename__ = "detection_rules"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    rule_type: Mapped[RuleType] = mapped_column(
        Enum(RuleType, name="rule_type_enum", values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        index=True,
    )
    severity: Mapped[RuleSeverity] = mapped_column(
        Enum(
            RuleSeverity, name="rule_severity_enum", values_callable=lambda x: [e.value for e in x]
        ),
        nullable=False,
        index=True,
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    conditions: Mapped[dict] = mapped_column(JSONB, nullable=False)
    mitre_tactics: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    mitre_techniques: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    suppression_window_secs: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    created_by_id: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    updated_by_id: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    __table_args__ = (Index("idx_rule_tenant_enabled", "tenant_id", "enabled"),)

    def __repr__(self) -> str:
        return f"<DetectionRule id={self.id} name={self.name} type={self.rule_type}>"
