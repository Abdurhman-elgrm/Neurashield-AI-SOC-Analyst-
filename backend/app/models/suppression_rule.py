from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, SoftDeleteMixin


class SuppressionRule(Base, TimestampMixin, SoftDeleteMixin):
    """
    User-defined alert suppression rule.
    When an alert matches ALL non-null fields of a rule, it is suppressed.

    detection_rule_id = NULL → match any rule
    hostname_pattern  = NULL → match any host  (supports fnmatch wildcards)
    category          = NULL → match any category
    min_severity      = NULL → match any severity
    """

    __tablename__ = "suppression_rules"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    detection_rule_id: Mapped[UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    hostname_pattern: Mapped[str | None] = mapped_column(String(255), nullable=True)
    category: Mapped[str | None] = mapped_column(String(32), nullable=True)
    min_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_by_id: Mapped[UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)

    def __repr__(self) -> str:
        return f"<SuppressionRule id={self.id} name={self.name!r}>"
