from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    rule_id: UUID | None
    triggering_event_id: UUID | None
    status: str
    severity: str
    title: str
    description: str | None
    source_host: str | None
    assignee_id: UUID | None
    acknowledged_at: datetime | None
    closed_at: datetime | None
    notes: str | None
    evidence: dict[str, Any]
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    created_at: datetime
    updated_at: datetime


class AlertUpdateRequest(BaseModel):
    status: str | None = Field(default=None, description="open|acknowledged|closed|false_positive")
    notes: str | None = None
    assignee_id: UUID | None = None


class AlertFilterParams(BaseModel):
    status: str | None = None
    severity: str | None = None
    source_host: str | None = None
    rule_id: UUID | None = None
    assignee_id: UUID | None = None
    from_ts: datetime | None = None
    to_ts: datetime | None = None
    cursor: str | None = None
    limit: int = 50
