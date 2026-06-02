from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class DetectionRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    name: str
    description: str | None
    rule_type: str
    severity: str
    enabled: bool
    conditions: dict[str, Any] | list[Any]
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    suppression_window_secs: int
    created_by_id: UUID | None
    created_at: datetime
    updated_at: datetime


class DetectionRuleCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    rule_type: str = Field(..., pattern="^(pattern|threshold)$")
    severity: str = Field(..., pattern="^(low|medium|high|critical)$")
    conditions: dict[str, Any] | list[Any]
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    suppression_window_secs: int = Field(default=300, ge=0, le=86400)


class DetectionRuleUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    severity: str | None = Field(default=None, pattern="^(low|medium|high|critical)$")
    enabled: bool | None = None
    conditions: dict[str, Any] | list[Any] | None = None
    mitre_tactics: list[str] | None = None
    mitre_techniques: list[str] | None = None
    suppression_window_secs: int | None = Field(default=None, ge=0, le=86400)
