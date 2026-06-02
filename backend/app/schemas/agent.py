from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class AgentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    name: str
    hostname: str
    os_type: str
    status: str
    agent_version: str | None
    ip_address: str | None
    last_seen_at: datetime | None
    config: dict[str, Any]
    tags: list[str]
    created_at: datetime
    updated_at: datetime


class AgentUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    config: dict[str, Any] | None = None
    tags: list[str] | None = None
