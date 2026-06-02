from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RawEventPayload(BaseModel):
    """
    A single raw event as submitted by an agent.
    The agent is responsible for basic timestamp formatting.
    All other normalization happens in the normalization worker.
    """

    model_config = ConfigDict(extra="allow")

    event_id: str = Field(
        ...,
        description="Agent-side unique ID (used for idempotency dedup)",
        max_length=255,
    )
    timestamp: datetime = Field(..., description="When the event occurred on the host")
    category: str = Field(..., max_length=64)
    hostname: str = Field(..., max_length=255)
    os_type: str = Field(..., max_length=32)

    # Optional structured sub-objects — agents may populate what they can
    process: dict[str, Any] | None = None
    user: dict[str, Any] | None = None
    network: dict[str, Any] | None = None
    file: dict[str, Any] | None = None
    registry: dict[str, Any] | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("category")
    @classmethod
    def validate_category(cls, v: str) -> str:
        allowed = {"process", "network", "file", "auth", "registry", "dns", "other"}
        if v.lower() not in allowed:
            return "other"
        return v.lower()


class IngestBatchRequest(BaseModel):
    """Batch ingestion payload from an agent."""

    events: list[RawEventPayload] = Field(..., min_length=1, max_length=500)


class IngestBatchResponse(BaseModel):
    accepted: int
    rejected: int
    duplicate: int
    stream_ids: list[str]


class HeartbeatRequest(BaseModel):
    """Agent heartbeat with optional OS telemetry."""

    agent_version: str | None = Field(default=None, max_length=64)
    ip_address: str | None = Field(default=None, max_length=45)
    os_metrics: dict[str, Any] = Field(default_factory=dict)


class AgentEnrollRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    hostname: str = Field(..., min_length=1, max_length=255)
    os_type: str = Field(..., max_length=32)
    agent_version: str | None = Field(default=None, max_length=64)
    ip_address: str | None = Field(default=None, max_length=45)
    tags: list[str] = Field(default_factory=list)

    @field_validator("os_type")
    @classmethod
    def validate_os_type(cls, v: str) -> str:
        allowed = {"windows", "linux", "macos"}
        v = v.lower()
        if v not in allowed:
            raise ValueError(f"os_type must be one of {allowed}")
        return v


class AgentEnrollResponse(BaseModel):
    agent_id: UUID
    enrollment_token: str
    config: dict[str, Any]
