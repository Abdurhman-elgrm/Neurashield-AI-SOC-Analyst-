from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class EventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    agent_id: UUID | None
    stream_id: str | None
    raw_id: str | None
    category: str
    severity: int
    event_timestamp: datetime
    ingested_at: datetime | None
    host_name: str | None
    source_ip: str | None
    dest_ip: str | None
    process_name: str | None
    username: str | None
    process: dict[str, Any] | None
    user: dict[str, Any] | None
    network: dict[str, Any] | None
    file: dict[str, Any] | None
    registry: dict[str, Any] | None
    tags: list[str]
    correlation_id: str | None = None
    session_id: str | None = None
    process_tree_id: str | None = None
    event_chain_id: str | None = None
    # GeoIP enrichment (Phase 1)
    geo_country: str | None = None
    geo_country_code: str | None = None
    geo_city: str | None = None
    geo_latitude: float | None = None
    geo_longitude: float | None = None
    geo_isp: str | None = None
    # Threat Intel enrichment (Phase 1)
    abuse_confidence: int = 0
    is_threat_ip: bool = False
    threat_intel_flags: list[str] = []
    # UEBA anomaly detection (Phase 2)
    anomaly_score: float = 0.0
    is_anomaly: bool = False
    ueba_flags: list[str] = []
    # Original raw agent payload (raw_payload column → exposed as "raw" for frontend)
    raw: dict[str, Any] | None = Field(None, validation_alias="raw_payload")


class EventFilterParams(BaseModel):
    category: str | None = None
    severity_min: int | None = None
    host_name: str | None = None
    agent_id: UUID | None = None
    from_ts: datetime | None = None
    to_ts: datetime | None = None
    cursor: str | None = None
    limit: int = 50
