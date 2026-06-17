"""
Base types for the external connector / parser registry.

Every connector parser transforms a vendor-specific payload into a list of
ParsedEvent objects.  The ConnectorService then serialises each ParsedEvent
into the standard raw_events Redis stream format so the existing normalisation
pipeline can process it without modification.
"""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class ParsedEvent:
    """Vendor-agnostic event produced by a ConnectorParser."""

    event_id: str
    timestamp: datetime
    category: str       # process | network | file | auth | registry | dns | other
    hostname: str
    os_type: str        # windows | linux | other
    severity: int = 1   # 1-4

    source_type: str = "unknown"   # wazuh | suricata | defender | syslog | generic

    process: dict[str, Any] | None = None
    user: dict[str, Any] | None = None
    network: dict[str, Any] | None = None
    file: dict[str, Any] | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_stream_message(self, tenant_id: str) -> dict[str, Any]:
        """Produce the dict written to the raw_events Redis stream."""
        return {
            "agent_id": "",          # no agent for connector events
            "tenant_id": tenant_id,
            "hostname": self.hostname,
            "os_type": self.os_type,
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "category": self.category,
            "severity": self.severity,
            "process": self.process,
            "user": self.user,
            "network": self.network,
            "file": self.file,
            "registry": None,
            "raw": {**self.raw, "source_type": self.source_type},
        }


class ConnectorParser(ABC):
    """Abstract base class for all connector parsers."""

    source_type: str = "unknown"

    @abstractmethod
    def parse(self, payload: Any) -> list[ParsedEvent]:
        """
        Transform a vendor-specific payload into ParsedEvent objects.
        Must never raise — return an empty list on unrecognised input.
        """

    @staticmethod
    def _make_event_id(prefix: str, data: Any = None) -> str:
        """Deterministic event ID: prefix + UUID based on str(data) or random."""
        if data is not None:
            return f"{prefix}_{uuid.uuid5(uuid.NAMESPACE_DNS, str(data))}"
        return f"{prefix}_{uuid.uuid4()}"

    @staticmethod
    def _now() -> datetime:
        return datetime.now(tz=timezone.utc)
