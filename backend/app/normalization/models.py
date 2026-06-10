from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class NormalizedProcess:
    pid: int | None = None
    ppid: int | None = None
    name: str | None = None
    executable: str | None = None
    command_line: str | None = None
    user: str | None = None
    hash_md5: str | None = None
    hash_sha256: str | None = None


@dataclass
class NormalizedNetwork:
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    direction: str | None = None
    bytes_sent: int | None = None
    bytes_received: int | None = None


@dataclass
class NormalizedFile:
    path: str | None = None
    name: str | None = None
    extension: str | None = None
    size: int | None = None
    hash_md5: str | None = None
    hash_sha256: str | None = None
    action: str | None = None


@dataclass
class NormalizedUser:
    name: str | None = None
    domain: str | None = None
    id: str | None = None
    is_privileged: bool = False


@dataclass
class NormalizedEvent:
    """
    ECS-inspired normalized event.  All normalization converges to this struct.
    Fields map 1:1 to the Event model JSONB columns.
    """

    event_id: str = ""
    timestamp: datetime | None = None
    ingested_at: datetime | None = None
    category: str = "other"
    severity: int = 1
    hostname: str = ""
    os_type: str = ""
    agent_id: str = ""
    tenant_id: str = ""

    process: NormalizedProcess | None = None
    network: NormalizedNetwork | None = None
    file: NormalizedFile | None = None
    user: NormalizedUser | None = None
    registry: dict[str, Any] | None = None

    tags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        import dataclasses

        def _convert(obj: Any) -> Any:
            if isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, dict):
                return {k: _convert(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_convert(i) for i in obj]
            return obj

        return _convert(dataclasses.asdict(self))

    @property
    def source_ip(self) -> str | None:
        return self.network.src_ip if self.network else None

    @property
    def dest_ip(self) -> str | None:
        return self.network.dst_ip if self.network else None

    @property
    def process_name(self) -> str | None:
        return self.process.name if self.process else None

    @property
    def username(self) -> str | None:
        return self.user.name if self.user else None
