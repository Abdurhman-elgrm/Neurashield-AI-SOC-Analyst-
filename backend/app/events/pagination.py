from __future__ import annotations

"""
Cursor-based pagination utilities for the Events Explorer.

Cursor format: base64url(timestamp_iso|event_id|sort_field|sort_dir)
The extra fields allow sort-stable pagination on non-timestamp sorts.
"""

import base64
from datetime import datetime
from uuid import UUID


class CursorError(ValueError):
    pass


def encode_cursor(ts: datetime, event_id: UUID, sort_field: str, sort_dir: str) -> str:
    raw = f"{ts.isoformat()}|{event_id}|{sort_field}|{sort_dir}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def decode_cursor(cursor: str) -> tuple[datetime, UUID, str, str]:
    """Returns (timestamp, event_id, sort_field, sort_dir)."""
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        parts = raw.split("|")
        if len(parts) != 4:
            raise CursorError("Malformed cursor")
        ts = datetime.fromisoformat(parts[0])
        event_id = UUID(parts[1])
        sort_field = parts[2]
        sort_dir = parts[3]
        return ts, event_id, sort_field, sort_dir
    except (ValueError, TypeError) as exc:
        raise CursorError(f"Invalid cursor: {exc}") from exc


def encode_simple_cursor(ts: datetime, event_id: UUID) -> str:
    """Compact cursor for APIs that always sort by event_timestamp DESC."""
    raw = f"{ts.isoformat()}|{event_id}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def decode_simple_cursor(cursor: str) -> tuple[datetime, UUID]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        ts_str, _, id_str = raw.partition("|")
        return datetime.fromisoformat(ts_str), UUID(id_str)
    except (ValueError, TypeError) as exc:
        raise CursorError(f"Invalid cursor: {exc}") from exc
