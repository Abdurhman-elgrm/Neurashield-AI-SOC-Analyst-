"""
Log Import API
--------------
POST /imports/upload  — upload a log file and inject events into the pipeline

Supported formats:
  • JSON   — array of event objects at root level
  • JSONL  — one JSON object per line (newline-delimited JSON)
  • CSV    — header row + data rows; category/hostname/timestamp required columns

The endpoint converts every record to RawEventPayload and publishes to the
same Redis raw_events stream that agents use.  The full normalization →
detection → correlation → investigation pipeline runs normally afterward.

Auth: requires INVESTIGATIONS_MANAGE permission (admin+).
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import UTC, datetime
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, File, UploadFile
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.core.exceptions import ValidationError
from app.core.redis import TenantRedisClient, get_redis
from app.ingestion.idempotency import IdempotencyStore
from app.ingestion.schemas import RawEventPayload
from app.models.tenant_member import TenantMember
from app.pipeline import stream_names
from app.pipeline.publisher import StreamPublisher
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse

log = structlog.get_logger(__name__)

router = APIRouter(prefix="/imports", tags=["Log Import"])

_MAX_FILE_BYTES = 50 * 1024 * 1024  # 50 MB hard limit
_MAX_EVENTS = 100_000  # safety ceiling per upload

SUPPORTED_FORMATS = ("json", "jsonl", "ndjson", "csv")


# ─── Response schema ──────────────────────────────────────────────────────────


class ImportResult(BaseModel):
    accepted: int
    duplicate: int
    rejected: int
    total: int
    format: str
    errors: list[str]  # up to 10 sample parse errors


# ─── Parsers ─────────────────────────────────────────────────────────────────


def _detect_format(filename: str, content_type: str) -> str:
    name = filename.lower()
    if name.endswith(".jsonl") or name.endswith(".ndjson"):
        return "jsonl"
    if name.endswith(".csv"):
        return "csv"
    if name.endswith(".json"):
        return "json"
    if "csv" in content_type:
        return "csv"
    return "json"


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


def _coerce_event(raw: dict) -> dict:
    """Ensure mandatory fields exist with sane defaults."""
    raw.setdefault("event_id", str(uuid.uuid4()))
    raw.setdefault("category", raw.pop("event_type", "other"))
    raw.setdefault("hostname", raw.pop("host", raw.pop("computer", "import-host")))
    raw.setdefault("os_type", raw.pop("os", "windows"))
    raw.setdefault("raw", {})

    # Normalize timestamp key variations
    for key in ("timestamp", "time", "datetime", "@timestamp", "EventTime", "TimeCreated"):
        if key in raw and key != "timestamp":
            raw["timestamp"] = raw.pop(key)
            break
    raw.setdefault("timestamp", _now_iso())

    # Ensure timestamp is parseable; fall back to now
    ts = raw["timestamp"]
    if isinstance(ts, (int, float)):
        # unix epoch (seconds or milliseconds)
        if ts > 1e10:
            ts /= 1000.0
        raw["timestamp"] = datetime.fromtimestamp(ts, tz=UTC).isoformat()
    elif isinstance(ts, str):
        try:
            datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            raw["timestamp"] = _now_iso()

    return raw


def _parse_json(data: bytes) -> tuple[list[dict], list[str]]:
    errors: list[str] = []
    try:
        parsed = json.loads(data)
    except json.JSONDecodeError as e:
        return [], [f"JSON parse error: {e}"]

    if isinstance(parsed, dict):
        parsed = [parsed]
    if not isinstance(parsed, list):
        return [], ["Root JSON element must be an array or object"]

    events = []
    for i, item in enumerate(parsed):
        if not isinstance(item, dict):
            errors.append(f"Row {i}: expected object, got {type(item).__name__}")
            continue
        events.append(_coerce_event(item))
    return events, errors


def _parse_jsonl(data: bytes) -> tuple[list[dict], list[str]]:
    events: list[dict] = []
    errors: list[str] = []
    for lineno, line in enumerate(data.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if not isinstance(obj, dict):
                errors.append(f"Line {lineno}: expected object")
                continue
            events.append(_coerce_event(obj))
        except json.JSONDecodeError as e:
            errors.append(f"Line {lineno}: {e}")
            if len(errors) >= 20:
                break
    return events, errors


def _parse_csv(data: bytes) -> tuple[list[dict], list[str]]:
    events: list[dict] = []
    errors: list[str] = []

    # Detect encoding
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("latin-1")

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return [], ["CSV file has no header row"]

    for rownum, row in enumerate(reader, 1):
        try:
            obj = {k: v for k, v in row.items() if k and v != ""}
            events.append(_coerce_event(obj))
        except Exception as e:
            errors.append(f"Row {rownum}: {e}")
            if len(errors) >= 20:
                break
    return events, errors


# ─── Endpoint ─────────────────────────────────────────────────────────────────


@router.post(
    "/upload",
    response_model=APIResponse[ImportResult],
    summary="Upload a log file and inject events into the detection pipeline",
)
async def upload_logs(
    file: Annotated[UploadFile, File(description="Log file — JSON, JSONL, or CSV")],
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[object, Depends(get_redis)],
) -> APIResponse[ImportResult]:
    m: TenantMember = member  # type: ignore[assignment]

    # ── Size guard ────────────────────────────────────────────────────────────
    raw_bytes = await file.read(_MAX_FILE_BYTES + 1)
    if len(raw_bytes) > _MAX_FILE_BYTES:
        raise ValidationError(
            f"File too large. Maximum allowed size is {_MAX_FILE_BYTES // (1024 * 1024)} MB."
        )
    if not raw_bytes:
        raise ValidationError("Uploaded file is empty.")

    # ── Detect format and parse ───────────────────────────────────────────────
    filename = file.filename or "upload"
    content_type = file.content_type or ""
    fmt = _detect_format(filename, content_type)

    if fmt == "jsonl":
        raw_events, parse_errors = _parse_jsonl(raw_bytes)
    elif fmt == "csv":
        raw_events, parse_errors = _parse_csv(raw_bytes)
    else:
        raw_events, parse_errors = _parse_json(raw_bytes)

    if not raw_events and parse_errors:
        raise ValidationError(
            f"Could not parse file as {fmt.upper()}. First error: {parse_errors[0]}"
        )

    if len(raw_events) > _MAX_EVENTS:
        raw_events = raw_events[:_MAX_EVENTS]
        parse_errors.append(f"Truncated to {_MAX_EVENTS:,} events (file contained more).")

    # ── Convert to RawEventPayload (validate) ─────────────────────────────────
    payloads: list[RawEventPayload] = []
    for i, ev in enumerate(raw_events):
        try:
            payloads.append(RawEventPayload.model_validate(ev))
        except Exception as e:
            if len(parse_errors) < 10:
                parse_errors.append(f"Event {i}: validation error — {e}")

    # ── Publish to pipeline ───────────────────────────────────────────────────
    from redis.asyncio import Redis

    redis_typed: Redis[str] = redis  # type: ignore[assignment]
    tenant_client = TenantRedisClient(redis_typed, str(m.tenant_id), stream_names.SUBSYSTEM)
    idempotency = IdempotencyStore(tenant_client)
    publisher = StreamPublisher(tenant_client)

    accepted = 0
    rejected = 0
    duplicates = 0

    for payload in payloads:
        if await idempotency.is_duplicate(payload.event_id):
            duplicates += 1
            continue
        try:
            message = {
                "agent_id": None,  # no physical agent — import source
                "tenant_id": str(m.tenant_id),
                "hostname": payload.hostname,
                "os_type": payload.os_type,
                "event_id": payload.event_id,
                "timestamp": payload.timestamp.isoformat()
                if isinstance(payload.timestamp, datetime)
                else str(payload.timestamp),
                "category": payload.category,
                "process": payload.process,
                "user": payload.user,
                "network": payload.network,
                "file": payload.file,
                "registry": payload.registry,
                "raw": payload.raw,
                "source": "import",
                "import_file": filename,
            }
            stream_id = await publisher.publish_raw_event(message)
            await idempotency.mark_seen(payload.event_id, stream_id)
            accepted += 1
        except Exception as exc:
            rejected += 1
            if len(parse_errors) < 10:
                parse_errors.append(f"Publish error: {exc}")

    log.info(
        "import_completed",
        tenant_id=str(m.tenant_id),
        imported_by=str(m.user_id),
        filename=filename,
        fmt=fmt,
        accepted=accepted,
        rejected=rejected,
        duplicates=duplicates,
    )

    return APIResponse.ok(
        ImportResult(
            accepted=accepted,
            duplicate=duplicates,
            rejected=rejected,
            total=len(payloads),
            format=fmt.upper(),
            errors=parse_errors[:10],
        )
    )
