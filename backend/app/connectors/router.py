"""
Connector ingestion router — POST /connectors/{source}/ingest

Accepts payloads from external security tools and routes them through
the parser registry into the raw_events pipeline.

Authentication: X-API-Key header (same API keys used by the dashboard).

Supported sources: wazuh | suricata | defender | syslog | generic | webhook

Example (Wazuh webhook):
  POST /api/v1/connectors/wazuh/ingest
  X-API-Key: ns_xxx...
  Content-Type: application/json
  {"id": "...", "rule": {...}, "agent": {...}}
"""
from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.registry import SUPPORTED_SOURCES, parser_registry
from app.connectors.service import ConnectorService
from app.core.database import get_db
from app.core.exceptions import UnauthorizedError
from app.core.redis import TenantRedisClient, get_redis
from app.pipeline import stream_names
from app.schemas.common import APIResponse

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/connectors", tags=["connectors"])


@router.get("", response_model=APIResponse[dict[str, Any]])
async def list_connectors() -> APIResponse[dict[str, Any]]:
    """List available connector sources and their expected payload formats."""
    return APIResponse.ok({
        "sources": SUPPORTED_SOURCES,
        "endpoint": "POST /api/v1/connectors/{source}/ingest",
        "auth": "X-API-Key: <your-api-key>",
        "formats": {
            "wazuh":    "Wazuh JSON alert object or array of alerts",
            "suricata": "Suricata EVE JSON object, array, or NDJSON string",
            "defender": "Microsoft Defender ATP alert object or {value: [...]}",
            "syslog":   "RFC 3164/5424 text, JSON {message: ...}, or array",
            "generic":  "Any JSON object or array — fields mapped best-effort",
            "webhook":  "Alias for generic",
        },
    })


@router.post("/{source}/ingest", response_model=APIResponse[dict[str, Any]])
async def connector_ingest(
    source: str,
    request: Request,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    db: Annotated[AsyncSession, Depends(get_db)] = None,  # type: ignore[assignment]
    redis: Annotated[Any, Depends(get_redis)] = None,
) -> APIResponse[dict[str, Any]]:

    # ── 1. Resolve API key → tenant_id ────────────────────────────────────────
    try:
        tenant_id: UUID = await ConnectorService.resolve_tenant(db, x_api_key or "")
    except UnauthorizedError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))
    finally:
        await db.commit()

    # ── 2. Validate source ────────────────────────────────────────────────────
    parser = parser_registry(source)
    if parser is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unsupported source '{source}'. Supported: {SUPPORTED_SOURCES}",
        )

    # ── 3. Read body (JSON or plain text) ─────────────────────────────────────
    content_type = request.headers.get("content-type", "")
    if "json" in content_type:
        try:
            payload: Any = await request.json()
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid JSON body",
            )
    else:
        raw_body = await request.body()
        payload = raw_body.decode(errors="replace")

    # ── 4. Parse ──────────────────────────────────────────────────────────────
    parsed_events = parser.parse(payload)
    if not parsed_events:
        return APIResponse.ok({"accepted": 0, "rejected": 0, "source_type": source})

    # ── 5. Queue to raw_events stream ─────────────────────────────────────────
    from redis.asyncio import Redis
    redis_typed: Redis[str] = redis  # type: ignore[assignment]
    tenant_client = TenantRedisClient(redis_typed, str(tenant_id), stream_names.SUBSYSTEM)

    result = await ConnectorService.ingest(
        tenant_id=tenant_id,
        parsed_events=parsed_events,
        redis_client=tenant_client,
        source_type=source,
    )

    return APIResponse.ok(result)
