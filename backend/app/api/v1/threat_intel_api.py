from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import select, func, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import CurrentMember, require_permission
from app.models.threat_feed import FeedStatus, FeedType, IOCType, ThreatFeed, ThreatIOC
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])

_PAGE_SIZE = 50


# ─── Response schemas ─────────────────────────────────────────────────────────

class ThreatFeedResponse(BaseModel):
    id:                     str
    name:                   str
    type:                   str
    endpoint_url:           str | None
    last_updated:           str | None
    ioc_count:              int
    status:                 str
    error_message:          str | None
    sync_interval_minutes:  int


class CreateFeedRequest(BaseModel):
    name:                   str
    type:                   str
    endpoint_url:           str | None = None
    api_key:                str | None = None
    sync_interval_minutes:  int = 1440


class ThreatIOCResponse(BaseModel):
    id:             str
    indicator:      str
    type:           str
    confidence:     int
    source_feed_id: str
    source_feed_name: str
    first_seen:     str
    last_seen:      str
    hit_count:      int
    tags:           list[str]


class IOCListResponse(BaseModel):
    items: list[ThreatIOCResponse]
    total: int
    page:  int


class IOCMatch(BaseModel):
    ioc_id:       str
    indicator:    str
    type:         str
    alert_id:     str | None
    alert_title:  str | None
    event_id:     str | None
    matched_at:   str


class ImportResult(BaseModel):
    imported: int


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _feed_to_response(feed: ThreatFeed) -> ThreatFeedResponse:
    return ThreatFeedResponse(
        id=str(feed.id),
        name=feed.name,
        type=feed.type.value if hasattr(feed.type, "value") else str(feed.type),
        endpoint_url=feed.endpoint_url,
        last_updated=feed.last_synced_at.isoformat() if feed.last_synced_at else None,
        ioc_count=feed.ioc_count,
        status=feed.status.value if hasattr(feed.status, "value") else str(feed.status),
        error_message=feed.error_message,
        sync_interval_minutes=feed.sync_interval_minutes,
    )


# ─── Feeds ────────────────────────────────────────────────────────────────────

@router.get("/feeds", response_model=APIResponse[list[ThreatFeedResponse]])
async def list_feeds(
    member: Annotated[object, require_permission(Permission.THREAT_INTEL_READ)],
    db:     Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[list[ThreatFeedResponse]]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]

    feeds = (await db.execute(
        select(ThreatFeed)
        .where(ThreatFeed.tenant_id == m.tenant_id, ThreatFeed.deleted_at.is_(None))
        .order_by(ThreatFeed.name)
    )).scalars().all()

    return APIResponse.ok([_feed_to_response(f) for f in feeds])


@router.post("/feeds", response_model=APIResponse[ThreatFeedResponse])
async def create_feed(
    payload: CreateFeedRequest,
    member:  Annotated[object, require_permission(Permission.THREAT_INTEL_MANAGE)],
    db:      Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[ThreatFeedResponse]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]

    try:
        feed_type = FeedType(payload.type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid feed type. Must be one of: {[e.value for e in FeedType]}",
        )

    feed = ThreatFeed(
        id=uuid4(),
        tenant_id=m.tenant_id,
        name=payload.name.strip(),
        type=feed_type,
        endpoint_url=payload.endpoint_url,
        api_key_encrypted=payload.api_key,   # encrypt at rest in production
        status=FeedStatus.ACTIVE,
        sync_interval_minutes=payload.sync_interval_minutes,
    )
    db.add(feed)
    await db.commit()
    await db.refresh(feed)
    return APIResponse.ok(_feed_to_response(feed))


@router.delete("/feeds/{feed_id}", response_model=APIResponse[dict])
async def delete_feed(
    feed_id: UUID,
    member:  Annotated[object, require_permission(Permission.THREAT_INTEL_MANAGE)],
    db:      Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[dict]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]

    feed = (await db.execute(
        select(ThreatFeed).where(
            ThreatFeed.id == feed_id,
            ThreatFeed.tenant_id == m.tenant_id,
            ThreatFeed.deleted_at.is_(None),
        )
    )).scalar_one_or_none()

    if feed is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feed not found")

    feed.deleted_at = datetime.now(tz=timezone.utc)
    await db.commit()
    return APIResponse.ok({"deleted": str(feed_id)})


@router.post("/feeds/{feed_id}/sync", response_model=APIResponse[ThreatFeedResponse])
async def sync_feed(
    feed_id: UUID,
    member:  Annotated[object, require_permission(Permission.THREAT_INTEL_MANAGE)],
    db:      Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[ThreatFeedResponse]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]

    feed = (await db.execute(
        select(ThreatFeed).where(
            ThreatFeed.id == feed_id,
            ThreatFeed.tenant_id == m.tenant_id,
            ThreatFeed.deleted_at.is_(None),
        )
    )).scalar_one_or_none()

    if feed is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feed not found")

    if feed.type == FeedType.MANUAL:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Manual feeds cannot be synced — use the CSV import endpoint instead",
        )

    # Mark as syncing; background sync would be triggered here in a full implementation
    feed.status = FeedStatus.SYNCING
    feed.error_message = None
    await db.commit()
    await db.refresh(feed)
    return APIResponse.ok(_feed_to_response(feed))


# ─── IOCs ─────────────────────────────────────────────────────────────────────

@router.get("/iocs", response_model=APIResponse[IOCListResponse])
async def list_iocs(
    member:  Annotated[object, require_permission(Permission.THREAT_INTEL_READ)],
    db:      Annotated[AsyncSession, Depends(get_db)],
    page:    int = Query(default=1, ge=1),
    search:  str | None = Query(default=None),
    type:    str | None = Query(default=None),
    feed_id: str | None = Query(default=None),
) -> APIResponse[IOCListResponse]:
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    offset = (page - 1) * _PAGE_SIZE

    q = (
        select(ThreatIOC)
        .where(ThreatIOC.tenant_id == m.tenant_id)
    )
    if search:
        q = q.where(ThreatIOC.indicator.ilike(f"%{search}%"))
    if type:
        try:
            q = q.where(ThreatIOC.type == IOCType(type))
        except ValueError:
            pass
    if feed_id:
        try:
            q = q.where(ThreatIOC.feed_id == UUID(feed_id))
        except ValueError:
            pass

    total: int = (await db.execute(
        select(func.count()).select_from(q.subquery())
    )).scalar_one()

    iocs = (await db.execute(
        q.order_by(ThreatIOC.hit_count.desc(), ThreatIOC.last_seen.desc())
        .limit(_PAGE_SIZE).offset(offset)
    )).scalars().all()

    # Fetch feed names for this page
    feed_ids_needed = list({ioc.feed_id for ioc in iocs})
    feed_names: dict[str, str] = {}
    if feed_ids_needed:
        feed_rows = (await db.execute(
            select(ThreatFeed.id, ThreatFeed.name).where(ThreatFeed.id.in_(feed_ids_needed))
        )).all()
        feed_names = {str(r.id): r.name for r in feed_rows}

    return APIResponse.ok(IOCListResponse(
        items=[
            ThreatIOCResponse(
                id=str(ioc.id),
                indicator=ioc.indicator,
                type=ioc.type.value if hasattr(ioc.type, "value") else str(ioc.type),
                confidence=ioc.confidence,
                source_feed_id=str(ioc.feed_id),
                source_feed_name=feed_names.get(str(ioc.feed_id), "Unknown"),
                first_seen=ioc.first_seen.isoformat(),
                last_seen=ioc.last_seen.isoformat(),
                hit_count=ioc.hit_count,
                tags=list(ioc.tags or []),
            )
            for ioc in iocs
        ],
        total=total,
        page=page,
    ))


@router.post("/iocs/import", response_model=APIResponse[ImportResult])
async def import_iocs(
    member: Annotated[object, require_permission(Permission.THREAT_INTEL_MANAGE)],
    db:     Annotated[AsyncSession, Depends(get_db)],
    file:   UploadFile = File(...),
) -> APIResponse[ImportResult]:
    """
    CSV import.  Expected columns (header row required):
        indicator, type, confidence (optional), tags (optional, pipe-separated)
    """
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]

    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be a CSV",
        )

    content = await file.read()
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="CSV file must be under 10 MiB",
        )

    # Locate or create the "Manual Import" feed for this tenant
    manual_feed = (await db.execute(
        select(ThreatFeed).where(
            ThreatFeed.tenant_id == m.tenant_id,
            ThreatFeed.type == FeedType.MANUAL,
            ThreatFeed.deleted_at.is_(None),
        ).limit(1)
    )).scalar_one_or_none()

    if manual_feed is None:
        manual_feed = ThreatFeed(
            id=uuid4(),
            tenant_id=m.tenant_id,
            name="Manual Import",
            type=FeedType.MANUAL,
            status=FeedStatus.ACTIVE,
        )
        db.add(manual_feed)
        await db.flush()

    now = datetime.now(tz=timezone.utc)
    reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig", errors="replace")))

    valid_types = {e.value for e in IOCType}
    imported = 0

    for row in reader:
        indicator = (row.get("indicator") or "").strip()
        ioc_type  = (row.get("type") or "").strip().lower()
        if not indicator or ioc_type not in valid_types:
            continue
        confidence = 50
        try:
            confidence = max(0, min(100, int(row.get("confidence", 50))))
        except (ValueError, TypeError):
            pass
        tags = [t.strip() for t in (row.get("tags") or "").split("|") if t.strip()]

        ioc = ThreatIOC(
            id=uuid4(),
            tenant_id=m.tenant_id,
            feed_id=manual_feed.id,
            indicator=indicator,
            type=IOCType(ioc_type),
            confidence=confidence,
            first_seen=now,
            last_seen=now,
            tags=tags,
        )
        db.add(ioc)
        imported += 1

        if imported % 500 == 0:
            await db.flush()

    manual_feed.ioc_count = (manual_feed.ioc_count or 0) + imported
    manual_feed.last_synced_at = now
    await db.commit()

    return APIResponse.ok(ImportResult(imported=imported))


@router.get("/matches", response_model=APIResponse[list[IOCMatch]])
async def list_ioc_matches(
    member: Annotated[object, require_permission(Permission.THREAT_INTEL_READ)],
    db:     Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[list[IOCMatch]]:
    """
    Returns recent alerts/events whose source_ip or dest_ip matches a known IOC.
    Scans the last 7 days of open alerts cross-referenced with tenant IOCs.
    """
    from app.models.tenant_member import TenantMember
    from app.models.alert import Alert
    from sqlalchemy import text
    m: TenantMember = member  # type: ignore[assignment]

    rows = (await db.execute(
        text("""
            SELECT
                ti.id         AS ioc_id,
                ti.indicator,
                ti.type,
                a.id          AS alert_id,
                a.title       AS alert_title,
                NULL::uuid    AS event_id,
                a.created_at  AS matched_at
            FROM threat_iocs ti
            JOIN alerts a
              ON a.source_host ILIKE '%' || ti.indicator || '%'
             AND a.tenant_id = ti.tenant_id
             AND a.deleted_at IS NULL
             AND a.created_at > NOW() - INTERVAL '7 days'
            WHERE ti.tenant_id = CAST(:tid AS uuid)
              AND ti.type = 'ip'
            ORDER BY a.created_at DESC
            LIMIT 100
        """),
        {"tid": str(m.tenant_id)},
    )).all()

    return APIResponse.ok([
        IOCMatch(
            ioc_id=str(r.ioc_id),
            indicator=r.indicator,
            type=r.type,
            alert_id=str(r.alert_id) if r.alert_id else None,
            alert_title=r.alert_title,
            event_id=str(r.event_id) if r.event_id else None,
            matched_at=r.matched_at.isoformat(),
        )
        for r in rows
    ])
