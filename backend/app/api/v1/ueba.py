from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse

router = APIRouter(prefix="/ueba", tags=["ueba"])


# ─── Response schemas ─────────────────────────────────────────────────────────


class RiskyUser(BaseModel):
    user_id: str
    username: str
    email: str | None
    department: str | None
    ueba_score: float
    top_flags: list[str]
    last_anomaly_at: str | None
    alert_count: int


class UEBARiskPoint(BaseModel):
    date: str
    score: float


class UEBAFlagCount(BaseModel):
    flag: str
    count: int


class ImpossibleTravelEntry(BaseModel):
    username: str
    location_1: str
    location_2: str
    time_delta_minutes: float
    detected_at: str


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.get("/top-users", response_model=APIResponse[list[RiskyUser]])
async def get_top_risky_users(
    member: Annotated[object, require_permission(Permission.UEBA_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = Query(default=20, ge=1, le=100),
) -> APIResponse[list[RiskyUser]]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    rows = (
        await db.execute(
            text("""
            SELECT
                username,
                MAX(anomaly_score)                                          AS ueba_score,
                COUNT(*) FILTER (WHERE is_anomaly)                         AS anomaly_count,
                MAX(event_timestamp) FILTER (WHERE is_anomaly)             AS last_anomaly_at
            FROM events
            WHERE tenant_id   = CAST(:tid AS uuid)
              AND username     IS NOT NULL
              AND username     <> ''
              AND event_timestamp > NOW() - INTERVAL '30 days'
            GROUP BY username
            HAVING MAX(anomaly_score) > 0
            ORDER BY MAX(anomaly_score) DESC
            LIMIT :lim
        """),
            {"tid": str(m.tenant_id), "lim": limit},
        )
    ).all()

    # Fetch top UEBA flags for each user in a single query
    usernames = [r.username for r in rows]
    flag_map: dict[str, list[str]] = {u: [] for u in usernames}
    alert_map: dict[str, int] = dict.fromkeys(usernames, 0)

    if usernames:
        placeholders = ", ".join(f":u{i}" for i in range(len(usernames)))
        params: dict = {"tid": str(m.tenant_id)}
        params.update({f"u{i}": u for i, u in enumerate(usernames)})

        flag_rows = (
            await db.execute(
                text(f"""
                SELECT username, flag, COUNT(*) AS cnt
                FROM events
                CROSS JOIN LATERAL jsonb_array_elements_text(ueba_flags) AS flag
                WHERE tenant_id = CAST(:tid AS uuid)
                  AND username IN ({placeholders})
                  AND event_timestamp > NOW() - INTERVAL '30 days'
                GROUP BY username, flag
                ORDER BY username, cnt DESC
            """),
                params,
            )
        ).all()
        for fr in flag_rows:
            if len(flag_map.get(fr.username, [])) < 5:
                flag_map.setdefault(fr.username, []).append(fr.flag)

        # Alert counts per username via source_host cross-reference
        alert_rows = (
            await db.execute(
                text(f"""
                SELECT e.username, COUNT(DISTINCT a.id) AS alert_count
                FROM events e
                JOIN alerts a ON a.source_host = e.host_name
                             AND a.tenant_id = e.tenant_id
                             AND a.status = 'open'
                             AND a.deleted_at IS NULL
                WHERE e.tenant_id = CAST(:tid AS uuid)
                  AND e.username IN ({placeholders})
                  AND e.event_timestamp > NOW() - INTERVAL '30 days'
                GROUP BY e.username
            """),
                params,
            )
        ).all()
        for ar in alert_rows:
            alert_map[ar.username] = int(ar.alert_count)

    users = [
        RiskyUser(
            user_id=r.username,
            username=r.username,
            email=None,
            department=None,
            ueba_score=round(float(r.ueba_score), 3),
            top_flags=flag_map.get(r.username, []),
            last_anomaly_at=r.last_anomaly_at.isoformat() if r.last_anomaly_at else None,
            alert_count=alert_map.get(r.username, 0),
        )
        for r in rows
    ]
    return APIResponse.ok(users)


@router.get("/user-timeline", response_model=APIResponse[list[UEBARiskPoint]])
async def get_user_timeline(
    member: Annotated[object, require_permission(Permission.UEBA_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    user_id: str = Query(...),
    timeRange: str = Query(default="30d"),
) -> APIResponse[list[UEBARiskPoint]]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    days = 30
    if timeRange.endswith("d"):
        try:
            days = int(timeRange[:-1])
        except ValueError:
            pass

    rows = (
        await db.execute(
            text("""
            SELECT
                DATE(event_timestamp AT TIME ZONE 'UTC') AS day,
                AVG(anomaly_score)                        AS avg_score
            FROM events
            WHERE tenant_id       = CAST(:tid AS uuid)
              AND username         = :username
              AND event_timestamp  > NOW() - CAST(:days || ' days' AS INTERVAL)
            GROUP BY day
            ORDER BY day
        """),
            {"tid": str(m.tenant_id), "username": user_id, "days": days},
        )
    ).all()

    return APIResponse.ok(
        [UEBARiskPoint(date=str(r.day), score=round(float(r.avg_score), 3)) for r in rows]
    )


@router.get("/flag-distribution", response_model=APIResponse[list[UEBAFlagCount]])
async def get_flag_distribution(
    member: Annotated[object, require_permission(Permission.UEBA_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[list[UEBAFlagCount]]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    rows = (
        await db.execute(
            text("""
            SELECT flag, COUNT(*) AS cnt
            FROM events
            CROSS JOIN LATERAL jsonb_array_elements_text(ueba_flags) AS flag
            WHERE tenant_id       = CAST(:tid AS uuid)
              AND event_timestamp  > NOW() - INTERVAL '30 days'
              AND jsonb_array_length(ueba_flags) > 0
            GROUP BY flag
            ORDER BY cnt DESC
            LIMIT 20
        """),
            {"tid": str(m.tenant_id)},
        )
    ).all()

    return APIResponse.ok([UEBAFlagCount(flag=r.flag, count=int(r.cnt)) for r in rows])


@router.get("/impossible-travel", response_model=APIResponse[list[ImpossibleTravelEntry]])
async def get_impossible_travel(
    member: Annotated[object, require_permission(Permission.UEBA_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[list[ImpossibleTravelEntry]]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    # First pass: events explicitly flagged as impossible_travel by the UEBA pipeline
    flagged = (
        await db.execute(
            text("""
            SELECT
                username,
                event_timestamp,
                geo_city,
                geo_country,
                geo_latitude,
                geo_longitude
            FROM events
            WHERE tenant_id       = CAST(:tid AS uuid)
              AND ueba_flags       @> '["impossible_travel"]'::jsonb
              AND username         IS NOT NULL
              AND event_timestamp  > NOW() - INTERVAL '7 days'
            ORDER BY username, event_timestamp DESC
            LIMIT 200
        """),
            {"tid": str(m.tenant_id)},
        )
    ).all()

    # Group flagged events into pairs for display
    from collections import defaultdict

    by_user: dict[str, list] = defaultdict(list)
    for r in flagged:
        by_user[r.username].append(r)

    entries: list[ImpossibleTravelEntry] = []
    for username, events in by_user.items():
        # Consecutive pairs
        for i in range(len(events) - 1):
            e1, e2 = events[i + 1], events[i]  # older first, newer second
            loc1 = f"{e1.geo_city or 'Unknown'}, {e1.geo_country or ''}"
            loc2 = f"{e2.geo_city or 'Unknown'}, {e2.geo_country or ''}"
            if loc1 == loc2:
                continue
            delta_min = (e2.event_timestamp - e1.event_timestamp).total_seconds() / 60
            entries.append(
                ImpossibleTravelEntry(
                    username=username,
                    location_1=loc1.strip(", "),
                    location_2=loc2.strip(", "),
                    time_delta_minutes=round(abs(delta_min), 1),
                    detected_at=e2.event_timestamp.isoformat(),
                )
            )
        if len(entries) >= 50:
            break

    return APIResponse.ok(entries[:50])
