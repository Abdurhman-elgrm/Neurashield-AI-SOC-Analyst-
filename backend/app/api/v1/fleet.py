from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models.agent import Agent, AgentStatus
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse

router = APIRouter(prefix="/fleet", tags=["fleet"])

_CURRENT_AGENT_VERSION = "1.0.0"
_STALE_THRESHOLD_HOURS = 24


# ─── Response schemas ─────────────────────────────────────────────────────────


class FleetAgent(BaseModel):
    agent_id: str
    hostname: str
    os_type: str
    os_version: str
    agent_version: str
    status: str
    last_seen: str
    ip_address: str
    lat: float | None
    lng: float | None
    country: str | None
    open_alert_count: int
    critical_alert_count: int
    risk_score: int
    tags: list[str]
    tenant_id: str
    enrolled_at: str
    update_available: bool


class FleetStats(BaseModel):
    total: int
    online: int
    offline: int
    stale: int
    online_pct: float
    critical_alerts_active: int
    agents_need_update: int


class FleetListResponse(BaseModel):
    agents: list[FleetAgent]
    stats: FleetStats
    total: int
    page: int


class VersionDistribution(BaseModel):
    version: str
    count: int


class HeartbeatDistribution(BaseModel):
    bucket: str
    label: str
    count: int


class BulkAgentRequest(BaseModel):
    agent_ids: list[str]


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _fleet_status(agent: Agent) -> str:
    if agent.status == AgentStatus.ONLINE:
        return "online"
    if agent.last_seen_at is not None:
        age = datetime.now(tz=UTC) - agent.last_seen_at
        if age < timedelta(hours=_STALE_THRESHOLD_HOURS):
            return "stale"
    return "offline"


def _risk_score(crit: int, high: int, med: int, low: int) -> int:
    return min(100, crit * 25 + high * 10 + med * 3 + low * 1)


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.get("/agents", response_model=APIResponse[FleetListResponse])
async def list_fleet_agents(
    member: Annotated[object, require_permission(Permission.FLEET_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    status: str | None = Query(default=None),
    os: str | None = Query(default=None),
    search: str | None = Query(default=None),
    tag: str | None = Query(default=None),
) -> APIResponse[FleetListResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    tenant_id = m.tenant_id
    limit = 50
    offset = (page - 1) * limit

    # ── Base agent query ──────────────────────────────────────────────────────
    q = select(Agent).where(Agent.tenant_id == tenant_id, Agent.deleted_at.is_(None))
    if os:
        q = q.where(Agent.os_type == os)
    if search:
        q = q.where(Agent.hostname.ilike(f"%{search}%"))
    if tag:
        q = q.where(Agent.tags.contains([tag]))

    total_q = select(func.count()).select_from(q.subquery())
    total: int = (await db.execute(total_q)).scalar_one()

    agents_result = await db.execute(q.order_by(Agent.hostname).limit(limit).offset(offset))
    agents = list(agents_result.scalars().all())

    # ── Alert counts per hostname (single query) ───────────────────────────────
    hostnames = [a.hostname for a in agents]
    alert_map: dict[str, dict[str, int]] = {}
    if hostnames:
        alert_q = (
            select(
                Alert.source_host,
                func.sum(case((Alert.severity == AlertSeverity.CRITICAL.value, 1), else_=0)).label(
                    "crit"
                ),
                func.sum(case((Alert.severity == AlertSeverity.HIGH.value, 1), else_=0)).label(
                    "high"
                ),
                func.sum(case((Alert.severity == AlertSeverity.MEDIUM.value, 1), else_=0)).label(
                    "med"
                ),
                func.sum(case((Alert.severity == AlertSeverity.LOW.value, 1), else_=0)).label(
                    "low"
                ),
                func.count().label("total"),
            )
            .where(
                Alert.tenant_id == tenant_id,
                Alert.status == AlertStatus.OPEN.value,
                Alert.deleted_at.is_(None),
                Alert.source_host.in_(hostnames),
            )
            .group_by(Alert.source_host)
        )
        for row in (await db.execute(alert_q)).all():
            alert_map[row.source_host] = {
                "crit": int(row.crit or 0),
                "high": int(row.high or 0),
                "med": int(row.med or 0),
                "low": int(row.low or 0),
                "total": int(row.total or 0),
            }

    # ── Fleet-wide stats ──────────────────────────────────────────────────────
    stats_q = await db.execute(
        select(
            func.count().label("total"),
            func.sum(case((Agent.status == AgentStatus.ONLINE.value, 1), else_=0)).label("online"),
        ).where(Agent.tenant_id == tenant_id, Agent.deleted_at.is_(None))
    )
    stats_row = stats_q.one()
    total_fleet: int = int(stats_row.total or 0)
    online_count: int = int(stats_row.online or 0)

    # Stale = offline but last seen < 24h
    stale_count_q = await db.execute(
        select(func.count()).where(
            Agent.tenant_id == tenant_id,
            Agent.deleted_at.is_(None),
            Agent.status == AgentStatus.OFFLINE.value,
            Agent.last_seen_at >= datetime.now(tz=UTC) - timedelta(hours=_STALE_THRESHOLD_HOURS),
        )
    )
    stale_count: int = stale_count_q.scalar_one()
    offline_count = total_fleet - online_count - stale_count

    critical_active_q = await db.execute(
        select(func.count())
        .select_from(Alert)
        .where(
            Alert.tenant_id == tenant_id,
            Alert.severity == AlertSeverity.CRITICAL.value,
            Alert.status == AlertStatus.OPEN.value,
            Alert.deleted_at.is_(None),
        )
    )
    critical_active: int = critical_active_q.scalar_one()

    needs_update = sum(1 for a in agents if (a.agent_version or "") != _CURRENT_AGENT_VERSION)

    # ── Filter by computed status if requested ────────────────────────────────
    fleet_agents = [
        FleetAgent(
            agent_id=str(a.id),
            hostname=a.hostname,
            os_type=a.os_type.value if hasattr(a.os_type, "value") else str(a.os_type),
            os_version=a.config.get("os_version", "") if isinstance(a.config, dict) else "",
            agent_version=a.agent_version or "",
            status=_fleet_status(a),
            last_seen=a.last_seen_at.isoformat() if a.last_seen_at else a.created_at.isoformat(),
            ip_address=a.ip_address or "",
            lat=None,
            lng=None,
            country=None,
            open_alert_count=alert_map.get(a.hostname, {}).get("total", 0),
            critical_alert_count=alert_map.get(a.hostname, {}).get("crit", 0),
            risk_score=_risk_score(
                alert_map.get(a.hostname, {}).get("crit", 0),
                alert_map.get(a.hostname, {}).get("high", 0),
                alert_map.get(a.hostname, {}).get("med", 0),
                alert_map.get(a.hostname, {}).get("low", 0),
            ),
            tags=list(a.tags or []),
            tenant_id=str(tenant_id),
            enrolled_at=a.created_at.isoformat(),
            update_available=(a.agent_version or "") != _CURRENT_AGENT_VERSION,
        )
        for a in agents
    ]

    if status:
        fleet_agents = [fa for fa in fleet_agents if fa.status == status]

    return APIResponse.ok(
        FleetListResponse(
            agents=fleet_agents,
            stats=FleetStats(
                total=total_fleet,
                online=online_count,
                offline=offline_count,
                stale=stale_count,
                online_pct=round(online_count / total_fleet * 100, 1) if total_fleet else 0.0,
                critical_alerts_active=critical_active,
                agents_need_update=needs_update,
            ),
            total=total,
            page=page,
        )
    )


@router.get("/stats", response_model=APIResponse[FleetStats])
async def get_fleet_stats(
    member: Annotated[object, require_permission(Permission.FLEET_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[FleetStats]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    tenant_id = m.tenant_id

    row = (
        await db.execute(
            select(
                func.count().label("total"),
                func.sum(case((Agent.status == AgentStatus.ONLINE.value, 1), else_=0)).label(
                    "online"
                ),
            ).where(Agent.tenant_id == tenant_id, Agent.deleted_at.is_(None))
        )
    ).one()
    total: int = int(row.total or 0)
    online: int = int(row.online or 0)

    stale: int = (
        await db.execute(
            select(func.count()).where(
                Agent.tenant_id == tenant_id,
                Agent.deleted_at.is_(None),
                Agent.status == AgentStatus.OFFLINE.value,
                Agent.last_seen_at
                >= datetime.now(tz=UTC) - timedelta(hours=_STALE_THRESHOLD_HOURS),
            )
        )
    ).scalar_one()

    critical_active: int = (
        await db.execute(
            select(func.count())
            .select_from(Alert)
            .where(
                Alert.tenant_id == tenant_id,
                Alert.severity == AlertSeverity.CRITICAL.value,
                Alert.status == AlertStatus.OPEN.value,
                Alert.deleted_at.is_(None),
            )
        )
    ).scalar_one()

    needs_update: int = (
        await db.execute(
            select(func.count()).where(
                Agent.tenant_id == tenant_id,
                Agent.deleted_at.is_(None),
                Agent.agent_version != _CURRENT_AGENT_VERSION,
            )
        )
    ).scalar_one()

    return APIResponse.ok(
        FleetStats(
            total=total,
            online=online,
            offline=total - online - stale,
            stale=stale,
            online_pct=round(online / total * 100, 1) if total else 0.0,
            critical_alerts_active=critical_active,
            agents_need_update=needs_update,
        )
    )


@router.get("/version-distribution", response_model=APIResponse[list[VersionDistribution]])
async def get_version_distribution(
    member: Annotated[object, require_permission(Permission.FLEET_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[list[VersionDistribution]]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    rows = (
        await db.execute(
            select(Agent.agent_version, func.count().label("count"))
            .where(
                Agent.tenant_id == m.tenant_id,
                Agent.deleted_at.is_(None),
                Agent.agent_version.isnot(None),
            )
            .group_by(Agent.agent_version)
            .order_by(func.count().desc())
        )
    ).all()

    return APIResponse.ok(
        [VersionDistribution(version=row.agent_version, count=row.count) for row in rows]
    )


@router.get("/heartbeat-distribution", response_model=APIResponse[list[HeartbeatDistribution]])
async def get_heartbeat_distribution(
    member: Annotated[object, require_permission(Permission.FLEET_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[list[HeartbeatDistribution]]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    now = datetime.now(tz=UTC)
    rows = (
        await db.execute(
            select(
                case(
                    (Agent.last_seen_at >= now - timedelta(minutes=5), "just_now"),
                    (Agent.last_seen_at >= now - timedelta(hours=1), "recent"),
                    (Agent.last_seen_at >= now - timedelta(hours=24), "stale"),
                    else_="offline",
                ).label("bucket"),
                func.count().label("count"),
            )
            .where(Agent.tenant_id == m.tenant_id, Agent.deleted_at.is_(None))
            .group_by("bucket")
        )
    ).all()

    bucket_labels = {
        "just_now": "< 5 min",
        "recent": "5 min – 1 hr",
        "stale": "1 – 24 hr",
        "offline": "> 24 hr",
    }
    bucket_order = ["just_now", "recent", "stale", "offline"]
    count_map = {r.bucket: r.count for r in rows}

    return APIResponse.ok(
        [
            HeartbeatDistribution(
                bucket=b,
                label=bucket_labels[b],
                count=count_map.get(b, 0),
            )
            for b in bucket_order
        ]
    )


@router.post("/bulk-update", response_model=APIResponse[dict])
async def bulk_update_agents(
    payload: BulkAgentRequest,
    member: Annotated[object, require_permission(Permission.FLEET_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[dict]:
    if not payload.agent_ids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No agent IDs provided")
    return APIResponse.ok({"queued": len(payload.agent_ids), "action": "update"})


@router.post("/bulk-reinstall", response_model=APIResponse[dict])
async def bulk_reinstall_agents(
    payload: BulkAgentRequest,
    member: Annotated[object, require_permission(Permission.FLEET_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[dict]:
    if not payload.agent_ids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No agent IDs provided")
    return APIResponse.ok({"queued": len(payload.agent_ids), "action": "reinstall"})
