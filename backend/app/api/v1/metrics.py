"""
SOC metrics API — real SQL over alerts + investigations.

SLA targets (minutes):
  critical : respond 15  / resolve 120
  high     : respond 60  / resolve 240
  medium   : respond 240 / resolve 480
  low      : respond 1440/ resolve 4320
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, and_, case, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models.alert import Alert
from app.models.investigation import Investigation
from app.models.user import User
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse

router = APIRouter(prefix="/metrics", tags=["metrics"])

# ─── SLA targets (minutes) ───────────────────────────────────────────────────

SLA_RESOLVE: dict[str, int] = {
    "critical": 120,
    "high":     240,
    "medium":   480,
    "low":      4320,
}
SLA_RESPOND: dict[str, int] = {
    "critical": 15,
    "high":     60,
    "medium":   240,
    "low":      1440,
}

# ─── Helpers ─────────────────────────────────────────────────────────────────

def _parse_range(time_range: str) -> datetime:
    """Return UTC datetime for the start of the requested period."""
    now = datetime.now(tz=timezone.utc)
    mapping = {
        "7d":  timedelta(days=7),
        "30d": timedelta(days=30),
        "90d": timedelta(days=90),
        "24h": timedelta(hours=24),
        "7days":  timedelta(days=7),
        "30days": timedelta(days=30),
    }
    delta = mapping.get(time_range, timedelta(days=30))
    return now - delta


def _elapsed_minutes(created: datetime, ended: datetime | None) -> float:
    """Minutes between created and ended (or now if open)."""
    end = ended or datetime.now(tz=timezone.utc)
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    return max(0.0, (end - created).total_seconds() / 60.0)


def _is_terminal(status: str) -> bool:
    return status in ("closed", "false_positive", "resolved")


# ─── /metrics/sla-summary ────────────────────────────────────────────────────

@router.get("/sla-summary", response_model=APIResponse[dict])
async def get_sla_summary(
    member: Annotated[object, require_permission(Permission.ALERTS_READ)],
    db: AsyncSession = Depends(get_db),
    timeRange: str = Query(default="30d"),
):
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    since = _parse_range(timeRange)

    result = await db.execute(
        select(Alert).where(
            Alert.tenant_id == m.tenant_id,
            Alert.created_at >= since,
        )
    )
    alerts = result.scalars().all()

    if not alerts:
        return APIResponse.ok({
            "compliance_pct": 0.0, "compliance_delta": 0.0,
            "total_breaches": 0, "breach_delta": 0,
            "avg_response_minutes": 0, "avg_resolve_minutes": 0,
            "within_sla": 0, "total": 0,
        })

    # Prior period for delta
    prior_since = since - (datetime.now(tz=timezone.utc) - since)
    prior_result = await db.execute(
        select(Alert).where(
            Alert.tenant_id == m.tenant_id,
            Alert.created_at >= prior_since,
            Alert.created_at < since,
        )
    )
    prior_alerts = prior_result.scalars().all()

    def _compute(alts: list[Alert]):
        total = len(alts)
        within_sla = 0
        breaches = 0
        resolve_times: list[float] = []
        respond_times: list[float] = []

        for a in alts:
            target_resolve = SLA_RESOLVE.get(a.severity.value if hasattr(a.severity, "value") else str(a.severity), 480)
            target_respond = SLA_RESPOND.get(a.severity.value if hasattr(a.severity, "value") else str(a.severity), 240)
            elapsed = _elapsed_minutes(a.created_at, a.updated_at if _is_terminal(a.status.value if hasattr(a.status, "value") else str(a.status)) else None)

            respond_times.append(min(elapsed, target_respond))  # capped at target for open
            if _is_terminal(a.status.value if hasattr(a.status, "value") else str(a.status)):
                resolve_times.append(elapsed)
                if elapsed <= target_resolve:
                    within_sla += 1
                else:
                    breaches += 1
            else:
                # Open alert: check if already over SLA
                if elapsed > target_resolve:
                    breaches += 1

        compliance = (within_sla / max(1, total)) * 100
        return {
            "total": total, "within_sla": within_sla,
            "breaches": breaches, "compliance": compliance,
            "avg_resolve": (sum(resolve_times) / len(resolve_times)) if resolve_times else 0,
            "avg_respond": (sum(respond_times) / len(respond_times)) if respond_times else 0,
        }

    curr  = _compute(alerts)
    prior = _compute(prior_alerts)

    return APIResponse.ok({
        "compliance_pct":        round(curr["compliance"], 1),
        "compliance_delta":      round(curr["compliance"] - prior["compliance"], 1),
        "total_breaches":        curr["breaches"],
        "breach_delta":          curr["breaches"] - prior["breaches"],
        "avg_response_minutes":  round(curr["avg_respond"]),
        "avg_resolve_minutes":   round(curr["avg_resolve"]),
        "within_sla":            curr["within_sla"],
        "total":                 curr["total"],
    })


# ─── /metrics/sla-by-severity ────────────────────────────────────────────────

@router.get("/sla-by-severity", response_model=APIResponse[list])
async def get_sla_by_severity(
    member: Annotated[object, require_permission(Permission.ALERTS_READ)],
    db: AsyncSession = Depends(get_db),
    timeRange: str = Query(default="30d"),
):
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    since = _parse_range(timeRange)

    result = await db.execute(
        select(Alert).where(
            Alert.tenant_id == m.tenant_id,
            Alert.created_at >= since,
        )
    )
    alerts = result.scalars().all()

    rows: dict[str, dict] = {}
    for sev in ["critical", "high", "medium", "low"]:
        rows[sev] = {
            "severity":        sev,
            "target_minutes":  SLA_RESOLVE[sev],
            "total_alerts":    0,
            "breached":        0,
            "elapsed_sum":     0.0,
        }

    for a in alerts:
        sev = (a.severity.value if hasattr(a.severity, "value") else str(a.severity)).lower()
        if sev not in rows:
            continue
        rows[sev]["total_alerts"] += 1
        target = SLA_RESOLVE[sev]
        status_str = a.status.value if hasattr(a.status, "value") else str(a.status)
        elapsed = _elapsed_minutes(a.created_at, a.updated_at if _is_terminal(status_str) else None)
        rows[sev]["elapsed_sum"] += elapsed
        if elapsed > target:
            rows[sev]["breached"] += 1

    out = []
    for sev in ["critical", "high", "medium", "low"]:
        r = rows[sev]
        total = r["total_alerts"]
        breached = r["breached"]
        within = total - breached
        avg = (r["elapsed_sum"] / total) if total else 0
        compliance = (within / max(1, total)) * 100
        out.append({
            "severity":       sev,
            "target_minutes": r["target_minutes"],
            "avg_minutes":    round(avg),
            "compliance_pct": round(compliance, 1),
            "total_alerts":   total,
            "breached":       breached,
        })
    return APIResponse.ok(out)


# ─── /metrics/sla-breaches ───────────────────────────────────────────────────

@router.get("/sla-breaches", response_model=APIResponse[dict])
async def get_sla_breaches(
    member: Annotated[object, require_permission(Permission.ALERTS_READ)],
    db: AsyncSession = Depends(get_db),
    timeRange: str = Query(default="30d"),
    page: int = Query(default=1, ge=1),
):
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    since = _parse_range(timeRange)
    page_size = 20

    result = await db.execute(
        select(Alert).where(
            Alert.tenant_id == m.tenant_id,
            Alert.created_at >= since,
        ).order_by(Alert.created_at.desc())
    )
    alerts = result.scalars().all()

    items = []
    for a in alerts:
        sev = (a.severity.value if hasattr(a.severity, "value") else str(a.severity)).lower()
        status_str = a.status.value if hasattr(a.status, "value") else str(a.status)
        target = SLA_RESOLVE.get(sev, 480)
        elapsed = _elapsed_minutes(a.created_at, a.updated_at if _is_terminal(status_str) else None)
        if elapsed > target:
            items.append({
                "alert_id":        str(a.id),
                "title":           a.title or "Untitled",
                "severity":        sev,
                "created_at":      a.created_at.isoformat(),
                "resolved_at":     a.updated_at.isoformat() if _is_terminal(status_str) else None,
                "assigned_to":     None,
                "elapsed_minutes": round(elapsed),
                "target_minutes":  target,
                "breach_type":     "resolution" if _is_terminal(status_str) else "response",
            })

    total = len(items)
    offset = (page - 1) * page_size
    return APIResponse.ok({
        "items": items[offset: offset + page_size],
        "total": total,
        "page":  page,
    })


# ─── /metrics/sla-breach-rate ────────────────────────────────────────────────

@router.get("/sla-breach-rate", response_model=APIResponse[list])
async def get_sla_breach_rate(
    member: Annotated[object, require_permission(Permission.ALERTS_READ)],
    db: AsyncSession = Depends(get_db),
    timeRange: str = Query(default="30d"),
):
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    since = _parse_range(timeRange)

    result = await db.execute(
        select(Alert).where(
            Alert.tenant_id == m.tenant_id,
            Alert.created_at >= since,
        ).order_by(Alert.created_at)
    )
    alerts = result.scalars().all()

    # Group by date
    by_date: dict[str, dict] = {}
    for a in alerts:
        date_key = a.created_at.strftime("%Y-%m-%d")
        if date_key not in by_date:
            by_date[date_key] = {"total": 0, "warn": 0, "crit": 0}
        by_date[date_key]["total"] += 1
        sev = (a.severity.value if hasattr(a.severity, "value") else str(a.severity)).lower()
        status_str = a.status.value if hasattr(a.status, "value") else str(a.status)
        elapsed = _elapsed_minutes(a.created_at, a.updated_at if _is_terminal(status_str) else None)
        warn_target = SLA_RESOLVE.get(sev, 480)
        crit_target = SLA_RESOLVE.get("critical", 120)
        if elapsed > warn_target:
            by_date[date_key]["warn"] += 1
        if elapsed > crit_target:
            by_date[date_key]["crit"] += 1

    out = []
    for date, d in sorted(by_date.items()):
        total = max(1, d["total"])
        out.append({
            "date":             date,
            "warn_breach_pct":  round((d["warn"] / total) * 100, 1),
            "crit_breach_pct":  round((d["crit"] / total) * 100, 1),
        })
    return APIResponse.ok(out)


# ─── /metrics/response-time-distribution ─────────────────────────────────────

@router.get("/response-time-distribution", response_model=APIResponse[list])
async def get_response_time_distribution(
    member: Annotated[object, require_permission(Permission.ALERTS_READ)],
    db: AsyncSession = Depends(get_db),
    timeRange: str = Query(default="30d"),
):
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    since = _parse_range(timeRange)

    result = await db.execute(
        select(Alert).where(
            Alert.tenant_id == m.tenant_id,
            Alert.created_at >= since,
        )
    )
    alerts = result.scalars().all()

    bins = [
        {"label": "<15m",   "max_minutes": 15,    "critical": 0, "high": 0, "medium": 0, "low": 0},
        {"label": "15-30m", "max_minutes": 30,    "critical": 0, "high": 0, "medium": 0, "low": 0},
        {"label": "30-60m", "max_minutes": 60,    "critical": 0, "high": 0, "medium": 0, "low": 0},
        {"label": "1-2h",   "max_minutes": 120,   "critical": 0, "high": 0, "medium": 0, "low": 0},
        {"label": "2-4h",   "max_minutes": 240,   "critical": 0, "high": 0, "medium": 0, "low": 0},
        {"label": "4-8h",   "max_minutes": 480,   "critical": 0, "high": 0, "medium": 0, "low": 0},
        {"label": ">8h",    "max_minutes": 99999, "critical": 0, "high": 0, "medium": 0, "low": 0},
    ]
    prev_max = 0
    for b in bins:
        b["_min"] = prev_max
        prev_max = b["max_minutes"]

    for a in alerts:
        sev = (a.severity.value if hasattr(a.severity, "value") else str(a.severity)).lower()
        if sev not in ("critical", "high", "medium", "low"):
            continue
        status_str = a.status.value if hasattr(a.status, "value") else str(a.status)
        elapsed = _elapsed_minutes(a.created_at, a.updated_at if _is_terminal(status_str) else None)
        for b in bins:
            if elapsed <= b["max_minutes"] and elapsed > b.get("_min", 0):
                b[sev] = b.get(sev, 0) + 1
                break

    return APIResponse.ok([{k: v for k, v in b.items() if not k.startswith("_")} for b in bins])


# ─── /metrics/analyst-sla ────────────────────────────────────────────────────

@router.get("/analyst-sla", response_model=APIResponse[list])
async def get_analyst_sla(
    member: Annotated[object, require_permission(Permission.ALERTS_READ)],
    db: AsyncSession = Depends(get_db),
    timeRange: str = Query(default="30d"),
):
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    since = _parse_range(timeRange)

    # Get investigations with assigned_to in this period
    result = await db.execute(
        select(Investigation).where(
            Investigation.tenant_id == m.tenant_id,
            Investigation.created_at >= since,
            Investigation.assigned_to.is_not(None),
        )
    )
    investigations = result.scalars().all()

    if not investigations:
        return APIResponse.ok([])

    # Collect unique analyst UUIDs
    analyst_ids = list({i.assigned_to for i in investigations if i.assigned_to})

    # Fetch user names
    user_result = await db.execute(
        select(User).where(User.id.in_(analyst_ids))
    )
    users = {u.id: u for u in user_result.scalars().all()}

    # Compute per-analyst stats
    analyst_stats: dict = {}
    for inv in investigations:
        uid = inv.assigned_to
        if uid not in analyst_stats:
            analyst_stats[uid] = {
                "user_id":        str(uid),
                "name":           users.get(uid, type("U", (), {"full_name": str(uid)[:8]})()).full_name,
                "handled":        0,
                "within_sla":     0,
                "open_breaches":  0,
                "resolve_times":  [],
                "respond_times":  [],
            }
        stats = analyst_stats[uid]
        stats["handled"] += 1

        status_str = inv.status if isinstance(inv.status, str) else inv.status.value
        elapsed = _elapsed_minutes(inv.created_at, inv.updated_at if status_str in ("resolved", "closed", "false_positive") else None)

        # Use threat_score-based SLA (high score = critical)
        sev = "critical" if inv.threat_score >= 80 else "high" if inv.threat_score >= 60 else "medium" if inv.threat_score >= 30 else "low"
        target = SLA_RESOLVE[sev]

        stats["respond_times"].append(min(elapsed, 60))  # first hour approximation
        if status_str in ("resolved", "closed", "false_positive"):
            stats["resolve_times"].append(elapsed)
            if elapsed <= target:
                stats["within_sla"] += 1
            # breach counted elsewhere
        else:
            if elapsed > target:
                stats["open_breaches"] += 1

    out = []
    for uid, s in analyst_stats.items():
        handled = s["handled"]
        within  = s["within_sla"]
        resolve_times = s["resolve_times"]
        respond_times = s["respond_times"]
        out.append({
            "user_id":               s["user_id"],
            "name":                  s["name"],
            "handled":               handled,
            "within_sla":            within,
            "compliance_pct":        round((within / max(1, handled)) * 100, 1),
            "avg_response_minutes":  round(sum(respond_times) / len(respond_times)) if respond_times else 0,
            "avg_resolve_minutes":   round(sum(resolve_times) / len(resolve_times)) if resolve_times else 0,
            "open_breaches":         s["open_breaches"],
        })

    return APIResponse.ok(sorted(out, key=lambda x: -x["compliance_pct"]))


# ─── /metrics/mttr ───────────────────────────────────────────────────────────

@router.get("/mttr", response_model=APIResponse[list])
async def get_mttr(
    member: Annotated[object, require_permission(Permission.ALERTS_READ)],
    db: AsyncSession = Depends(get_db),
    timeRange: str = Query(default="30d"),
):
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    since = _parse_range(timeRange)

    result = await db.execute(
        select(Alert).where(
            Alert.tenant_id == m.tenant_id,
            Alert.created_at >= since,
        )
    )
    alerts = result.scalars().all()

    buckets: dict[str, list[float]] = {"critical": [], "high": [], "medium": [], "low": []}
    for a in alerts:
        sev = (a.severity.value if hasattr(a.severity, "value") else str(a.severity)).lower()
        if sev not in buckets:
            continue
        status_str = a.status.value if hasattr(a.status, "value") else str(a.status)
        if _is_terminal(status_str):
            elapsed = _elapsed_minutes(a.created_at, a.updated_at)
            buckets[sev].append(elapsed)

    out = []
    for sev in ["critical", "high", "medium", "low"]:
        vals = sorted(buckets[sev])
        n = len(vals)
        mean   = sum(vals) / n if n else 0
        median = vals[n // 2] if n else 0
        out.append({
            "severity":        sev,
            "mean_minutes":    round(mean),
            "median_minutes":  round(median),
            "sample_count":    n,
        })
    return APIResponse.ok(out)


# ─── /metrics/alert-volume ───────────────────────────────────────────────────

@router.get("/alert-volume", response_model=APIResponse[list])
async def get_alert_volume(
    member: Annotated[object, require_permission(Permission.ALERTS_READ)],
    db: AsyncSession = Depends(get_db),
    timeRange: str = Query(default="30d"),
    group_by: str = Query(default="day,severity"),
):
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    since = _parse_range(timeRange)

    result = await db.execute(
        select(Alert).where(
            Alert.tenant_id == m.tenant_id,
            Alert.created_at >= since,
        ).order_by(Alert.created_at)
    )
    alerts = result.scalars().all()

    by_date: dict[str, dict] = {}
    for a in alerts:
        date_key = a.created_at.strftime("%Y-%m-%d")
        if date_key not in by_date:
            by_date[date_key] = {"date": date_key, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        sev = (a.severity.value if hasattr(a.severity, "value") else str(a.severity)).lower()
        if sev in by_date[date_key]:
            by_date[date_key][sev] += 1

    return APIResponse.ok(list(by_date.values()))


# ─── /metrics/analyst-performance ────────────────────────────────────────────

@router.get("/analyst-performance", response_model=APIResponse[list])
async def get_analyst_performance(
    member: Annotated[object, require_permission(Permission.ALERTS_READ)],
    db: AsyncSession = Depends(get_db),
    timeRange: str = Query(default="30d"),
):
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    since = _parse_range(timeRange)
    today_start = datetime.now(tz=timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    result = await db.execute(
        select(Investigation).where(
            Investigation.tenant_id == m.tenant_id,
            Investigation.created_at >= since,
        )
    )
    investigations = result.scalars().all()

    analyst_ids = list({i.assigned_to for i in investigations if i.assigned_to})
    if not analyst_ids:
        return APIResponse.ok([])

    user_result = await db.execute(select(User).where(User.id.in_(analyst_ids)))
    users = {u.id: u for u in user_result.scalars().all()}

    stats: dict = {}
    for inv in investigations:
        uid = inv.assigned_to
        if not uid:
            continue
        if uid not in stats:
            u = users.get(uid)
            stats[uid] = {
                "user_id":    str(uid),
                "name":       getattr(u, "full_name", None) or getattr(u, "email", str(uid)[:8]),
                "email":      getattr(u, "email", ""),
                "triaged_today": 0,
                "open_count": 0,
                "resolve_times": [],
            }
        s = stats[uid]
        status_str = inv.status if isinstance(inv.status, str) else inv.status.value
        if _is_terminal(status_str):
            if inv.updated_at and inv.updated_at.replace(tzinfo=timezone.utc) >= today_start:
                s["triaged_today"] += 1
            s["resolve_times"].append(_elapsed_minutes(inv.created_at, inv.updated_at))
        else:
            s["open_count"] += 1

    out = []
    for s in stats.values():
        rt = s["resolve_times"]
        out.append({
            "user_id":               s["user_id"],
            "name":                  s["name"],
            "email":                 s["email"],
            "alerts_triaged_today":  s["triaged_today"],
            "avg_resolution_minutes": round(sum(rt) / len(rt)) if rt else 0,
            "open_assignments":      s["open_count"],
        })
    return APIResponse.ok(sorted(out, key=lambda x: -x["alerts_triaged_today"]))


# ─── /metrics/verdict-distribution ───────────────────────────────────────────

@router.get("/verdict-distribution", response_model=APIResponse[dict])
async def get_verdict_distribution(
    member: Annotated[object, require_permission(Permission.ALERTS_READ)],
    db: AsyncSession = Depends(get_db),
    timeRange: str = Query(default="30d"),
):
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    since = _parse_range(timeRange)

    result = await db.execute(
        select(Investigation.verdict, Investigation.status).where(
            Investigation.tenant_id == m.tenant_id,
            Investigation.created_at >= since,
        )
    )
    rows = result.all()

    counts = {"true_positive": 0, "false_positive": 0, "benign": 0, "unknown": 0}
    for verdict, status in rows:
        verdict_str = (verdict or "").lower()
        status_str = (status if isinstance(status, str) else status.value).lower()
        if verdict_str == "true_positive" or status_str == "true_positive":
            counts["true_positive"] += 1
        elif verdict_str == "false_positive" or status_str == "false_positive":
            counts["false_positive"] += 1
        elif verdict_str == "benign":
            counts["benign"] += 1
        else:
            counts["unknown"] += 1

    return APIResponse.ok(counts)


# ─── /dashboard/geo-threats ──────────────────────────────────────────────────
# Note: this is served under /dashboard prefix but logically belongs here.
# We mount it here and alias it in the router.

@router.get("/geo-threats-data", response_model=APIResponse[list], include_in_schema=False)
async def _get_geo_threats_internal(
    member: Annotated[object, require_permission(Permission.ALERTS_READ)],
    db: AsyncSession = Depends(get_db),
    timeRange: str = Query(default="24h"),
):
    """Internal — called by /dashboard/geo-threats alias."""
    from app.models.tenant_member import TenantMember
    m: TenantMember = member  # type: ignore[assignment]
    since = _parse_range(timeRange)

    result = await db.execute(
        select(Alert.evidence, Alert.severity).where(
            Alert.tenant_id == m.tenant_id,
            Alert.created_at >= since,
            Alert.evidence.is_not(None),
        )
    )
    rows = result.all()

    # Extract country/lat/lng from evidence.network or evidence.risk_context
    country_counts: dict[str, dict] = {}
    for ev, sev in rows:
        if not ev:
            continue
        network = ev.get("network") or {}
        geo = network.get("geo") or ev.get("geo") or {}
        country = geo.get("country") or network.get("country") or ev.get("country")
        lat = geo.get("lat") or network.get("lat")
        lng = geo.get("lng") or geo.get("lon") or network.get("lng")
        if not country or lat is None or lng is None:
            continue
        sev_str = sev.value if hasattr(sev, "value") else str(sev)
        key = country
        if key not in country_counts:
            country_counts[key] = {"lat": lat, "lng": lng, "count": 0, "severity": sev_str, "country": country}
        country_counts[key]["count"] += 1
        # Escalate severity if needed
        sev_order = ["low", "medium", "high", "critical"]
        existing_idx = sev_order.index(country_counts[key]["severity"]) if country_counts[key]["severity"] in sev_order else 0
        curr_idx = sev_order.index(sev_str) if sev_str in sev_order else 0
        if curr_idx > existing_idx:
            country_counts[key]["severity"] = sev_str

    return APIResponse.ok(list(country_counts.values()))
