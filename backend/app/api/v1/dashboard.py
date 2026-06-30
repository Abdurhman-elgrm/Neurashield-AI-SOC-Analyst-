"""
Dashboard API — real-time security operations metrics.

All endpoints are scoped to the calling member's tenant and accept a
`time_range` query parameter to control the look-back window.

Endpoints:
  GET /dashboard/summary             — KPI cards (alerts, investigations, ingestion, agents)
  GET /dashboard/ingestion-rate      — event/sec time-series
  GET /dashboard/detection-health    — rule health + top firing rules
  GET /dashboard/mitre-coverage      — MITRE ATT&CK heatmap data from real alerts
  GET /dashboard/correlation-activity — active investigations + recent correlations
  GET /dashboard/ai-operations       — AI analysis queue + verdict statistics
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.core.redis import get_redis_optional
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse

from redis.asyncio import Redis

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

# ─── KPI cache helpers (30-second TTL) ───────────────────────────────────────
# Keys are stored under tenant:{tid}:dashboard: to match the TenantRedisClient
# namespace convention, providing consistent tenant isolation across all Redis usage.

_KPI_TTL = 30
_KPI_SUBSYSTEM = "dashboard"


def _kpi_key(tenant_id: str, slug: str, time_range: str) -> str:
    tr_hash = hashlib.md5(time_range.encode()).hexdigest()[:8]
    return f"tenant:{tenant_id}:{_KPI_SUBSYSTEM}:kpi:{slug}:{tr_hash}"


async def _kpi_get(redis: Redis | None, key: str) -> str | None:
    if redis is None:
        return None
    try:
        return await redis.get(key)
    except Exception:
        return None


async def _kpi_set(redis: Redis | None, key: str, value: str) -> None:
    if redis is None:
        return
    try:
        await redis.set(key, value, ex=_KPI_TTL)
    except Exception:
        pass


async def _invalidate_dashboard_cache(tenant_id: str) -> None:
    """Delete all cached dashboard KPIs for a tenant. Called on alert/event write."""
    try:
        from app.core.redis import redis_manager

        redis = redis_manager.get_client()
        # Pattern matches all dashboard KPI keys under the tenant namespace.
        pattern = f"tenant:{tenant_id}:{_KPI_SUBSYSTEM}:*"
        keys_to_delete: list[str] = []
        async for key in redis.scan_iter(match=pattern, count=100):
            keys_to_delete.append(key)
        if keys_to_delete:
            await redis.delete(*keys_to_delete)
    except Exception:
        pass


# ─── Time-range helpers ───────────────────────────────────────────────────────

DashboardTimeRange = Literal["last_15m", "last_1h", "last_6h", "last_24h", "last_7d"]

_TR_MINUTES: dict[str, int] = {
    "last_15m": 15,
    "last_1h": 60,
    "last_6h": 360,
    "last_24h": 1440,
    "last_7d": 10080,
}

# Bucket size (seconds) for ingestion-rate time-series.
# Chosen so each range produces ~15–50 data points.
_TR_BUCKET_SECS: dict[str, int] = {
    "last_15m": 60,  # 15 x 1-min buckets
    "last_1h": 120,  # 30 x 2-min buckets
    "last_6h": 600,  # 36 x 10-min buckets
    "last_24h": 1800,  # 48 x 30-min buckets
    "last_7d": 14400,  # 42 x 4-hour buckets
}

# A rule is "noisy" if it fires more than this many times per 24 h.
_NOISY_RULE_THRESHOLD = 50


def _window(time_range: str) -> tuple[datetime, datetime, int]:
    """Return (period_start, now, bucket_secs) for a time-range string."""
    now = datetime.now(tz=UTC)
    minutes = _TR_MINUTES.get(time_range, 1440)
    bucket = _TR_BUCKET_SECS.get(time_range, 1800)
    return now - timedelta(minutes=minutes), now, bucket


# ─── Response schemas (mirror frontend TypeScript interfaces exactly) ─────────


class AlertKPI(BaseModel):
    total: int = 0
    open: int = 0
    critical: int = 0
    high: int = 0
    delta24h: float = 0.0  # % change vs equal-length previous period
    criticalDelta24h: float = 0.0  # % change vs equal-length previous period


class InvestigationKPI(BaseModel):
    active: int = 0
    correlated: int = 0
    aiPending: int = 0
    delta24h: float = 0.0  # % change vs equal-length previous period


class IngestionKPI(BaseModel):
    epsNow: float = 0.0
    epsPeak: float = 0.0
    totalEvents: int = 0
    deltaPercent: float = 0.0


class AgentKPI(BaseModel):
    online: int = 0
    total: int = 0
    offline: int = 0


class DetectionKPI(BaseModel):
    rulesTriggered: int = 0
    activeRules: int = 0
    noisyRules: int = 0
    delta24h: float = 0.0  # % change vs equal-length previous period


class DashboardSummary(BaseModel):
    alerts: AlertKPI = AlertKPI()
    investigations: InvestigationKPI = InvestigationKPI()
    ingestion: IngestionKPI = IngestionKPI()
    agents: AgentKPI = AgentKPI()
    detection: DetectionKPI = DetectionKPI()
    generatedAt: str = ""


class IngestionRatePoint(BaseModel):
    timestamp: str
    eps: float
    normalizedEps: float
    alertsCreated: int


class IngestionRateSeries(BaseModel):
    points: list[IngestionRatePoint] = []
    averageEps: float = 0.0
    peakEps: float = 0.0


class DetectionRuleHealth(BaseModel):
    ruleId: str
    ruleName: str
    triggeredCount: int
    alertsCreated: int
    suppressedCount: int = 0
    lastTriggeredAt: str | None
    avgLatencyMs: float = 0.0
    status: Literal["active", "noisy", "disabled", "error"]


class DetectionHealthData(BaseModel):
    activeRules: int = 0
    disabledRules: int = 0
    noisyRules: int = 0
    errorRules: int = 0
    avgLatencyMs: float = 0.0
    ingestionToDetectionMs: float = 0.0
    topRules: list[DetectionRuleHealth] = []


class TechniqueStat(BaseModel):
    techniqueId: str
    count: int
    criticalCount: int
    highCount: int
    mediumCount: int
    latestAt: str


class MitreCoverageData(BaseModel):
    techniqueCounts: dict[str, TechniqueStat] = {}
    totalAlerts: int = 0
    coveredTechniques: int = 0
    topTechnique: str | None = None
    generatedAt: str = ""


class CorrelationEvent(BaseModel):
    id: str
    investigationId: str
    investigationTitle: str
    alertCount: int
    entityCount: int
    behaviorMatches: list[str]
    severity: str
    correlatedAt: str


class CorrelationActivityData(BaseModel):
    activeInvestigations: int = 0
    totalGroupedAlerts: int = 0
    totalEntities: int = 0
    recentCorrelations: list[CorrelationEvent] = []


class AIVerdict(BaseModel):
    verdict: str
    confidence: float
    investigationId: str
    title: str
    analyzedAt: str | None


class AIOperationsData(BaseModel):
    queueDepth: int = 0
    analyzedLast24h: int = 0
    truePositiveCount: int = 0
    falsePositiveCount: int = 0
    pendingCount: int = 0
    avgConfidence: float = 0.0
    recentVerdicts: list[AIVerdict] = []


# ─── Score → severity helper ──────────────────────────────────────────────────


def _score_to_severity(score: int) -> str:
    if score >= 76:
        return "critical"
    if score >= 51:
        return "high"
    if score >= 26:
        return "medium"
    return "low"


def _pct_delta(current: int, prev: int) -> float:
    """Return % change from prev → current, capped at ±999.9%.
    Returns 0.0 when prev is 0 (undefined percentage)."""
    if prev == 0:
        return 0.0
    raw = ((current - prev) / prev) * 100.0
    return round(max(min(raw, 999.9), -999.9), 1)


# ─── /dashboard/summary ───────────────────────────────────────────────────────


@router.get("/summary", response_model=APIResponse[DashboardSummary])
async def get_dashboard_summary(
    member: Annotated[object, require_permission(Permission.EVENTS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[Redis | None, Depends(get_redis_optional)],
    time_range: DashboardTimeRange = Query(default="last_24h"),
) -> APIResponse[DashboardSummary]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    tid = str(m.tenant_id)

    cache_key = _kpi_key(tid, "summary", time_range)
    if (cached := await _kpi_get(redis, cache_key)) is not None:
        return APIResponse[DashboardSummary].model_validate_json(cached)

    period_start, now, _ = _window(time_range)
    prev_start = period_start - (now - period_start)  # equal-length previous period

    # ── Alerts ────────────────────────────────────────────────────────────────
    # total = every non-deleted alert so it matches the Alerts page count.
    # critical/high = open+acknowledged only (actionable workload).
    # delta uses new alerts created in the period vs the previous period.
    alert_row = (
        await db.execute(
            text("""
        SELECT
            COUNT(*)                                                                                        AS total,
            COUNT(*) FILTER (WHERE status = 'open')                                                        AS open,
            COUNT(*) FILTER (WHERE severity = 'critical' AND status NOT IN ('closed','false_positive'))    AS critical,
            COUNT(*) FILTER (WHERE severity = 'high'     AND status NOT IN ('closed','false_positive'))    AS high,
            COUNT(*) FILTER (WHERE created_at >= :ps)                                                      AS new_curr,
            COUNT(*) FILTER (WHERE created_at >= :prev_ps AND created_at < :ps)                            AS new_prev,
            COUNT(*) FILTER (WHERE severity = 'critical' AND created_at >= :ps)                            AS crit_curr,
            COUNT(*) FILTER (WHERE severity = 'critical' AND created_at >= :prev_ps AND created_at < :ps)  AS crit_prev
        FROM alerts
        WHERE tenant_id = CAST(:tid AS uuid)
          AND deleted_at IS NULL
    """),
            {"tid": tid, "ps": period_start, "prev_ps": prev_start},
        )
    ).fetchone()

    alerts = AlertKPI(
        total=alert_row.total or 0,
        open=alert_row.open or 0,
        critical=alert_row.critical or 0,
        high=alert_row.high or 0,
        delta24h=_pct_delta(alert_row.new_curr or 0, alert_row.new_prev or 0),
        criticalDelta24h=_pct_delta(alert_row.crit_curr or 0, alert_row.crit_prev or 0),
    )

    # ── Investigations ────────────────────────────────────────────────────────
    inv_row = (
        await db.execute(
            text("""
        SELECT
            COUNT(*) FILTER (WHERE status NOT IN ('closed','resolved','false_positive') AND created_at >= :ps) AS active,
            COUNT(*) FILTER (WHERE confidence IN ('high','confirmed') AND created_at >= :ps)                   AS correlated,
            COUNT(*) FILTER (WHERE created_at >= :prev_ps AND created_at < :ps AND status NOT IN ('closed','resolved','false_positive')) AS prev_active
        FROM investigations
        WHERE tenant_id = CAST(:tid AS uuid)
    """),
            {"tid": tid, "ps": period_start, "prev_ps": prev_start},
        )
    ).fetchone()

    # AI Queue: alerts that have NOT yet been analysed by the AI engine.
    # The alert AI runs synchronously in the detection worker but can fail;
    # this count catches any that fell through (metadata column stores the result).
    ai_pending_row = (
        await db.execute(
            text("""
        SELECT COUNT(*) AS ai_pending
        FROM alerts
        WHERE tenant_id = CAST(:tid AS uuid)
          AND deleted_at IS NULL
          AND status = 'open'
          AND (metadata IS NULL OR metadata->'ai_analysis' IS NULL)
          AND created_at >= :ps
    """),
            {"tid": tid, "ps": period_start},
        )
    ).fetchone()

    inv_active = inv_row.active or 0
    prev_active = inv_row.prev_active or 0

    investigations = InvestigationKPI(
        active=inv_active,
        correlated=inv_row.correlated or 0,
        aiPending=ai_pending_row.ai_pending or 0,
        delta24h=_pct_delta(inv_active, prev_active),
    )

    # ── Events / ingestion ────────────────────────────────────────────────────
    # Compute total + previous-period total, plus the peak EPS across
    # fixed 5-minute buckets within the current period.
    ev_row = (
        await db.execute(
            text("""
        SELECT
            COUNT(*) FILTER (WHERE event_timestamp >= :ps)                AS total,
            COUNT(*) FILTER (WHERE event_timestamp >= :prev_ps AND event_timestamp < :ps) AS prev_total
        FROM events
        WHERE tenant_id = CAST(:tid AS uuid)
    """),
            {"tid": tid, "ps": period_start, "prev_ps": prev_start},
        )
    ).fetchone()

    # Peak EPS: max events in any single 5-minute bucket within the period.
    # Using a 300-second bucket gives a stable, comparable peak regardless of
    # the time_range chosen (unlike the ingestion-rate endpoint whose bucket
    # size varies per range).
    _PEAK_BUCKET_SECS = 300
    peak_row = (
        await db.execute(
            text("""
        SELECT COALESCE(MAX(bucket_count), 0) AS peak_count
        FROM (
            SELECT COUNT(*) AS bucket_count
            FROM events
            WHERE tenant_id = CAST(:tid AS uuid)
              AND event_timestamp >= :ps
            GROUP BY (EXTRACT(EPOCH FROM event_timestamp)::bigint / :bsecs)
        ) sub
    """),
            {"tid": tid, "ps": period_start, "bsecs": _PEAK_BUCKET_SECS},
        )
    ).fetchone()

    total_events = ev_row.total or 0
    prev_events = ev_row.prev_total or 0
    period_secs = max((now - period_start).total_seconds(), 1)
    eps_now = round(total_events / period_secs, 3)
    eps_peak = round((peak_row.peak_count or 0) / _PEAK_BUCKET_SECS, 3)
    delta_pct = _pct_delta(total_events, prev_events)

    ingestion = IngestionKPI(
        epsNow=eps_now,
        epsPeak=eps_peak,
        totalEvents=total_events,
        deltaPercent=delta_pct,
    )

    # ── Agents ────────────────────────────────────────────────────────────────
    ag_row = (
        await db.execute(
            text("""
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE status = 'online')  AS online,
            COUNT(*) FILTER (WHERE status = 'offline') AS offline
        FROM agents
        WHERE tenant_id = CAST(:tid AS uuid) AND deleted_at IS NULL
    """),
            {"tid": tid},
        )
    ).fetchone()

    agents = AgentKPI(
        total=ag_row.total or 0,
        online=ag_row.online or 0,
        offline=ag_row.offline or 0,
    )

    # ── Detection rules — current + previous period in one CTE ───────────────
    det_row = (
        await db.execute(
            text("""
        WITH per_rule AS (
            SELECT
                rule_id,
                COUNT(*) FILTER (WHERE created_at >= :ps)                          AS cnt_curr,
                COUNT(*) FILTER (WHERE created_at >= :prev_ps AND created_at < :ps) AS cnt_prev
            FROM alerts
            WHERE tenant_id   = CAST(:tid AS uuid)
              AND created_at >= :prev_ps
              AND deleted_at  IS NULL
              AND rule_id     IS NOT NULL
            GROUP BY rule_id
        )
        SELECT
            COUNT(*) FILTER (WHERE cnt_curr > :threshold)  AS noisy,
            COUNT(*) FILTER (WHERE cnt_curr > 0)           AS triggered_rules,
            COUNT(*) FILTER (WHERE cnt_prev > 0)           AS prev_triggered_rules
        FROM per_rule
    """),
            {
                "tid": tid,
                "ps": period_start,
                "prev_ps": prev_start,
                "threshold": _NOISY_RULE_THRESHOLD,
            },
        )
    ).fetchone()

    rule_base = (
        await db.execute(
            text("""
        SELECT
            COUNT(*) FILTER (WHERE enabled)     AS active,
            COUNT(*) FILTER (WHERE NOT enabled) AS disabled
        FROM detection_rules
        WHERE tenant_id = CAST(:tid AS uuid) AND deleted_at IS NULL
    """),
            {"tid": tid},
        )
    ).fetchone()

    curr_triggered = det_row.triggered_rules or 0
    prev_triggered = det_row.prev_triggered_rules or 0

    detection = DetectionKPI(
        activeRules=rule_base.active or 0,
        rulesTriggered=curr_triggered,
        noisyRules=det_row.noisy or 0,
        delta24h=_pct_delta(curr_triggered, prev_triggered),
    )

    result = APIResponse.ok(
        DashboardSummary(
            alerts=alerts,
            investigations=investigations,
            ingestion=ingestion,
            agents=agents,
            detection=detection,
            generatedAt=now.isoformat(),
        )
    )
    await _kpi_set(redis, cache_key, result.model_dump_json())
    return result


# ─── /dashboard/ingestion-rate ────────────────────────────────────────────────


@router.get("/ingestion-rate", response_model=APIResponse[IngestionRateSeries])
async def get_ingestion_rate(
    member: Annotated[object, require_permission(Permission.EVENTS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[Redis | None, Depends(get_redis_optional)],
    time_range: DashboardTimeRange = Query(default="last_24h"),
) -> APIResponse[IngestionRateSeries]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    tid = str(m.tenant_id)

    cache_key = _kpi_key(tid, "ingestion-rate", time_range)
    if (cached := await _kpi_get(redis, cache_key)) is not None:
        return APIResponse[IngestionRateSeries].model_validate_json(cached)

    period_start, now, bucket_secs = _window(time_range)

    # Events bucketed by custom interval via epoch arithmetic
    ev_rows = (
        await db.execute(
            text("""
        SELECT
            to_timestamp(
                (EXTRACT(EPOCH FROM event_timestamp)::bigint / :bsecs) * :bsecs
            ) AS bucket_ts,
            COUNT(*) AS event_count
        FROM events
        WHERE tenant_id = CAST(:tid AS uuid)
          AND event_timestamp >= :ps
          AND event_timestamp <= :now
        GROUP BY 1
        ORDER BY 1
    """),
            {"tid": tid, "ps": period_start, "now": now, "bsecs": bucket_secs},
        )
    ).fetchall()

    # Alerts bucketed the same way
    al_rows = (
        await db.execute(
            text("""
        SELECT
            to_timestamp(
                (EXTRACT(EPOCH FROM created_at)::bigint / :bsecs) * :bsecs
            ) AS bucket_ts,
            COUNT(*) AS alert_count
        FROM alerts
        WHERE tenant_id = CAST(:tid AS uuid)
          AND created_at >= :ps
          AND created_at <= :now
          AND deleted_at IS NULL
        GROUP BY 1
        ORDER BY 1
    """),
            {"tid": tid, "ps": period_start, "now": now, "bsecs": bucket_secs},
        )
    ).fetchall()

    alert_map: dict[str, int] = {str(r.bucket_ts): (r.alert_count or 0) for r in al_rows}

    points: list[IngestionRatePoint] = []
    for r in ev_rows:
        eps = round((r.event_count or 0) / bucket_secs, 4)
        ts = r.bucket_ts.isoformat() if r.bucket_ts else ""
        points.append(
            IngestionRatePoint(
                timestamp=ts,
                eps=eps,
                normalizedEps=eps,
                alertsCreated=alert_map.get(str(r.bucket_ts), 0),
            )
        )

    eps_values = [p.eps for p in points]
    peak_eps = max(eps_values) if eps_values else 0.0
    avg_eps = round(sum(eps_values) / len(eps_values), 4) if eps_values else 0.0

    # Normalize eps values now that we know the peak
    if peak_eps > 0:
        for p in points:
            p.normalizedEps = round(p.eps / peak_eps * 100, 1)

    result = APIResponse.ok(
        IngestionRateSeries(
            points=points,
            averageEps=avg_eps,
            peakEps=peak_eps,
        )
    )
    await _kpi_set(redis, cache_key, result.model_dump_json())
    return result


# ─── /dashboard/detection-health ─────────────────────────────────────────────


@router.get("/detection-health", response_model=APIResponse[DetectionHealthData])
async def get_detection_health(
    member: Annotated[object, require_permission(Permission.RULES_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[Redis | None, Depends(get_redis_optional)],
    time_range: DashboardTimeRange = Query(default="last_24h"),
) -> APIResponse[DetectionHealthData]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    tid = str(m.tenant_id)

    cache_key = _kpi_key(tid, "detection-health", time_range)
    if (cached := await _kpi_get(redis, cache_key)) is not None:
        return APIResponse[DetectionHealthData].model_validate_json(cached)

    period_start, now, _ = _window(time_range)

    # Rule counts
    counts_row = (
        await db.execute(
            text("""
        SELECT
            COUNT(*) FILTER (WHERE enabled)     AS active,
            COUNT(*) FILTER (WHERE NOT enabled) AS disabled
        FROM detection_rules
        WHERE tenant_id = CAST(:tid AS uuid) AND deleted_at IS NULL
    """),
            {"tid": tid},
        )
    ).fetchone()

    # Per-rule alert stats in period
    rule_rows = (
        await db.execute(
            text("""
        SELECT
            r.id        AS rule_id,
            r.name      AS rule_name,
            r.enabled   AS enabled,
            COUNT(a.id) AS alert_count,
            MAX(a.created_at) AS last_triggered_at,
            AVG(
                EXTRACT(EPOCH FROM (a.created_at - e.event_timestamp)) * 1000.0
            ) FILTER (WHERE e.event_timestamp IS NOT NULL) AS avg_latency_ms
        FROM detection_rules r
        LEFT JOIN alerts a
            ON  a.rule_id   = r.id
            AND a.tenant_id = r.tenant_id
            AND a.created_at >= :ps
            AND a.deleted_at IS NULL
        LEFT JOIN events e
            ON e.id = a.triggering_event_id
        WHERE r.tenant_id = CAST(:tid AS uuid)
          AND r.deleted_at IS NULL
        GROUP BY r.id, r.name, r.enabled
        ORDER BY alert_count DESC
        LIMIT 20
    """),
            {"tid": tid, "ps": period_start},
        )
    ).fetchall()

    noisy_count = 0
    top_rules: list[DetectionRuleHealth] = []
    all_latencies: list[float] = []

    for r in rule_rows:
        cnt = r.alert_count or 0
        latency = round(float(r.avg_latency_ms), 1) if r.avg_latency_ms else 0.0
        if latency > 0:
            all_latencies.append(latency)

        if not r.enabled:
            status: str = "disabled"
        elif cnt >= _NOISY_RULE_THRESHOLD:
            status = "noisy"
            noisy_count += 1
        else:
            status = "active"

        last_at = r.last_triggered_at.isoformat() if r.last_triggered_at else None
        top_rules.append(
            DetectionRuleHealth(
                ruleId=str(r.rule_id),
                ruleName=r.rule_name,
                triggeredCount=cnt,
                alertsCreated=cnt,
                suppressedCount=0,
                lastTriggeredAt=last_at,
                avgLatencyMs=latency,
                status=status,  # type: ignore[arg-type]
            )
        )

    avg_latency = round(sum(all_latencies) / len(all_latencies), 1) if all_latencies else 0.0

    result = APIResponse.ok(
        DetectionHealthData(
            activeRules=counts_row.active or 0,
            disabledRules=counts_row.disabled or 0,
            noisyRules=noisy_count,
            errorRules=0,
            avgLatencyMs=avg_latency,
            ingestionToDetectionMs=avg_latency,
            topRules=top_rules[:10],
        )
    )
    await _kpi_set(redis, cache_key, result.model_dump_json())
    return result


# ─── /dashboard/mitre-coverage ────────────────────────────────────────────────


@router.get("/mitre-coverage", response_model=APIResponse[MitreCoverageData])
async def get_mitre_coverage(
    member: Annotated[object, require_permission(Permission.EVENTS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[Redis | None, Depends(get_redis_optional)],
    time_range: DashboardTimeRange = Query(default="last_24h"),
) -> APIResponse[MitreCoverageData]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    tid = str(m.tenant_id)

    cache_key = _kpi_key(tid, "mitre-coverage", time_range)
    if (cached := await _kpi_get(redis, cache_key)) is not None:
        return APIResponse[MitreCoverageData].model_validate_json(cached)

    period_start, now, _ = _window(time_range)

    # Expand JSONB array of technique IDs per alert and aggregate counts per technique
    rows = (
        await db.execute(
            text("""
        SELECT
            technique,
            COUNT(*)                                            AS total,
            COUNT(*) FILTER (WHERE severity = 'critical')      AS critical_count,
            COUNT(*) FILTER (WHERE severity = 'high')          AS high_count,
            COUNT(*) FILTER (WHERE severity = 'medium')        AS medium_count,
            MAX(created_at)                                     AS latest_at
        FROM (
            SELECT
                jsonb_array_elements_text(mitre_techniques) AS technique,
                severity,
                created_at
            FROM alerts
            WHERE tenant_id   = CAST(:tid AS uuid)
              AND created_at  >= :ps
              AND deleted_at  IS NULL
              AND mitre_techniques IS NOT NULL
              AND mitre_techniques != 'null'::jsonb
              AND jsonb_array_length(mitre_techniques) > 0
        ) sub
        WHERE technique IS NOT NULL AND technique != ''
        GROUP BY technique
        ORDER BY total DESC
        LIMIT 100
    """),
            {"tid": tid, "ps": period_start},
        )
    ).fetchall()

    # Total alerts with any MITRE data in period
    total_row = (
        await db.execute(
            text("""
        SELECT COUNT(*) AS total
        FROM alerts
        WHERE tenant_id = CAST(:tid AS uuid)
          AND created_at >= :ps
          AND deleted_at IS NULL
    """),
            {"tid": tid, "ps": period_start},
        )
    ).fetchone()

    technique_counts: dict[str, TechniqueStat] = {}
    top_technique: str | None = None
    top_count = 0

    for r in rows:
        tid_str = r.technique
        cnt = r.total or 0
        technique_counts[tid_str] = TechniqueStat(
            techniqueId=tid_str,
            count=cnt,
            criticalCount=r.critical_count or 0,
            highCount=r.high_count or 0,
            mediumCount=r.medium_count or 0,
            latestAt=r.latest_at.isoformat() if r.latest_at else now.isoformat(),
        )
        if cnt > top_count:
            top_count = cnt
            top_technique = tid_str

    result = APIResponse.ok(
        MitreCoverageData(
            techniqueCounts=technique_counts,
            totalAlerts=total_row.total or 0,
            coveredTechniques=len(technique_counts),
            topTechnique=top_technique,
            generatedAt=now.isoformat(),
        )
    )
    await _kpi_set(redis, cache_key, result.model_dump_json())
    return result


# ─── /dashboard/correlation-activity ─────────────────────────────────────────


@router.get("/correlation-activity", response_model=APIResponse[CorrelationActivityData])
async def get_correlation_activity(
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[Redis | None, Depends(get_redis_optional)],
    time_range: DashboardTimeRange = Query(default="last_24h"),
) -> APIResponse[CorrelationActivityData]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    tid = str(m.tenant_id)

    cache_key = _kpi_key(tid, "correlation-activity", time_range)
    if (cached := await _kpi_get(redis, cache_key)) is not None:
        return APIResponse[CorrelationActivityData].model_validate_json(cached)

    period_start, now, _ = _window(time_range)
    _TERMINAL = ("closed", "resolved", "false_positive")

    # Aggregate counts for active investigations
    agg_row = (
        await db.execute(
            text("""
        SELECT
            COUNT(*)                                                         AS active,
            COALESCE(SUM(jsonb_array_length(triggering_alert_ids)), 0)       AS grouped_alerts,
            -- Count entities inside context_json->entities array if present
            COALESCE(SUM(
                CASE
                    WHEN context_json IS NOT NULL
                         AND context_json ? 'entities'
                         AND jsonb_typeof(context_json->'entities') = 'array'
                    THEN jsonb_array_length(context_json->'entities')
                    ELSE 0
                END
            ), 0)                                                            AS total_entities
        FROM investigations
        WHERE tenant_id = CAST(:tid AS uuid)
          AND status NOT IN ('closed', 'resolved', 'false_positive')
    """),
            {"tid": tid},
        )
    ).fetchone()

    # Recent investigations as correlation events (up to 10)
    inv_rows = (
        await db.execute(
            text("""
        SELECT
            id,
            title,
            executive_summary,
            threat_score,
            triggering_alert_ids,
            behaviors_json,
            context_json,
            created_at
        FROM investigations
        WHERE tenant_id = CAST(:tid AS uuid)
          AND created_at >= :ps
        ORDER BY created_at DESC
        LIMIT 10
    """),
            {"tid": tid, "ps": period_start},
        )
    ).fetchall()

    recent: list[CorrelationEvent] = []
    for r in inv_rows:
        # Human-readable title
        title = (
            r.title
            or (r.executive_summary[:80] if r.executive_summary else None)
            or "Untitled Investigation"
        )

        # Alert count from triggering_alert_ids JSONB array
        alert_ids = r.triggering_alert_ids or []
        alert_count = len(alert_ids) if isinstance(alert_ids, list) else 0

        # Entity count from context_json
        ctx = r.context_json or {}
        entity_count = len(ctx.get("entities", [])) if isinstance(ctx, dict) else 0

        # Behavior names from behaviors_json
        behaviors: list[str] = []
        bj = r.behaviors_json or {}
        if isinstance(bj, dict):
            for b in bj.get("detected_behaviors", []):
                name = b.get("behavior_name") if isinstance(b, dict) else None
                if name:
                    behaviors.append(name)

        recent.append(
            CorrelationEvent(
                id=str(r.id),
                investigationId=str(r.id),
                investigationTitle=title,
                alertCount=alert_count,
                entityCount=entity_count,
                behaviorMatches=behaviors[:5],
                severity=_score_to_severity(r.threat_score or 0),
                correlatedAt=r.created_at.isoformat() if r.created_at else now.isoformat(),
            )
        )

    result = APIResponse.ok(
        CorrelationActivityData(
            activeInvestigations=agg_row.active or 0,
            totalGroupedAlerts=int(agg_row.grouped_alerts or 0),
            totalEntities=int(agg_row.total_entities or 0),
            recentCorrelations=recent,
        )
    )
    await _kpi_set(redis, cache_key, result.model_dump_json())
    return result


# ─── /dashboard/ai-operations ────────────────────────────────────────────────


@router.get("/ai-operations", response_model=APIResponse[AIOperationsData])
async def get_ai_operations(
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[Redis | None, Depends(get_redis_optional)],
    time_range: DashboardTimeRange = Query(default="last_24h"),
) -> APIResponse[AIOperationsData]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    tid = str(m.tenant_id)

    cache_key = _kpi_key(tid, "ai-operations", time_range)
    if (cached := await _kpi_get(redis, cache_key)) is not None:
        return APIResponse[AIOperationsData].model_validate_json(cached)

    period_start, now, _ = _window(time_range)
    cutoff_24h = now - timedelta(hours=24)

    # Aggregate AI stats
    stats_row = (
        await db.execute(
            text("""
        SELECT
            COUNT(*) FILTER (
                WHERE ai_analysis_json IS NOT NULL
                  AND created_at >= :cutoff24
            )                                                   AS analyzed_24h,
            COUNT(*) FILTER (
                WHERE verdict = 'true_positive'
                  AND created_at >= :ps
            )                                                   AS true_positive,
            COUNT(*) FILTER (
                WHERE (verdict = 'false_positive' OR status = 'false_positive')
                  AND created_at >= :ps
            )                                                   AS false_positive,
            COUNT(*) FILTER (
                WHERE ai_analysis_json IS NULL
                  AND status NOT IN ('closed', 'resolved', 'false_positive')
            )                                                   AS pending,
            AVG(
                CAST(
                    ai_analysis_json->>'confidence_score' AS float
                )
            ) FILTER (
                WHERE ai_analysis_json IS NOT NULL
                  AND ai_analysis_json->>'confidence_score' IS NOT NULL
                  AND created_at >= :ps
            )                                                   AS avg_confidence
        FROM investigations
        WHERE tenant_id = CAST(:tid AS uuid)
    """),
            {"tid": tid, "ps": period_start, "cutoff24": cutoff_24h},
        )
    ).fetchone()

    # Recent verdicts from investigations with AI analysis
    verdict_rows = (
        await db.execute(
            text("""
        SELECT
            id,
            title,
            executive_summary,
            verdict,
            tp_probability,
            fp_probability,
            ai_analysis_json,
            created_at
        FROM investigations
        WHERE tenant_id = CAST(:tid AS uuid)
          AND created_at >= :ps
          AND (verdict IS NOT NULL OR ai_analysis_json IS NOT NULL)
        ORDER BY created_at DESC
        LIMIT 10
    """),
            {"tid": tid, "ps": period_start},
        )
    ).fetchall()

    pending = stats_row.pending or 0
    recent_verdicts: list[AIVerdict] = []
    for r in verdict_rows:
        # Determine verdict: use explicit verdict column, fall back to AI analysis
        ai = r.ai_analysis_json or {}
        v = r.verdict or ai.get("verdict") or "pending"
        # Normalize verdict to frontend enum values
        if v in ("true_positive",):
            verdict_str = "true_positive"
        elif v in ("false_positive",):
            verdict_str = "false_positive"
        elif v in ("benign",):
            verdict_str = "benign"
        else:
            verdict_str = "pending"

        # Confidence: prefer ai_analysis confidence_score (0-100), else derive from tp_probability
        raw_conf = ai.get("confidence_score")
        if raw_conf is not None:
            confidence = float(raw_conf)
        elif r.tp_probability is not None:
            confidence = round(float(r.tp_probability) * 100, 1)
        else:
            confidence = 0.0

        title = (
            r.title
            or (r.executive_summary[:60] if r.executive_summary else None)
            or "Investigation"
        )

        analyzed_at = r.created_at.isoformat() if r.ai_analysis_json and r.created_at else None

        recent_verdicts.append(
            AIVerdict(
                verdict=verdict_str,
                confidence=confidence,
                investigationId=str(r.id),
                title=title,
                analyzedAt=analyzed_at,
            )
        )

    avg_conf = round(float(stats_row.avg_confidence), 1) if stats_row.avg_confidence else 0.0

    result = APIResponse.ok(
        AIOperationsData(
            queueDepth=pending,
            analyzedLast24h=stats_row.analyzed_24h or 0,
            truePositiveCount=stats_row.true_positive or 0,
            falsePositiveCount=stats_row.false_positive or 0,
            pendingCount=pending,
            avgConfidence=avg_conf,
            recentVerdicts=recent_verdicts,
        )
    )
    await _kpi_set(redis, cache_key, result.model_dump_json())
    return result


# ─── /dashboard/geo-threats ──────────────────────────────────────────────────


@router.get("/geo-threats", response_model=APIResponse[list])
async def get_geo_threats(
    member: Annotated[object, require_permission(Permission.ALERTS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    time_range: str = Query(default="24h"),
) -> APIResponse[list]:
    """Return geo-located threat sources from alert network evidence."""
    from datetime import datetime, timedelta

    from app.models.alert import Alert
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    mapping = {"24h": 24, "last_24h": 24, "48h": 48, "7d": 168, "last_7d": 168}
    hours = mapping.get(time_range, 24)
    since = datetime.now(tz=UTC) - timedelta(hours=hours)

    result = await db.execute(
        select(Alert.evidence, Alert.severity).where(
            Alert.tenant_id == m.tenant_id,
            Alert.created_at >= since,
            Alert.evidence.is_not(None),
        )
    )
    rows = result.all()

    sev_order = ["low", "medium", "high", "critical"]
    country_map: dict[str, dict] = {}
    for ev, sev in rows:
        if not ev:
            continue
        network = ev.get("network") or {}
        geo = network.get("geo") or ev.get("geo") or {}
        country = geo.get("country") or network.get("country")
        lat = geo.get("lat") or network.get("lat")
        lng = geo.get("lng") or geo.get("lon") or network.get("lng")
        if not country or lat is None or lng is None:
            continue
        sev_str = sev.value if hasattr(sev, "value") else str(sev)
        if country not in country_map:
            country_map[country] = {
                "lat": lat,
                "lng": lng,
                "count": 0,
                "severity": "low",
                "country": country,
            }
        country_map[country]["count"] += 1
        existing_idx = (
            sev_order.index(country_map[country]["severity"])
            if country_map[country]["severity"] in sev_order
            else 0
        )
        curr_idx = sev_order.index(sev_str) if sev_str in sev_order else 0
        if curr_idx > existing_idx:
            country_map[country]["severity"] = sev_str

    return APIResponse.ok(list(country_map.values()))


# ─── /dashboard/alert-heatmap ────────────────────────────────────────────────


@router.get("/alert-heatmap", response_model=APIResponse[list])
async def get_alert_heatmap(
    member: Annotated[object, require_permission(Permission.ALERTS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    timeRange: str = Query(default="last_7d"),
) -> APIResponse[list]:
    """Alert volume grouped by day-of-week × hour-of-day for a heatmap view."""
    from app.models.alert import Alert
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    mapping = {
        "last_24h": 1,
        "24h": 1,
        "last_7d": 7,
        "7d": 7,
        "last_6h": 1,
        "last_15m": 1,
        "last_1h": 1,
        "30d": 30,
    }
    days = mapping.get(timeRange, 7)
    since = datetime.now(tz=UTC) - timedelta(days=days)

    result = await db.execute(
        select(Alert.created_at).where(
            Alert.tenant_id == m.tenant_id,
            Alert.created_at >= since,
        )
    )
    timestamps = result.scalars().all()

    counts: dict[tuple[int, int], int] = {}
    for ts in timestamps:
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        key = (ts.weekday() + 1) % 7, ts.hour  # Mon=0 in Python, convert to Sun=0
        counts[key] = counts.get(key, 0) + 1

    cells = [
        {"day": d, "hour": h, "count": counts.get((d, h), 0)} for d in range(7) for h in range(24)
    ]
    return APIResponse.ok(cells)


# ─── /dashboard/mttr-trend ───────────────────────────────────────────────────


@router.get("/mttr-trend", response_model=APIResponse[list])
async def get_mttr_trend(
    member: Annotated[object, require_permission(Permission.ALERTS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[list]:
    """Weekly MTTR trend for the past 8 weeks."""
    from app.models.alert import Alert
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    since = datetime.now(tz=UTC) - timedelta(weeks=8)
    result = await db.execute(
        select(Alert)
        .where(
            Alert.tenant_id == m.tenant_id,
            Alert.created_at >= since,
        )
        .order_by(Alert.created_at)
    )
    alerts = result.scalars().all()

    # Group by ISO week + severity
    from collections import defaultdict

    week_sev: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    for a in alerts:
        ts = a.created_at
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        status_str = a.status.value if hasattr(a.status, "value") else str(a.status)
        if status_str not in ("closed", "false_positive", "resolved"):
            continue
        elapsed = (
            max(0.0, (a.updated_at - a.created_at).total_seconds() / 60.0) if a.updated_at else 0
        )
        # Round to Monday
        monday = ts - timedelta(days=ts.weekday())
        week_key = monday.strftime("%Y-%m-%d")
        sev = (a.severity.value if hasattr(a.severity, "value") else str(a.severity)).lower()
        if sev in ("critical", "high", "medium"):
            week_sev[week_key][sev].append(elapsed)

    out = []
    for week in sorted(week_sev.keys()):
        d = week_sev[week]
        out.append(
            {
                "week": week,
                "critical_minutes": round(sum(d["critical"]) / len(d["critical"]))
                if d["critical"]
                else 0,
                "high_minutes": round(sum(d["high"]) / len(d["high"])) if d["high"] else 0,
                "medium_minutes": round(sum(d["medium"]) / len(d["medium"])) if d["medium"] else 0,
            }
        )
    return APIResponse.ok(out)


# ─── /dashboard/top-entities ─────────────────────────────────────────────────


@router.get("/top-entities", response_model=APIResponse[dict])
async def get_top_entities(
    member: Annotated[object, require_permission(Permission.ALERTS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    timeRange: str = Query(default="last_24h"),
) -> APIResponse[dict]:
    """Top 5 hosts, users, and IPs by alert count."""
    from app.models.alert import Alert
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    mapping = {
        "last_15m": timedelta(minutes=15),
        "last_1h": timedelta(hours=1),
        "last_6h": timedelta(hours=6),
        "last_24h": timedelta(hours=24),
        "last_7d": timedelta(days=7),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
    }
    delta = mapping.get(timeRange, timedelta(hours=24))
    since = datetime.now(tz=UTC) - delta

    result = await db.execute(
        select(Alert).where(
            Alert.tenant_id == m.tenant_id,
            Alert.created_at >= since,
        )
    )
    alerts = result.scalars().all()

    SEV_ORDER = ["low", "medium", "high", "critical"]

    def _aggregate(key_fn):
        counts: dict[str, dict] = {}
        for a in alerts:
            key = key_fn(a)
            if not key:
                continue
            sev = (a.severity.value if hasattr(a.severity, "value") else str(a.severity)).lower()
            if key not in counts:
                counts[key] = {"name": key, "count": 0, "severity_max": "low"}
            counts[key]["count"] += 1
            existing = counts[key]["severity_max"]
            if SEV_ORDER.index(sev) > SEV_ORDER.index(existing if existing in SEV_ORDER else "low"):
                counts[key]["severity_max"] = sev
        return sorted(counts.values(), key=lambda x: -x["count"])[:5]

    return APIResponse.ok(
        {
            "hosts": _aggregate(lambda a: a.source_host),
            "users": _aggregate(lambda a: a.username),
            "ips": _aggregate(lambda a: a.source_ip),
        }
    )
