"""
Compliance reporting endpoint.

GET /reports/compliance?framework=soc2|iso27001|pci_dss&from_days=30

Returns an aggregated security posture summary suitable for compliance evidence
packs (SOC 2 Type II, ISO 27001, PCI-DSS).  All data is tenant-scoped.

The report is intentionally read-only and deterministic — the same parameters
always produce the same data for the same period.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models.generated_report import GeneratedReport
from app.models.tenant_member import TenantMember
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse, PaginatedResponse
from app.services.report_generator_service import ReportGeneratorService

router = APIRouter(prefix="/reports", tags=["reports"])


# ─── Response schema ──────────────────────────────────────────────────────────


class AlertSummary(BaseModel):
    total: int = 0
    open: int = 0
    acknowledged: int = 0
    closed: int = 0
    false_positive: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    mean_time_to_acknowledge_hours: float | None = None
    mean_time_to_close_hours: float | None = None


class InvestigationSummary(BaseModel):
    total: int = 0
    open: int = 0
    closed: int = 0
    high_confidence: int = 0
    avg_threat_score: float | None = None
    behaviors_detected: list[str] = Field(default_factory=list)


class AgentSummary(BaseModel):
    total_agents: int = 0
    online_agents: int = 0
    offline_agents: int = 0
    coverage_pct: float = 0.0


class EventSummary(BaseModel):
    total_events: int = 0
    by_category: dict[str, int] = Field(default_factory=dict)


class ComplianceFrameworkControl(BaseModel):
    control_id: str
    control_name: str
    status: Literal["pass", "partial", "fail", "not_applicable"]
    evidence: str
    metric: str | None = None


class ComplianceReport(BaseModel):
    framework: str
    tenant_id: str
    generated_at: str
    period_start: str
    period_end: str
    alerts: AlertSummary
    investigations: InvestigationSummary
    agents: AgentSummary
    events: EventSummary
    controls: list[ComplianceFrameworkControl]


# ─── Framework control mappings ───────────────────────────────────────────────


def _soc2_controls(
    alerts: AlertSummary,
    investigations: InvestigationSummary,
    agents: AgentSummary,
) -> list[ComplianceFrameworkControl]:
    fp_rate = alerts.false_positive / alerts.total if alerts.total else 0.0
    ack_ok = (
        alerts.mean_time_to_acknowledge_hours is not None
        and alerts.mean_time_to_acknowledge_hours <= 4.0
    )
    return [
        ComplianceFrameworkControl(
            control_id="CC7.2",
            control_name="System Monitoring",
            status="pass" if agents.coverage_pct >= 80 else "partial",
            evidence=f"{agents.online_agents}/{agents.total_agents} agents online ({agents.coverage_pct:.0f}% coverage)",
            metric=f"{agents.coverage_pct:.1f}%",
        ),
        ComplianceFrameworkControl(
            control_id="CC7.3",
            control_name="Incident Identification and Response",
            status="pass" if ack_ok else "partial",
            evidence=(
                f"Mean time to acknowledge: {alerts.mean_time_to_acknowledge_hours:.1f}h"
                if alerts.mean_time_to_acknowledge_hours
                else "No alerts acknowledged in period"
            ),
            metric=f"{alerts.mean_time_to_acknowledge_hours:.1f}h"
            if alerts.mean_time_to_acknowledge_hours
            else None,
        ),
        ComplianceFrameworkControl(
            control_id="CC9.2",
            control_name="Risk Monitoring",
            status="pass" if investigations.high_confidence < 5 else "partial",
            evidence=f"{investigations.high_confidence} high-confidence investigation(s) in period",
            metric=str(investigations.high_confidence),
        ),
        ComplianceFrameworkControl(
            control_id="CC3.2",
            control_name="Alert Quality (FP Rate)",
            status="pass" if fp_rate <= 0.20 else "partial",
            evidence=f"False positive rate: {fp_rate:.0%} ({alerts.false_positive}/{alerts.total} alerts)",
            metric=f"{fp_rate:.0%}",
        ),
    ]


def _iso27001_controls(
    alerts: AlertSummary,
    investigations: InvestigationSummary,
    agents: AgentSummary,
) -> list[ComplianceFrameworkControl]:
    return [
        ComplianceFrameworkControl(
            control_id="A.12.4.1",
            control_name="Event Logging",
            status="pass" if agents.online_agents > 0 else "fail",
            evidence=f"{agents.online_agents} agent(s) actively collecting events",
            metric=str(agents.online_agents),
        ),
        ComplianceFrameworkControl(
            control_id="A.16.1.2",
            control_name="Reporting Information Security Events",
            status="pass" if alerts.total >= 0 else "not_applicable",
            evidence=f"{alerts.total} security alert(s) generated in period",
            metric=str(alerts.total),
        ),
        ComplianceFrameworkControl(
            control_id="A.16.1.5",
            control_name="Response to Information Security Incidents",
            status="pass" if alerts.open == 0 else "partial",
            evidence=f"{alerts.open} unresolved alert(s) remain open",
            metric=str(alerts.open),
        ),
        ComplianceFrameworkControl(
            control_id="A.12.6.1",
            control_name="Management of Technical Vulnerabilities",
            status="pass" if investigations.high_confidence < 3 else "partial",
            evidence=f"{investigations.high_confidence} high-confidence investigation(s) identified",
            metric=str(investigations.high_confidence),
        ),
    ]


def _pci_dss_controls(
    alerts: AlertSummary,
    agents: AgentSummary,
    events: EventSummary,
) -> list[ComplianceFrameworkControl]:
    return [
        ComplianceFrameworkControl(
            control_id="PCI 10.2",
            control_name="Implement audit trails for all system components",
            status="pass" if events.total_events > 0 else "fail",
            evidence=f"{events.total_events} events logged across all agents",
            metric=str(events.total_events),
        ),
        ComplianceFrameworkControl(
            control_id="PCI 10.6",
            control_name="Review logs and security events daily",
            status="pass" if alerts.acknowledged > 0 or alerts.closed > 0 else "partial",
            evidence=f"{alerts.acknowledged + alerts.closed} alert(s) reviewed in period",
            metric=str(alerts.acknowledged + alerts.closed),
        ),
        ComplianceFrameworkControl(
            control_id="PCI 11.4",
            control_name="Use intrusion detection/prevention systems",
            status="pass" if agents.online_agents > 0 else "fail",
            evidence=f"{agents.online_agents} active detection agent(s)",
            metric=str(agents.online_agents),
        ),
        ComplianceFrameworkControl(
            control_id="PCI 12.10",
            control_name="Maintain and implement an incident response plan",
            status="pass" if alerts.mean_time_to_close_hours is not None else "partial",
            evidence=(
                f"Mean time to close: {alerts.mean_time_to_close_hours:.1f}h"
                if alerts.mean_time_to_close_hours
                else "No alerts closed in period"
            ),
            metric=f"{alerts.mean_time_to_close_hours:.1f}h"
            if alerts.mean_time_to_close_hours
            else None,
        ),
    ]


# ─── Endpoint ─────────────────────────────────────────────────────────────────


@router.get("/compliance", response_model=APIResponse[ComplianceReport])
async def get_compliance_report(
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    framework: Literal["soc2", "iso27001", "pci_dss"] = Query(default="soc2"),
    from_days: int = Query(default=30, ge=1, le=365),
) -> APIResponse[ComplianceReport]:
    m: TenantMember = member  # type: ignore[assignment]
    tenant_id = m.tenant_id

    now = datetime.now(tz=UTC)
    period_start = now - timedelta(days=from_days)

    # ── Alert metrics ─────────────────────────────────────────────────────────
    alert_rows = await db.execute(
        text("""
        SELECT
            COUNT(*) FILTER (WHERE TRUE)                              AS total,
            COUNT(*) FILTER (WHERE status = 'open')                   AS open,
            COUNT(*) FILTER (WHERE status = 'acknowledged')           AS acknowledged,
            COUNT(*) FILTER (WHERE status = 'closed')                 AS closed,
            COUNT(*) FILTER (WHERE status = 'false_positive')         AS false_positive,
            COUNT(*) FILTER (WHERE severity = 'critical')             AS critical,
            COUNT(*) FILTER (WHERE severity = 'high')                 AS high,
            COUNT(*) FILTER (WHERE severity = 'medium')               AS medium,
            COUNT(*) FILTER (WHERE severity = 'low')                  AS low,
            AVG(EXTRACT(EPOCH FROM (acknowledged_at - created_at)) / 3600.0)
                FILTER (WHERE acknowledged_at IS NOT NULL)            AS mtta_hours,
            AVG(EXTRACT(EPOCH FROM (closed_at - created_at)) / 3600.0)
                FILTER (WHERE closed_at IS NOT NULL)                  AS mttc_hours
        FROM alerts
        WHERE tenant_id = CAST(:tid AS uuid)
          AND created_at >= :period_start
          AND deleted_at IS NULL
    """),
        {"tid": str(tenant_id), "period_start": period_start},
    )
    ar = alert_rows.fetchone()

    alerts = AlertSummary(
        total=ar.total or 0,
        open=ar.open or 0,
        acknowledged=ar.acknowledged or 0,
        closed=ar.closed or 0,
        false_positive=ar.false_positive or 0,
        by_severity={
            "critical": ar.critical or 0,
            "high": ar.high or 0,
            "medium": ar.medium or 0,
            "low": ar.low or 0,
        },
        mean_time_to_acknowledge_hours=round(float(ar.mtta_hours), 2) if ar.mtta_hours else None,
        mean_time_to_close_hours=round(float(ar.mttc_hours), 2) if ar.mttc_hours else None,
    )

    # ── Investigation metrics ─────────────────────────────────────────────────
    inv_rows = await db.execute(
        text("""
        SELECT
            COUNT(*) FILTER (WHERE TRUE)                          AS total,
            COUNT(*) FILTER (WHERE status NOT IN ('closed','resolved','false_positive')) AS open,
            COUNT(*) FILTER (WHERE status IN ('closed','resolved','false_positive'))     AS closed,
            COUNT(*) FILTER (WHERE confidence = 'high')               AS high_confidence,
            AVG(threat_score)                                          AS avg_score
        FROM investigations
        WHERE tenant_id = CAST(:tid AS uuid)
          AND created_at >= :period_start
    """),
        {"tid": str(tenant_id), "period_start": period_start},
    )
    ir = inv_rows.fetchone()

    # Collect distinct behavior names from JSONB
    beh_rows = await db.execute(
        text("""
        SELECT DISTINCT jsonb_array_elements(behaviors_json->'detected_behaviors')->>'behavior_name' AS bname
        FROM investigations
        WHERE tenant_id = CAST(:tid AS uuid)
          AND created_at >= :period_start
          AND behaviors_json IS NOT NULL
        LIMIT 20
    """),
        {"tid": str(tenant_id), "period_start": period_start},
    )
    behaviors = [r[0] for r in beh_rows.fetchall() if r[0]]

    investigations = InvestigationSummary(
        total=ir.total or 0,
        open=ir.open or 0,
        closed=ir.closed or 0,
        high_confidence=ir.high_confidence or 0,
        avg_threat_score=round(float(ir.avg_score), 1) if ir.avg_score else None,
        behaviors_detected=behaviors,
    )

    # ── Agent metrics ─────────────────────────────────────────────────────────
    agent_rows = await db.execute(
        text("""
        SELECT
            COUNT(*)                                                  AS total,
            COUNT(*) FILTER (WHERE status = 'online')                 AS online,
            COUNT(*) FILTER (WHERE status = 'offline')                AS offline
        FROM agents
        WHERE tenant_id = CAST(:tid AS uuid)
          AND deleted_at IS NULL
    """),
        {"tid": str(tenant_id)},
    )
    agr = agent_rows.fetchone()
    total_agents = agr.total or 0
    online_agents = agr.online or 0
    coverage = round(online_agents / total_agents * 100, 1) if total_agents else 0.0

    agents = AgentSummary(
        total_agents=total_agents,
        online_agents=online_agents,
        offline_agents=agr.offline or 0,
        coverage_pct=coverage,
    )

    # ── Event metrics ─────────────────────────────────────────────────────────
    ev_rows = await db.execute(
        text("""
        SELECT category, COUNT(*) AS cnt
        FROM events
        WHERE tenant_id = CAST(:tid AS uuid)
          AND event_timestamp >= :period_start
        GROUP BY category
        LIMIT 20
    """),
        {"tid": str(tenant_id), "period_start": period_start},
    )
    by_cat = {r[0]: r[1] for r in ev_rows.fetchall() if r[0]}
    events = EventSummary(
        total_events=sum(by_cat.values()),
        by_category=by_cat,
    )

    # ── Build controls ────────────────────────────────────────────────────────
    if framework == "soc2":
        controls = _soc2_controls(alerts, investigations, agents)
    elif framework == "iso27001":
        controls = _iso27001_controls(alerts, investigations, agents)
    else:
        controls = _pci_dss_controls(alerts, agents, events)

    report = ComplianceReport(
        framework=framework,
        tenant_id=str(tenant_id),
        generated_at=now.isoformat(),
        period_start=period_start.isoformat(),
        period_end=now.isoformat(),
        alerts=alerts,
        investigations=investigations,
        agents=agents,
        events=events,
        controls=controls,
    )
    return APIResponse.ok(report)


# ─── Generated Reports ────────────────────────────────────────────────────────


class GeneratedReportSummary(BaseModel):
    id: str
    report_type: str
    title: str
    status: str
    period_days: int
    period_start: str
    period_end: str
    created_at: str


class GeneratedReportDetail(GeneratedReportSummary):
    sections: list | None = None
    metrics: dict | None = None
    error_message: str | None = None


class GenerateReportRequest(BaseModel):
    report_type: Literal["executive_summary", "threat_report", "compliance_summary"] = (
        "executive_summary"
    )
    period_days: int = Field(default=30, ge=7, le=365)


@router.post("/generate", response_model=APIResponse[GeneratedReportSummary], status_code=201)
async def generate_report(
    payload: GenerateReportRequest,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[GeneratedReportSummary]:
    m: TenantMember = member  # type: ignore[assignment]

    from app.models.tenant import Tenant

    tenant_result = await db.execute(select(Tenant.name).where(Tenant.id == m.tenant_id))
    company_name = tenant_result.scalar_one_or_none() or "Your Organization"

    report = await ReportGeneratorService.generate(
        db=db,
        tenant_id=m.tenant_id,
        report_type=payload.report_type,
        period_days=payload.period_days,
        company_name=company_name,
        created_by_id=m.user_id,
    )
    await db.commit()
    return APIResponse.ok(_to_summary(report))


@router.get("/generated", response_model=PaginatedResponse[GeneratedReportSummary])
async def list_generated_reports(
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=100),
) -> PaginatedResponse[GeneratedReportSummary]:
    m: TenantMember = member  # type: ignore[assignment]

    total = (
        await db.execute(select(func.count()).where(GeneratedReport.tenant_id == m.tenant_id))
    ).scalar_one()

    rows = (
        (
            await db.execute(
                select(GeneratedReport)
                .where(GeneratedReport.tenant_id == m.tenant_id)
                .order_by(GeneratedReport.created_at.desc())
                .offset((page - 1) * limit)
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )

    return PaginatedResponse[GeneratedReportSummary].offset(
        data=[_to_summary(r) for r in rows],
        page=page,
        limit=limit,
        total=total,
    )


@router.get("/generated/{report_id}", response_model=APIResponse[GeneratedReportDetail])
async def get_generated_report(
    report_id: str,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[GeneratedReportDetail]:
    from uuid import UUID as _UUID

    from app.core.exceptions import NotFoundError

    m: TenantMember = member  # type: ignore[assignment]
    try:
        rid = _UUID(report_id)
    except ValueError:
        from app.core.exceptions import ValidationError

        raise ValidationError("Invalid report ID") from None

    result = await db.execute(
        select(GeneratedReport).where(
            GeneratedReport.id == rid,
            GeneratedReport.tenant_id == m.tenant_id,
        )
    )
    report = result.scalar_one_or_none()
    if report is None:
        raise NotFoundError(f"Report {report_id} not found")

    return APIResponse.ok(
        GeneratedReportDetail(
            **_to_summary(report).model_dump(),
            sections=report.sections,
            metrics=report.metrics,
            error_message=report.error_message,
        )
    )


def _to_summary(r: GeneratedReport) -> GeneratedReportSummary:
    return GeneratedReportSummary(
        id=str(r.id),
        report_type=r.report_type,
        title=r.title,
        status=r.status,
        period_days=r.period_days,
        period_start=r.period_start.isoformat(),
        period_end=r.period_end.isoformat(),
        created_at=r.created_at.isoformat(),
    )
