"""
AI-powered security report generation service.

Collects tenant metrics for a given period, calls the LLM to write
professional narrative sections, and persists the result as a GeneratedReport.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from uuid import UUID

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.generated_report import GeneratedReport

log = structlog.get_logger(__name__)

# ─── Severity ordering for filtering ─────────────────────────────────────────

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

REPORT_TYPE_LABELS = {
    "executive_summary":   "Executive Security Summary",
    "threat_report":       "Threat Intelligence Report",
    "compliance_summary":  "Compliance & Audit Summary",
}


# ─── Metrics collection ───────────────────────────────────────────────────────

async def _collect_metrics(db: AsyncSession, tenant_id: UUID, period_start: datetime, period_end: datetime) -> dict:
    tid = str(tenant_id)

    alert_row = (await db.execute(text("""
        SELECT
            COUNT(*)                                                        AS total,
            COUNT(*) FILTER (WHERE status = 'open')                         AS open,
            COUNT(*) FILTER (WHERE status = 'acknowledged')                 AS acknowledged,
            COUNT(*) FILTER (WHERE status = 'closed')                       AS closed,
            COUNT(*) FILTER (WHERE status = 'false_positive')               AS false_positive,
            COUNT(*) FILTER (WHERE severity = 'critical')                   AS critical,
            COUNT(*) FILTER (WHERE severity = 'high')                       AS high,
            COUNT(*) FILTER (WHERE severity = 'medium')                     AS medium,
            COUNT(*) FILTER (WHERE severity = 'low')                        AS low,
            AVG(EXTRACT(EPOCH FROM (acknowledged_at - created_at)) / 3600)
                FILTER (WHERE acknowledged_at IS NOT NULL)                  AS mtta_hours,
            AVG(EXTRACT(EPOCH FROM (closed_at - created_at)) / 3600)
                FILTER (WHERE closed_at IS NOT NULL)                        AS mttc_hours
        FROM alerts
        WHERE tenant_id = CAST(:tid AS uuid)
          AND created_at BETWEEN :start AND :end
          AND deleted_at IS NULL
    """), {"tid": tid, "start": period_start, "end": period_end})).fetchone()

    inv_row = (await db.execute(text("""
        SELECT
            COUNT(*)                                                        AS total,
            COUNT(*) FILTER (WHERE status NOT IN ('closed','resolved','false_positive')) AS open,
            COUNT(*) FILTER (WHERE confidence = 'high')                     AS high_confidence,
            AVG(threat_score)                                               AS avg_score
        FROM investigations
        WHERE tenant_id = CAST(:tid AS uuid)
          AND created_at BETWEEN :start AND :end
    """), {"tid": tid, "start": period_start, "end": period_end})).fetchone()

    agent_row = (await db.execute(text("""
        SELECT
            COUNT(*)                                      AS total,
            COUNT(*) FILTER (WHERE status = 'online')     AS online
        FROM agents
        WHERE tenant_id = CAST(:tid AS uuid)
          AND deleted_at IS NULL
    """), {"tid": tid})).fetchone()

    # Top MITRE techniques from alerts
    mitre_rows = (await db.execute(text("""
        SELECT jsonb_array_elements_text(mitre_techniques) AS technique, COUNT(*) AS cnt
        FROM alerts
        WHERE tenant_id = CAST(:tid AS uuid)
          AND created_at BETWEEN :start AND :end
          AND deleted_at IS NULL
          AND mitre_techniques IS NOT NULL
        GROUP BY technique
        ORDER BY cnt DESC
        LIMIT 5
    """), {"tid": tid, "start": period_start, "end": period_end})).fetchall()

    # Top affected hosts
    host_rows = (await db.execute(text("""
        SELECT source_host, COUNT(*) AS cnt
        FROM alerts
        WHERE tenant_id = CAST(:tid AS uuid)
          AND created_at BETWEEN :start AND :end
          AND deleted_at IS NULL
          AND source_host IS NOT NULL
        GROUP BY source_host
        ORDER BY cnt DESC
        LIMIT 5
    """), {"tid": tid, "start": period_start, "end": period_end})).fetchall()

    total_agents = agent_row.total or 0
    online_agents = agent_row.online or 0

    return {
        "alerts": {
            "total": alert_row.total or 0,
            "open": alert_row.open or 0,
            "acknowledged": alert_row.acknowledged or 0,
            "closed": alert_row.closed or 0,
            "false_positive": alert_row.false_positive or 0,
            "by_severity": {
                "critical": alert_row.critical or 0,
                "high": alert_row.high or 0,
                "medium": alert_row.medium or 0,
                "low": alert_row.low or 0,
            },
            "mtta_hours": round(float(alert_row.mtta_hours), 1) if alert_row.mtta_hours else None,
            "mttc_hours": round(float(alert_row.mttc_hours), 1) if alert_row.mttc_hours else None,
        },
        "investigations": {
            "total": inv_row.total or 0,
            "open": inv_row.open or 0,
            "high_confidence": inv_row.high_confidence or 0,
            "avg_threat_score": round(float(inv_row.avg_score), 1) if inv_row.avg_score else None,
        },
        "agents": {
            "total": total_agents,
            "online": online_agents,
            "coverage_pct": round(online_agents / total_agents * 100, 1) if total_agents else 0.0,
        },
        "top_techniques": [{"technique": r[0], "count": r[1]} for r in mitre_rows],
        "top_hosts": [{"host": r[0], "count": r[1]} for r in host_rows],
    }


# ─── LLM prompt builders ─────────────────────────────────────────────────────

def _metrics_summary(m: dict) -> str:
    a = m["alerts"]
    inv = m["investigations"]
    ag = m["agents"]
    lines = [
        f"- Total alerts: {a['total']} (critical: {a['by_severity']['critical']}, high: {a['by_severity']['high']}, medium: {a['by_severity']['medium']}, low: {a['by_severity']['low']})",
        f"- Open alerts: {a['open']} | Closed: {a['closed']} | False positives: {a['false_positive']}",
        f"- MTTA: {a['mtta_hours']}h | MTTC: {a['mttc_hours']}h" if a['mtta_hours'] else "- No acknowledged/closed alerts in period",
        f"- Investigations: {inv['total']} total, {inv['open']} open, {inv['high_confidence']} high-confidence",
        f"- Avg threat score: {inv['avg_threat_score']}/100" if inv['avg_threat_score'] else "",
        f"- Agent coverage: {ag['online']}/{ag['total']} agents online ({ag['coverage_pct']}%)",
    ]
    if m["top_techniques"]:
        techniques = ", ".join(f"{t['technique']} ({t['count']})" for t in m["top_techniques"])
        lines.append(f"- Top MITRE techniques: {techniques}")
    if m["top_hosts"]:
        hosts = ", ".join(f"{h['host']} ({h['count']} alerts)" for h in m["top_hosts"])
        lines.append(f"- Most targeted hosts: {hosts}")
    return "\n".join(l for l in lines if l)


def _build_prompt(report_type: str, company_name: str, period_days: int, metrics_text: str) -> tuple[str, str]:
    system = (
        "You are a senior cybersecurity analyst writing professional enterprise security reports. "
        "Write in clear, concise business English. Be specific — use the numbers provided. "
        "Each section should be 2-4 sentences of executive-quality prose. "
        "Return ONLY a JSON array of section objects with keys 'title' and 'content'. "
        "No markdown outside the JSON. No extra explanation."
    )

    if report_type == "executive_summary":
        prompt = f"""Write an Executive Security Summary for {company_name} covering the last {period_days} days.

Security metrics:
{metrics_text}

Return a JSON array with exactly these sections:
[
  {{"title": "Security Posture Overview", "content": "..."}},
  {{"title": "Key Incidents & Threats", "content": "..."}},
  {{"title": "Response Performance", "content": "..."}},
  {{"title": "Risk Assessment", "content": "..."}},
  {{"title": "Strategic Recommendations", "content": "..."}}
]"""

    elif report_type == "threat_report":
        prompt = f"""Write a Threat Intelligence Report for {company_name} covering the last {period_days} days.

Security metrics:
{metrics_text}

Return a JSON array with exactly these sections:
[
  {{"title": "Threat Landscape Summary", "content": "..."}},
  {{"title": "Attack Vector Analysis", "content": "..."}},
  {{"title": "Affected Assets & Exposure", "content": "..."}},
  {{"title": "MITRE ATT&CK Observations", "content": "..."}},
  {{"title": "Tactical Mitigations", "content": "..."}}
]"""

    else:  # compliance_summary
        prompt = f"""Write a Compliance & Audit Summary for {company_name} covering the last {period_days} days.

Security metrics:
{metrics_text}

Return a JSON array with exactly these sections:
[
  {{"title": "Monitoring & Detection Coverage", "content": "..."}},
  {{"title": "Incident Response Posture", "content": "..."}},
  {{"title": "Audit Trail Quality", "content": "..."}},
  {{"title": "Control Effectiveness", "content": "..."}},
  {{"title": "Remediation & Action Items", "content": "..."}}
]"""

    return system, prompt


def _parse_sections(raw: str) -> list[dict]:
    raw = raw.strip()
    # Strip markdown code fences if present
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()
    try:
        sections = json.loads(raw)
        if isinstance(sections, list):
            return [{"title": s.get("title", ""), "content": s.get("content", "")} for s in sections]
    except Exception:
        pass
    # Fallback: return raw as single section
    return [{"title": "Report", "content": raw}]


# ─── Background task ──────────────────────────────────────────────────────────

async def _generate_in_background(report_id: UUID, tenant_id: UUID, report_type: str,
                                   period_days: int, company_name: str) -> None:
    await asyncio.sleep(1)  # let the creating transaction commit
    from app.core.database import database_manager
    from app.ai.llm_manager import get_llm_manager

    async with database_manager.session() as db:
        try:
            from sqlalchemy import select
            result = await db.execute(
                select(GeneratedReport).where(GeneratedReport.id == report_id)
            )
            report = result.scalar_one_or_none()
            if report is None:
                return

            now = datetime.now(tz=timezone.utc)
            period_start = now - timedelta(days=period_days)

            metrics = await _collect_metrics(db, tenant_id, period_start, now)
            metrics_text = _metrics_summary(metrics)

            system_prompt, user_prompt = _build_prompt(report_type, company_name, period_days, metrics_text)

            llm = get_llm_manager()
            raw = await llm.generate(
                prompt=user_prompt,
                system_prompt=system_prompt,
                max_tokens=2048,
            )
            sections = _parse_sections(raw)

            report.sections = sections
            report.metrics = metrics
            report.status = "completed"
            await db.commit()
            log.info("report_generated", report_id=str(report_id), type=report_type)

        except Exception as exc:
            log.error("report_generation_failed", report_id=str(report_id), error=str(exc)[:300])
            try:
                from sqlalchemy import select, update
                await db.execute(
                    update(GeneratedReport)
                    .where(GeneratedReport.id == report_id)
                    .values(status="failed", error_message=str(exc)[:500])
                )
                await db.commit()
            except Exception:
                pass


# ─── Public API ───────────────────────────────────────────────────────────────

class ReportGeneratorService:

    @staticmethod
    async def generate(
        db: AsyncSession,
        tenant_id: UUID,
        report_type: str,
        period_days: int,
        company_name: str,
        created_by_id: UUID,
    ) -> GeneratedReport:
        now = datetime.now(tz=timezone.utc)
        period_start = now - timedelta(days=period_days)
        label = REPORT_TYPE_LABELS.get(report_type, "Security Report")
        title = f"{label} — {now.strftime('%b %d, %Y')}"

        report = GeneratedReport(
            tenant_id=tenant_id,
            report_type=report_type,
            title=title,
            status="generating",
            period_days=period_days,
            period_start=period_start,
            period_end=now,
            created_by_id=created_by_id,
        )
        db.add(report)
        await db.flush()

        asyncio.create_task(
            _generate_in_background(report.id, tenant_id, report_type, period_days, company_name)
        )
        return report
