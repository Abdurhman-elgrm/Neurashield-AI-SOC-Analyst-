from __future__ import annotations

from uuid import UUID

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.analyzer import _sanitize_field

log = structlog.get_logger(__name__)

CHAT_MODES = {
    "deep_dive": {
        "label": "Deep Dive",
        "instruction": "Perform deep technical analysis. Explain attack chain, TTPs, and timeline. Be thorough and technical.",
    },
    "threat_actor": {
        "label": "Threat Actor",
        "instruction": "Profile the threat actor based on observed TTPs. Map to known APT groups if applicable. Focus on attribution indicators.",
    },
    "false_positive": {
        "label": "False Positive",
        "instruction": "Help the analyst determine if this is a false positive. List reasons it could be benign vs malicious. Give a verdict with confidence.",
    },
}


async def build_soc_context(
    db: AsyncSession,
    tenant_id: UUID,
    investigation_id: UUID | None = None,
) -> dict:
    """Query live SOC state for context injection. Never raises — returns partial on error."""
    from app.models.agent import Agent, AgentStatus
    from app.models.alert import Alert, AlertSeverity, AlertStatus
    from app.models.investigation import Investigation

    context: dict = {}

    # 1. Recent high/critical open alerts
    try:
        result = await db.execute(
            select(Alert)
            .where(
                Alert.tenant_id == tenant_id,
                Alert.severity.in_([AlertSeverity.HIGH, AlertSeverity.CRITICAL]),
                Alert.status == AlertStatus.OPEN,
            )
            .order_by(Alert.created_at.desc())
            .limit(5)
        )
        alerts = result.scalars().all()
        context["alerts"] = [
            {
                "id": str(a.id),
                "title": a.title,
                "severity": a.severity.value if hasattr(a.severity, "value") else str(a.severity),
                "host": a.source_host or "unknown",
            }
            for a in alerts
        ]
    except Exception:
        log.warning("soc_context_alerts_failed", exc_info=True)
        context["alerts"] = []

    # 2. Active investigations
    try:
        result = await db.execute(
            select(Investigation)
            .where(
                Investigation.tenant_id == tenant_id,
                Investigation.status.not_in(["closed", "false_positive"]),
            )
            .order_by(Investigation.created_at.desc())
            .limit(3)
        )
        investigations = result.scalars().all()
        context["investigations"] = [
            {
                "id": str(inv.id),
                "title": inv.title or f"Investigation {inv.investigation_group_id[:8]}",
                "status": inv.status,
            }
            for inv in investigations
        ]
    except Exception:
        log.warning("soc_context_investigations_failed", exc_info=True)
        context["investigations"] = []

    # 3. Agent counts by status
    try:
        result = await db.execute(
            select(Agent.status, func.count(Agent.id).label("count"))
            .where(Agent.tenant_id == tenant_id)
            .group_by(Agent.status)
        )
        rows = result.all()
        online = sum(r.count for r in rows if str(r.status) in ("online", AgentStatus.ONLINE.value))
        offline = sum(
            r.count for r in rows if str(r.status) not in ("online", AgentStatus.ONLINE.value)
        )
        context["agents"] = {"online": online, "offline": offline}
    except Exception:
        log.warning("soc_context_agents_failed", exc_info=True)
        context["agents"] = {"online": 0, "offline": 0}

    # 4. Current investigation detail
    if investigation_id:
        try:
            result = await db.execute(
                select(Investigation).where(
                    Investigation.id == investigation_id,
                    Investigation.tenant_id == tenant_id,
                )
            )
            inv = result.scalar_one_or_none()
            if inv:
                behaviors: list = []
                if inv.behaviors_json and isinstance(inv.behaviors_json, list):
                    behaviors = inv.behaviors_json[:5]
                context["current_investigation"] = {
                    "id": str(inv.id),
                    "title": inv.title or f"Investigation {inv.investigation_group_id[:8]}",
                    "status": inv.status,
                    "verdict": inv.verdict,
                    "behaviors": behaviors,
                }
        except Exception:
            log.warning("soc_context_current_inv_failed", exc_info=True)

    return context


def build_system_prompt(mode: str, soc_context: dict, history_text: str = "") -> str:
    mode_config = CHAT_MODES.get(mode, CHAT_MODES["deep_dive"])

    # Sanitize DB-sourced values before embedding in system prompt
    sanitized_alerts = [
        {
            **a,
            "title": _sanitize_field(a.get("title", ""), max_len=100) or "(untitled)",
            "host": _sanitize_field(a.get("host", ""), max_len=50) or "unknown",
        }
        for a in soc_context.get("alerts", [])
    ]
    sanitized_investigations = [
        {
            **i,
            "title": _sanitize_field(i.get("title", ""), max_len=100) or "(untitled)",
        }
        for i in soc_context.get("investigations", [])
    ]

    alerts_text = (
        "\n".join(
            f"  - [{a['severity'].upper()}] {a['title']} on {a.get('host', 'unknown')}"
            for a in sanitized_alerts
        )
        or "  None"
    )

    investigations_text = (
        "\n".join(f"  - {i['title']} ({i['status']})" for i in sanitized_investigations) or "  None"
    )

    agents = soc_context.get("agents", {})

    current_inv = ""
    if soc_context.get("current_investigation"):
        inv = soc_context["current_investigation"]
        current_inv = f"\nCurrent Investigation: {inv['title']} [{inv['status']}]"
        if inv.get("verdict"):
            current_inv += f" | Verdict: {inv['verdict']}"

    history_section = ""
    if history_text:
        history_section = f"\n## Recent Conversation\n{history_text}\n"

    return f"""You are NEURASHIELD, an expert AI SOC analyst assistant.

## Current SOC State
Open Critical/High Alerts:
{alerts_text}

Active Investigations:
{investigations_text}

Agents: {agents.get("online", 0)} online, {agents.get("offline", 0)} offline
{current_inv}

## Your Task
Mode: {mode_config["label"]}
{mode_config["instruction"]}

Be concise, technical, and actionable. Use markdown for formatting when helpful.
Reference specific alerts or investigations from context when relevant.{history_section}"""
