"""
Notification service — dispatches email notifications for security events.
All functions open their own DB sessions and are safe to run as background tasks.
Never raises — email failure must never block the pipeline.
"""

from __future__ import annotations

from uuid import UUID

import structlog

log = structlog.get_logger(__name__)


async def notify_alert_email(
    alert_id: str,
    tenant_id: UUID,
    alert_title: str,
    severity: str,
    source_host: str | None,
    ai_metadata: dict | None,
) -> None:
    """Send HIGH/CRITICAL alert emails to all members who opted in."""
    try:
        from sqlalchemy import select

        from app.core.config import get_settings
        from app.core.database import database_manager
        from app.models.tenant_member import TenantMember
        from app.models.user import User
        from app.services.email_service import send_alert_email

        settings = get_settings()
        alert_url = f"{settings.FRONTEND_URL}/alerts"

        ai = (ai_metadata or {}).get("ai_analysis", {})
        mitre = ai.get("mitre_technique")
        action = ai.get("recommended_action")

        async with database_manager.session() as db:
            result = await db.execute(
                select(TenantMember, User)
                .join(User, TenantMember.user_id == User.id)
                .where(
                    TenantMember.tenant_id == tenant_id,
                    TenantMember.deleted_at.is_(None),
                )
            )
            for member, user in result.fetchall():
                prefs = member.notification_preferences or {}
                if prefs.get("email_high_critical_alerts", True):
                    await send_alert_email(
                        to_email=user.email,
                        recipient_name=user.full_name or user.email,
                        alert_title=alert_title,
                        severity=severity,
                        source_host=source_host,
                        mitre_technique=mitre,
                        recommended_action=action,
                        alert_url=alert_url,
                    )
    except Exception:
        log.warning("notify_alert_email_failed", alert_id=alert_id, exc_info=True)


async def notify_agent_offline_email(
    agent_id: str,
    hostname: str,
    tenant_id: UUID,
    last_seen: str,
) -> None:
    """Send agent-offline emails to all members who opted in."""
    try:
        from sqlalchemy import select

        from app.core.config import get_settings
        from app.core.database import database_manager
        from app.models.tenant_member import TenantMember
        from app.models.user import User
        from app.services.email_service import send_agent_offline_email

        settings = get_settings()
        agents_url = f"{settings.FRONTEND_URL}/agents"

        async with database_manager.session() as db:
            result = await db.execute(
                select(TenantMember, User)
                .join(User, TenantMember.user_id == User.id)
                .where(
                    TenantMember.tenant_id == tenant_id,
                    TenantMember.deleted_at.is_(None),
                )
            )
            for member, user in result.fetchall():
                prefs = member.notification_preferences or {}
                if prefs.get("email_agent_offline", True):
                    await send_agent_offline_email(
                        to_email=user.email,
                        recipient_name=user.full_name or user.email,
                        hostname=hostname,
                        last_seen=last_seen,
                        agents_url=agents_url,
                    )
    except Exception:
        log.warning("notify_agent_offline_failed", agent_id=agent_id, exc_info=True)


async def notify_investigation_email(
    investigation_id: str,
    tenant_id: str,
    title: str,
    threat_score: int,
    verdict_suggestion: str | None,
) -> None:
    """Send new-investigation emails to all members who opted in."""
    try:
        from sqlalchemy import select

        from app.core.config import get_settings
        from app.core.database import database_manager
        from app.models.tenant_member import TenantMember
        from app.models.user import User
        from app.services.email_service import send_investigation_email

        settings = get_settings()
        inv_url = f"{settings.FRONTEND_URL}/investigations/{investigation_id}"

        try:
            tenant_uuid = UUID(tenant_id)
        except ValueError:
            return

        async with database_manager.session() as db:
            result = await db.execute(
                select(TenantMember, User)
                .join(User, TenantMember.user_id == User.id)
                .where(
                    TenantMember.tenant_id == tenant_uuid,
                    TenantMember.deleted_at.is_(None),
                )
            )
            for member, user in result.fetchall():
                prefs = member.notification_preferences or {}
                if prefs.get("email_new_investigation", False):
                    await send_investigation_email(
                        to_email=user.email,
                        recipient_name=user.full_name or user.email,
                        investigation_title=title,
                        threat_score=threat_score,
                        verdict_suggestion=verdict_suggestion,
                        investigation_url=inv_url,
                    )
    except Exception:
        log.warning(
            "notify_investigation_failed",
            investigation_id=investigation_id,
            exc_info=True,
        )
