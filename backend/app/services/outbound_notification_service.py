"""
Outbound notification dispatcher — sends alert notifications to configured
channels (Slack, Microsoft Teams, generic webhook, PagerDuty, email).

Never raises — channel delivery failure must never block the detection pipeline.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from uuid import UUID

import structlog

log = structlog.get_logger(__name__)

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_PAGERDUTY_SEVERITY_MAP = {
    "critical": "critical",
    "high": "error",
    "medium": "warning",
    "low": "info",
}
_SEV_COLORS = {
    "critical": "#EF4444",
    "high":     "#F97316",
    "medium":   "#F59E0B",
    "low":      "#3B82F6",
}


async def dispatch_alert_to_channels(
    tenant_id: UUID,
    alert_id: str,
    title: str,
    severity: str,
    source_host: str | None,
    mitre_techniques: list[str] | None,
    created_at: datetime | None,
) -> None:
    """
    Load all enabled notification channels for the tenant and dispatch
    the alert to each one that meets the min_severity threshold.
    Non-blocking — all failures are swallowed and logged.
    """
    try:
        from app.core.database import database_manager
        from app.models.notification_channel import NotificationChannel
        from sqlalchemy import select

        async with database_manager.session() as db:
            result = await db.execute(
                select(NotificationChannel).where(
                    NotificationChannel.tenant_id == tenant_id,
                    NotificationChannel.enabled.is_(True),
                    NotificationChannel.deleted_at.is_(None),
                )
            )
            channels = list(result.scalars().all())

        sev_rank = _SEVERITY_RANK.get(severity.lower(), 0)
        for channel in channels:
            min_rank = _SEVERITY_RANK.get(channel.min_severity.lower(), 3)
            if sev_rank < min_rank:
                continue
            try:
                await _dispatch_to_channel(
                    channel_type=channel.type,
                    config=dict(channel.config),
                    alert_id=alert_id,
                    title=title,
                    severity=severity,
                    source_host=source_host,
                    mitre_techniques=mitre_techniques or [],
                    created_at=created_at or datetime.now(tz=timezone.utc),
                )
            except Exception as exc:
                log.warning(
                    "outbound_channel_dispatch_failed",
                    channel_id=str(channel.id),
                    channel_type=channel.type,
                    error=str(exc),
                )
    except Exception as exc:
        log.warning("outbound_dispatch_failed", tenant_id=str(tenant_id), error=str(exc))


async def dispatch_test_notification(channel: object) -> bool:
    """Send a test message to a channel config. Returns True on success."""
    from app.models.notification_channel import NotificationChannel
    ch: NotificationChannel = channel  # type: ignore
    try:
        await _dispatch_to_channel(
            channel_type=ch.type,
            config=dict(ch.config),
            alert_id="TEST-000",
            title="NEURASHIELD Test Notification",
            severity="medium",
            source_host="test-host",
            mitre_techniques=["T1078"],
            created_at=datetime.now(tz=timezone.utc),
            is_test=True,
        )
        return True
    except Exception as exc:
        log.warning("test_notification_failed", channel_type=ch.type, error=str(exc))
        return False


async def _dispatch_to_channel(
    channel_type: str,
    config: dict,
    alert_id: str,
    title: str,
    severity: str,
    source_host: str | None,
    mitre_techniques: list[str],
    created_at: datetime,
    is_test: bool = False,
) -> None:
    if channel_type == "slack":
        await _send_slack(config, alert_id, title, severity, source_host, mitre_techniques, is_test)
    elif channel_type == "teams":
        await _send_teams(config, alert_id, title, severity, source_host, mitre_techniques, is_test)
    elif channel_type == "webhook":
        await _send_webhook(config, alert_id, title, severity, source_host, mitre_techniques, created_at, is_test)
    elif channel_type == "pagerduty":
        await _send_pagerduty(config, alert_id, title, severity, source_host, mitre_techniques, is_test)
    elif channel_type == "email":
        await _send_email_channel(config, alert_id, title, severity, source_host, mitre_techniques, is_test)


async def _send_slack(
    config: dict,
    alert_id: str,
    title: str,
    severity: str,
    source_host: str | None,
    mitre_techniques: list[str],
    is_test: bool,
) -> None:
    import httpx
    webhook_url = config["webhook_url"]
    sev_upper = severity.upper()
    color = _SEV_COLORS.get(severity.lower(), "#6366F1")
    prefix = "[TEST] " if is_test else ""

    fields = [{"type": "mrkdwn", "text": f"*Severity*\n{sev_upper}"}]
    if source_host:
        fields.append({"type": "mrkdwn", "text": f"*Host*\n`{source_host}`"})
    if mitre_techniques:
        fields.append({"type": "mrkdwn", "text": f"*MITRE*\n{', '.join(mitre_techniques[:3])}"})

    payload = {
        "attachments": [{
            "color": color,
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*{prefix}Security Alert — {sev_upper}*\n{title}",
                    },
                },
                {
                    "type": "section",
                    "fields": fields,
                },
                {
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": f"Alert ID: `{alert_id}` · NEURASHIELD SOC"}],
                },
            ],
        }]
    }

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(webhook_url, json=payload)
    if resp.status_code != 200:
        raise RuntimeError(f"Slack webhook returned {resp.status_code}: {resp.text[:200]}")
    log.info("slack_notification_sent", alert_id=alert_id, is_test=is_test)


async def _send_teams(
    config: dict,
    alert_id: str,
    title: str,
    severity: str,
    source_host: str | None,
    mitre_techniques: list[str],
    is_test: bool,
) -> None:
    import httpx
    webhook_url = config["webhook_url"]
    sev_upper = severity.upper()
    color = _SEV_COLORS.get(severity.lower(), "#6366F1").lstrip("#")
    prefix = "[TEST] " if is_test else ""

    facts = [{"name": "Severity", "value": sev_upper}]
    if source_host:
        facts.append({"name": "Host", "value": source_host})
    if mitre_techniques:
        facts.append({"name": "MITRE", "value": ", ".join(mitre_techniques[:3])})
    facts.append({"name": "Alert ID", "value": alert_id})

    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": color,
        "summary": f"{prefix}Security Alert — {sev_upper}: {title}",
        "sections": [{
            "activityTitle": f"{prefix}Security Alert — {sev_upper}",
            "activityText": title,
            "facts": facts,
        }],
    }

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(webhook_url, json=payload)
    if resp.status_code != 200:
        raise RuntimeError(f"Teams webhook returned {resp.status_code}: {resp.text[:200]}")
    log.info("teams_notification_sent", alert_id=alert_id, is_test=is_test)


async def _send_webhook(
    config: dict,
    alert_id: str,
    title: str,
    severity: str,
    source_host: str | None,
    mitre_techniques: list[str],
    created_at: datetime,
    is_test: bool,
) -> None:
    import httpx
    url = config["url"]
    secret = config.get("secret", "")
    extra_headers: dict = config.get("headers", {})

    body = {
        "alert_id": alert_id,
        "title": title,
        "severity": severity,
        "source_host": source_host,
        "mitre_techniques": mitre_techniques,
        "timestamp": created_at.isoformat(),
        "platform": "neurashield",
        "is_test": is_test,
    }
    body_bytes = json.dumps(body, separators=(",", ":")).encode()

    headers = {"Content-Type": "application/json", **extra_headers}
    if secret:
        sig = hmac.new(secret.encode(), body_bytes, hashlib.sha256).hexdigest()
        headers["X-Neurashield-Signature"] = f"sha256={sig}"

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(url, content=body_bytes, headers=headers)
    if resp.status_code >= 400:
        raise RuntimeError(f"Webhook returned {resp.status_code}: {resp.text[:200]}")
    log.info("webhook_notification_sent", alert_id=alert_id, is_test=is_test)


async def _send_pagerduty(
    config: dict,
    alert_id: str,
    title: str,
    severity: str,
    source_host: str | None,
    mitre_techniques: list[str],
    is_test: bool,
) -> None:
    import httpx
    integration_key = config["integration_key"]
    pd_severity = _PAGERDUTY_SEVERITY_MAP.get(severity.lower(), "error")

    payload = {
        "routing_key": integration_key,
        "event_action": "trigger",
        "dedup_key": f"neurashield-{alert_id}",
        "payload": {
            "summary": f"[{'TEST - ' if is_test else ''}NEURASHIELD] {title}",
            "severity": pd_severity,
            "source": source_host or "neurashield",
            "custom_details": {
                "alert_id": alert_id,
                "severity": severity,
                "mitre_techniques": mitre_techniques,
            },
        },
    }

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            "https://events.pagerduty.com/v2/enqueue",
            json=payload,
            headers={"Content-Type": "application/json"},
        )
    if resp.status_code not in (200, 202):
        raise RuntimeError(f"PagerDuty returned {resp.status_code}: {resp.text[:200]}")
    log.info("pagerduty_notification_sent", alert_id=alert_id, is_test=is_test)


async def _send_email_channel(
    config: dict,
    alert_id: str,
    title: str,
    severity: str,
    source_host: str | None,
    mitre_techniques: list[str],
    is_test: bool,
) -> None:
    from app.core.config import get_settings
    from app.services.email_service import send_alert_email

    settings = get_settings()
    recipients: list[str] = config.get("recipients", [])
    prefix = "[TEST] " if is_test else ""
    alert_url = f"{settings.FRONTEND_URL}/alerts"
    mitre = ", ".join(mitre_techniques[:3]) if mitre_techniques else None

    for email in recipients:
        await send_alert_email(
            to_email=email,
            recipient_name=email,
            alert_title=f"{prefix}{title}",
            severity=severity,
            source_host=source_host,
            mitre_technique=mitre,
            recommended_action=None,
            alert_url=alert_url,
        )
    log.info("email_channel_notification_sent", alert_id=alert_id, recipient_count=len(recipients), is_test=is_test)
