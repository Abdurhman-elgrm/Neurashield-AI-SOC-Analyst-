"""
Email service — Resend (primary) with SMTP fallback.
Resend uses HTTPS so it works on Railway without port-blocking issues.
Never raises — email failure must never block business logic.
"""
from __future__ import annotations

import structlog
from app.core.config import get_settings

log = structlog.get_logger(__name__)


# ─── HTML wrapper ─────────────────────────────────────────────────────────────

def _html_wrapper(title: str, content: str, cta_url: str = "", cta_text: str = "") -> str:
    cta_block = ""
    if cta_url and cta_text:
        cta_block = f"""
        <div style="text-align:center;margin:28px 0;">
          <a href="{cta_url}" style="background:#6366F1;color:#ffffff;
             padding:12px 28px;border-radius:6px;text-decoration:none;
             font-weight:600;font-size:14px;display:inline-block;
             letter-spacing:0.3px;">
            {cta_text}
          </a>
        </div>"""

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
</head>
<body style="margin:0;padding:0;background:#0A0A0A;
             font-family:'Segoe UI',Helvetica,Arial,sans-serif;">
  <div style="max-width:540px;margin:40px auto;padding:0 16px;">

    <!-- Logo -->
    <div style="text-align:center;margin-bottom:28px;">
      <div style="font-size:22px;font-weight:800;color:#F5F7FA;
                  letter-spacing:-0.5px;">
        NEURA<span style="color:#6366F1;">SHIELD</span>
      </div>
      <div style="font-size:10px;color:#5C6373;margin-top:3px;
                  text-transform:uppercase;letter-spacing:2.5px;">
        AI SOC Platform
      </div>
    </div>

    <!-- Card -->
    <div style="background:#111318;border:1px solid rgba(255,255,255,0.08);
                border-radius:12px;padding:32px 28px;">
      <h2 style="color:#F5F7FA;font-size:17px;margin:0 0 20px;
                 font-weight:700;line-height:1.3;">
        {title}
      </h2>
      {content}
      {cta_block}
    </div>

    <!-- Footer -->
    <div style="text-align:center;margin-top:24px;padding-bottom:40px;">
      <p style="color:#3A4150;font-size:11px;margin:0;line-height:1.6;">
        NEURASHIELD AI SOC Platform &nbsp;&middot;&nbsp; Automated notification<br>
        You're receiving this as a workspace member.
      </p>
    </div>

  </div>
</body>
</html>"""


# ─── Internal send helper ─────────────────────────────────────────────────────

async def _send_email(
    to_email: str,
    subject: str,
    body_text: str,
    body_html: str = "",
) -> bool:
    """
    Try Resend first (HTTPS, works on Railway).
    Fall back to SMTP for local dev.
    Returns True on success.
    """
    settings = get_settings()

    # ── Brevo (HTTPS, no port-blocking issues) ───────────────────────────────
    if settings.BREVO_API_KEY:
        try:
            import httpx as _httpx
            from_email = settings.BREVO_FROM_EMAIL or settings.SMTP_FROM_EMAIL or settings.SMTP_USER
            payload: dict = {
                "sender":      {"name": "NEURASHIELD SOC", "email": from_email},
                "to":          [{"email": to_email}],
                "subject":     subject,
                "textContent": body_text,
            }
            if body_html:
                payload["htmlContent"] = body_html
            async with _httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    "https://api.brevo.com/v3/smtp/email",
                    headers={"api-key": settings.BREVO_API_KEY, "Content-Type": "application/json"},
                    json=payload,
                )
            if resp.status_code in (200, 201):
                log.info("email_sent_brevo", to=to_email, subject=subject[:60])
                return True
            log.warning("email_brevo_failed", to=to_email, status=resp.status_code, body=resp.text[:300])
            # fall through to next provider
        except Exception as exc:
            log.warning("email_brevo_error", to=to_email, error=str(exc))
            # fall through to next provider

    # ── Resend ────────────────────────────────────────────────────────────────
    if settings.RESEND_API_KEY:
        try:
            import resend as resend_sdk
            resend_sdk.api_key = settings.RESEND_API_KEY
            from_addr = settings.RESEND_FROM_EMAIL or "NEURASHIELD <onboarding@resend.dev>"
            params: dict = {"from": from_addr, "to": [to_email], "subject": subject, "text": body_text}
            if body_html:
                params["html"] = body_html
            resend_sdk.Emails.send(params)
            log.info("email_sent_resend", to=to_email, subject=subject[:60])
            return True
        except Exception as exc:
            log.warning("email_resend_error", to=to_email, error=str(exc))
            # fall through to SMTP

    # ── SMTP (Gmail app-password fallback) ────────────────────────────────────
    if settings.SMTP_HOST and settings.SMTP_USER and settings.SMTP_PASSWORD:
        try:
            import aiosmtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText

            from_addr = settings.SMTP_FROM_EMAIL or settings.SMTP_USER
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"]    = f"NEURASHIELD SOC <{from_addr}>"
            msg["To"]      = to_email
            msg.attach(MIMEText(body_text, "plain", "utf-8"))
            if body_html:
                msg.attach(MIMEText(body_html, "html", "utf-8"))

            await aiosmtplib.send(
                msg,
                hostname=settings.SMTP_HOST,
                port=int(settings.SMTP_PORT),
                username=settings.SMTP_USER,
                password=settings.SMTP_PASSWORD,
                use_tls=int(settings.SMTP_PORT) == 465,
                start_tls=int(settings.SMTP_PORT) == 587,
                timeout=15,
            )
            log.info("email_sent_smtp", to=to_email, subject=subject[:60])
            return True
        except Exception as exc:
            log.warning("email_smtp_error", to=to_email, error=str(exc))

    log.warning("email_all_providers_failed", to=to_email, subject=subject[:80])
    return False


# ─── Public email functions ───────────────────────────────────────────────────

async def send_verification_email(
    to_email: str,
    full_name: str,
    verify_url: str,
) -> bool:
    subject = "Verify your NEURASHIELD account"

    body_text = f"""Hi {full_name},

Welcome to NEURASHIELD SOC Platform!

Please verify your email address to activate your account:
{verify_url}

This link expires in 24 hours.

If you did not create this account, you can safely ignore this email.

-- NEURASHIELD SOC Platform
"""

    content_html = f"""
<p style="color:#B8C0CC;font-size:14px;line-height:1.7;margin:0 0 20px;">
  Hi <strong style="color:#F5F7FA;">{full_name}</strong>,<br>
  Welcome to NEURASHIELD SOC Platform. Please verify your email address
  to complete your account setup.
</p>
<div style="background:rgba(99,102,241,0.08);
            border:1px solid rgba(99,102,241,0.2);
            border-radius:8px;padding:14px 16px;margin-bottom:20px;">
  <div style="font-size:11px;color:#5C6373;text-transform:uppercase;
              letter-spacing:1px;margin-bottom:4px;">Account email</div>
  <div style="font-size:14px;font-weight:600;color:#F5F7FA;">{to_email}</div>
</div>
<p style="color:#5C6373;font-size:12px;line-height:1.6;margin:0;">
  This link expires in 24 hours.<br>
  If you did not create this account, you can safely ignore this email.
</p>
"""
    body_html = _html_wrapper(
        title="Verify your email address",
        content=content_html,
        cta_url=verify_url,
        cta_text="Verify Email Address",
    )
    return await _send_email(to_email, subject, body_text, body_html)


async def send_invitation_email(
    to_email: str,
    invited_by_name: str,
    tenant_name: str,
    accept_url: str,
    role: str = "analyst",
    expires_hours: int = 48,
) -> bool:
    subject = f"You're invited to join {tenant_name} on NEURASHIELD"

    body_text = f"""Hi,

{invited_by_name} has invited you to join {tenant_name} on NEURASHIELD SOC Platform.

Role: {role.capitalize()}

Accept your invitation:
{accept_url}

This invitation expires in {expires_hours} hours.

-- NEURASHIELD SOC Platform
"""

    content_html = f"""
<p style="color:#B8C0CC;font-size:14px;line-height:1.7;margin:0 0 20px;">
  <strong style="color:#F5F7FA;">{invited_by_name}</strong> has invited
  you to join <strong style="color:#F5F7FA;">{tenant_name}</strong>
  on NEURASHIELD SOC Platform.
</p>
<div style="background:rgba(99,102,241,0.1);
            border:1px solid rgba(99,102,241,0.25);
            border-radius:8px;padding:14px 16px;margin-bottom:20px;">
  <div style="font-size:11px;color:#5C6373;text-transform:uppercase;
              letter-spacing:1px;margin-bottom:4px;">Your role</div>
  <div style="font-size:14px;font-weight:600;color:#F5F7FA;
              text-transform:capitalize;">{role}</div>
</div>
<p style="color:#5C6373;font-size:12px;line-height:1.6;margin:0;">
  This invitation expires in {expires_hours} hours.<br>
  If you already have an account, you'll be asked to sign in.
</p>
"""
    body_html = _html_wrapper(
        title=f"You're invited to {tenant_name}",
        content=content_html,
        cta_url=accept_url,
        cta_text="Accept Invitation →",
    )
    return await _send_email(to_email, subject, body_text, body_html)


async def send_alert_email(
    to_email: str,
    recipient_name: str,
    alert_title: str,
    severity: str,
    source_host: str | None,
    mitre_technique: str | None,
    recommended_action: str | None,
    alert_url: str,
) -> bool:
    severity_upper = severity.upper()
    sev_colors: dict[str, tuple[str, str]] = {
        "CRITICAL": ("#EF4444", "rgba(239,68,68,0.15)"),
        "HIGH":     ("#F97316", "rgba(249,115,22,0.15)"),
        "MEDIUM":   ("#F59E0B", "rgba(245,158,11,0.15)"),
        "LOW":      ("#3B82F6", "rgba(59,130,246,0.15)"),
    }
    sev_color, sev_bg = sev_colors.get(severity_upper, ("#6366F1", "rgba(99,102,241,0.15)"))

    subject = f"[{severity_upper}] Security Alert: {alert_title}"
    body_text = (
        f"Security alert on {source_host or 'unknown host'}: {alert_title}\n"
        f"View: {alert_url}"
    )

    rows: list[tuple[str, str]] = []
    if source_host:
        rows.append(("Host", source_host))
    if mitre_technique:
        rows.append(("MITRE Technique", mitre_technique))
    if recommended_action:
        rows.append(("Recommended Action", recommended_action))

    rows_html = "".join(f"""
    <div style="display:flex;justify-content:space-between;
                padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.05);">
      <span style="color:#5C6373;font-size:12px;">{k}</span>
      <span style="color:#F5F7FA;font-size:12px;font-weight:500;">{v}</span>
    </div>""" for k, v in rows)

    content_html = f"""
<div style="display:inline-block;padding:4px 12px;border-radius:4px;
            background:{sev_bg};border:1px solid {sev_color}33;
            color:{sev_color};font-size:11px;font-weight:700;
            letter-spacing:1px;margin-bottom:20px;">
  {severity_upper}
</div>
<p style="color:#F5F7FA;font-size:15px;font-weight:600;
          margin:0 0 20px;line-height:1.4;">
  {alert_title}
</p>
<div style="border:1px solid rgba(255,255,255,0.06);
            border-radius:8px;padding:0 16px;margin-bottom:8px;">
  {rows_html}
</div>
"""
    body_html = _html_wrapper(
        title="Security Alert Detected",
        content=content_html,
        cta_url=alert_url,
        cta_text="View Alert →",
    )
    return await _send_email(to_email, subject, body_text, body_html)


async def send_agent_offline_email(
    to_email: str,
    recipient_name: str,
    hostname: str,
    last_seen: str,
    agents_url: str,
) -> bool:
    subject = f"Agent Offline: {hostname}"
    body_text = f"Agent {hostname} went offline. Last seen: {last_seen}\nView: {agents_url}"

    content_html = f"""
<div style="background:rgba(249,115,22,0.1);border:1px solid rgba(249,115,22,0.25);
            border-radius:8px;padding:16px;margin-bottom:20px;">
  <div style="font-size:11px;color:#5C6373;text-transform:uppercase;
              letter-spacing:1px;margin-bottom:6px;">Offline Device</div>
  <div style="font-size:18px;font-weight:700;color:#F5F7FA;
              font-family:'Courier New',monospace;">
    {hostname}
  </div>
  <div style="font-size:12px;color:#F97316;margin-top:6px;">
    Last seen: {last_seen}
  </div>
</div>
<p style="color:#B8C0CC;font-size:13px;line-height:1.6;margin:0;">
  This may indicate a network issue, system shutdown, or agent process termination.
</p>
"""
    body_html = _html_wrapper(
        title="⚠️ Agent Went Offline",
        content=content_html,
        cta_url=agents_url,
        cta_text="View Agents →",
    )
    return await _send_email(to_email, subject, body_text, body_html)


async def send_password_reset_email(
    to_email: str,
    full_name: str,
    reset_url: str,
) -> bool:
    subject = "Reset your NEURASHIELD password"

    body_text = f"""Hi {full_name},

We received a request to reset the password for your NEURASHIELD account.

Reset your password here:
{reset_url}

This link expires in 1 hour.

If you did not request a password reset, you can safely ignore this email.
Your password will not be changed.

-- NEURASHIELD SOC Platform
"""

    content_html = f"""
<p style="color:#B8C0CC;font-size:14px;line-height:1.7;margin:0 0 20px;">
  Hi <strong style="color:#F5F7FA;">{full_name}</strong>,<br>
  We received a request to reset the password for your NEURASHIELD account.
  Click the button below to set a new password.
</p>
<div style="background:rgba(239,68,68,0.08);
            border:1px solid rgba(239,68,68,0.2);
            border-radius:8px;padding:14px 16px;margin-bottom:20px;">
  <div style="font-size:11px;color:#5C6373;text-transform:uppercase;
              letter-spacing:1px;margin-bottom:4px;">Account</div>
  <div style="font-size:14px;font-weight:600;color:#F5F7FA;">{to_email}</div>
</div>
<p style="color:#5C6373;font-size:12px;line-height:1.6;margin:0;">
  This link expires in 1 hour.<br>
  If you did not request a password reset, no action is needed — your password
  will not be changed.
</p>
"""
    body_html = _html_wrapper(
        title="Reset your password",
        content=content_html,
        cta_url=reset_url,
        cta_text="Reset Password →",
    )
    return await _send_email(to_email, subject, body_text, body_html)


async def send_investigation_email(
    to_email: str,
    recipient_name: str,
    investigation_title: str,
    threat_score: int,
    verdict_suggestion: str | None,
    investigation_url: str,
) -> bool:
    subject = f"New Investigation: {investigation_title}"

    verdict_map = {
        "true_positive":       ("Likely True Positive",  "#EF4444", "rgba(239,68,68,0.12)"),
        "false_positive":      ("Likely False Positive",  "#10B981", "rgba(16,185,129,0.12)"),
        "needs_investigation": ("Needs Investigation",    "#F59E0B", "rgba(245,158,11,0.12)"),
    }

    verdict_html = ""
    verdict_text = ""
    if verdict_suggestion and verdict_suggestion in verdict_map:
        label, color, bg = verdict_map[verdict_suggestion]
        verdict_html = f"""
<div style="display:inline-block;padding:4px 12px;border-radius:4px;
            background:{bg};border:1px solid {color}33;
            color:{color};font-size:11px;font-weight:700;
            letter-spacing:0.5px;margin-bottom:16px;">
  {label}
</div>"""
        verdict_text = f"\nAI Verdict: {label}"

    bar_pct = min(100, max(0, threat_score))
    bar_color = "#EF4444" if bar_pct >= 75 else "#F59E0B" if bar_pct >= 50 else "#3B82F6"

    body_text = (
        f"New investigation: {investigation_title}\n"
        f"Threat Score: {threat_score}/100{verdict_text}\n"
        f"Review: {investigation_url}"
    )

    content_html = f"""
<p style="color:#B8C0CC;font-size:14px;line-height:1.6;margin:0 0 20px;">
  {investigation_title}
</p>
{verdict_html}
<div style="margin-bottom:20px;">
  <div style="display:flex;justify-content:space-between;margin-bottom:6px;">
    <span style="font-size:11px;color:#5C6373;text-transform:uppercase;
                 letter-spacing:1px;">Threat Score</span>
    <span style="font-size:13px;font-weight:700;color:{bar_color};">{threat_score}/100</span>
  </div>
  <div style="background:rgba(255,255,255,0.06);border-radius:3px;height:6px;">
    <div style="background:{bar_color};width:{bar_pct}%;height:6px;
                border-radius:3px;"></div>
  </div>
</div>
"""
    body_html = _html_wrapper(
        title="New Security Investigation",
        content=content_html,
        cta_url=investigation_url,
        cta_text="Review Investigation →",
    )
    return await _send_email(to_email, subject, body_text, body_html)
