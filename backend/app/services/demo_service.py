"""
Demo mode service — creates the demo tenant + user if not present,
seeds the entire database with realistic data for every page, and
issues a token pair without any password check.

The demo account is completely isolated from real tenants.
Demo data resets automatically every 24 h when demo_login() is called.
"""
from __future__ import annotations

import random
import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import structlog
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, create_refresh_token, hash_password
from app.models.agent import Agent, AgentOsType, AgentStatus, ContainmentState
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.audit_log import AuditLog
from app.models.detection_rule import DetectionRule, RuleSeverity, RuleType
from app.models.heartbeat import Heartbeat
from app.models.investigation import Investigation
from app.models.playbook import Playbook, PlaybookStep
from app.models.refresh_token import RefreshToken
from app.models.suppression_rule import SuppressionRule
from app.models.tenant import Tenant
from app.models.tenant_member import TenantMember
from app.models.user import User
from app.schemas.auth import TokenPair

logger = structlog.get_logger(__name__)

# ─── Demo constants ───────────────────────────────────────────────────────────

DEMO_TENANT_SLUG  = "neurashield-demo"
DEMO_USER_EMAIL   = "demo@neurashield.io"
DEMO_USER_NAME    = "Demo Analyst"
DEMO_TENANT_NAME  = "NEURASHIELD Demo"
DEMO_RESEED_HOURS = 24

_NOW = lambda: datetime.now(timezone.utc)
_AGO = lambda **kw: datetime.now(timezone.utc) - timedelta(**kw)


def _rand_ip() -> str:
    return f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"


# ─── Main entry point ─────────────────────────────────────────────────────────

async def demo_login(db: AsyncSession) -> TokenPair:
    """
    Return a valid token pair for the demo user.
    Creates tenant + user + full seed data on first call.
    Reseeds all data after DEMO_RESEED_HOURS.
    """
    tenant = await _get_or_create_tenant(db)
    user   = await _get_or_create_user(db, tenant)

    # Reseed check: newest alert age
    needs_reseed = True
    result = await db.execute(
        select(Alert.created_at)
        .where(Alert.tenant_id == tenant.id)
        .order_by(Alert.created_at.desc())
        .limit(1)
    )
    latest = result.scalar_one_or_none()
    if latest is not None:
        if latest.tzinfo is None:
            latest = latest.replace(tzinfo=timezone.utc)
        needs_reseed = (_NOW() - latest).total_seconds() > DEMO_RESEED_HOURS * 3600

    if needs_reseed:
        logger.info("demo_reseed_start", tenant_id=str(tenant.id))
        await _wipe_tenant_data(db, str(tenant.id))
        await _seed_all(db, tenant, user)
        logger.info("demo_reseed_done", tenant_id=str(tenant.id))

    # Issue tokens — skip all credential checks
    access_token       = create_access_token(str(user.id), {"email_verified": True})
    refresh_token, jti = create_refresh_token(str(user.id))

    db.add(RefreshToken(
        id=uuid4(), user_id=user.id, jti=jti,
        expires_at=_NOW() + timedelta(days=7),
    ))
    await db.commit()

    return TokenPair(access_token=access_token, refresh_token=refresh_token)


# ─── Tenant / user helpers ────────────────────────────────────────────────────

async def _get_or_create_tenant(db: AsyncSession) -> Tenant:
    res = await db.execute(select(Tenant).where(Tenant.slug == DEMO_TENANT_SLUG))
    tenant = res.scalar_one_or_none()
    if tenant is None:
        tenant = Tenant(
            id=uuid4(), name=DEMO_TENANT_NAME, slug=DEMO_TENANT_SLUG,
            is_active=True, timezone="UTC",
        )
        db.add(tenant)
        await db.flush()
    return tenant


async def _get_or_create_user(db: AsyncSession, tenant: Tenant) -> User:
    res = await db.execute(select(User).where(User.email == DEMO_USER_EMAIL))
    user = res.scalar_one_or_none()
    if user is None:
        user = User(
            id=uuid4(), email=DEMO_USER_EMAIL,
            password_hash=hash_password(secrets.token_hex(32)),
            full_name=DEMO_USER_NAME, is_active=True,
            email_verified=True, job_title="Senior SOC Analyst",
        )
        db.add(user)
        await db.flush()

    # Ensure membership
    res2 = await db.execute(
        select(TenantMember).where(
            TenantMember.tenant_id == tenant.id,
            TenantMember.user_id   == user.id,
        )
    )
    if res2.scalar_one_or_none() is None:
        db.add(TenantMember(
            id=uuid4(), tenant_id=tenant.id, user_id=user.id,
            role="admin", joined_at=_NOW(),
        ))
        await db.flush()

    return user


# ─── Wipe ─────────────────────────────────────────────────────────────────────

async def _wipe_tenant_data(db: AsyncSession, tenant_id: str) -> None:
    for table in [
        "playbook_steps", "playbook_runs", "playbooks",
        "suppression_rules", "audit_logs",
        "alerts", "investigations",
        "detection_rules", "heartbeats", "agents",
    ]:
        await db.execute(
            text(f"DELETE FROM {table} WHERE tenant_id = :tid::uuid"),
            {"tid": tenant_id},
        )
    await db.flush()


# ─── Master seed ──────────────────────────────────────────────────────────────

async def _seed_all(db: AsyncSession, tenant: Tenant, user: User) -> None:
    tid = tenant.id
    uid = user.id
    rules  = await _seed_rules(db, tid, uid)
    agents = await _seed_agents(db, tid)
    alerts = await _seed_alerts(db, tid, rules, agents)
    invs   = await _seed_investigations(db, tid, uid, alerts)
    await _seed_playbooks(db, tid, uid, invs, alerts)
    await _seed_suppression_rules(db, tid, uid, rules)
    await _seed_audit_log(db, tid, uid)
    await db.commit()


# ─── Detection rules ──────────────────────────────────────────────────────────

RULE_DEFS = [
    ("Lateral Movement via PsExec",          "critical", "pattern",   ["lateral-movement"],      ["T1570"],       True),
    ("Mimikatz Credential Dumping",          "critical", "pattern",   ["credential-access"],     ["T1003.001"],   True),
    ("Ransomware File Extension Change",     "critical", "pattern",   ["impact"],                ["T1486"],       True),
    ("PowerShell Encoded Command Execution", "high",     "pattern",   ["execution"],             ["T1059.001"],   True),
    ("Suspicious WMI Execution",             "high",     "pattern",   ["execution"],             ["T1047"],       True),
    ("Port Scan Detected",                   "high",     "threshold", ["discovery"],             ["T1046"],       True),
    ("Brute Force — SSH Login Failures",     "high",     "threshold", ["credential-access"],     ["T1110.001"],   True),
    ("DNS Tunneling Detected",               "medium",   "pattern",   ["command-and-control"],   ["T1071.004"],   True),
    ("Outbound Connection on Uncommon Port", "medium",   "pattern",   ["command-and-control"],   ["T1571"],       True),
    ("Scheduled Task Creation",              "medium",   "pattern",   ["persistence"],           ["T1053.005"],   True),
    ("Registry Autorun Key Modified",        "medium",   "pattern",   ["persistence"],           ["T1547.001"],   True),
    ("Process Injection Detected",           "high",     "pattern",   ["defense-evasion"],       ["T1055"],       True),
    ("Suspicious Parent-Child Process",      "medium",   "pattern",   ["execution"],             ["T1204"],       True),
    ("Data Exfiltration via HTTP POST",      "critical", "pattern",   ["exfiltration"],          ["T1041"],       True),
    ("Kerberoasting Attack",                 "critical", "pattern",   ["credential-access"],     ["T1558.003"],   True),
    ("LSASS Memory Access",                  "critical", "pattern",   ["credential-access"],     ["T1003.001"],   True),
    ("Suspicious DLL Load",                  "high",     "pattern",   ["defense-evasion"],       ["T1574"],       True),
    ("Failed Admin Login — Multiple Hosts",  "high",     "threshold", ["lateral-movement"],      ["T1021"],       True),
    ("USB Device Connected",                 "low",      "pattern",   ["initial-access"],        ["T1091"],       True),
    ("Noisy Scan Rule",                      "low",      "pattern",   ["discovery"],             ["T1018"],       False),
]


async def _seed_rules(db: AsyncSession, tid, uid) -> list[DetectionRule]:
    rules = []
    for name, sev, rtype, tactics, techniques, enabled in RULE_DEFS:
        r = DetectionRule(
            id=uuid4(), tenant_id=tid, name=name,
            description=f"Detects {name.lower()} activity across all monitored endpoints.",
            rule_type=RuleType(rtype), severity=RuleSeverity(sev), enabled=enabled,
            conditions={"field": "process.name", "op": "contains", "value": name[:8].lower()},
            mitre_tactics=tactics, mitre_techniques=techniques,
            suppression_window_secs=300, created_by_id=uid,
        )
        db.add(r)
        rules.append(r)
    await db.flush()
    return rules


# ─── Agents ───────────────────────────────────────────────────────────────────

AGENT_DEFS = [
    ("DC01-PRIMARY",     "windows", "online",  "4.2.1", "10.0.1.10",    ["domain-controller", "critical-asset"]),
    ("WEB-SRV-01",       "linux",   "online",  "4.2.1", "10.0.1.20",    ["web-server", "dmz"]),
    ("DEV-LAPTOP-JD",    "windows", "online",  "4.2.0", "192.168.1.5",  ["developer", "endpoint"]),
    ("BUILD-AGENT-01",   "linux",   "online",  "4.2.1", "10.0.2.15",    ["ci-cd", "build"]),
    ("FINANCE-WS-01",    "windows", "online",  "4.1.9", "192.168.1.8",  ["finance", "sensitive"]),
    ("MGMT-SERVER-02",   "windows", "online",  "4.2.1", "10.0.1.30",    ["management", "admin"]),
    ("MAIL-SRV-01",      "linux",   "online",  "4.2.0", "10.0.1.15",    ["mail-server", "critical-asset"]),
    ("HR-LAPTOP-01",     "windows", "offline", "4.1.8", "192.168.1.12", ["hr", "endpoint"]),
    ("SALES-WS-03",      "windows", "offline", "4.0.5", "192.168.1.22", ["sales", "endpoint"]),
    ("DB-CLUSTER-01",    "linux",   "online",  "4.2.1", "10.0.3.5",     ["database", "critical-asset"]),
    ("EXEC-LAPTOP-CEO",  "macos",   "online",  "4.2.1", "192.168.1.3",  ["executive", "sensitive"]),
    ("JUMPBOX-01",       "linux",   "online",  "4.2.1", "10.0.1.5",     ["jumpbox", "bastion"]),
    ("LEGACY-SERVER-01", "windows", "stale",   "3.9.2", "10.0.4.50",    ["legacy", "eol"]),
    ("IOT-GATEWAY-01",   "linux",   "offline", "4.0.1", "10.0.5.1",     ["iot", "gateway"]),
    ("BACKUP-SRV-01",    "linux",   "online",  "4.2.0", "10.0.3.10",    ["backup", "storage"]),
]


async def _seed_agents(db: AsyncSession, tid) -> list[Agent]:
    agents = []
    for hostname, os_type, status, version, ip, tags in AGENT_DEFS:
        a = Agent(
            id=uuid4(), tenant_id=tid, name=hostname, hostname=hostname,
            os_type=AgentOsType(os_type), status=AgentStatus(status),
            agent_version=version, ip_address=ip,
            enrollment_token_hash=f"hmac_sha256:{secrets.token_hex(32)}",
            last_seen_at=(_AGO(minutes=random.randint(1, 120))
                          if status == "online" else _AGO(hours=random.randint(3, 72))),
            tags=tags, config={},
            containment_state=ContainmentState.NONE,
        )
        db.add(a)
        agents.append(a)
        await db.flush()

        if status in ("online", "stale"):
            for i in range(24):
                db.add(Heartbeat(
                    id=uuid4(), agent_id=a.id, tenant_id=tid,
                    received_at=_AGO(hours=i, minutes=random.randint(0, 59)),
                    agent_version=version, ip_address=ip,
                    os_metrics={
                        "cpu_pct":  round(random.uniform(5, 85), 1),
                        "mem_pct":  round(random.uniform(30, 90), 1),
                        "disk_pct": round(random.uniform(20, 70), 1),
                    },
                ))

    await db.flush()
    return agents


# ─── Alerts ───────────────────────────────────────────────────────────────────

ALERT_TEMPLATES = [
    ("Mimikatz Credential Dumping on {host}",               "critical", ["credential-access"],   ["T1003.001"], "open"),
    ("Ransomware Encryption Activity — {host}",             "critical", ["impact"],              ["T1486"],     "open"),
    ("Lateral Movement via PsExec from {host}",             "critical", ["lateral-movement"],    ["T1570"],     "open"),
    ("Kerberoasting Attack — Service Ticket Requested",     "critical", ["credential-access"],   ["T1558.003"], "open"),
    ("LSASS Memory Access on {host}",                       "critical", ["credential-access"],   ["T1003.001"], "acknowledged"),
    ("Data Exfiltration via HTTP POST from {host}",         "critical", ["exfiltration"],        ["T1041"],     "open"),
    ("Suspicious PowerShell on {host}",                     "high",     ["execution"],           ["T1059.001"], "open"),
    ("WMI Execution — Suspicious Child Process on {host}",  "high",     ["execution"],           ["T1047"],     "open"),
    ("Port Scan from {host} — 1,240 ports",                 "high",     ["discovery"],           ["T1046"],     "acknowledged"),
    ("SSH Brute Force on {host} — 847 attempts",            "high",     ["credential-access"],   ["T1110.001"], "open"),
    ("Process Injection into svchost.exe on {host}",        "high",     ["defense-evasion"],     ["T1055"],     "open"),
    ("Suspicious DLL Load by chrome.exe on {host}",         "high",     ["defense-evasion"],     ["T1574"],     "closed"),
    ("Admin Login Failure — 12 hosts in 5 minutes",         "high",     ["lateral-movement"],    ["T1021"],     "open"),
    ("DNS Tunneling — Encoded queries on {host}",           "medium",   ["command-and-control"], ["T1071.004"], "open"),
    ("Outbound C2 Connection on Port 4444 from {host}",     "medium",   ["command-and-control"], ["T1571"],     "open"),
    ("Scheduled Task Created: WindowsUpdate.exe on {host}", "medium",   ["persistence"],         ["T1053.005"], "open"),
    ("Registry Run Key Added — Unknown Process on {host}",  "medium",   ["persistence"],         ["T1547.001"], "acknowledged"),
    ("Suspicious Parent-Child: explorer.exe → cmd.exe",    "medium",   ["execution"],           ["T1204"],     "open"),
    ("Failed Authentication — 23 attempts on {host}",       "medium",   ["credential-access"],   ["T1110"],     "open"),
    ("Outbound Traffic to IOC: 185.220.101.x",              "medium",   ["command-and-control"], ["T1041"],     "open"),
    ("USB Mass Storage Device Connected on {host}",         "low",      ["initial-access"],      ["T1091"],     "closed"),
    ("RDP Enabled Remotely on {host}",                      "low",      ["lateral-movement"],    ["T1021.001"], "open"),
    ("Temp File Execution from %TEMP% on {host}",           "low",      ["execution"],           ["T1204.002"], "open"),
    ("Cleartext Credentials in Process Args on {host}",     "low",      ["credential-access"],   ["T1552.004"], "false_positive"),
    ("New Local Admin Account Created on {host}",           "high",     ["persistence"],         ["T1136.001"], "open"),
]


async def _seed_alerts(db: AsyncSession, tid, rules: list[DetectionRule], agents: list[Agent]) -> list[Alert]:
    online_agents = [a for a in agents if a.status == AgentStatus.ONLINE] or agents
    alerts = []

    for title_tpl, sev, tactics, techniques, status_val in ALERT_TEMPLATES:
        for _ in range(random.randint(3, 6)):
            agent  = random.choice(online_agents)
            rule   = random.choice(rules)
            title  = title_tpl.replace("{host}", agent.hostname)
            a = Alert(
                id=uuid4(), tenant_id=tid, rule_id=rule.id,
                status=AlertStatus(status_val), severity=AlertSeverity(sev),
                title=title,
                description=(
                    f"Detection engine flagged suspicious activity on {agent.hostname}. "
                    f"Immediate investigation recommended. Source IP: {agent.ip_address}."
                ),
                source_host=agent.hostname,
                mitre_tactics=tactics, mitre_techniques=techniques,
                evidence={
                    "process": "powershell.exe",
                    "pid": random.randint(1000, 9999),
                    "cmdline": "cmd /c whoami",
                    "parent": "explorer.exe",
                    "user": random.choice(["SYSTEM", "NETWORK SERVICE", "john.doe", "admin"]),
                    "host": agent.hostname, "ip": agent.ip_address,
                },
                ai_metadata={
                    "ai_analysis": {
                        "summary": f"Alert on {agent.hostname} — {tactics[0]} via {techniques[0]}.",
                        "risk_factors": ["Unusual process execution", "Known attack pattern"],
                        "recommended_actions": ["Isolate host", "Dump memory", "Check lateral movement"],
                    }
                },
                created_at=_AGO(hours=random.randint(0, 168), minutes=random.randint(0, 59)),
            )
            db.add(a)
            alerts.append(a)

    await db.flush()
    return alerts


# ─── Investigations ───────────────────────────────────────────────────────────

_BEHAVIORS = [
    ["credential-access", "lateral-movement"],
    ["initial-access", "execution", "persistence"],
    ["execution", "defense-evasion", "impact"],
    ["discovery", "lateral-movement", "exfiltration"],
    ["command-and-control", "exfiltration"],
]

INV_TEMPLATES = [
    ("APT29 Lateral Movement Campaign — Finance Dept",   95, "high",   "investigating",  "true_positive"),
    ("Ransomware Pre-Staging on DC01-PRIMARY",           92, "high",   "investigating",  None),
    ("Credential Harvesting via Mimikatz — 3 Hosts",    88, "high",   "triaged",        None),
    ("C2 Beacon to 185.220.101.47 — Cobalt Strike",      85, "high",   "active",         "true_positive"),
    ("SSH Brute Force Campaign from 45.33.32.156",       78, "medium", "investigating",  None),
    ("PowerShell Empire Stager on BUILD-AGENT-01",       82, "high",   "new",            None),
    ("Kerberoasting Attack — Multiple Service Accounts", 90, "high",   "contained",      "true_positive"),
    ("Suspicious WMI Execution Chain — WEB-SRV-01",     71, "medium", "active",         None),
    ("Data Exfiltration Attempt — FINANCE-WS-01",       87, "high",   "resolved",       "true_positive"),
    ("USB-Based Malware — HR-LAPTOP-01",                55, "low",    "false_positive", "false_positive"),
    ("DNS Tunneling — Periodic Beacons Detected",        68, "medium", "triaged",        None),
    ("Registry Persistence — SALES-WS-03",              49, "low",    "new",            None),
]


async def _seed_investigations(db: AsyncSession, tid, uid, alerts: list[Alert]) -> list[Investigation]:
    invs = []
    critical_alerts = [a for a in alerts if a.severity == AlertSeverity.CRITICAL]
    high_alerts     = [a for a in alerts if a.severity == AlertSeverity.HIGH]
    fallback        = critical_alerts + high_alerts or alerts

    for title, score, confidence, status_val, verdict in INV_TEMPLATES:
        pool = (critical_alerts if score >= 80 else high_alerts) or fallback
        linked   = random.sample(pool, min(random.randint(3, 8), len(pool)))
        behaviors = random.choice(_BEHAVIORS)
        created   = _AGO(hours=random.randint(1, 120))

        inv = Investigation(
            id=uuid4(), tenant_id=tid,
            investigation_group_id=f"GRP-{uuid4().hex[:12].upper()}",
            threat_score=score, confidence=confidence,
            tp_probability=round(random.uniform(0.6, 0.97), 2),
            fp_probability=round(random.uniform(0.03, 0.2), 2),
            title=title,
            executive_summary=(
                f"Investigation detected {title.lower()}. "
                f"Threat score: {score}/100. Analysts should review immediately."
            ),
            technical_summary=(
                f"Multiple detection rules triggered across {random.randint(2,5)} hosts. "
                f"MITRE techniques: {', '.join(behaviors)}. "
                f"Evidence includes process logs, network captures, and registry artifacts."
            ),
            attack_progression=[
                {"stage": s, "confidence": round(random.uniform(0.6, 0.98), 2)} for s in behaviors
            ],
            recommended_actions=[
                "Isolate affected hosts immediately",
                "Revoke potentially compromised credentials",
                "Review network traffic for lateral movement",
                "Preserve forensic evidence before remediation",
                "Notify management per IR plan",
            ],
            status=status_val, source="auto",
            assigned_to=uid if random.random() > 0.4 else None,
            verdict=verdict,
            verdict_set_at=_AGO(hours=random.randint(0, 2)) if verdict else None,
            verdict_set_by=uid if verdict else None,
            triggering_alert_ids=[str(a.id) for a in linked],
            created_at=created,
            timeline_json={
                "events": [
                    {
                        "at": _AGO(hours=i).isoformat(),
                        "type": random.choice(["alert", "action", "note"]),
                        "description": random.choice([
                            "Alert triggered by detection rule",
                            "Analyst acknowledged alert",
                            "Containment action initiated",
                            "Evidence collected from endpoint",
                            "Network block applied at perimeter",
                        ]),
                    }
                    for i in range(random.randint(4, 12), 0, -1)
                ]
            },
            graph_json={
                "nodes": [
                    {"node_id": f"host-{i}", "node_type": "host", "label": f"HOST-{i:02d}",
                     "event_count": random.randint(5, 50),
                     "first_seen": _AGO(hours=5).timestamp(),
                     "last_seen":  _AGO(hours=1).timestamp(),
                     "attributes": {"suspicious": random.random() > 0.5}}
                    for i in range(random.randint(3, 7))
                ] + [
                    {"node_id": f"user-{i}", "node_type": "user", "label": f"user{i}@corp.local",
                     "event_count": random.randint(2, 20),
                     "first_seen": _AGO(hours=4).timestamp(),
                     "last_seen":  _AGO(hours=1).timestamp(),
                     "attributes": {"suspicious": True}}
                    for i in range(random.randint(1, 3))
                ],
                "edges": [
                    {"source": f"host-{i % 7}", "target": f"user-{random.randint(0,2)}",
                     "edge_type": random.choice(["executes", "authenticates", "spawns"]),
                     "weight": random.randint(1, 10)}
                    for i in range(random.randint(4, 10))
                ],
                "node_count": 8, "edge_count": 7, "max_depth": 4,
                "attack_paths": [["user-0", "host-1", "host-2"]],
            },
            ai_analysis_json={
                "threat_actor": "APT29" if score > 85 else "Unknown",
                "campaign": "Operation ShadowNet" if score > 85 else None,
                "ioc_summary": {
                    "ips": [_rand_ip() for _ in range(3)],
                    "domains": ["update-service.cc", "cdn-cache.io"],
                    "hashes": [secrets.token_hex(32) for _ in range(2)],
                },
                "attack_narrative": (
                    f"Attacker gained initial access via {random.choice(['phishing','exploit','supply chain'])} "
                    f"then escalated privileges using credential dumping. Lateral movement observed across "
                    f"{random.randint(2,5)} internal segments."
                ),
                "mitre_coverage": [
                    {"tactic": b, "techniques": [f"T{random.randint(1001,1600)}"]} for b in behaviors
                ],
                "confidence_reasoning": "Multiple correlated alerts with consistent IOCs across hosts.",
            },
        )
        db.add(inv)
        invs.append(inv)

    await db.flush()
    return invs


# ─── Playbooks ────────────────────────────────────────────────────────────────

_PLAYBOOK_STEPS = [
    ("Triage Alert and Validate",         "detection",     "completed"),
    ("Identify Affected Hosts",           "investigation", "completed"),
    ("Preserve Evidence",                 "investigation", "completed"),
    ("Isolate Affected Systems",          "containment",   "completed"),
    ("Revoke Compromised Credentials",    "containment",   "pending"),
    ("Remove Malicious Artifacts",        "eradication",   "pending"),
    ("Scan for Lateral Movement",         "eradication",   "pending"),
    ("Restore from Clean Backup",         "recovery",      "pending"),
    ("Re-enable Network Access",          "recovery",      "pending"),
    ("Notify Stakeholders",               "communication", "completed"),
    ("Conduct Post-Incident Review",      "communication", "pending"),
]

_PLAYBOOK_DEFS = [
    ("Ransomware IR Playbook",           "critical", "in_progress"),
    ("Credential Theft Response",        "critical", "in_progress"),
    ("Lateral Movement Containment",     "high",     "draft"),
    ("C2 Beaconing Response",            "high",     "completed"),
    ("Phishing Investigation Playbook",  "medium",   "draft"),
    ("Data Exfiltration Response Plan",  "critical", "in_progress"),
]


async def _seed_playbooks(db: AsyncSession, tid, uid, invs: list[Investigation], alerts: list[Alert]) -> None:
    c_invs   = [i for i in invs if i.threat_score >= 80] or invs
    c_alerts = [a for a in alerts if a.severity == AlertSeverity.CRITICAL] or alerts

    for idx, (pb_title, pb_sev, pb_status) in enumerate(_PLAYBOOK_DEFS):
        pb = Playbook(
            id=uuid4(), tenant_id=tid,
            incident_id=f"INC-{uuid4().hex[:8].upper()}",
            title=pb_title, severity=pb_sev,
            source_host=random.choice(["DC01-PRIMARY", "WEB-SRV-01", "FINANCE-WS-01"]),
            status=pb_status, generated_by="llm", created_by_id=uid,
            investigation_id=c_invs[idx % len(c_invs)].id,
            alert_id=c_alerts[idx % len(c_alerts)].id,
        )
        db.add(pb)
        await db.flush()

        is_active = pb_status in ("in_progress", "completed")
        for i, (step_title, cat, step_status) in enumerate(_PLAYBOOK_STEPS):
            db.add(PlaybookStep(
                id=uuid4(), playbook_id=pb.id,
                step_order=i + 1, category=cat, title=step_title,
                description=f"Step {i+1}: {step_title} — follow standard runbook procedure.",
                status=step_status if is_active else "pending",
                requires_human_approval=True,
                completed_at=_AGO(hours=random.randint(1, 12)) if step_status == "completed" and is_active else None,
            ))

    await db.flush()


# ─── Suppression rules ────────────────────────────────────────────────────────

async def _seed_suppression_rules(db: AsyncSession, tid, uid, rules: list[DetectionRule]) -> None:
    defs = [
        ("Suppress USB alerts on exec laptops",  "USB known-good on C-suite devices",    rules[18].id, "EXEC-LAPTOP*", "low",    True,  30),
        ("Mute legacy server scan alerts",        "Legacy-01 generates false positives",  rules[5].id,  "LEGACY*",      "medium", True,  90),
        ("Dev environment false positives",       "CI/CD builds trigger port scan rules", rules[5].id,  "BUILD-AGENT*", "medium", True,  14),
        ("HR endpoint — maintenance window",      "Scheduled maintenance suppression",    None,         "HR-LAPTOP*",   None,     False,  3),
        ("Sales team — VPN reconnect noise",      "VPN client reconnects generate alerts",rules[6].id,  "SALES-WS*",    "low",    True,   7),
    ]
    for name, reason, rule_id, host_pat, sev, enabled, days in defs:
        db.add(SuppressionRule(
            id=uuid4(), tenant_id=tid, name=name,
            description=reason, reason=reason,
            detection_rule_id=rule_id,
            hostname_pattern=host_pat, min_severity=sev,
            enabled=enabled, expires_at=_NOW() + timedelta(days=days),
            created_by_id=uid,
        ))
    await db.flush()


# ─── Audit log ────────────────────────────────────────────────────────────────

_AUDIT = [
    ("alert.acknowledged",          "alert",         {"before": {"status": "open"},        "after": {"status": "acknowledged"}}),
    ("investigation.created",       "investigation", {"after": {"status": "new"}}),
    ("rule.updated",                "rule",          {"before": {"severity": "medium"},    "after": {"severity": "high"}}),
    ("user.login",                  "user",          None),
    ("alert.closed",                "alert",         {"before": {"status": "acknowledged"},"after": {"status": "closed"}}),
    ("investigation.status_change", "investigation", {"before": {"status": "new"},         "after": {"status": "investigating"}}),
    ("rule.created",                "rule",          {"after": {"enabled": True}}),
    ("agent.registered",            "agent",         {"after": {"status": "online"}}),
    ("suppression.created",         "suppression",   {"after": {"enabled": True}}),
    ("alert.false_positive",        "alert",         {"before": {"status": "open"},        "after": {"status": "false_positive"}}),
    ("investigation.verdict",       "investigation", {"after": {"verdict": "true_positive"}}),
    ("user.logout",                 "user",          None),
    ("agent.offline",               "agent",         {"after": {"status": "offline"}}),
    ("playbook.executed",           "investigation", {"after": {"status": "in_progress"}}),
    ("rule.disabled",               "rule",          {"before": {"enabled": True},         "after": {"enabled": False}}),
]


async def _seed_audit_log(db: AsyncSession, tid, uid) -> None:
    for _ in range(80):
        action, resource_type, changes = random.choice(_AUDIT)
        db.add(AuditLog(
            id=uuid4(), tenant_id=tid, actor_id=uid,
            action=action, resource_type=resource_type,
            resource_id=uuid4(), changes=changes,
            ip_address=random.choice(["192.168.1.5", "10.0.1.10", "172.16.0.3"]),
            created_at=_AGO(hours=random.randint(0, 168), minutes=random.randint(0, 59)),
        ))
    await db.flush()
