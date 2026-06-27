"""
Playbook Generator Service — SOAR automation for incident response.

Generation chain (5-level fallback):
  1. Template cache hit       — exact technique match in DB
  2. Tactic fallback          — template matching tactic only
  3. Category fallback        — template matching category only
  4. LLM generation           — structured JSON prompt to Groq/Gemini
  5. Generic 8-step fallback  — always succeeds

Variables substituted into step descriptions:
  {source_ip}, {username}, {device_name}, {device_os}, {incident_id},
  {company_name}, {attempt_count}, {timeframe}, {protocol}, {port},
  {technique_id}, {technique_name}, {cve_id}, {cvss_score}, {timestamp},
  {analyst_note}
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.playbook import (
    Playbook,
    PlaybookRun,
    PlaybookStep,
    PlaybookTemplate,
    PlaybookTemplateStep,
)

logger = structlog.get_logger(__name__)

# ── 16 substitution variables ─────────────────────────────────────────────────
_VARIABLE_DEFAULTS: dict[str, str] = {
    "source_ip": "Unknown IP",
    "username": "Unknown User",
    "device_name": "Unknown Device",
    "device_os": "Unknown OS",
    "incident_id": "INC-UNKNOWN",
    "company_name": "Your Organization",
    "attempt_count": "multiple",
    "timeframe": "the last 24 hours",
    "protocol": "Unknown Protocol",
    "port": "Unknown Port",
    "technique_id": "T0000",
    "technique_name": "Unknown Technique",
    "cve_id": "N/A",
    "cvss_score": "N/A",
    "timestamp": datetime.now(tz=UTC).isoformat(),
    "analyst_note": "[ANALYST: Review and adapt these steps to your environment]",
}

# ── Generic 8-step fallback playbook ─────────────────────────────────────────
_GENERIC_STEPS = [
    {
        "step_order": 1,
        "category": "triage",
        "title": "Triage and Initial Assessment",
        "description_template": (
            "Review the alert for {incident_id} triggered on {device_name} ({source_ip}) "
            "at {timestamp}. Determine urgency, validate the alert is not a false positive, "
            "and assign an initial priority level."
        ),
        "expected_result": "Alert validated and priority assigned.",
        "requires_human_approval": True,
        "is_critical": True,
        "can_run_parallel": False,
    },
    {
        "step_order": 2,
        "category": "investigation",
        "title": "Evidence Collection",
        "description_template": (
            "Collect all available evidence: process logs, network connections, "
            "file system changes, and authentication records on {device_name}. "
            "Preserve memory dumps if malware is suspected."
        ),
        "command_windows": "Get-WinEvent -LogName Security -MaxEvents 500 | Export-Csv evidence.csv",
        "command_linux": "journalctl --since '24 hours ago' > evidence.log && last > logins.log",
        "expected_result": "Evidence package collected and stored securely.",
        "requires_human_approval": False,
        "is_critical": True,
        "can_run_parallel": True,
    },
    {
        "step_order": 3,
        "category": "investigation",
        "title": "Scope Determination",
        "description_template": (
            "Determine the blast radius of the incident. Identify all affected systems, "
            "users ({username}), and data. Check lateral movement indicators."
        ),
        "expected_result": "Affected asset list documented with confidence level.",
        "requires_human_approval": True,
        "is_critical": True,
        "can_run_parallel": False,
    },
    {
        "step_order": 4,
        "category": "containment",
        "title": "Initial Containment",
        "description_template": (
            "Apply immediate containment to limit further damage. "
            "Consider isolating {device_name} from the network if active threat is confirmed. "
            "Block the source IP {source_ip} at the perimeter firewall."
        ),
        "expected_result": "Threat contained — no further lateral spread observed.",
        "requires_human_approval": True,
        "is_critical": True,
        "can_run_parallel": False,
        "action_type": "isolate_device",
    },
    {
        "step_order": 5,
        "category": "investigation",
        "title": "Root Cause Analysis",
        "description_template": (
            "Perform deep investigation to identify the root cause. "
            "Trace the attack path using {technique_id} ({technique_name}) indicators. "
            "Identify the initial access vector and full kill chain."
        ),
        "expected_result": "Root cause identified and documented with full attack chain.",
        "requires_human_approval": True,
        "is_critical": False,
        "can_run_parallel": False,
    },
    {
        "step_order": 6,
        "category": "eradication",
        "title": "Threat Eradication",
        "description_template": (
            "Remove all malicious artifacts from affected systems. "
            "Revoke compromised credentials for {username}. "
            "Patch identified vulnerabilities ({cve_id}, CVSS: {cvss_score})."
        ),
        "command_windows": "Remove-MaliciousArtifacts.ps1 -TargetHost {device_name}",
        "command_linux": "clamscan --remove=yes --recursive /",
        "expected_result": "All malicious artifacts removed and verified clean.",
        "requires_human_approval": True,
        "is_critical": True,
        "can_run_parallel": False,
    },
    {
        "step_order": 7,
        "category": "recovery",
        "title": "Recovery and Verification",
        "description_template": (
            "Restore {device_name} to normal operations from a known-good state. "
            "Verify system integrity, re-enable services, and confirm monitoring is active. "
            "Confirm no re-infection within 48 hours of recovery."
        ),
        "expected_result": "System restored, verified clean, and monitoring active.",
        "requires_human_approval": True,
        "is_critical": True,
        "can_run_parallel": False,
    },
    {
        "step_order": 8,
        "category": "documentation",
        "title": "Documentation and Lessons Learned",
        "description_template": (
            "Document the full incident timeline for {incident_id}. "
            "Update threat intelligence with IOCs from this incident. "
            "Schedule a post-incident review with {company_name} security team within 5 business days. "
            "{analyst_note}"
        ),
        "expected_result": "Incident report completed and distributed to stakeholders.",
        "requires_human_approval": False,
        "is_critical": False,
        "can_run_parallel": False,
    },
]

# ── Attack-specific context injected into the LLM prompt ─────────────────────
_ATTACK_CONTEXT: dict[str, str] = {
    "T1486": (
        "ATTACK: Ransomware — Data Encrypted for Impact\n"
        "INDICATORS: Encrypted file extensions (.locked, .crypted, .enc, custom), ransom note files "
        "(README.txt, HOW_TO_DECRYPT.txt, RECOVER_FILES.html), mass file-rename events, "
        "shadow copy deletion (vssadmin delete shadows /all /quiet), "
        "C2 beacon before detonation.\n"
        "PRIORITY: IMMEDIATE isolation. Every minute of delay = more encrypted files.\n"
        "KEY COMMANDS:\n"
        "  Windows: Get-ChildItem C:\\ -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Extension -match 'locked|enc|crypt'} | Measure-Object\n"
        "  Windows: vssadmin list shadows\n"
        "  Linux: find / -name '*.locked' -o -name 'README.txt' 2>/dev/null | head -50\n"
        "FAMILIES: LockBit 3.0, BlackCat/ALPHV, Cl0p, Conti, Ryuk, REvil/Sodinokibi"
    ),
    "T1059": (
        "ATTACK: Command & Scripting Interpreter abuse\n"
        "INDICATORS: Encoded PowerShell (-EncodedCommand, -enc), suspicious parent process "
        "(Office app spawning cmd/powershell), LOLBIN usage (mshta, wscript, cscript, regsvr32), "
        "download cradles (IEX, Invoke-Expression, DownloadString).\n"
        "KEY COMMANDS:\n"
        "  Windows: Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 100 | Select Message | Out-File ps_log.txt\n"
        "  Windows: Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} | Where-Object {$_.Message -match 'powershell|cmd|wscript'}\n"
        "  Linux: cat /var/log/auth.log | grep -i bash | tail -200\n"
        "FOCUS: Decode base64 payloads, identify download domains, trace parent-child process chain."
    ),
    "T1055": (
        "ATTACK: Process Injection\n"
        "INDICATORS: Unusual parent-child relationships, CreateRemoteThread API calls, "
        "processes without matching disk image (hollowed processes), "
        "svchost.exe spawning unexpected children, memory region with RWX permissions.\n"
        "KEY COMMANDS:\n"
        "  Windows: Get-Process | Where-Object {$_.MainModule.FileName -ne $null} | Select Name,Id,Path\n"
        "  Windows: tasklist /m | findstr -i unusual.dll\n"
        "TOOLS: Process Hacker, PE-sieve, Malfind (Volatility), Get-InjectedThread.ps1"
    ),
    "T1003": (
        "ATTACK: OS Credential Dumping\n"
        "INDICATORS: LSASS memory access (OpenProcess on lsass.exe), Mimikatz signatures, "
        "SAM/NTDS.dit access, /proc/1/maps lsass dump on Linux, "
        "WDigest authentication enabled (reg key).\n"
        "KEY COMMANDS:\n"
        "  Windows: Get-WinEvent -FilterHashtable @{LogName='Security';Id=4656} | Where-Object {$_.Message -match 'lsass'}\n"
        "  Windows: reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\n"
        "PRIORITY: Rotate ALL credentials for affected accounts immediately after containment."
    ),
    "T1078": (
        "ATTACK: Valid Account Abuse\n"
        "INDICATORS: Unusual login hours, source IP mismatch, impossible travel, "
        "MFA bypass attempts, service account used interactively, "
        "account used from multiple geos within short window.\n"
        "KEY COMMANDS:\n"
        "  Windows: Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625} | Group-Object {$_.Properties[5].Value} | Sort Count -Desc\n"
        "  Windows: Search-ADAccount -AccountName {username} | Get-ADUser -Properties LastLogonDate,PasswordLastSet\n"
        "FOCUS: Identify all sessions, active tokens, and services authenticated with this account."
    ),
    "T1110": (
        "ATTACK: Brute Force\n"
        "INDICATORS: High volume of Event ID 4625 (failed logon), same source IP, "
        "sequential username enumeration, credential stuffing pattern, "
        "RDP/SSH/VPN authentication failures.\n"
        "KEY COMMANDS:\n"
        "  Windows: Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} | Group-Object {$_.Properties[19].Value} | Sort Count -Desc | Select -First 20\n"
        "  Linux: grep 'Failed password' /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr | head -20\n"
        "THRESHOLD: >10 failures from same IP in 5 minutes = confirmed brute force."
    ),
    "T1021": (
        "ATTACK: Lateral Movement via Remote Services\n"
        "INDICATORS: PsExec usage, WMI remote execution, RDP to unusual hosts, "
        "net use connections, admin$ shares access, "
        "Service creation on remote hosts.\n"
        "KEY COMMANDS:\n"
        "  Windows: Get-WinEvent -FilterHashtable @{LogName='Security';Id=4648} | Select-Object TimeCreated,Message\n"
        "  Windows: Get-WinEvent -FilterHashtable @{LogName='Security';Id=7045} | Where-Object {$_.Message -match 'PSEXESVC|RemComSvc'}\n"
        "FOCUS: Map full lateral movement chain, identify all compromised hosts."
    ),
    "T1566": (
        "ATTACK: Phishing\n"
        "INDICATORS: Suspicious email attachment (Office macro, .lnk, .iso, .zip), "
        "browser launching unexpected process, Office spawning cmd/powershell, "
        "user reporting suspicious email, domain spoofing.\n"
        "KEY COMMANDS:\n"
        "  Windows: Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} | Where-Object {$_.Message -match 'winword|excel|outlook'}\n"
        "FOCUS: Identify all users who received the same email, check email gateway logs."
    ),
    "T1190": (
        "ATTACK: Exploit Public-Facing Application\n"
        "INDICATORS: Web server anomalous requests (SQLi, path traversal, RCE patterns), "
        "unexpected process spawned by web server (iis, apache, nginx spawning cmd/bash), "
        "WAF alerts, CVE exploit signatures in IDS logs.\n"
        "KEY COMMANDS:\n"
        "  Linux: tail -1000 /var/log/nginx/access.log | grep -E '(\\.\\.|\\.\\./|exec|eval|SELECT|UNION)'\n"
        "  Linux: ps aux | grep -E '(apache|nginx|iis)' | awk '{print $1,$2,$11}'\n"
        "FOCUS: Capture and preserve web server logs before rotation. Identify exploit payload."
    ),
    "T1041": (
        "ATTACK: Exfiltration Over C2 Channel\n"
        "INDICATORS: Large outbound data transfers, unusual DNS queries (DGA domains), "
        "periodic beaconing (fixed interval connections), "
        "HTTPS to uncategorized IPs, data compressed/encrypted before transfer.\n"
        "KEY COMMANDS:\n"
        "  Windows: netstat -anob | findstr ESTABLISHED\n"
        "  Linux: ss -tnp | grep ESTABLISHED && lsof -i -n | grep ESTABLISHED\n"
        "FOCUS: Calculate total bytes transferred, identify destination IPs, block at perimeter."
    ),
}

# ── LLM system prompt ─────────────────────────────────────────────────────────
_LLM_SYSTEM_PROMPT = """\
You are an elite Tier-3 SOC Incident Responder with SANS GIAC GCIH, GCFA, and GCFE certifications.
You have 15+ years responding to APTs, ransomware, insider threats, and supply chain attacks for Fortune 500 companies.
You write SOAR playbooks used in production by enterprise security teams globally.

MANDATORY RULES — violating any rule makes the playbook worthless:
1. Every step MUST be specific to the provided technique, tactic, severity, and affected host — NO generic steps
2. Commands MUST be REAL, executable PowerShell/bash commands (not pseudocode or comments)
3. Step titles MUST be action-verb phrases: "Isolate {device_name} from network" not "Containment"
4. description_template MUST reference specific IOCs, process names, registry keys, file paths, or network artifacts relevant to the attack
5. expected_result MUST describe what the analyst will literally observe on screen (specific output, not vague "success")
6. hint MUST provide a technical analyst tip: evasion tricks to watch for, known tool behavior, detection gotchas
7. Generate EXACTLY 8-10 steps covering the full cycle: triage → investigation → containment → eradication → recovery → documentation
8. Mark is_critical=true for steps that are time-sensitive or irreversible
9. Mark can_run_parallel=true ONLY for non-destructive investigation steps that gather evidence without modifying state
10. Use action_type for automated SOAR actions: "isolate_device", "revoke_credentials", "quarantine_device"

Respond ONLY with valid JSON — no markdown, no explanation, no preamble.
The JSON must be an array of step objects with this exact schema:
[
  {
    "step_order": 1,
    "category": "triage|investigation|containment|eradication|recovery|documentation",
    "title": "Action verb phrase referencing specific artifact",
    "description_template": "Detailed step using {variables} and specific technical terms",
    "command_windows": "Real PowerShell command or null",
    "command_linux": "Real bash command or null",
    "expected_result": "Specific observable outcome the analyst will see",
    "can_run_parallel": false,
    "requires_human_approval": true,
    "is_critical": false,
    "hint": "Technical analyst tip or null",
    "mitre_reference": "T1xxx or null",
    "action_type": "isolate_device|revoke_credentials|quarantine_device or null",
    "step_order_dependencies": []
  }
]
Available template variables: {source_ip} {username} {device_name} {device_os} {incident_id} {company_name} {attempt_count} {timeframe} {protocol} {port} {technique_id} {technique_name} {cve_id} {cvss_score} {timestamp} {analyst_note}
"""


class PlaybookGeneratorService:
    @staticmethod
    async def generate_incident_id(db: AsyncSession, tenant_id: UUID) -> str:
        today = datetime.now(tz=UTC).strftime("%Y%m%d")
        prefix = f"INC-{today}-"
        result = await db.execute(
            select(func.count()).where(
                Playbook.tenant_id == tenant_id,
                Playbook.incident_id.like(f"{prefix}%"),
                Playbook.deleted_at.is_(None),
            )
        )
        count = (result.scalar_one() or 0) + 1
        return f"{prefix}{count:04d}"

    @staticmethod
    def _extract_variables(
        alert_title: str,
        severity: str,
        source_host: str | None,
        mitre_techniques: list[str],
        evidence: dict[str, Any],
        incident_id: str,
        company_name: str,
    ) -> dict[str, str]:
        vars_: dict[str, str] = dict(_VARIABLE_DEFAULTS)
        vars_["incident_id"] = incident_id
        vars_["company_name"] = company_name
        vars_["timestamp"] = datetime.now(tz=UTC).isoformat()
        if source_host:
            vars_["device_name"] = source_host
        # Flatten evidence fields
        for key, field in [
            ("source_ip", "source_ip"),
            ("username", "username"),
            ("device_os", "os_type"),
            ("attempt_count", "attempt_count"),
            ("protocol", "protocol"),
            ("port", "port"),
            ("cve_id", "cve_id"),
            ("cvss_score", "cvss_score"),
        ]:
            v = evidence.get(field) or evidence.get(key)
            if v is not None:
                vars_[key] = str(v)
        if mitre_techniques:
            first = str(mitre_techniques[0])
            vars_["technique_id"] = first
            vars_["technique_name"] = _technique_name(first)
        return vars_

    @staticmethod
    def _substitute(template: str | None, variables: dict[str, str]) -> str | None:
        if template is None:
            return None
        result = template
        for key, value in variables.items():
            result = result.replace(f"{{{key}}}", str(value))
        return result

    @classmethod
    async def generate(
        cls,
        db: AsyncSession,
        tenant_id: UUID,
        alert_id: UUID | None,
        alert_title: str,
        severity: str,
        source_host: str | None,
        mitre_techniques: list[str],
        mitre_tactics: list[str],
        evidence: dict[str, Any],
        company_name: str,
        investigation_id: UUID | None = None,
        created_by_id: UUID | None = None,
    ) -> Playbook:
        incident_id = await cls.generate_incident_id(db, tenant_id)
        variables = cls._extract_variables(
            alert_title=alert_title,
            severity=severity,
            source_host=source_host,
            mitre_techniques=mitre_techniques,
            evidence=evidence,
            incident_id=incident_id,
            company_name=company_name,
        )

        # Determine primary technique/tactic/category for template lookup
        primary_technique = mitre_techniques[0] if mitre_techniques else None
        primary_tactic = mitre_tactics[0] if mitre_tactics else None
        category = _infer_category(primary_technique, primary_tactic, alert_title)

        # ── Fallback chain ────────────────────────────────────────────────────
        template_steps, generated_by, template_id = await cls._resolve_steps(
            db=db,
            tenant_id=tenant_id,
            technique=primary_technique,
            tactic=primary_tactic,
            category=category,
            variables=variables,
            alert_title=alert_title,
            severity=severity,
            source_host=source_host,
        )

        # ── Persist playbook ──────────────────────────────────────────────────
        playbook = Playbook(
            tenant_id=tenant_id,
            template_id=template_id,
            alert_id=alert_id,
            investigation_id=investigation_id,
            incident_id=incident_id,
            title=f"[{severity.upper()}] {alert_title}",
            severity=severity,
            source_host=source_host,
            status="pending",
            variables=variables,
            generated_by=generated_by,
            created_by_id=created_by_id,
        )
        db.add(playbook)
        await db.flush()

        for raw_step in template_steps:
            step = PlaybookStep(
                playbook_id=playbook.id,
                step_order=raw_step["step_order"],
                category=raw_step.get("category", "investigation"),
                title=raw_step["title"],
                description=cls._substitute(raw_step.get("description_template"), variables),
                command_windows=cls._substitute(raw_step.get("command_windows"), variables),
                command_linux=cls._substitute(raw_step.get("command_linux"), variables),
                expected_result=cls._substitute(raw_step.get("expected_result"), variables),
                requires_human_approval=raw_step.get("requires_human_approval", True),
                is_critical=raw_step.get("is_critical", False),
                can_run_parallel=raw_step.get("can_run_parallel", False),
                action_type=raw_step.get("action_type"),
            )
            db.add(step)

        logger.info(
            "playbook_generated",
            playbook_id=str(playbook.id),
            incident_id=incident_id,
            generated_by=generated_by,
            steps=len(template_steps),
        )
        return playbook

    @classmethod
    async def _resolve_steps(
        cls,
        db: AsyncSession,
        tenant_id: UUID,
        technique: str | None,
        tactic: str | None,
        category: str | None,
        variables: dict[str, str],
        alert_title: str,
        severity: str,
        source_host: str | None,
    ) -> tuple[list[dict[str, Any]], str, UUID | None]:

        # Level 1: exact technique match (system or tenant templates)
        if technique:
            steps, tmpl_id = await cls._load_template_steps(db, tenant_id, technique=technique)
            if steps:
                return steps, "template", tmpl_id

        # Level 2: tactic match
        if tactic:
            steps, tmpl_id = await cls._load_template_steps(db, tenant_id, tactic=tactic)
            if steps:
                return steps, "template_tactic", tmpl_id

        # Level 3: category match
        if category:
            steps, tmpl_id = await cls._load_template_steps(db, tenant_id, category=category)
            if steps:
                return steps, "template_category", tmpl_id

        # Level 4: LLM generation
        try:
            llm_steps = await cls._generate_with_llm(
                technique=technique,
                tactic=tactic,
                alert_title=alert_title,
                severity=severity,
                source_host=source_host,
                variables=variables,
            )
            if llm_steps:
                return llm_steps, "llm", None
        except Exception:
            logger.warning("playbook_llm_generation_failed", exc_info=True)

        # Level 5: generic fallback
        return list(_GENERIC_STEPS), "fallback", None

    @staticmethod
    async def _load_template_steps(
        db: AsyncSession,
        tenant_id: UUID,
        technique: str | None = None,
        tactic: str | None = None,
        category: str | None = None,
    ) -> tuple[list[dict[str, Any]], UUID | None]:
        query = select(PlaybookTemplate).where(
            PlaybookTemplate.enabled.is_(True),
            PlaybookTemplate.deleted_at.is_(None),
            (PlaybookTemplate.tenant_id == tenant_id) | (PlaybookTemplate.is_system.is_(True)),
        )
        if technique:
            query = query.where(PlaybookTemplate.technique == technique)
        elif tactic:
            query = query.where(PlaybookTemplate.tactic == tactic)
        elif category:
            query = query.where(PlaybookTemplate.category == category)
        else:
            return [], None

        # Tenant-specific templates take precedence over system templates
        query = query.order_by(
            PlaybookTemplate.is_system.asc(),
            PlaybookTemplate.created_at.desc(),
        ).limit(1)

        result = await db.execute(query)
        template = result.scalar_one_or_none()
        if template is None:
            return [], None

        step_result = await db.execute(
            select(PlaybookTemplateStep)
            .where(PlaybookTemplateStep.template_id == template.id)
            .order_by(PlaybookTemplateStep.step_order)
        )
        steps_orm = list(step_result.scalars().all())
        steps = [
            {
                "step_order": s.step_order,
                "category": s.category,
                "title": s.title,
                "description_template": s.description_template,
                "command_windows": s.command_windows,
                "command_linux": s.command_linux,
                "expected_result": s.expected_result,
                "can_run_parallel": s.can_run_parallel,
                "requires_human_approval": s.requires_human_approval,
                "is_critical": s.is_critical,
                "hint": s.hint,
                "mitre_reference": s.mitre_reference,
                "action_type": s.action_type,
                "step_order_dependencies": s.step_order_dependencies,
            }
            for s in steps_orm
        ]
        return steps, template.id

    @staticmethod
    async def _generate_with_llm(
        technique: str | None,
        tactic: str | None,
        alert_title: str,
        severity: str,
        source_host: str | None,
        variables: dict[str, str],
    ) -> list[dict[str, Any]]:
        from app.ai.llm_manager import get_llm_manager

        llm = get_llm_manager()

        # Look up human-readable technique name
        tech_name = _technique_name(technique or "")
        # Strip the base technique (T1059.001 → T1059) for context lookup
        base_tech = (technique or "").split(".")[0].upper()
        attack_context = _ATTACK_CONTEXT.get(base_tech, "")

        severity_guidance = {
            "critical": "CRITICAL: This is a P1 incident. All containment actions must complete within 15 minutes. Alert CISO immediately.",
            "high": "HIGH severity: Contain within 1 hour. Escalate to senior analyst.",
            "medium": "MEDIUM severity: Investigate and contain within 4 hours. Standard escalation path.",
            "low": "LOW severity: Investigate within 24 hours. Document and monitor.",
        }.get(severity.lower(), "")

        technique_line = (
            f"{technique} — {tech_name}"
            if tech_name != "Unknown Technique"
            else (technique or "Unknown")
        )

        var_block = "\n".join(f"  {{{k}}}: {v}" for k, v in variables.items())

        prompt = f"""\
=== INCIDENT BRIEF ===
Incident ID:    {variables.get("incident_id", "INC-UNKNOWN")}
Timestamp:      {variables.get("timestamp", "Unknown")}
Alert:          {alert_title}
Severity:       {severity.upper()}  — {severity_guidance}

=== AFFECTED ASSET ===
Host:           {source_host or variables.get("device_name", "Unknown")}
OS:             {variables.get("device_os", "Unknown")}
Source IP:      {variables.get("source_ip", "Unknown")}
Username:       {variables.get("username", "Unknown")}
Organization:   {variables.get("company_name", "Unknown")}

=== ATTACK CLASSIFICATION ===
MITRE Technique: {technique_line}
MITRE Tactic:    {tactic or "Unknown"}
{attack_context}

=== AVAILABLE CONTEXT VARIABLES ===
{var_block}

=== TASK ===
Generate a complete tactical incident response playbook for the attack above.
- Every step title must name the specific artifact or system being acted on
- Every command must be real and executable, tailored to {source_host or "the affected host"}
- Use {technique or "the detected technique"} specific IOCs and artifacts in descriptions
- Cover the full lifecycle: Triage → Investigation → Containment → Eradication → Recovery → Documentation
Respond ONLY with the JSON array."""

        raw = await llm.generate(prompt, system_prompt=_LLM_SYSTEM_PROMPT, max_tokens=4000)

        # Strip any markdown code fences if the model added them
        raw = re.sub(r"```(?:json)?\s*", "", raw).strip().rstrip("`").strip()

        steps: list[dict[str, Any]] = json.loads(raw)
        if not isinstance(steps, list) or len(steps) == 0:
            raise ValueError("LLM returned empty or non-list response")

        # Ensure required fields
        for i, step in enumerate(steps, 1):
            step.setdefault("step_order", i)
            step.setdefault("category", "investigation")
            step.setdefault("requires_human_approval", True)
            step.setdefault("is_critical", False)
            step.setdefault("can_run_parallel", False)
            step.setdefault("step_order_dependencies", [])

        return steps

    @staticmethod
    async def execute_playbook(
        db: AsyncSession,
        tenant_id: UUID,
        playbook_id: UUID,
        actor_id: UUID | None,
        mode: str = "manual",
    ) -> PlaybookRun:
        result = await db.execute(
            select(Playbook).where(
                Playbook.id == playbook_id,
                Playbook.tenant_id == tenant_id,
                Playbook.deleted_at.is_(None),
            )
        )
        playbook = result.scalar_one_or_none()
        if playbook is None:
            from app.core.exceptions import NotFoundError

            raise NotFoundError(f"Playbook {playbook_id} not found")

        step_count_result = await db.execute(
            select(func.count()).where(PlaybookStep.playbook_id == playbook_id)
        )
        steps_total = step_count_result.scalar_one()

        playbook.status = "in_progress"
        run = PlaybookRun(
            playbook_id=playbook_id,
            tenant_id=tenant_id,
            mode=mode,
            status="running",
            steps_total=steps_total,
            actor_id=actor_id,
        )
        db.add(run)
        await db.flush()
        return run

    @staticmethod
    async def complete_step(
        db: AsyncSession,
        tenant_id: UUID,
        playbook_id: UUID,
        step_id: UUID,
        actor_id: UUID,
        notes: str | None = None,
        result_text: str | None = None,
    ) -> PlaybookStep:
        # Verify playbook belongs to tenant
        pb_result = await db.execute(
            select(Playbook).where(
                Playbook.id == playbook_id,
                Playbook.tenant_id == tenant_id,
                Playbook.deleted_at.is_(None),
            )
        )
        if pb_result.scalar_one_or_none() is None:
            from app.core.exceptions import NotFoundError

            raise NotFoundError(f"Playbook {playbook_id} not found")

        step_result = await db.execute(
            select(PlaybookStep).where(
                PlaybookStep.id == step_id,
                PlaybookStep.playbook_id == playbook_id,
            )
        )
        step = step_result.scalar_one_or_none()
        if step is None:
            from app.core.exceptions import NotFoundError

            raise NotFoundError(f"Step {step_id} not found")

        step.status = "completed"
        step.completed_at = datetime.now(tz=UTC)
        step.completed_by_id = actor_id
        if notes:
            step.notes = notes
        if result_text:
            step.result = result_text

        # Check if all steps are done → update playbook status
        total_result = await db.execute(
            select(func.count()).where(PlaybookStep.playbook_id == playbook_id)
        )
        done_result = await db.execute(
            select(func.count()).where(
                PlaybookStep.playbook_id == playbook_id,
                PlaybookStep.status.in_(["completed", "skipped"]),
            )
        )
        total = total_result.scalar_one()
        done = done_result.scalar_one()
        if done >= total:
            pb_update = await db.execute(select(Playbook).where(Playbook.id == playbook_id))
            pb = pb_update.scalar_one_or_none()
            if pb:
                pb.status = "completed"

        await db.flush()
        return step


# ── Helpers ───────────────────────────────────────────────────────────────────

_TECHNIQUE_NAMES: dict[str, str] = {
    # Initial Access
    "T1190": "Exploit Public-Facing Application",
    "T1133": "External Remote Services",
    "T1566": "Phishing",
    "T1078": "Valid Accounts",
    "T1091": "Replication Through Removable Media",
    "T1195": "Supply Chain Compromise",
    "T1199": "Trusted Relationship",
    # Execution
    "T1059": "Command and Scripting Interpreter",
    "T1047": "Windows Management Instrumentation",
    "T1053": "Scheduled Task/Job",
    "T1106": "Native API",
    "T1569": "System Services",
    "T1204": "User Execution",
    # Persistence
    "T1098": "Account Manipulation",
    "T1136": "Create Account",
    "T1543": "Create or Modify System Process",
    "T1547": "Boot or Logon Autostart Execution",
    "T1574": "Hijack Execution Flow",
    # Privilege Escalation
    "T1055": "Process Injection",
    "T1068": "Exploitation for Privilege Escalation",
    "T1134": "Access Token Manipulation",
    "T1548": "Abuse Elevation Control Mechanism",
    # Defense Evasion
    "T1027": "Obfuscated Files or Information",
    "T1036": "Masquerading",
    "T1070": "Indicator Removal",
    "T1112": "Modify Registry",
    "T1218": "System Binary Proxy Execution",
    "T1562": "Impair Defenses",
    # Credential Access
    "T1003": "OS Credential Dumping",
    "T1040": "Network Sniffing",
    "T1110": "Brute Force",
    "T1539": "Steal Web Session Cookie",
    "T1555": "Credentials from Password Stores",
    "T1558": "Steal or Forge Kerberos Tickets",
    # Discovery
    "T1016": "System Network Configuration Discovery",
    "T1018": "Remote System Discovery",
    "T1046": "Network Service Discovery",
    "T1057": "Process Discovery",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1087": "Account Discovery",
    # Lateral Movement
    "T1021": "Remote Services",
    "T1072": "Software Deployment Tools",
    "T1080": "Taint Shared Content",
    "T1550": "Use Alternate Authentication Material",
    # Collection
    "T1005": "Data from Local System",
    "T1074": "Data Staged",
    "T1114": "Email Collection",
    "T1560": "Archive Collected Data",
    # Command and Control
    "T1071": "Application Layer Protocol",
    "T1095": "Non-Application Layer Protocol",
    "T1105": "Ingress Tool Transfer",
    "T1571": "Non-Standard Port",
    "T1572": "Protocol Tunneling",
    # Exfiltration
    "T1041": "Exfiltration Over C2 Channel",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1567": "Exfiltration Over Web Service",
    # Impact
    "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact",
    "T1489": "Service Stop",
    "T1490": "Inhibit System Recovery",
    "T1491": "Defacement",
    "T1498": "Network Denial of Service",
    "T1499": "Endpoint Denial of Service",
    "T1529": "System Shutdown/Reboot",
}

_TACTIC_NAMES: dict[str, str] = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
}


def _technique_name(technique_id: str) -> str:
    base = technique_id.split(".")[0].upper()
    return _TECHNIQUE_NAMES.get(base, "Unknown Technique")


_CATEGORY_MAP: dict[str, str] = {
    "T1486": "ransomware",
    "T1003": "credential_theft",
    "T1110": "credential_theft",
    "T1078": "credential_theft",
    "T1071": "beaconing",
    "T1041": "beaconing",
    "T1055": "privilege_escalation",
    "T1021": "lateral_movement",
    "T1047": "lateral_movement",
}


def _infer_category(technique: str | None, tactic: str | None, title: str) -> str | None:
    if technique:
        base = technique.split(".")[0].upper()
        cat = _CATEGORY_MAP.get(base)
        if cat:
            return cat
    title_lower = title.lower()
    if "ransomware" in title_lower or "encrypt" in title_lower:
        return "ransomware"
    if "credential" in title_lower or "password" in title_lower or "brute" in title_lower:
        return "credential_theft"
    if "beacon" in title_lower or "c2" in title_lower or "command and control" in title_lower:
        return "beaconing"
    if "lateral" in title_lower or "remote" in title_lower:
        return "lateral_movement"
    if "privilege" in title_lower or "escalation" in title_lower:
        return "privilege_escalation"
    return None
