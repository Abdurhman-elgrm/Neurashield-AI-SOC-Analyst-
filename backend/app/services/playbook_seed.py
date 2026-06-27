"""
Seeds system-level IR playbook templates at application startup.
Idempotent — skips templates that already exist (matched by name + is_system).
"""

from __future__ import annotations

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.playbook import PlaybookTemplate, PlaybookTemplateStep

logger = structlog.get_logger(__name__)

# ── Pre-built SOAR playbook definitions ───────────────────────────────────────

_SYSTEM_TEMPLATES: list[dict] = [
    {
        "name": "Ransomware Response",
        "description": "Comprehensive response playbook for ransomware incidents (T1486).",
        "technique": "T1486",
        "tactic": "TA0040",
        "category": "ransomware",
        "steps": [
            {
                "step_order": 1,
                "category": "triage",
                "title": "Immediate Isolation",
                "description_template": (
                    "CRITICAL: Immediately isolate {device_name} from the network to prevent ransomware spread. "
                    "Do NOT shut down — preserve memory for forensics. "
                    "Alert incident response team for {incident_id}."
                ),
                "is_critical": True,
                "requires_human_approval": True,
                "action_type": "isolate_device",
                "can_run_parallel": False,
                "expected_result": "Device isolated, spread halted.",
            },
            {
                "step_order": 2,
                "category": "investigation",
                "title": "Identify Patient Zero",
                "description_template": (
                    "Determine the initial infection vector on {device_name}. "
                    "Examine email logs, browser history, RDP logs, and recently opened files. "
                    "Check if {username} opened any phishing emails or attachments in {timeframe}."
                ),
                "command_windows": "Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4624} | Select-Object -Last 100",
                "command_linux": "last -20 && grep 'Failed password' /var/log/auth.log | tail -50",
                "is_critical": True,
                "requires_human_approval": True,
                "can_run_parallel": True,
                "expected_result": "Initial infection vector identified.",
            },
            {
                "step_order": 3,
                "category": "investigation",
                "title": "Map Encryption Scope",
                "description_template": (
                    "Identify all encrypted files and affected shared drives. "
                    "Locate the ransomware binary and determine the ransomware family. "
                    "Check for {technique_id} indicators (file extension changes, ransom notes)."
                ),
                "command_windows": "Get-ChildItem -Recurse -Filter '*.encrypted' | Measure-Object",
                "command_linux": "find / -name '*.encrypted' -o -name 'READ_ME*.txt' 2>/dev/null | head -20",
                "is_critical": True,
                "requires_human_approval": False,
                "can_run_parallel": True,
                "expected_result": "Full scope of encrypted files documented.",
            },
            {
                "step_order": 4,
                "category": "investigation",
                "title": "Lateral Movement Check",
                "description_template": (
                    "Verify whether ransomware has spread to other systems. "
                    "Examine network shares, AD replication logs, and SMB connections from {device_name} ({source_ip}). "
                    "Check domain controller logs for suspicious authentication."
                ),
                "command_windows": "Get-SmbOpenFile | Select-Object ClientComputerName, Path",
                "command_linux": "ss -tnp | grep ESTABLISHED",
                "is_critical": True,
                "requires_human_approval": True,
                "can_run_parallel": False,
                "expected_result": "Lateral movement assessment complete — additional systems identified or ruled out.",
            },
            {
                "step_order": 5,
                "category": "eradication",
                "title": "Eradication and Recovery",
                "description_template": (
                    "DO NOT pay the ransom. Restore {device_name} from the most recent clean backup. "
                    "Verify backup integrity before restoration. "
                    "If no backup: investigate decryption tools for this ransomware family. "
                    "Change all credentials for {username} and affected accounts."
                ),
                "is_critical": True,
                "requires_human_approval": True,
                "can_run_parallel": False,
                "expected_result": "System restored from backup, ransomware eradicated.",
            },
            {
                "step_order": 6,
                "category": "recovery",
                "title": "Harden and Reconnect",
                "description_template": (
                    "Before reconnecting {device_name}: enable controlled folder access, "
                    "deploy EDR, patch OS to latest version, and disable unnecessary RDP. "
                    "Reconnect to network only after security team sign-off. {analyst_note}"
                ),
                "is_critical": True,
                "requires_human_approval": True,
                "can_run_parallel": False,
                "expected_result": "System hardened and safely reconnected to network.",
            },
        ],
    },
    {
        "name": "Credential Theft Response",
        "description": "Response playbook for credential dumping and brute force attacks (T1003/T1110).",
        "technique": "T1003",
        "tactic": "TA0006",
        "category": "credential_theft",
        "steps": [
            {
                "step_order": 1,
                "category": "triage",
                "title": "Assess Credential Exposure",
                "description_template": (
                    "For incident {incident_id}: Determine which credentials were compromised. "
                    "Identify {username} and any other accounts accessed from {source_ip}. "
                    "Check authentication logs for {attempt_count} failed attempts in {timeframe}."
                ),
                "is_critical": True,
                "requires_human_approval": True,
                "can_run_parallel": False,
                "expected_result": "Compromised account list documented.",
            },
            {
                "step_order": 2,
                "category": "containment",
                "title": "Revoke Compromised Credentials",
                "description_template": (
                    "Immediately disable or reset credentials for {username} and all accounts "
                    "accessed from {source_ip}. Force MFA re-enrollment. "
                    "Revoke all active sessions and OAuth tokens."
                ),
                "command_windows": "Disable-ADAccount -Identity {username}; Set-ADAccountPassword -Identity {username} -Reset",
                "command_linux": "passwd -l {username} && pkill -u {username}",
                "is_critical": True,
                "requires_human_approval": True,
                "action_type": "revoke_credentials",
                "can_run_parallel": False,
                "expected_result": "All compromised credentials revoked and sessions terminated.",
            },
            {
                "step_order": 3,
                "category": "investigation",
                "title": "Audit Privileged Access",
                "description_template": (
                    "Review all privileged operations performed by {username} during the attack window. "
                    "Check for new admin accounts, scheduled tasks, registry modifications, or data access. "
                    "Examine AD for changes made in {timeframe}."
                ),
                "command_windows": "Search-ADAccount -LockedOut | Get-ADUser",
                "command_linux": "grep 'sudo' /var/log/auth.log | grep {username}",
                "is_critical": True,
                "requires_human_approval": True,
                "can_run_parallel": True,
                "expected_result": "Full audit of post-compromise activity completed.",
            },
            {
                "step_order": 4,
                "category": "containment",
                "title": "Block Attack Source",
                "description_template": (
                    "Block {source_ip} at the perimeter firewall and WAF. "
                    "Add to threat intelligence blocklist. "
                    "Enable account lockout policies if brute force was detected on {protocol}:{port}."
                ),
                "is_critical": False,
                "requires_human_approval": True,
                "can_run_parallel": True,
                "expected_result": "Attack source blocked across all perimeter controls.",
            },
            {
                "step_order": 5,
                "category": "eradication",
                "title": "Remove Persistence Mechanisms",
                "description_template": (
                    "Search for and remove any persistence installed using compromised credentials: "
                    "scheduled tasks, startup scripts, SSH authorized_keys, cron jobs, "
                    "and new user accounts on {device_name}. {analyst_note}"
                ),
                "command_windows": "Get-ScheduledTask | Where-Object {$_.TaskPath -like '*Startup*'}",
                "command_linux": "crontab -l -u {username}; ls -la ~/.ssh/",
                "is_critical": True,
                "requires_human_approval": True,
                "can_run_parallel": False,
                "expected_result": "All persistence mechanisms identified and removed.",
            },
        ],
    },
    {
        "name": "C2 Beaconing Response",
        "description": "Response playbook for C2 beaconing and data exfiltration (T1071/T1041).",
        "technique": "T1071",
        "tactic": "TA0011",
        "category": "beaconing",
        "steps": [
            {
                "step_order": 1,
                "category": "investigation",
                "title": "Confirm C2 Communication",
                "description_template": (
                    "Validate that {device_name} ({source_ip}) is communicating with a C2 server. "
                    "Capture network traffic on {protocol}:{port} for analysis. "
                    "Check DNS resolution history for suspicious domains in {timeframe}."
                ),
                "command_windows": "netstat -anob | findstr ESTABLISHED",
                "command_linux": "ss -tnp | grep ESTABLISHED && netstat -r",
                "is_critical": True,
                "requires_human_approval": True,
                "can_run_parallel": False,
                "expected_result": "C2 communication confirmed with IOCs documented.",
            },
            {
                "step_order": 2,
                "category": "containment",
                "title": "Block C2 Infrastructure",
                "description_template": (
                    "Block the C2 destination IP/domain at the DNS, proxy, and firewall level. "
                    "Terminate the active connection from {device_name}. "
                    "Deploy threat intel to EDR for automatic blocking."
                ),
                "is_critical": True,
                "requires_human_approval": True,
                "can_run_parallel": False,
                "expected_result": "C2 channels blocked, active connections terminated.",
            },
            {
                "step_order": 3,
                "category": "investigation",
                "title": "Identify Implant",
                "description_template": (
                    "Locate the malware implant on {device_name} using process, file, and registry analysis. "
                    "Identify the {technique_id} delivery mechanism. "
                    "Extract IOCs for threat hunting across the environment."
                ),
                "command_windows": "Get-Process | Select-Object Name,Id,Path | Sort-Object CPU -Descending",
                "command_linux": "ps aux --sort=-%cpu | head -20 && lsof -i",
                "is_critical": True,
                "requires_human_approval": True,
                "can_run_parallel": True,
                "expected_result": "Malware implant located and IOCs extracted.",
            },
            {
                "step_order": 4,
                "category": "investigation",
                "title": "Assess Data Exfiltration",
                "description_template": (
                    "Determine if data was exfiltrated from {device_name}. "
                    "Review outbound traffic volume anomalies, DLP logs, and cloud upload activity. "
                    "Identify sensitive data at risk and notify {company_name} compliance team."
                ),
                "is_critical": True,
                "requires_human_approval": True,
                "can_run_parallel": True,
                "expected_result": "Data exfiltration scope assessed and documented.",
            },
            {
                "step_order": 5,
                "category": "eradication",
                "title": "Remove Implant and Restore",
                "description_template": (
                    "Remove the malware implant from {device_name}. "
                    "Restore from clean backup if system integrity is compromised. "
                    "Re-image if necessary. Deploy updated EDR signatures. {analyst_note}"
                ),
                "is_critical": True,
                "requires_human_approval": True,
                "can_run_parallel": False,
                "expected_result": "Implant removed, system integrity verified.",
            },
        ],
    },
    {
        "name": "Privilege Escalation Response",
        "description": "Response playbook for privilege escalation attacks (T1055/T1053).",
        "technique": "T1055",
        "tactic": "TA0004",
        "category": "privilege_escalation",
        "steps": [
            {
                "step_order": 1,
                "category": "triage",
                "title": "Confirm Escalation",
                "description_template": (
                    "Confirm that {username} has gained unauthorized elevated privileges on {device_name}. "
                    "Review audit logs for {technique_id} indicators at {timestamp}. "
                    "Determine if escalation is ongoing or completed."
                ),
                "is_critical": True,
                "requires_human_approval": True,
                "can_run_parallel": False,
                "expected_result": "Privilege escalation confirmed with scope defined.",
            },
            {
                "step_order": 2,
                "category": "containment",
                "title": "Revoke Elevated Privileges",
                "description_template": (
                    "Immediately revoke escalated privileges from {username}. "
                    "Remove from admin/sudo groups. Invalidate privilege tokens. "
                    "Force logout of active sessions on {device_name}."
                ),
                "command_windows": "Remove-LocalGroupMember -Group 'Administrators' -Member {username}",
                "command_linux": "gpasswd -d {username} sudo && pkill -u {username}",
                "is_critical": True,
                "requires_human_approval": True,
                "action_type": "revoke_credentials",
                "can_run_parallel": False,
                "expected_result": "Elevated privileges revoked and sessions terminated.",
            },
            {
                "step_order": 3,
                "category": "investigation",
                "title": "Identify Vulnerability",
                "description_template": (
                    "Identify the vulnerability or misconfiguration exploited for escalation. "
                    "Check for known vulnerabilities ({cve_id}, CVSS: {cvss_score}) on {device_os}. "
                    "Review SUID binaries, kernel exploits, and service misconfigurations."
                ),
                "command_windows": "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10",
                "command_linux": "find / -perm -4000 -type f 2>/dev/null && uname -r",
                "is_critical": True,
                "requires_human_approval": True,
                "can_run_parallel": True,
                "expected_result": "Escalation vector identified and documented.",
            },
            {
                "step_order": 4,
                "category": "eradication",
                "title": "Patch and Harden",
                "description_template": (
                    "Apply security patches for the identified vulnerability on {device_name}. "
                    "Implement principle of least privilege for {username} and similar accounts. "
                    "Deploy vulnerability scanner to find similar issues across the environment. {analyst_note}"
                ),
                "is_critical": True,
                "requires_human_approval": True,
                "can_run_parallel": False,
                "expected_result": "Vulnerability patched and system hardened.",
            },
        ],
    },
    {
        "name": "Lateral Movement Response",
        "description": "Response playbook for lateral movement detection (T1021/T1047).",
        "technique": "T1021",
        "tactic": "TA0008",
        "category": "lateral_movement",
        "steps": [
            {
                "step_order": 1,
                "category": "investigation",
                "title": "Map Attack Path",
                "description_template": (
                    "Map the complete lateral movement path starting from {device_name} ({source_ip}). "
                    "Identify all systems accessed by the attacker using {username} credentials. "
                    "Review authentication logs for {technique_id} activity in {timeframe}."
                ),
                "command_windows": "Get-WinEvent -LogName Security | Where-Object {$_.Id -in @(4624, 4648, 4672)}",
                "command_linux": "last -20 && grep 'Accepted' /var/log/auth.log | tail -100",
                "is_critical": True,
                "requires_human_approval": True,
                "can_run_parallel": False,
                "expected_result": "Full lateral movement path documented with all pivot points.",
            },
            {
                "step_order": 2,
                "category": "containment",
                "title": "Contain Affected Systems",
                "description_template": (
                    "Isolate all systems on the lateral movement path. "
                    "Disable the jump account {username} and revoke its credentials. "
                    "Segment the affected network segment."
                ),
                "is_critical": True,
                "requires_human_approval": True,
                "action_type": "isolate_device",
                "can_run_parallel": False,
                "expected_result": "All pivot systems isolated, lateral movement halted.",
            },
            {
                "step_order": 3,
                "category": "investigation",
                "title": "Identify Objective",
                "description_template": (
                    "Determine the attacker's objective — data theft, ransomware staging, or persistence. "
                    "Review what data was accessed on each pivot system. "
                    "Check for tools dropped (Mimikatz, PSExec, etc.) on {device_name}."
                ),
                "command_windows": "Get-EventLog -LogName Security -InstanceId 4624,4648 -Newest 200",
                "command_linux": "find /tmp /var/tmp -newer /etc/passwd -type f 2>/dev/null",
                "is_critical": True,
                "requires_human_approval": True,
                "can_run_parallel": True,
                "expected_result": "Attacker objective and data exposure scope determined.",
            },
            {
                "step_order": 4,
                "category": "eradication",
                "title": "Eradicate and Harden",
                "description_template": (
                    "Remove all attacker tools and persistence from affected systems. "
                    "Reset credentials for all accounts used in the attack chain. "
                    "Implement network segmentation to prevent future lateral movement. "
                    "Enable MFA for RDP and SMB access. {analyst_note}"
                ),
                "is_critical": True,
                "requires_human_approval": True,
                "can_run_parallel": False,
                "expected_result": "All systems cleaned, credentials reset, network segmented.",
            },
        ],
    },
]


async def seed_system_playbook_templates(db: AsyncSession) -> None:
    seeded = 0
    for tmpl_data in _SYSTEM_TEMPLATES:
        # Idempotent check by name + is_system
        existing = await db.execute(
            select(PlaybookTemplate).where(
                PlaybookTemplate.name == tmpl_data["name"],
                PlaybookTemplate.is_system.is_(True),
                PlaybookTemplate.deleted_at.is_(None),
            )
        )
        if existing.scalar_one_or_none() is not None:
            continue

        template = PlaybookTemplate(
            tenant_id=None,
            name=tmpl_data["name"],
            description=tmpl_data.get("description"),
            tactic=tmpl_data.get("tactic"),
            technique=tmpl_data.get("technique"),
            category=tmpl_data.get("category"),
            is_system=True,
            enabled=True,
        )
        db.add(template)
        await db.flush()

        for step_data in tmpl_data.get("steps", []):
            step = PlaybookTemplateStep(
                template_id=template.id,
                step_order=step_data["step_order"],
                category=step_data.get("category", "investigation"),
                title=step_data["title"],
                description_template=step_data.get("description_template"),
                command_windows=step_data.get("command_windows"),
                command_linux=step_data.get("command_linux"),
                expected_result=step_data.get("expected_result"),
                can_run_parallel=step_data.get("can_run_parallel", False),
                requires_human_approval=step_data.get("requires_human_approval", True),
                is_critical=step_data.get("is_critical", False),
                hint=step_data.get("hint"),
                action_type=step_data.get("action_type"),
                step_order_dependencies=[],
            )
            db.add(step)

        seeded += 1

    if seeded:
        await db.commit()
        logger.info("playbook_templates_seeded", count=seeded)
