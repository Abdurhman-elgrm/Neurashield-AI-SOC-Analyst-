"""
Built-in attack chain rules — 12 patterns covering the full MITRE ATT&CK kill chain.

Each rule correlates multiple alerts on the same host within a time window.
When matched, a new critical chain alert is created summarising the attack path.
"""

from __future__ import annotations

from .models import AttackChainRule, ChainStage

# ─── Stage keyword banks ──────────────────────────────────────────────────────

_CRED_DUMP = ChainStage(
    name="Credential Access",
    keywords=(
        "mimikatz",
        "lsass",
        "credential dump",
        "sam hive",
        "ntds",
        "dcsync",
        "sekurlsa",
        "lsadump",
        "pass-the-hash",
        "procdump",
        "wce",
        "pwdump",
        "lazagne",
        "rubeus",
    ),
)

_LATERAL = ChainStage(
    name="Lateral Movement",
    keywords=(
        "lateral movement",
        "psexec",
        "wmi remote",
        "wmi /node",
        "rdp",
        "remote interactive",
        "admin share",
        "type 3",
        "pass-the-ticket",
        "kerberos rc4",
        "dcom",
        "winrm",
    ),
)

_RECON = ChainStage(
    name="Discovery / Recon",
    keywords=(
        "enumeration",
        "net.exe",
        "whoami",
        "systeminfo",
        "ad recon",
        "bloodhound",
        "sharphound",
        "adfind",
        "powerview",
        "system enumeration",
        "user / group",
        "port scan",
    ),
)

_PERSISTENCE = ChainStage(
    name="Persistence",
    keywords=(
        "run key",
        "startup folder",
        "scheduled task",
        "service install",
        "wmi permanent",
        "com hijack",
        "autorun",
        "persistence",
        "new service",
        "registry autorun",
    ),
)

_DEFENSE_EVASION = ChainStage(
    name="Defense Evasion",
    keywords=(
        "log clear",
        "firewall disabled",
        "defender disabled",
        "amsi bypass",
        "etw",
        "audit log cleared",
        "1102",
        "4719",
        "applocker bypass",
        "script block logging disabled",
    ),
)

_EXECUTION = ChainStage(
    name="Execution",
    keywords=(
        "powershell",
        "encoded command",
        "download cradle",
        "mshta",
        "regsvr32",
        "rundll32",
        "wscript",
        "cscript",
        "installutil",
        "certutil",
        "bits",
        ".net compiler",
    ),
)

_INITIAL_ACCESS = ChainStage(
    name="Initial Access",
    keywords=(
        "office application spawning",
        "browser spawning",
        "macro",
        "drive-by",
        "phishing",
        "mshta - html",
        "exploited",
    ),
)

_BRUTE_FORCE = ChainStage(
    name="Brute Force",
    keywords=(
        "brute force",
        "failed logon threshold",
        "multiple.*failed",
        "credential stuffing",
        "ssh brute",
        "4625",
    ),
)

_LOGON_SUCCESS = ChainStage(
    name="Successful Authentication",
    keywords=(
        "logon success",
        "4624",
        "successful login",
        "authentication success",
        "token impersonation",
    ),
)

_RANSOMWARE = ChainStage(
    name="Ransomware Indicator",
    keywords=(
        "shadow copy",
        "vssadmin",
        "bcdedit",
        "wbadmin",
        "ransomware",
        "cipher wipe",
        "backup catalog",
        "file extension",
    ),
)

_EXFIL = ChainStage(
    name="Exfiltration",
    keywords=(
        "exfiltration",
        "archive tool",
        "ftp upload",
        "dns tunnel",
        "bits transfer",
        "data compression",
        "7z",
        "winrar",
    ),
)

_C2 = ChainStage(
    name="Command and Control",
    keywords=(
        "c2",
        "cobalt strike",
        "beacon",
        "dns tunneling",
        "tcp socket",
        "high port",
        "reverse shell",
        "netcat",
        "suspicious.*port",
    ),
)

_PRIV_ESC = ChainStage(
    name="Privilege Escalation",
    keywords=(
        "privilege escal",
        "setcbprivilege",
        "sedebuggprivilege",
        "alwaysinstallelevated",
        "cmstp",
        "token impersonation",
        "4672",
        "special privileges",
    ),
)

_HASH_IOC = ChainStage(
    name="Known Malware Hash",
    keywords=("malwarebazaar", "hash confirmed", "hash ioc"),
)

_PROCESS_INJECT = ChainStage(
    name="Process Injection",
    keywords=(
        "remote thread",
        "process inject",
        "sysmon event 8",
        "process hollow",
        "reflective",
    ),
)


# ─── Built-in chains ──────────────────────────────────────────────────────────

BUILTIN_CHAINS: tuple[AttackChainRule, ...] = (
    AttackChainRule(
        name="Brute Force → Account Compromise",
        description=(
            "Multiple failed logons followed by a successful authentication on the same host — "
            "indicates a successful brute force or credential stuffing attack."
        ),
        stages=(_BRUTE_FORCE, _LOGON_SUCCESS),
        window_secs=1800,
        final_severity="critical",
        mitre_tactics=("Credential Access", "Initial Access"),
        mitre_techniques=("T1110", "T1078"),
        min_stages=2,
    ),
    AttackChainRule(
        name="Credential Dump → Lateral Movement",
        description=(
            "Credential dumping followed by lateral movement — "
            "the attacker harvested credentials and is now moving across the network."
        ),
        stages=(_CRED_DUMP, _LATERAL),
        window_secs=3600,
        final_severity="critical",
        mitre_tactics=("Credential Access", "Lateral Movement"),
        mitre_techniques=("T1003", "T1021"),
        min_stages=2,
    ),
    AttackChainRule(
        name="Discovery → Privilege Escalation",
        description=(
            "Reconnaissance followed by privilege escalation — "
            "the attacker mapped the environment then elevated permissions to move deeper."
        ),
        stages=(_RECON, _PRIV_ESC),
        window_secs=7200,
        final_severity="high",
        mitre_tactics=("Discovery", "Privilege Escalation"),
        mitre_techniques=("T1069", "T1134"),
        min_stages=2,
    ),
    AttackChainRule(
        name="Defense Evasion → Execution",
        description=(
            "Defenses disabled then malicious code executed — "
            "the attacker blinded security tools before running their payload."
        ),
        stages=(_DEFENSE_EVASION, _EXECUTION),
        window_secs=1800,
        final_severity="critical",
        mitre_tactics=("Defense Evasion", "Execution"),
        mitre_techniques=("T1562", "T1059"),
        min_stages=2,
    ),
    AttackChainRule(
        name="Process Injection → C2 Beacon",
        description=(
            "Code injected into a host process followed by outbound C2 communication — "
            "classic post-exploitation implant establishing persistent command channel."
        ),
        stages=(_PROCESS_INJECT, _C2),
        window_secs=900,
        final_severity="critical",
        mitre_tactics=("Defense Evasion", "Command and Control"),
        mitre_techniques=("T1055", "T1071"),
        min_stages=2,
    ),
    AttackChainRule(
        name="Ransomware Multi-Stage Attack",
        description=(
            "Multiple ransomware preparation indicators detected in quick succession — "
            "shadow copies, boot recovery, and/or backup deletion before encryption."
        ),
        stages=(_RANSOMWARE, _RANSOMWARE),
        window_secs=600,
        final_severity="critical",
        mitre_tactics=("Impact",),
        mitre_techniques=("T1490", "T1486"),
        min_stages=2,
    ),
    AttackChainRule(
        name="Initial Access → Malicious Execution",
        description=(
            "Suspicious delivery mechanism (Office macro, browser exploit) followed by "
            "script execution — confirms a successful phishing or drive-by download attack."
        ),
        stages=(_INITIAL_ACCESS, _EXECUTION),
        window_secs=1800,
        final_severity="critical",
        mitre_tactics=("Initial Access", "Execution"),
        mitre_techniques=("T1566", "T1059"),
        min_stages=2,
    ),
    AttackChainRule(
        name="Persistence → C2 Communication",
        description=(
            "Persistence mechanism established then outbound C2 traffic detected — "
            "the attacker has secured long-term access and is actively communicating."
        ),
        stages=(_PERSISTENCE, _C2),
        window_secs=3600,
        final_severity="high",
        mitre_tactics=("Persistence", "Command and Control"),
        mitre_techniques=("T1547", "T1071"),
        min_stages=2,
    ),
    AttackChainRule(
        name="Credential Dump → Exfiltration",
        description=(
            "Credentials harvested then data exfiltration initiated — "
            "the attacker stole credentials and is staging or moving data out."
        ),
        stages=(_CRED_DUMP, _EXFIL),
        window_secs=7200,
        final_severity="high",
        mitre_tactics=("Credential Access", "Exfiltration"),
        mitre_techniques=("T1003", "T1048"),
        min_stages=2,
    ),
    AttackChainRule(
        name="Known Malware → Lateral Movement",
        description=(
            "A confirmed malware hash found on host followed by lateral movement — "
            "the malware is actively spreading across the network."
        ),
        stages=(_HASH_IOC, _LATERAL),
        window_secs=3600,
        final_severity="critical",
        mitre_tactics=("Execution", "Lateral Movement"),
        mitre_techniques=("T1204", "T1021"),
        min_stages=2,
    ),
    AttackChainRule(
        name="Full Kill Chain: Recon → Credential Dump → Lateral Movement",
        description=(
            "Three-stage kill chain confirmed on this host — "
            "reconnaissance, credential harvesting, and lateral movement all observed. "
            "Active intrusion in progress."
        ),
        stages=(_RECON, _CRED_DUMP, _LATERAL),
        window_secs=10800,
        final_severity="critical",
        mitre_tactics=("Discovery", "Credential Access", "Lateral Movement"),
        mitre_techniques=("T1069", "T1003", "T1021"),
        min_stages=3,
    ),
    AttackChainRule(
        name="Defense Evasion → Credential Dump → Persistence",
        description=(
            "Attacker disabled defenses, dumped credentials, and established persistence — "
            "full foothold achieved; host is fully compromised."
        ),
        stages=(_DEFENSE_EVASION, _CRED_DUMP, _PERSISTENCE),
        window_secs=10800,
        final_severity="critical",
        mitre_tactics=("Defense Evasion", "Credential Access", "Persistence"),
        mitre_techniques=("T1562", "T1003", "T1547"),
        min_stages=3,
    ),
)
