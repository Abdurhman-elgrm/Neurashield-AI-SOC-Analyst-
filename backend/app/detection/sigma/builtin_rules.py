from __future__ import annotations

from typing import Any

# ─── Standard Sigma YAML rules ────────────────────────────────────────────────
# Parsed by the Sigma parser and stored as DetectionRules.

BUILTIN_SIGMA_YAML: list[str] = [
    # ── Windows: Credential Access ────────────────────────────────────────────
    """
title: Mimikatz Credential Dumping
description: Detects Mimikatz usage via known executable names or command-line credential access patterns
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith:
      - '\\mimikatz.exe'
      - '\\mimilib.dll'
  selection_cmd:
    CommandLine|contains:
      - 'sekurlsa::logonpasswords'
      - 'lsadump::sam'
      - 'lsadump::dcsync'
      - 'privilege::debug'
      - 'token::elevate'
      - 'lsadump::lsa'
  condition: 1 of selection*
level: critical
tags:
  - attack.credential_access
  - attack.t1003
""",
    """
title: Suspicious LSASS Memory Access
description: Detects suspicious access to LSASS process — common credential dumping technique
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'procdump'
      - 'minidump'
    CommandLine|contains:
      - 'lsass'
  condition: selection
level: critical
tags:
  - attack.credential_access
  - attack.t1003.001
""",
    # ── Windows: Execution / LOLBins ──────────────────────────────────────────
    """
title: PowerShell Encoded Command Execution
description: Detects PowerShell with an encoded command parameter — common malware obfuscation technique
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
      - ' -e '
  filter_len:
    CommandLine|re: '.*-(e|enc|EncodedCommand)\\s+[A-Za-z0-9+/]{10,}'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001
""",
    """
title: Certutil Suspicious Usage
description: Certutil used to download, encode, or decode files — common malware dropper and evasion technique
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\certutil.exe'
    CommandLine|contains:
      - '-urlcache'
      - '-decode'
      - '-decodehex'
      - '-encode'
      - 'http'
      - 'ftp'
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1140
""",
    """
title: Suspicious MSHTA Remote Execution
description: MSHTA executing remote scripts or URLs — common initial access and execution vector
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\mshta.exe'
    CommandLine|contains:
      - 'http'
      - 'javascript'
      - 'vbscript'
      - '.hta'
      - 'ftp:'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1218.005
""",
    """
title: Suspicious Rundll32 Execution
description: Rundll32 executing scripts or non-standard DLL patterns — common LOLBin abuse
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\rundll32.exe'
    CommandLine|contains:
      - 'javascript:'
      - 'vbscript:'
      - ',StartscanW'
      - 'shell32.dll,ShellExec_RunDLL'
      - 'url.dll,FileProtocolHandler'
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1218.011
""",
    """
title: Regsvr32 COM Scriptlet Execution
description: Regsvr32 used to execute COM scriptlets — common AppLocker bypass
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\regsvr32.exe'
    CommandLine|contains:
      - '/s'
      - '/u'
      - 'http'
      - '.sct'
      - 'scrobj'
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1218.010
""",
    # ── Windows: Lateral Movement ─────────────────────────────────────────────
    """
title: PsExec Lateral Movement
description: PsExec or compatible tool used for remote execution — lateral movement indicator
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith:
      - '\\PsExec.exe'
      - '\\PsExec64.exe'
  selection_svc:
    Image|endswith: '\\services.exe'
    CommandLine|contains: 'PSEXESVC'
  condition: 1 of selection*
level: high
tags:
  - attack.lateral_movement
  - attack.t1021.002
""",
    """
title: WMI Remote Execution
description: WMIC used with /node parameter indicating remote execution
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\wmic.exe'
    CommandLine|contains: '/node:'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.lateral_movement
  - attack.t1047
""",
    # ── Windows: Discovery ────────────────────────────────────────────────────
    """
title: Net.exe Domain Reconnaissance
description: Net.exe used for domain user/group enumeration — common discovery technique
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\\net.exe'
      - '\\net1.exe'
    CommandLine|contains:
      - 'user /domain'
      - 'group /domain'
      - 'localgroup administrators'
      - 'accounts /domain'
      - 'view /domain'
  condition: selection
level: medium
tags:
  - attack.discovery
  - attack.t1087
""",
    # ── Windows: Persistence ──────────────────────────────────────────────────
    """
title: Suspicious Scheduled Task Creation
description: Scheduled task created that executes a script or shell — common persistence mechanism
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\schtasks.exe'
    CommandLine|contains: '/create'
    CommandLine|contains:
      - 'powershell'
      - 'cmd /c'
      - 'wscript'
      - 'cscript'
      - 'mshta'
      - 'rundll32'
      - 'regsvr32'
  condition: selection
level: high
tags:
  - attack.persistence
  - attack.t1053.005
""",
    """
title: Registry Run Key Persistence
description: Executable or script added to registry Run/RunOnce key for persistence
status: stable
logsource:
  category: registry_set
  product: windows
detection:
  selection:
    TargetObject|contains:
      - '\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
      - '\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
      - '\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run'
    Details|contains:
      - 'powershell'
      - 'cmd.exe'
      - 'wscript'
      - 'cscript'
      - 'mshta'
      - 'rundll32'
      - 'regsvr32'
  condition: selection
level: high
tags:
  - attack.persistence
  - attack.t1547.001
""",
    # ── Linux: Execution ──────────────────────────────────────────────────────
    """
title: Linux Reverse Shell Indicators
description: Common reverse shell patterns detected on Linux — execution via bash TCP, netcat, or python socket
status: stable
logsource:
  category: process_creation
  product: linux
detection:
  selection_bash:
    CommandLine|contains:
      - '/dev/tcp/'
      - 'bash -i'
      - '0>&1'
      - '>&2'
  selection_nc:
    Image|endswith:
      - '/nc'
      - '/ncat'
      - '/netcat'
    CommandLine|contains:
      - ' -e '
  selection_python:
    Image|contains: 'python'
    CommandLine|contains|all:
      - 'socket'
      - '/bin/sh'
  condition: 1 of selection*
level: critical
tags:
  - attack.execution
  - attack.t1059.004
""",
    """
title: Suspicious Linux Execution from Temp Directory
description: Process executed from /tmp or /dev/shm — common malware drop-and-execute location
status: stable
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|startswith:
      - '/tmp/'
      - '/dev/shm/'
      - '/var/tmp/'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059
""",
    # ── Linux: Persistence ────────────────────────────────────────────────────
    """
title: Linux Crontab Persistence
description: Crontab file modified — common Linux persistence technique
status: stable
logsource:
  category: file_event
  product: linux
detection:
  selection:
    TargetFilename|startswith:
      - '/etc/cron'
      - '/var/spool/cron'
  condition: selection
level: medium
tags:
  - attack.persistence
  - attack.t1053.003
""",
    # ── DNS: C2 Detection ─────────────────────────────────────────────────────
    """
title: Suspicious Long DNS Hostname (DNS Tunneling)
description: Unusually long subdomain query often indicates DNS tunneling for C2 data exfiltration
status: experimental
logsource:
  category: dns_query
detection:
  selection:
    QueryName|re: '^[a-zA-Z0-9_-]{25,}\\..*$'
  condition: selection
level: medium
tags:
  - attack.command_and_control
  - attack.t1071.004
""",
    # ── Windows: AMSI Bypass ──────────────────────────────────────────────────
    """
title: AMSI Bypass Attempt via Reflection
description: Detects PowerShell commands using .NET reflection to patch or disable AMSI — allows malicious scripts to run without antivirus scanning
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
    CommandLine|contains:
      - 'amsiInitFailed'
      - 'AmsiScanBuffer'
      - 'amsiContext'
      - 'AmsiUtils'
      - '[Ref].Assembly'
      - 'System.Management.Automation.AmsiUtils'
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1562.001
""",
    # ── Windows: BITS Abuse ───────────────────────────────────────────────────
    """
title: BITS Transfer Job Used for Payload Download
description: BITSAdmin or PowerShell Start-BitsTransfer used to download a file — abuses Background Intelligent Transfer Service to blend download traffic
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection_bitsadmin:
    Image|endswith: '\\bitsadmin.exe'
    CommandLine|contains:
      - '/transfer'
      - '/addfile'
      - '/create'
  selection_powershell:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
    CommandLine|contains:
      - 'Start-BitsTransfer'
      - 'BitsJob'
  condition: 1 of selection*
level: medium
tags:
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1197
""",
    # ── Windows: Suspicious Parent-Child Process ──────────────────────────────
    """
title: Office Application Spawning Script Interpreter
description: Microsoft Office application spawning a script interpreter or command shell — primary indicator of macro-based malware execution
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|contains:
      - '\\WINWORD.EXE'
      - '\\EXCEL.EXE'
      - '\\POWERPNT.EXE'
      - '\\OUTLOOK.EXE'
      - '\\MSPUB.EXE'
      - '\\VISIO.EXE'
    Image|endswith:
      - '\\cmd.exe'
      - '\\powershell.exe'
      - '\\wscript.exe'
      - '\\cscript.exe'
      - '\\mshta.exe'
      - '\\rundll32.exe'
      - '\\regsvr32.exe'
  condition: selection
level: high
tags:
  - attack.initial_access
  - attack.execution
  - attack.t1566.001
  - attack.t1059
""",
    # ── Windows: Browser Spawning Shell ──────────────────────────────────────
    """
title: Browser Spawning Command Shell (Drive-By Download Indicator)
description: Web browser spawning a command-line interpreter — strong indicator of drive-by download or browser exploit delivering a payload
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|contains:
      - '\\chrome.exe'
      - '\\firefox.exe'
      - '\\msedge.exe'
      - '\\iexplore.exe'
      - '\\opera.exe'
      - '\\brave.exe'
    Image|endswith:
      - '\\cmd.exe'
      - '\\powershell.exe'
      - '\\wscript.exe'
      - '\\cscript.exe'
      - '\\mshta.exe'
  condition: selection
level: high
tags:
  - attack.initial_access
  - attack.execution
  - attack.t1189
  - attack.t1059
""",
    # ── Windows: Cobalt Strike Indicators ────────────────────────────────────
    """
title: Cobalt Strike Beacon Named Pipe Pattern
description: Process created a named pipe matching common Cobalt Strike beacon patterns — strong indicator of active C2 implant
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'postex_'
      - 'msagent_'
      - 'status_'
      - 'mojo.5688'
      - 'wkssvc_'
      - 'ntsvcs'
      - 'DserNamePipe'
  condition: selection
level: critical
tags:
  - attack.command_and_control
  - attack.t1071
  - attack.t1090
""",
    # ── Windows: Living-Off-the-Land Execution Chain ──────────────────────────
    """
title: Suspicious Script Execution via WScript or CScript from Temp
description: WScript or CScript executing a script from a temporary directory — common malware delivery pattern to avoid detection by path-based rules
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\\wscript.exe'
      - '\\cscript.exe'
    CommandLine|contains:
      - '\\Temp\\'
      - '\\AppData\\'
      - '\\Users\\Public\\'
      - '\\ProgramData\\'
      - '\\Downloads\\'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1059.005
""",
    # ── Linux: Privilege Escalation via SUID Binary ───────────────────────────
    """
title: SUID Binary Execution for Privilege Escalation
description: Execution of known SUID binaries used for privilege escalation (GTFOBins) — attackers use these to obtain root shell from a low-privileged user
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains:
      - 'python -c "import os; os.setuid(0)'
      - 'perl -e "use POSIX"'
      - 'find / -perm -u=s'
      - 'find . -exec /bin/sh'
      - 'nmap --interactive'
      - 'vim -c ":!sh"'
      - 'awk "BEGIN {system'
  condition: selection
level: high
tags:
  - attack.privilege_escalation
  - attack.t1548.001
""",
    # ── Windows: Ransomware Staging ───────────────────────────────────────────
    """
title: Ransomware Staging - Mass Rename or Extension Change
description: Process modifying or renaming large numbers of files with suspicious extensions appended — characteristic first stage of ransomware file encryption
status: experimental
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetFilename|endswith:
      - '.encrypted'
      - '.locked'
      - '.crypto'
      - '.enc'
      - '.crypt'
      - '.locky'
      - '.cerber'
      - '.zepto'
      - '.odin'
      - '.aesir'
      - '.wnry'
      - '.wncry'
      - '.wncrypt'
  condition: selection
level: critical
tags:
  - attack.impact
  - attack.t1486
""",
]


# ─── Native UEBA catch-all rules (conditions already in our format) ────────────
# These don't map to standard Sigma logsources, so they're defined directly.

BUILTIN_UEBA_RULES: list[dict[str, Any]] = [
    {
        "title": "UEBA Strong Behavioral Anomaly",
        "description": (
            "UEBA detected a strong behavioral anomaly (score >= 0.80). "
            "High probability of malicious activity based on significant deviation from baseline."
        ),
        "severity": "high",
        "conditions": [
            {"field": "ueba_is_anomaly", "op": "eq", "value": True},
            {"field": "ueba_score", "op": "gte", "value": 0.8},
        ],
        "mitre_techniques": [],
        "mitre_tactics": [],
    },
    {
        "title": "UEBA Critical Attack Chain - Impossible Travel",
        "description": (
            "UEBA detected impossible travel: authentication from two geographically distant "
            "locations within an impossible timeframe. Likely account compromise."
        ),
        "severity": "critical",
        "conditions": [
            {"field": "ueba_flags", "op": "list_contains", "value": "impossible_travel"},
        ],
        "mitre_techniques": ["T1078"],
        "mitre_tactics": ["initial-access"],
    },
    {
        "title": "UEBA Critical Attack Chain - Brute Force Success",
        "description": (
            "UEBA detected successful authentication following multiple failed attempts. "
            "Likely brute force attack leading to account compromise."
        ),
        "severity": "critical",
        "conditions": [
            {"field": "ueba_flags", "op": "list_contains", "value": "brute_force_success"},
        ],
        "mitre_techniques": ["T1110"],
        "mitre_tactics": ["credential-access"],
    },
    {
        "title": "UEBA Lateral Movement Detected",
        "description": (
            "UEBA detected lateral movement behavior: entity accessing multiple systems "
            "significantly beyond its normal baseline pattern."
        ),
        "severity": "high",
        "conditions": [
            {
                "op": "any_of",
                "conditions": [
                    {"field": "ueba_flags", "op": "list_contains", "value": "lateral_movement"},
                    {
                        "field": "ueba_flags",
                        "op": "list_contains",
                        "value": "lateral_movement_xdomain",
                    },
                ],
            },
        ],
        "mitre_techniques": ["T1021"],
        "mitre_tactics": ["lateral-movement"],
    },
    {
        "title": "UEBA Off-Hours Access Anomaly",
        "description": (
            "UEBA detected significant access outside the entity's normal working hours. "
            "May indicate account compromise or insider threat activity."
        ),
        "severity": "medium",
        "conditions": [
            {"field": "ueba_flags", "op": "list_contains", "value": "off_hours_access"},
            {"field": "ueba_score", "op": "gte", "value": 0.6},
        ],
        "mitre_techniques": [],
        "mitre_tactics": [],
    },
    {
        "title": "UEBA Confirmed Threat IP Behavioral Anomaly",
        "description": (
            "Communication with a confirmed malicious IP combined with a behavioral anomaly. "
            "High-confidence indicator of active threat actor activity."
        ),
        "severity": "critical",
        "conditions": [
            {"field": "is_threat_ip", "op": "eq", "value": True},
            {"field": "ueba_is_anomaly", "op": "eq", "value": True},
        ],
        "mitre_techniques": [],
        "mitre_tactics": ["command-and-control"],
    },
]
