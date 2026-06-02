"""
Shared fixtures for the correlation layer test suite.

Run from the backend/ directory:
    cd backend && python -m pytest tests/correlation/ -v

Or with PYTHONPATH:
    PYTHONPATH=backend python -m pytest backend/tests/correlation/ -v
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.normalization.models import (
    NormalizedEvent,
    NormalizedFile,
    NormalizedNetwork,
    NormalizedProcess,
    NormalizedUser,
)

# ── Constants used across tests ───────────────────────────────────────────────

TENANT_ID = "tenant-aaaabbbb-0000-1111-2222-333344445555"
AGENT_ID  = "agent-ccccdddd-0000-1111-2222-333344445555"
HOSTNAME  = "WORKSTATION-01"
TS        = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


# ── NormalizedEvent factory ───────────────────────────────────────────────────

def make_event(
    *,
    event_id:  str = "evt-001",
    hostname:  str = HOSTNAME,
    tenant_id: str = TENANT_ID,
    agent_id:  str = AGENT_ID,
    category:  str = "process",
    os_type:   str = "windows",
    process:   NormalizedProcess | None = None,
    network:   NormalizedNetwork | None = None,
    file:      NormalizedFile    | None = None,
    user:      NormalizedUser    | None = None,
    raw:       dict | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=TS,
        category=category,
        severity=2,
        hostname=hostname,
        os_type=os_type,
        agent_id=agent_id,
        tenant_id=tenant_id,
        process=process,
        network=network,
        file=file,
        user=user,
        raw=raw or {},
    )


# ── Sysmon raw event helpers ──────────────────────────────────────────────────

def sysmon_eid1(
    *,
    image:            str = r"C:\Windows\System32\cmd.exe",
    proc_guid:        str = "{11111111-1111-1111-1111-111111111111}",
    parent_guid:      str = "{22222222-2222-2222-2222-222222222222}",
    parent_image:     str = r"C:\Windows\explorer.exe",
    cmd_line:         str = "cmd.exe /c whoami",
    user:             str = "CORP\\john.doe",
    logon_id:         str = "0x3e9",
    hashes:           str = "MD5=abc123def456,SHA256=deadbeef0011223344556677889900aabb",
    pid:              int = 1234,
    ppid:             int = 5678,
) -> dict:
    return {
        "EventID":            "1",
        "ProcessGuid":        proc_guid,
        "ProcessId":          str(pid),
        "Image":              image,
        "CommandLine":        cmd_line,
        "User":               user,
        "ParentProcessGuid":  parent_guid,
        "ParentProcessId":    str(ppid),
        "ParentImage":        parent_image,
        "Hashes":             hashes,
        "LogonId":            logon_id,
    }


def sysmon_eid3(
    *,
    proc_guid:    str = "{11111111-1111-1111-1111-111111111111}",
    image:        str = r"C:\Windows\System32\svchost.exe",
    src_ip:       str = "10.0.0.5",
    dst_ip:       str = "93.184.216.34",
    dst_hostname: str = "example.com",
    dst_port:     int = 443,
) -> dict:
    return {
        "EventID":             "3",
        "ProcessGuid":         proc_guid,
        "Image":               image,
        "SourceIp":            src_ip,
        "DestinationIp":       dst_ip,
        "DestinationPort":     str(dst_port),
        "DestinationHostname": dst_hostname,
    }


def sysmon_eid22(
    *,
    proc_guid:  str = "{11111111-1111-1111-1111-111111111111}",
    query_name: str = "evil.example.com",
) -> dict:
    return {
        "EventID":    "22",
        "ProcessGuid": proc_guid,
        "QueryName":  query_name,
    }


def win_security_4624(
    *,
    subject_user:   str = "SYSTEM",
    subject_domain: str = "NT AUTHORITY",
    subject_logon:  str = "0x3e7",
    target_user:    str = "john.doe",
    target_domain:  str = "CORP",
    target_logon:   str = "0x3e9",
    ip_address:     str = "192.168.1.100",
) -> dict:
    return {
        "EventID":          "4624",
        "SubjectUserName":  subject_user,
        "SubjectDomainName": subject_domain,
        "SubjectLogonId":   subject_logon,
        "TargetUserName":   target_user,
        "TargetDomainName": target_domain,
        "TargetLogonId":    target_logon,
        "IpAddress":        ip_address,
    }


def linux_execve(
    *,
    uid:   str = "1000",
    auid:  str = "1000",
    pid:   int = 12345,
    ppid:  int = 5678,
    exe:   str = "/bin/bash",
    comm:  str = "bash",
    proctitle: str = "bash -c id",
) -> dict:
    return {
        "type":       "EXECVE",
        "uid":        uid,
        "auid":       auid,
        "pid":        str(pid),
        "ppid":       str(ppid),
        "exe":        exe,
        "comm":       comm,
        "proctitle":  proctitle,
    }
