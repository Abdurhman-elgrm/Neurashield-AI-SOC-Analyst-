"""Unit tests for the normalization pipeline."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.normalization.mapper import map_stream_message_to_normalized
from app.normalization.models import NormalizedEvent
from app.normalization.windows import normalize_windows_event
from app.normalization.linux import normalize_linux_event


def _base_message(**kwargs) -> dict:
    defaults = {
        "agent_id": "00000000-0000-0000-0000-000000000001",
        "tenant_id": "00000000-0000-0000-0000-000000000002",
        "hostname": "WIN-TEST01",
        "os_type": "windows",
        "event_id": "evt-001",
        "timestamp": "2025-05-22T10:00:00Z",
        "category": "process",
        "raw": {},
    }
    defaults.update(kwargs)
    return defaults


class TestMapperBasics:

    def test_timestamp_parsed_from_iso(self):
        msg = _base_message(timestamp="2025-05-22T10:00:00+00:00")
        event = map_stream_message_to_normalized(msg)
        assert event.timestamp is not None
        assert event.timestamp.tzinfo is not None

    def test_unknown_timestamp_falls_back_to_now(self):
        msg = _base_message(timestamp=None)
        event = map_stream_message_to_normalized(msg)
        assert event.timestamp is not None

    def test_severity_string_mapped_correctly(self):
        for sev_str, expected in [("low", 1), ("info", 1), ("medium", 2), ("high", 3), ("critical", 4)]:
            msg = _base_message(severity=sev_str)
            event = map_stream_message_to_normalized(msg)
            assert event.severity == expected

    def test_unknown_category_defaults_to_other(self):
        msg = _base_message(category="something_weird")
        event = map_stream_message_to_normalized(msg)
        assert event.category == "other"

    def test_fields_preserved(self):
        msg = _base_message(hostname="SERVER01", os_type="linux")
        event = map_stream_message_to_normalized(msg)
        assert event.hostname == "SERVER01"
        assert event.os_type == "linux"
        assert event.agent_id == "00000000-0000-0000-0000-000000000001"


class TestWindowsNormalization:

    def test_sysmon_process_create(self):
        msg = _base_message(
            event_id_windows="1",
            Image=r"C:\Windows\System32\cmd.exe",
            CommandLine="cmd.exe /c whoami",
            ProcessId="1234",
            ParentProcessId="500",
            User="DOMAIN\\user1",
            Hashes="MD5=abc123,SHA256=def456",
        )
        from app.normalization.models import NormalizedEvent
        base = NormalizedEvent(
            event_id="evt-001",
            timestamp=datetime.now(tz=timezone.utc),
            category="process",
            hostname="WIN01",
            os_type="windows",
            agent_id="agent1",
            tenant_id="tenant1",
        )
        result = normalize_windows_event(msg, base)
        assert result.process is not None
        assert result.process.name == "cmd.exe"
        assert result.process.pid == 1234
        assert result.process.command_line == "cmd.exe /c whoami"
        assert result.process.hash_md5 == "abc123"
        assert result.process.hash_sha256 == "def456"

    def test_sysmon_network_connect(self):
        msg = _base_message(
            event_id_windows="3",
            SourceIp="192.168.1.10",
            SourcePort="54321",
            DestinationIp="8.8.8.8",
            DestinationPort="53",
            Protocol="udp",
            Initiated="true",
        )
        from app.normalization.models import NormalizedEvent
        base = NormalizedEvent(
            event_id="evt-002",
            timestamp=datetime.now(tz=timezone.utc),
            category="network",
            hostname="WIN01",
            os_type="windows",
            agent_id="agent1",
            tenant_id="tenant1",
        )
        result = normalize_windows_event(msg, base)
        assert result.network is not None
        assert result.network.src_ip == "192.168.1.10"
        assert result.network.dst_ip == "8.8.8.8"
        assert result.network.dst_port == 53
        assert result.network.direction == "outbound"

    def test_windows_logon_event_4624(self):
        msg = _base_message(
            event_id_windows="4624",
            TargetUserName="jsmith",
            TargetDomainName="CORP",
            TargetUserSid="S-1-5-21-xxx",
        )
        from app.normalization.models import NormalizedEvent
        base = NormalizedEvent(
            event_id="evt-003",
            timestamp=datetime.now(tz=timezone.utc),
            category="auth",
            hostname="WIN01",
            os_type="windows",
            agent_id="agent1",
            tenant_id="tenant1",
        )
        result = normalize_windows_event(msg, base)
        assert result.category == "auth"
        assert result.user is not None
        assert result.user.name == "jsmith"
        assert result.user.domain == "CORP"


class TestLinuxNormalization:

    def test_execve_syscall(self):
        msg = _base_message(
            os_type="linux",
            syscall="execve",
            exe="/bin/bash",
            a0="/bin/bash",
            a1="-c",
            a2="id",
            pid="4567",
        )
        from app.normalization.models import NormalizedEvent
        base = NormalizedEvent(
            event_id="evt-004",
            timestamp=datetime.now(tz=timezone.utc),
            category="process",
            hostname="linux01",
            os_type="linux",
            agent_id="agent1",
            tenant_id="tenant1",
        )
        result = normalize_linux_event(msg, base)
        assert result.category == "process"
        assert result.process is not None
        assert result.process.name == "bash"

    def test_failed_setuid_severity(self):
        msg = _base_message(
            os_type="linux",
            syscall="setuid",
            category="auth",
            res="failed",
        )
        from app.normalization.models import NormalizedEvent
        base = NormalizedEvent(
            event_id="evt-005",
            timestamp=datetime.now(tz=timezone.utc),
            category="auth",
            hostname="linux01",
            os_type="linux",
            agent_id="agent1",
            tenant_id="tenant1",
            severity=1,
        )
        result = normalize_linux_event(msg, base)
        assert result.severity == 2
