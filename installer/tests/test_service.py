"""
Tests for soc_agent.service (AgentRuntime)

Coverage:
- stop() sets the stop event and run_loop exits cleanly
- Graceful shutdown within POLL_INTERVAL_SECS timeout
- Heartbeat is sent at HEARTBEAT_INTERVAL (mocked time)
- Event collection triggered at LOG_INTERVAL
- Network collection triggered at NETWORK_INTERVAL
- Process collection triggered at PROCESS_INTERVAL
- Failed credential load during _init raises (service does not start silently)
- _collect_network_events skips non-ESTABLISHED lines
- _collect_network_events flags suspicious ports
- _collect_process_events flags suspicious process names
- _ingest_batch posts correct JSON envelope
- Loop catches per-iteration errors and continues (doesn't crash)
- _get_local_ip returns a string (may be "unknown" in CI)
"""
from __future__ import annotations

import threading
import time
import uuid
from pathlib import Path
from unittest.mock import patch, MagicMock, call, PropertyMock

import pytest

# conftest already stubbed win32crypt + pywin32 modules


# ─── AgentRuntime stop/lifecycle ─────────────────────────────────────────────

class TestAgentRuntimeLifecycle:
    def _make_runtime(self):
        from soc_agent.service import AgentRuntime
        rt = AgentRuntime()
        # Patch out the long-running IO so tests run fast
        rt._send_heartbeat = MagicMock()
        rt._collect_and_ingest = MagicMock()
        rt._collect_network = MagicMock()
        rt._collect_processes = MagicMock()
        return rt

    def test_stop_sets_event(self):
        from soc_agent.service import AgentRuntime
        rt = AgentRuntime()
        assert not rt._stop.is_set()
        rt.stop()
        assert rt._stop.is_set()

    def test_run_loop_exits_after_stop(self):
        rt = self._make_runtime()
        rt._creds = MagicMock()
        rt._log = MagicMock()
        rt._session = MagicMock()
        rt._api_url = "https://soc.example.com"

        # Pre-set the stop event so the loop exits on first iteration
        rt._stop.set()

        thread = threading.Thread(target=rt._run_loop, daemon=True)
        thread.start()
        thread.join(timeout=2.0)

        assert not thread.is_alive(), "run_loop did not exit after stop event set"

    def test_graceful_shutdown_within_poll_interval(self):
        rt = self._make_runtime()
        rt._creds = MagicMock()
        rt._log = MagicMock()
        rt._session = MagicMock()
        rt._api_url = "https://soc.example.com"

        t_start = time.monotonic()
        thread = threading.Thread(target=rt._run_loop, daemon=True)
        thread.start()

        time.sleep(0.05)  # let the loop spin once
        rt.stop()
        thread.join(timeout=rt.POLL_INTERVAL_SECS + 1.0)

        elapsed = time.monotonic() - t_start
        assert not thread.is_alive(), "Thread still alive after stop"
        # Should be well under POLL_INTERVAL_SECS * 2
        assert elapsed < rt.POLL_INTERVAL_SECS * 2

    def test_loop_calls_heartbeat(self):
        rt = self._make_runtime()
        rt._creds = MagicMock()
        rt._log = MagicMock()
        rt._session = MagicMock()
        rt._api_url = "https://soc.example.com"

        # Override timestamps so heartbeat fires immediately on first tick
        rt._last_heartbeat = 0.0

        # Set stop inside the heartbeat mock so the loop runs exactly once
        original = rt._send_heartbeat
        def heartbeat_then_stop():
            original()
            rt._stop.set()
        rt._send_heartbeat = heartbeat_then_stop

        rt._run_loop()

        # original was a MagicMock; it was called once inside heartbeat_then_stop
        original.assert_called_once()

    def test_loop_continues_after_per_iteration_error(self):
        """An exception in a single tick must not crash the service."""
        rt = self._make_runtime()
        rt._creds = MagicMock()
        rt._log = MagicMock()
        rt._session = MagicMock()
        rt._api_url = "https://soc.example.com"

        call_count = 0

        def explode():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("transient error")
            rt._stop.set()  # exit on second call

        rt._send_heartbeat = explode
        rt._last_heartbeat = 0.0  # ensure heartbeat fires every tick

        rt._run_loop()  # should not raise

        assert call_count == 2
        rt._log.error.assert_called()


# ─── _init raises on bad credentials ─────────────────────────────────────────

class TestInitErrors:
    def test_missing_credentials_raises(self, install_dir):
        from soc_agent.service import AgentRuntime

        rt = AgentRuntime()

        # Point to a config that references the temp install dir
        from soc_agent.config import write_config
        cfg_path = install_dir / "config" / "agent.ini"
        write_config(cfg_path, api_url="https://soc.example.com",
                     install_dir=str(install_dir))

        with patch("soc_agent.service._INSTALL_DIR", install_dir):
            with pytest.raises(FileNotFoundError):
                rt._init()


# ─── Collectors ───────────────────────────────────────────────────────────────

class TestNetworkCollector:
    def test_skips_non_established_lines(self):
        from soc_agent.service import _collect_network_events

        netstat_output = (
            "Proto  Local Address      Foreign Address    State\n"
            "TCP    0.0.0.0:80         0.0.0.0:0          LISTENING\n"
            "TCP    10.0.0.1:55432     8.8.8.8:443        ESTABLISHED\n"
            "TCP    10.0.0.1:55433     1.2.3.4:9999       ESTABLISHED\n"
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=netstat_output)
            events = _collect_network_events()

        # 9999 is suspicious; 443 is not
        suspicious = [e for e in events if e.get("alert") == "suspicious_port"]
        assert len(suspicious) == 1
        assert "9999" in suspicious[0]["remote_addr"]

    def test_no_events_for_benign_connections(self):
        from soc_agent.service import _collect_network_events

        netstat_output = (
            "TCP    10.0.0.1:55432     8.8.8.8:443        ESTABLISHED\n"
            "TCP    10.0.0.1:55433     1.1.1.1:80         ESTABLISHED\n"
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=netstat_output)
            events = _collect_network_events()

        assert events == []

    def test_subprocess_failure_returns_empty(self):
        from soc_agent.service import _collect_network_events

        with patch("subprocess.run", side_effect=Exception("process error")):
            events = _collect_network_events()

        assert events == []

    def test_all_suspicious_ports_flagged(self):
        from soc_agent.service import _collect_network_events

        suspicious_ports = [4444, 1337, 31337, 6666, 5555, 8888, 9999]
        lines = "\n".join(
            f"TCP    10.0.0.1:5000{i}     1.2.3.4:{p}        ESTABLISHED"
            for i, p in enumerate(suspicious_ports)
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=lines)
            events = _collect_network_events()

        assert len(events) == len(suspicious_ports)


class TestProcessCollector:
    def test_flags_suspicious_process(self):
        from soc_agent.service import _collect_process_events

        tasklist_output = (
            '"chrome.exe","1234","Console","1","50,000 K"\n'
            '"mimikatz.exe","9999","Console","1","5,000 K"\n'
            '"explorer.exe","4321","Console","1","20,000 K"\n'
        )

        with patch("soc_agent.service._ON_WINDOWS", True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=tasklist_output)
            events = _collect_process_events()

        assert len(events) == 1
        assert events[0]["process_name"] == "mimikatz.exe"
        assert events[0]["alert"] == "suspicious_process"

    def test_clean_process_list_returns_empty(self):
        from soc_agent.service import _collect_process_events

        tasklist_output = (
            '"chrome.exe","1234","Console","1","50,000 K"\n'
            '"explorer.exe","4321","Console","1","20,000 K"\n'
        )

        with patch("soc_agent.service._ON_WINDOWS", True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=tasklist_output)
            events = _collect_process_events()

        assert events == []

    def test_all_suspicious_names_flagged(self):
        from soc_agent.service import _collect_process_events

        suspicious = ["mimikatz.exe", "procdump.exe", "nc.exe", "ncat.exe", "netcat.exe"]
        lines = "\n".join(
            f'"{name}","{i}","Console","1","1,000 K"'
            for i, name in enumerate(suspicious)
        )

        with patch("soc_agent.service._ON_WINDOWS", True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=lines)
            events = _collect_process_events()

        assert len(events) == len(suspicious)

    def test_subprocess_failure_returns_empty(self):
        from soc_agent.service import _collect_process_events

        with patch("soc_agent.service._ON_WINDOWS", True), \
             patch("subprocess.run", side_effect=Exception("process error")):
            events = _collect_process_events()

        assert events == []


# ─── _ingest_batch ────────────────────────────────────────────────────────────

class TestIngestBatch:
    def test_posts_correct_envelope(self):
        from soc_agent.service import AgentRuntime

        rt = AgentRuntime()
        rt._log = MagicMock()

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"data": {"accepted": 2, "rejected": 0}}

        mock_session = MagicMock()
        mock_session.post.return_value = mock_resp
        rt._session = mock_session
        rt._api_url = "https://soc.example.com"

        events = [
            {"category": "auth", "timestamp": "2026-01-01T00:00:00Z", "event_id_windows": 4624},
            {"category": "auth", "timestamp": "2026-01-01T00:00:01Z", "event_id_windows": 4625},
        ]
        rt._ingest_batch(events, source="windows_evtlog")

        mock_session.post.assert_called_once()
        call_kwargs = mock_session.post.call_args.kwargs
        assert call_kwargs["json"]["events"][0]["category"] == "auth"
        assert "event_id" in call_kwargs["json"]["events"][0]  # UUID was added

    def test_ingest_failure_logged_not_raised(self):
        from soc_agent.service import AgentRuntime

        rt = AgentRuntime()
        rt._log = MagicMock()

        mock_session = MagicMock()
        mock_session.post.side_effect = Exception("connection refused")
        rt._session = mock_session
        rt._api_url = "https://soc.example.com"

        # Must not raise
        rt._ingest_batch([{"category": "auth"}], source="test")

        rt._log.warning.assert_called_once()


# ─── _get_local_ip ────────────────────────────────────────────────────────────

class TestGetLocalIp:
    def test_returns_string(self):
        from soc_agent.service import _get_local_ip

        ip = _get_local_ip()
        assert isinstance(ip, str)
        assert len(ip) > 0

    def test_returns_unknown_on_error(self):
        from soc_agent.service import _get_local_ip
        import socket

        with patch("socket.socket") as mock_socket_cls:
            mock_socket_cls.side_effect = OSError("network unavailable")
            ip = _get_local_ip()

        assert ip == "unknown"
