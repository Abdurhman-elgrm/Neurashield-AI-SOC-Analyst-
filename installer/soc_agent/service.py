"""
SOC Analyst Agent — Windows Service (pywin32)

Installation:
    python service.py install
    python service.py start
    python service.py stop
    python service.py remove

The service:
  1. Loads encrypted runtime credentials (DPAPI).
  2. Sends heartbeats to the SOC Platform every 20 seconds.
  3. Collects and batches Windows Security / System / Application events.
  4. Posts event batches to /api/v1/agents/ingest.
  5. Responds to SERVICE_CONTROL_STOP within 5 seconds (graceful shutdown).
  6. The SCM recovery policy (set by bootstrap.ps1) restarts it on crash.
  7. Applies exponential backoff on repeated backend failures.
  8. Detects token revocation (401) and shuts down gracefully.
"""
from __future__ import annotations

import os
import platform
import socket
import sys
import threading
import time
from pathlib import Path

# ─── Windows service boilerplate ─────────────────────────────────────────────
#
# pywin32 is only available on Windows.  Guard every import so the module
# remains importable on Linux/CI for testing purposes.

_ON_WINDOWS = platform.system() == "Windows"

if _ON_WINDOWS:
    import win32event          # type: ignore[import]
    import win32service        # type: ignore[import]
    import win32serviceutil    # type: ignore[import]
    import servicemanager      # type: ignore[import]

# ─── Locate the agent install directory ──────────────────────────────────────

_INSTALL_DIR = Path(
    os.environ.get("SOC_INSTALL_DIR", "C:\\ProgramData\\SOCAnalyst")
)

# Add bin/ to sys.path so soc_agent package is importable when running as svc
_BIN_DIR = _INSTALL_DIR / "bin"
if str(_BIN_DIR) not in sys.path:
    sys.path.insert(0, str(_BIN_DIR))


# ─── Exponential backoff tracker ─────────────────────────────────────────────

class _BackoffTracker:
    """
    Tracks consecutive failures and computes an exponential backoff delay.
    Thread-safe via a simple lock — only used from the single run_loop thread.
    """

    def __init__(self, base_secs: int = 30, max_secs: int = 300) -> None:
        self._base = base_secs
        self._max = max_secs
        self._failures = 0
        self._lock = threading.Lock()

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0

    def record_failure(self) -> None:
        with self._lock:
            self._failures = min(self._failures + 1, 8)

    @property
    def next_interval(self) -> int:
        with self._lock:
            return min(self._max, self._base * (2 ** self._failures))

    @property
    def consecutive_failures(self) -> int:
        with self._lock:
            return self._failures


# ─── Agent runtime ────────────────────────────────────────────────────────────

class AgentRuntime:
    """
    The long-running agent logic — runs inside the Windows service.
    Uses threading.Event for cooperative stop so we never block
    more than POLL_INTERVAL_SECS seconds on shutdown.
    """

    HEARTBEAT_INTERVAL   = 20    # seconds (base; multiplied by backoff)
    LOG_INTERVAL         = 10    # seconds
    NETWORK_INTERVAL     = 300   # seconds
    PROCESS_INTERVAL     = 300   # seconds
    POLL_INTERVAL_SECS   = 5     # main loop tick

    # After this many consecutive heartbeat failures, log a degraded-mode warning
    DEGRADED_THRESHOLD   = 3

    def __init__(self) -> None:
        self._stop    = threading.Event()
        self._session: "requests.Session | None" = None
        self._creds:   "RuntimeCredentials | None" = None
        self._log:     "BoundLogger | None" = None

        self._last_heartbeat = 0.0
        self._last_log_run   = 0.0
        self._last_net_run   = 0.0
        self._last_proc_run  = 0.0

        self._heartbeat_backoff = _BackoffTracker(base_secs=self.HEARTBEAT_INTERVAL, max_secs=300)
        self._ingest_backoff    = _BackoffTracker(base_secs=self.LOG_INTERVAL, max_secs=120)

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Called from SvcDoRun — blocks until stop() is called."""
        self._init()
        self._run_loop()

    def stop(self) -> None:
        """Signal the run loop to exit — returns quickly."""
        self._stop.set()

    # ── Initialisation ───────────────────────────────────────────────────────

    def _init(self) -> None:
        from soc_agent.config import read_config, locate_config
        from soc_agent.log_manager import setup_service_logging
        from soc_agent.credential_store import load_credentials

        config   = read_config(locate_config(_INSTALL_DIR))
        log_dir  = _INSTALL_DIR / "logs"
        self._log = setup_service_logging(
            log_dir,
            log_level=config.get("log_level", "INFO"),
            max_bytes=int(config.get("log_max_bytes", str(10 * 1024 * 1024))),
            backup_count=int(config.get("log_backup_count", "5")),
        ).bind(service="SOCAnalystAgent")

        self._log.info("agent_starting", install_dir=str(_INSTALL_DIR))

        cred_path = _INSTALL_DIR / "credentials" / "runtime.dat"
        try:
            self._creds = load_credentials(cred_path)
        except Exception as exc:
            self._log.error("credential_load_failed", error=str(exc))
            raise

        import requests as _req
        self._session = _req.Session()
        self._session.headers.update({
            "X-Agent-ID":    str(self._creds.agent_id),
            "X-Agent-Token": self._creds.enrollment_token,
            "X-Tenant-ID":   str(self._creds.tenant_id),
            "Content-Type":  "application/json",
        })
        self._api_url = self._creds.api_url

        self._log.info(
            "agent_initialised",
            agent_id=str(self._creds.agent_id),
            tenant_id=str(self._creds.tenant_id),
            api_url=self._api_url,
        )

        self._log_startup_diagnostics(config)

    def _log_startup_diagnostics(self, config: object) -> None:
        """Emit a one-time diagnostic log entry at startup for observability."""
        try:
            import subprocess, datetime as _dt
            uptime_info = ""
            if _ON_WINDOWS:
                result = subprocess.run(
                    ["net", "statistics", "workstation"],
                    capture_output=True, text=True, timeout=5,
                )
                for line in result.stdout.splitlines():
                    if "Statistics since" in line or "Statistic" in line:
                        uptime_info = line.strip()
                        break

            self._log.info(
                "agent_startup_diagnostics",
                python_version=platform.python_version(),
                platform=platform.platform(),
                hostname=socket.gethostname(),
                install_dir=str(_INSTALL_DIR),
                api_url=self._api_url,
                agent_id=str(self._creds.agent_id),
                tenant_id=str(self._creds.tenant_id),
                on_windows=_ON_WINDOWS,
                startup_time=_dt.datetime.utcnow().isoformat() + "Z",
                uptime_hint=uptime_info,
            )
        except Exception:
            pass  # diagnostics are best-effort

    # ── Main loop ─────────────────────────────────────────────────────────────

    def _run_loop(self) -> None:
        while not self._stop.is_set():
            now = time.monotonic()

            try:
                hb_interval = self._heartbeat_backoff.next_interval
                if now - self._last_heartbeat >= hb_interval:
                    self._send_heartbeat()
                    self._last_heartbeat = now

                ingest_interval = self._ingest_backoff.next_interval
                if now - self._last_log_run >= ingest_interval:
                    self._collect_and_ingest()
                    self._last_log_run = now

                if now - self._last_net_run >= self.NETWORK_INTERVAL:
                    self._collect_network()
                    self._last_net_run = now

                if now - self._last_proc_run >= self.PROCESS_INTERVAL:
                    self._collect_processes()
                    self._last_proc_run = now

            except Exception as exc:
                self._log.error("loop_iteration_error", error=str(exc), exc_info=True)

            self._stop.wait(timeout=self.POLL_INTERVAL_SECS)

        self._log.info("agent_stopped_cleanly")

    # ── Heartbeat ─────────────────────────────────────────────────────────────

    def _send_heartbeat(self) -> None:
        try:
            resp = self._session.post(
                f"{self._api_url}/api/v1/agents/heartbeat",
                json={
                    "agent_version": "2.0.0",
                    "ip_address":    _get_local_ip(),
                    "os_metrics":    {},
                },
                timeout=10,
            )

            # 401 = token revoked or invalid — stop the service gracefully
            if resp.status_code == 401:
                self._log.error(
                    "agent_credentials_rejected",
                    status_code=401,
                    hint="Enrollment token was revoked or is invalid. Agent will stop.",
                )
                self.stop()
                return

            resp.raise_for_status()
            self._heartbeat_backoff.record_success()

            if self._heartbeat_backoff.consecutive_failures > 0:
                self._log.info("heartbeat_recovered", backoff_reset=True)

            self._log.debug("heartbeat_sent")

        except Exception as exc:
            self._heartbeat_backoff.record_failure()
            failures = self._heartbeat_backoff.consecutive_failures
            next_retry = self._heartbeat_backoff.next_interval

            if failures == self.DEGRADED_THRESHOLD:
                self._log.warning(
                    "agent_entering_degraded_mode",
                    consecutive_failures=failures,
                    next_retry_secs=next_retry,
                    error=str(exc),
                )
            else:
                self._log.warning(
                    "heartbeat_failed",
                    error=str(exc),
                    consecutive_failures=failures,
                    next_retry_secs=next_retry,
                )

    # ── Event collection and ingestion ────────────────────────────────────────

    def _collect_and_ingest(self) -> None:
        events = _collect_windows_events() if _ON_WINDOWS else []
        if not events:
            return
        self._ingest_batch(events, source="windows_evtlog")

    def _collect_network(self) -> None:
        events = _collect_network_events()
        if events:
            self._ingest_batch(events, source="network_monitor")

    def _collect_processes(self) -> None:
        events = _collect_process_events()
        if events:
            self._ingest_batch(events, source="process_monitor")

    def _ingest_batch(self, events: list[dict], source: str) -> None:
        import uuid as _uuid
        import datetime as _dt
        payload = {
            "events": [
                {
                    "event_id": str(_uuid.uuid4()),
                    "timestamp": e.get("timestamp", _dt.datetime.utcnow().isoformat() + "Z"),
                    "category":  e.get("category", "other"),
                    "raw":       e,
                }
                for e in events
            ]
        }
        try:
            resp = self._session.post(
                f"{self._api_url}/api/v1/agents/ingest",
                json=payload,
                timeout=30,
            )

            # 401 = credentials revoked — same as heartbeat
            if resp.status_code == 401:
                self._log.error(
                    "agent_credentials_rejected_on_ingest",
                    status_code=401,
                    hint="Enrollment token was revoked. Agent will stop.",
                )
                self.stop()
                return

            resp.raise_for_status()
            result = resp.json().get("data", {})
            self._ingest_backoff.record_success()
            self._log.info(
                "batch_ingested",
                source=source,
                accepted=result.get("accepted", 0),
                rejected=result.get("rejected", 0),
            )
        except Exception as exc:
            self._ingest_backoff.record_failure()
            self._log.warning(
                "ingest_failed",
                source=source,
                error=str(exc),
                consecutive_failures=self._ingest_backoff.consecutive_failures,
                next_retry_secs=self._ingest_backoff.next_interval,
            )


# ─── Collectors ───────────────────────────────────────────────────────────────

def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unknown"


def _collect_windows_events() -> list[dict]:
    """Read new events from the Windows Security event log."""
    events = []
    try:
        import win32evtlog  # type: ignore[import]
        state_file = _INSTALL_DIR / "state" / "evtlog_checkpoint.json"
        last_record: dict = {}
        if state_file.exists():
            import json
            try:
                last_record = json.loads(state_file.read_text())
            except Exception:
                pass

        for channel in ("Security", "System"):
            handle = win32evtlog.OpenEventLog(None, channel)
            flags  = (
                win32evtlog.EVENTLOG_BACKWARDS_READ
                | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            )
            last = last_record.get(channel, 0)
            new_last = last

            batch = []
            done  = False
            while not done:
                records = win32evtlog.ReadEventLog(handle, flags, 0) or []
                if not records:
                    break
                for ev in records:
                    if ev.RecordNumber <= last:
                        done = True
                        break
                    batch.append(ev)
                    if len(batch) >= 200:
                        done = True
                        break

            for ev in batch:
                new_last = max(new_last, ev.RecordNumber)
                events.append({
                    "category":          "auth" if channel == "Security" else "other",
                    "timestamp":         ev.TimeGenerated.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "event_id_windows":  ev.EventID & 0xFFFF,
                    "source":            ev.SourceName,
                    "channel":           channel,
                    "record":            ev.RecordNumber,
                })
            last_record[channel] = new_last
            win32evtlog.CloseEventLog(handle)

        # Save checkpoint atomically
        import json
        state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(last_record))
        tmp.replace(state_file)

    except Exception:
        pass
    return events


def _collect_network_events() -> list[dict]:
    import subprocess, datetime as _dt
    events = []
    _SUSPICIOUS_PORTS = {4444, 1337, 31337, 6666, 5555, 8888, 9999}
    try:
        out = subprocess.run(
            ["netstat", "-ano"] if _ON_WINDOWS else ["netstat", "-tn"],
            capture_output=True, text=True, timeout=15,
        ).stdout
        for line in out.splitlines():
            if "ESTABLISHED" not in line:
                continue
            parts = line.split()
            remote = parts[2] if _ON_WINDOWS else (parts[4] if len(parts) > 4 else "")
            if ":" not in remote:
                continue
            try:
                port = int(remote.rsplit(":", 1)[-1])
                if port in _SUSPICIOUS_PORTS:
                    events.append({
                        "category":    "network",
                        "timestamp":   _dt.datetime.utcnow().isoformat() + "Z",
                        "remote_addr": remote,
                        "alert":       "suspicious_port",
                    })
            except ValueError:
                pass
    except Exception:
        pass
    return events


def _collect_process_events() -> list[dict]:
    import subprocess, datetime as _dt
    events = []
    _SUSPICIOUS = {"mimikatz.exe", "procdump.exe", "nc.exe", "ncat.exe", "netcat.exe"}
    try:
        if _ON_WINDOWS:
            out = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=15,
            ).stdout
            for line in out.splitlines():
                name = line.strip().strip('"').split('","')[0].lower()
                if name in _SUSPICIOUS:
                    events.append({
                        "category":     "process",
                        "timestamp":    _dt.datetime.utcnow().isoformat() + "Z",
                        "process_name": name,
                        "alert":        "suspicious_process",
                    })
    except Exception:
        pass
    return events


# ─── pywin32 Service class ────────────────────────────────────────────────────

if _ON_WINDOWS:
    class SOCAnalystAgentService(win32serviceutil.ServiceFramework):
        _svc_name_         = "SOCAnalystAgent"
        _svc_display_name_ = "SOC Analyst Agent"
        _svc_description_  = "Security event collection and forwarding for SOC Platform v2"

        def __init__(self, args: list) -> None:
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)
            self._runtime    = AgentRuntime()

        def SvcDoRun(self) -> None:
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            try:
                self._runtime.start()          # blocks until stop() called
            except Exception as exc:
                servicemanager.LogErrorMsg(f"SOCAnalystAgent crashed: {exc}")
                raise

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._runtime.stop()
            win32event.SetEvent(self._stop_event)


# ─── Entry point ─────────────────────────────────────────────────────────────

def main() -> None:
    if _ON_WINDOWS:
        if len(sys.argv) == 1:
            # Called by SCM to start the service
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(SOCAnalystAgentService)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            # Called with install / start / stop / remove
            win32serviceutil.HandleCommandLine(SOCAnalystAgentService)
    else:
        # Non-Windows: run the agent directly (useful for Docker/CI)
        runtime = AgentRuntime()
        import signal
        signal.signal(signal.SIGTERM, lambda *_: runtime.stop())
        signal.signal(signal.SIGINT,  lambda *_: runtime.stop())
        runtime.start()


if __name__ == "__main__":
    main()
