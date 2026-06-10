#!/usr/bin/env python3
"""
NEURASHIELD SOC Agent v2.0
Reads credentials from C:\ProgramData\SOCAnalyst\credentials.json
Uses V2 backend authentication (X-Agent-ID + X-Agent-Token + X-Tenant-ID)
"""

import datetime
import gzip
import hashlib
import json
import os
import platform
import re
import socket
import sqlite3
import subprocess
import sys
import threading
import time

try:
    import requests
except ImportError:
    os.system(f'"{sys.executable}" -m pip install requests --quiet')
    import requests

# ── Config ────────────────────────────────────────────────────────────────────

_AGENT_DIR      = r"C:\ProgramData\SOCAnalyst"
_CREDS_FILE     = os.path.join(_AGENT_DIR, "credentials.json")
_LOG_PATH       = os.path.join(_AGENT_DIR, "agent_v2.log")
_Q_DB_PATH      = os.path.join(_AGENT_DIR, "event_queue_v2.db")
_CHECKPOINT_FILE = os.path.join(_AGENT_DIR, "checkpoint_v2.json")
_LOG_MAX_BYTES  = 10 * 1024 * 1024


def _load_credentials():
    if not os.path.exists(_CREDS_FILE):
        raise RuntimeError(
            f"Credentials not found at {_CREDS_FILE}. "
            "Run bootstrap.ps1 first to enroll this device."
        )
    with open(_CREDS_FILE, encoding="utf-8") as f:
        creds = json.load(f)
    missing = [k for k in ("agent_id", "enrollment_token", "tenant_id", "api_url")
               if not creds.get(k)]
    if missing:
        raise RuntimeError(f"credentials.json missing fields: {missing}")
    return creds


_creds           = _load_credentials()
API_ENDPOINT     = _creds["api_url"].rstrip("/")
AGENT_ID         = _creds["agent_id"]
ENROLLMENT_TOKEN = _creds["enrollment_token"]
TENANT_ID        = _creds["tenant_id"]
_HOSTNAME        = _creds.get("hostname") or platform.node()

# ── Logging ───────────────────────────────────────────────────────────────────


def _open_log():
    try:
        return open(_LOG_PATH, "a", encoding="utf-8", errors="replace", buffering=1)
    except Exception:
        return None


_LOG_FH = _open_log()

import builtins as _builtins
_orig_print = _builtins.print


def _tee_print(*a, **kw):
    global _LOG_FH
    kw.setdefault("flush", True)
    if _LOG_FH:
        try:
            if _LOG_FH.tell() > _LOG_MAX_BYTES:
                _LOG_FH.close()
                bak = _LOG_PATH + ".1"
                try:
                    if os.path.exists(bak):
                        os.remove(bak)
                    os.rename(_LOG_PATH, bak)
                except Exception:
                    pass
                _LOG_FH = _open_log()
            sep = kw.get("sep", " ")
            end = kw.get("end", "\n")
            _LOG_FH.write(sep.join(str(x) for x in a) + end)
            _LOG_FH.flush()
        except Exception:
            pass
    try:
        _orig_print(*a, **kw)
    except Exception:
        pass


_builtins.print = _tee_print


def _now():
    return datetime.datetime.now().strftime("%H:%M:%S")


def _utc_iso():
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

# ── Auth headers ──────────────────────────────────────────────────────────────


def _agent_headers():
    """V2 auth: all three headers are required by the backend."""
    return {
        "X-Agent-ID":    AGENT_ID,
        "X-Agent-Token": ENROLLMENT_TOKEN,
        "X-Tenant-ID":   TENANT_ID,
        "Content-Type":  "application/json",
    }

# ── HTTP helpers ──────────────────────────────────────────────────────────────


_AGENT_REVOKED = False


def _post(path: str, payload: dict, timeout: int = 10) -> bool:
    global _AGENT_REVOKED
    if _AGENT_REVOKED:
        return False
    for attempt in range(3):
        try:
            r = requests.post(
                f"{API_ENDPOINT}{path}",
                json=payload,
                headers=_agent_headers(),
                timeout=timeout,
            )
            if r.status_code == 401:
                _AGENT_REVOKED = True
                print(f"[{_now()}] Agent credentials rejected (401) — re-enroll this device")
                return False
            if r.status_code == 410:
                _AGENT_REVOKED = True
                print(f"[{_now()}] Agent removed from dashboard (410)")
                return False
            r.raise_for_status()
            return True
        except requests.exceptions.RequestException as exc:
            if attempt < 2:
                time.sleep(2 ** attempt)
            else:
                print(f"[{_now()}] POST {path} failed: {exc}")
    return False

# ── Heartbeat ─────────────────────────────────────────────────────────────────

HEARTBEAT_INTERVAL = 20  # seconds


def _get_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return None


def _heartbeat() -> bool:
    """POST /api/v1/agents/heartbeat — schema: HeartbeatRequest"""
    os_metrics = {}
    try:
        import psutil
        os_metrics = {
            "cpu_percent":  psutil.cpu_percent(interval=0.1),
            "memory_percent": psutil.virtual_memory().percent,
            "uptime_seconds": time.time() - psutil.boot_time(),
        }
    except ImportError:
        pass

    payload = {
        "agent_version": "2.0.0",
        "ip_address":    _get_ip(),
        "os_metrics":    os_metrics,
    }
    return _post("/api/v1/agents/heartbeat", payload, timeout=5)

# ── Event format conversion ───────────────────────────────────────────────────


def _source_to_category(source_name: str) -> str:
    """Map V1 source_name to V2 category enum."""
    s = source_name.lower()
    if any(x in s for x in ("security", "auth", "logon", "kerberos", "ntlm")):
        return "auth"
    if "network" in s:
        return "network"
    if any(x in s for x in ("process", "sysmon", "powershell", "scheduler", "wmi")):
        return "process"
    if any(x in s for x in ("fim", "file", "applocker")):
        return "file"
    if "registry" in s:
        return "registry"
    if "dns" in s:
        return "dns"
    return "other"


def _v1_to_v2_event(v1_event: dict) -> dict:
    """Convert a V1-style log entry to a V2 RawEventPayload dict."""
    raw_msg  = v1_event.get("raw_message", "")
    src_name = v1_event.get("source_name", "unknown")
    ts       = v1_event.get("timestamp", _utc_iso())

    # Stable unique ID: sha256 of channel + timestamp + first 200 chars of message
    uid_src  = f"{src_name}|{ts}|{raw_msg[:200]}"
    event_id = hashlib.sha256(uid_src.encode("utf-8", "replace")).hexdigest()[:32]

    # Try to parse event_id number from "EventID 4624: ..." messages
    process_data = None
    user_data    = None
    raw_extra    = {"source": src_name, "message": raw_msg}

    evt_match = re.match(r"EventID\s+(\d+):\s*(.*)", raw_msg, re.DOTALL)
    if evt_match:
        raw_extra["event_id_number"] = int(evt_match.group(1))
        raw_extra["event_detail"]    = evt_match.group(2)[:500]

    # Extract Account Name if present (for auth events)
    acct_match = re.search(r"Account Name:\s*(.+)", raw_msg)
    if acct_match:
        user_data = {"username": acct_match.group(1).strip()}

    # Extract process name if present
    proc_match = re.search(r"New Process Name:\s*(.+)", raw_msg)
    if proc_match:
        process_data = {"name": os.path.basename(proc_match.group(1).strip())}

    event = {
        "event_id":  event_id,
        "timestamp": ts,
        "category":  _source_to_category(src_name),
        "hostname":  _HOSTNAME,
        "os_type":   "windows" if platform.system() == "Windows" else platform.system().lower(),
        "raw":       raw_extra,
    }
    if process_data:
        event["process"] = process_data
    if user_data:
        event["user"] = user_data

    return event

# ── Queue ─────────────────────────────────────────────────────────────────────

_Q_BATCH_SIZE  = 20
_Q_MAX_RETRIES = 5
_Q_BASE_BACKOFF = 10.0
_Q_MAX_BACKOFF  = 300.0


class _EventQueue:
    def __init__(self, db_path):
        self._lock = threading.RLock()
        self._db   = sqlite3.connect(db_path, check_same_thread=False)
        self._db.executescript("""
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS queue (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_hash    TEXT    NOT NULL UNIQUE,
    payload       TEXT    NOT NULL,
    created_at    REAL    NOT NULL,
    retry_count   INTEGER NOT NULL DEFAULT 0,
    next_retry_at REAL    NOT NULL DEFAULT 0
);
""")
        self._db.commit()

    def enqueue(self, events: list):
        if not events:
            return
        now = time.time()
        with self._lock:
            for evt in events:
                raw = json.dumps(evt, sort_keys=True, separators=(",", ":"))
                h   = hashlib.sha256(raw.encode()).hexdigest()
                try:
                    self._db.execute(
                        "INSERT INTO queue(event_hash,payload,created_at) VALUES(?,?,?)",
                        (h, raw, now),
                    )
                except sqlite3.IntegrityError:
                    pass
            self._db.commit()

    def fetch_batch(self):
        now = time.time()
        with self._lock:
            return self._db.execute(
                "SELECT id,payload,retry_count FROM queue "
                "WHERE next_retry_at<=? ORDER BY created_at ASC LIMIT ?",
                (now, _Q_BATCH_SIZE),
            ).fetchall()

    def ack(self, ids):
        if not ids:
            return
        with self._lock:
            self._db.execute(
                "DELETE FROM queue WHERE id IN ({})".format(",".join("?" * len(ids))), ids
            )
            self._db.commit()

    def nack(self, id_, retry_count):
        now = time.time()
        new_retry = retry_count + 1
        with self._lock:
            if new_retry >= _Q_MAX_RETRIES:
                self._db.execute("DELETE FROM queue WHERE id=?", (id_,))
            else:
                backoff = min(_Q_BASE_BACKOFF * (2 ** (new_retry - 1)), _Q_MAX_BACKOFF)
                self._db.execute(
                    "UPDATE queue SET retry_count=?,next_retry_at=? WHERE id=?",
                    (new_retry, now + backoff, id_),
                )
            self._db.commit()


class _QueueDrainer:
    def __init__(self, queue):
        self._q = queue
        t = threading.Thread(target=self._loop, daemon=True, name="QueueDrainer")
        t.start()

    def _loop(self):
        while True:
            try:
                self._drain()
            except Exception:
                pass
            time.sleep(5)

    def _drain(self):
        rows = self._q.fetch_batch()
        if not rows:
            return

        ids          = [r[0] for r in rows]
        retry_counts = {r[0]: r[2] for r in rows}
        events = []
        bad    = []
        for id_, payload_str, _ in rows:
            try:
                events.append(json.loads(payload_str))
            except Exception:
                bad.append(id_)
        for id_ in bad:
            self._q.nack(id_, retry_counts[id_])
        ids    = [i for i in ids    if i not in set(bad)]
        events = [events[k] for k, r in enumerate(rows) if r[0] not in set(bad)]
        if not ids:
            return

        # V2 ingest endpoint: POST /api/v1/agents/ingest
        # Body: IngestBatchRequest = { "events": [RawEventPayload, ...] }
        # Regular JSON (no gzip — backend has no decompression middleware)
        payload = {"events": events}

        err = ""
        for attempt in range(3):
            try:
                r = requests.post(
                    f"{API_ENDPOINT}/api/v1/agents/ingest",
                    json=payload,
                    headers=_agent_headers(),
                    timeout=30,
                )
                if r.status_code == 200:
                    self._q.ack(ids)
                    print(f"[{_now()}] [Q] Delivered {len(ids)} events")
                    return
                if r.status_code in (401, 403, 410):
                    for id_ in ids:
                        self._q.nack(id_, retry_counts[id_])
                    print(f"[{_now()}] [Q] Auth error {r.status_code} — stopping delivery")
                    return
                err = f"http_{r.status_code}: {r.text[:200]}"
            except Exception as exc:
                err = str(exc)[:200]
            if attempt < 2:
                time.sleep(2 ** attempt)

        for id_ in ids:
            self._q.nack(id_, retry_counts[id_])
        print(f"[{_now()}] [Q] Delivery failed: {err}")


_queue   = None
_drainer = None


def _init_queue():
    global _queue, _drainer
    if _queue is None:
        _queue   = _EventQueue(_Q_DB_PATH)
        _drainer = _QueueDrainer(_queue)


def _queue_events(v1_logs: list):
    """Convert V1 log entries to V2 format and enqueue."""
    if not v1_logs or _queue is None:
        return
    v2_events = [_v1_to_v2_event(e) for e in v1_logs]
    _queue.enqueue(v2_events)

# ── Monitoring (ported from V1 soc_agent.py) ─────────────────────────────────

# -- Constants -----------------------------------------------------------------

_SUSPICIOUS_PORTS = {
    4444, 1337, 31337, 6666, 6667, 6668, 6669,
    9001, 9030, 5555, 8888, 9999, 12345, 54321, 65535,
}

_SUSPICIOUS_PROC_NAMES = {
    "mimikatz.exe", "procdump.exe", "wce.exe", "pwdump.exe",
    "nc.exe", "ncat.exe", "netcat.exe", "psexec.exe", "psexecsvc.exe",
    "lazagne.exe", "sharpdump.exe", "rubeus.exe", "bloodhound.exe",
    "cobaltstrike.exe", "beacon.exe",
}

_SUSPICIOUS_PROC_DIRS = (
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "\\users\\public\\", "\\programdata\\",
    "/tmp/", "/dev/shm/", "/var/tmp/",
)

_FIM_TARGETS_WINDOWS = [
    r"C:\Windows\System32\drivers\etc\hosts",
    r"C:\Windows\System32\userinit.exe",
    r"C:\Windows\System32\winlogon.exe",
    r"C:\Windows\System32\cmd.exe",
]

_FIM_TARGETS_LINUX = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/crontab", "/etc/hosts",
]

_fim_hashes:        dict = {}
_seen_connections:  dict = {}
_SEEN_CONNECTION_TTL = 3600

_SKIP_IDS = {
    4798, 4799, 5379, 4634, 4608, 4609, 4616,
    4902, 4904, 4905, 5038, 5061, 105, 16, 0,
}

_ALWAYS_SEND_IDS = {
    4625, 4648, 4720, 4722, 4724, 4725, 4726,
    4728, 4732, 4756, 4776, 4698, 4702,
    7045, 1102, 4719, 5152, 5157,
}

_SAFE_PROCESSES = {
    "svchost.exe", "searchindexer.exe", "wmiprvse.exe", "runtimebroker.exe",
    "taskhostw.exe", "sihost.exe", "fontdrvhost.exe", "dwm.exe", "csrss.exe",
    "smss.exe", "lsass.exe", "services.exe", "winlogon.exe", "wininit.exe",
    "msmpeng.exe", "nissrv.exe", "spoolsv.exe", "msdtc.exe",
    "dllhost.exe", "conhost.exe", "explorer.exe",
}

_SYSTEM_ACCOUNTS  = {"system", "network service", "local service"}
CAPTURE_ALL_EVENTS = True

_WIN_MODERN_CHANNELS = [
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-WMI-Activity/Operational",
    "Microsoft-Windows-AppLocker/EXE and DLL",
    "Microsoft-Windows-Firewall-With-Advanced-Security/Firewall",
    "Microsoft-Windows-DNS-Client/Operational",
]

_EVTID_FIELDS = {
    4624: [("Account Name", 5), ("Logon Type", 8), ("Network Address", 18),
           ("Process Name", 17), ("Subject Account Name", 1)],
    4625: [("Account Name", 5), ("Failure Reason", 7), ("Logon Type", 10),
           ("Network Address", 19), ("Subject Account Name", 1)],
    4648: [("Account Name", 6), ("Target Server Name", 9), ("Network Address", 12)],
    4672: [("Account Name", 1), ("Privileges", 4)],
    4688: [("Subject Account Name", 1), ("New Process Name", 5),
           ("Creator Process Name", 9), ("Process Command Line", 10)],
    4720: [("Account Name", 1), ("New Account Name", 4)],
    4726: [("Account Name", 1), ("Target Account Name", 4)],
    4732: [("Account Name", 1), ("Member Name", 4), ("Group Name", 6)],
    4740: [("Account Name", 0), ("Workstation Name", 1)],
    4776: [("Logon Account", 1), ("Source Workstation", 2), ("Error Code", 3)],
    7045: [("Service Name", 0), ("Image Path", 1), ("Service Type", 2)],
}

# -- Checkpoint ----------------------------------------------------------------

_win_last_record:    dict = {}
_win_modern_last_ts: dict = {}
_linux_tailers:      dict = {}


def _load_checkpoint():
    try:
        if os.path.exists(_CHECKPOINT_FILE):
            with open(_CHECKPOINT_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_checkpoint():
    try:
        tmp = _CHECKPOINT_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump({
                "win_last_record":    dict(_win_last_record),
                "win_modern_last_ts": dict(_win_modern_last_ts),
                "linux_positions":    {p: t.pos for p, t in _linux_tailers.items()},
            }, f)
        os.replace(tmp, _CHECKPOINT_FILE)
    except Exception:
        pass

# -- Smart filter --------------------------------------------------------------


def should_send_event(event_id, inserts):
    inserts = inserts or ()
    if event_id in _SKIP_IDS:
        return False
    if event_id in _ALWAYS_SEND_IDS:
        return True
    if event_id == 4624:
        try:
            if str(inserts[8]).strip() == "5":
                return False
        except Exception:
            pass
        try:
            if str(inserts[5]).strip().lower() in _SYSTEM_ACCOUNTS or \
               str(inserts[5]).strip().lower().endswith("$"):
                return False
        except Exception:
            pass
        return True
    if event_id == 4672:
        try:
            subj = str(inserts[1]).strip().lower()
            if subj in _SYSTEM_ACCOUNTS or subj.endswith("$"):
                return False
        except Exception:
            pass
        return True
    if event_id == 4688:
        try:
            proc_name = str(inserts[5]).strip().split("\\")[-1].lower()
            if proc_name in _SAFE_PROCESSES:
                return False
        except Exception:
            pass
        return True
    return False

# -- Event message formatter ---------------------------------------------------


def _fmt_event_message(ev, channel):
    event_id = ev.EventID & 0xFFFF
    inserts  = ev.StringInserts or ()
    try:
        import win32evtlogutil
        msg = win32evtlogutil.SafeFormatMessage(ev, ev.SourceName)
        if msg and msg.strip() and "could not be found" not in msg:
            return msg.strip().replace("\r\n", "\n").replace("\r", "\n")
    except Exception:
        pass
    if event_id in _EVTID_FIELDS and inserts:
        lines = []
        for label, idx in _EVTID_FIELDS[event_id]:
            if idx < len(inserts):
                val = str(inserts[idx]).strip()
                if val and val != "-" and not val.startswith("%%"):
                    lines.append(f"{label}: {val}")
        if lines:
            return "\n".join(lines)
    if inserts:
        return " ".join(str(s) for s in inserts)
    return ""

# -- Windows log reader --------------------------------------------------------


def _read_windows_logs() -> list:
    try:
        import win32evtlog
    except ImportError:
        print(f"[{_now()}] pywin32 not installed — skipping Windows logs")
        return []

    logs = []
    for channel in ("Security", "System", "Application"):
        try:
            handle   = win32evtlog.OpenEventLog(None, channel)
            flags    = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            last     = _win_last_record.get(channel, 0)
            new_last = last

            _cutoff   = None
            _is_first = (last == 0)
            if _is_first:
                _cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=2)

            all_new = []
            done    = False
            while not done:
                batch = win32evtlog.ReadEventLog(handle, flags, 0) or []
                if not batch:
                    break
                if not all_new and batch[0].RecordNumber < last:
                    last     = 0
                    new_last = 0
                for ev in batch:
                    if ev.RecordNumber <= last:
                        done = True
                        break
                    if _cutoff and ev.TimeGenerated.replace(tzinfo=None) < _cutoff:
                        done = True
                        break
                    all_new.append(ev)
                    if _is_first and len(all_new) >= 500:
                        done = True
                        break

            for ev in all_new:
                new_last = max(new_last, ev.RecordNumber)
                event_id = ev.EventID & 0xFFFF

                if CAPTURE_ALL_EVENTS:
                    if event_id in _SKIP_IDS:
                        continue
                elif not should_send_event(event_id, ev.StringInserts):
                    continue

                full_msg = _fmt_event_message(ev, channel)
                logs.append({
                    "source_name": f"{channel}/{ev.SourceName}",
                    "timestamp":   ev.TimeGenerated.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "raw_message": f"EventID {event_id}: {full_msg or '(no message)'}",
                })

            _win_last_record[channel] = new_last
            win32evtlog.CloseEventLog(handle)
        except Exception as exc:
            print(f"[{_now()}] Error reading {channel} log: {exc}")

    return logs


def _read_win_modern_channels() -> list:
    logs = []
    try:
        import win32evtlog as _w32
    except ImportError:
        return []

    import xml.etree.ElementTree as _et
    NS  = "http://schemas.microsoft.com/win/2004/08/events/event"
    _SYS = "{" + NS + "}System"
    _TC  = "{" + NS + "}TimeCreated"
    _EID = "{" + NS + "}EventID"
    _DATA = "{" + NS + "}Data"

    for channel in _WIN_MODERN_CHANNELS:
        try:
            last_ts   = _win_modern_last_ts.get(channel)
            _is_first = (last_ts is None)
            if last_ts:
                xpath = "*[System[TimeCreated[@SystemTime>'" + last_ts + "']]]"
            else:
                cutoff = (datetime.datetime.utcnow() - datetime.timedelta(hours=2)
                          ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
                xpath = "*[System[TimeCreated[@SystemTime>'" + cutoff + "']]]"

            try:
                query = _w32.EvtQuery(
                    channel,
                    _w32.EvtQueryChannelPath | _w32.EvtQueryForwardDirection,
                    xpath,
                )
            except Exception:
                continue

            new_ts = last_ts
            count  = 0
            while not (_is_first and count >= 200):
                try:
                    evts = _w32.EvtNext(query, 10)
                except Exception:
                    break
                if not evts:
                    break
                for evt in evts:
                    try:
                        xml_str = _w32.EvtRender(evt, _w32.EvtRenderEventXml)
                        root    = _et.fromstring(xml_str)
                        sys_el  = root.find(_SYS)
                        ts_el   = sys_el.find(_TC) if sys_el is not None else None
                        ts      = ts_el.get("SystemTime") if ts_el is not None else _utc_iso()
                        eid_el  = sys_el.find(_EID) if sys_el is not None else None
                        eid     = eid_el.text if eid_el is not None else "0"
                        parts   = []
                        for d in root.iter(_DATA):
                            name = d.get("Name", "")
                            val  = (d.text or "").strip()
                            if name and val:
                                parts.append(f"{name}={val}")
                            elif val:
                                parts.append(val)
                        msg = "; ".join(parts) if parts else "(no data)"
                        if not new_ts or ts > new_ts:
                            new_ts = ts
                        logs.append({
                            "source_name": channel,
                            "timestamp":   ts,
                            "raw_message": f"EventID {eid}: {msg}",
                        })
                        count += 1
                    except Exception:
                        count += 1
            if new_ts:
                _win_modern_last_ts[channel] = new_ts
        except Exception:
            continue

    return logs

# -- Linux log reader ----------------------------------------------------------


class _FileTailer:
    def __init__(self, path):
        self.path = path
        self.pos  = os.path.getsize(path) if os.path.exists(path) else 0

    def new_lines(self):
        if not os.path.exists(self.path):
            return []
        try:
            with open(self.path, errors="replace") as f:
                f.seek(0, 2)
                fsize = f.tell()
                if self.pos > fsize:
                    self.pos = 0
                f.seek(self.pos)
                lines    = f.readlines()
                self.pos = f.tell()
            return [l.rstrip() for l in lines if l.strip()]
        except Exception:
            return []


_LINUX_KEYWORDS = {
    "failed", "failure", "invalid", "error", "unauthorized",
    "authentication failure", "permission denied", "sudo",
    "accepted password", "accepted publickey", "refused",
}

_LINUX_LOG_SOURCES = [
    ("/var/log/auth.log",     True),
    ("/var/log/secure",       True),
    ("/var/log/audit/audit.log", True),
    ("/var/log/fail2ban.log", True),
    ("/var/log/syslog",       False),
    ("/var/log/messages",     False),
]

_TS_SYSLOG = re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b')
_TS_ISO    = re.compile(r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})')
_MONTH_ABR = {
    'jan':1,'feb':2,'mar':3,'apr':4,'may':5,'jun':6,
    'jul':7,'aug':8,'sep':9,'oct':10,'nov':11,'dec':12,
}


def _parse_log_timestamp(line):
    try:
        m = _TS_SYSLOG.match(line)
        if m:
            parts = m.group(1).split()
            mon = _MONTH_ABR.get(parts[0].lower()[:3])
            if mon:
                day = int(parts[1])
                h, mi, s = [int(x) for x in parts[2].split(':')]
                now = datetime.datetime.utcnow()
                dt  = datetime.datetime(now.year, mon, day, h, mi, s)
                if dt > now + datetime.timedelta(days=1):
                    dt = dt.replace(year=now.year - 1)
                return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        m = _TS_ISO.match(line)
        if m:
            dt = datetime.datetime.strptime(m.group(1).replace(' ', 'T'), "%Y-%m-%dT%H:%M:%S")
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        pass
    return None


def _read_linux_logs():
    logs = []
    for path, send_all in _LINUX_LOG_SOURCES:
        if not os.path.exists(path):
            continue
        if path not in _linux_tailers:
            _linux_tailers[path] = _FileTailer(path)
        for line in _linux_tailers[path].new_lines():
            if send_all or any(kw in line.lower() for kw in _LINUX_KEYWORDS):
                logs.append({
                    "source_name": os.path.basename(path),
                    "timestamp":   _parse_log_timestamp(line) or _utc_iso(),
                    "raw_message": line,
                })
    return logs

# -- Network monitor -----------------------------------------------------------


def _collect_network_connections():
    logs = []
    try:
        if platform.system() == "Windows":
            out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=15).stdout
        else:
            out = subprocess.run(["netstat", "-tn"],  capture_output=True, text=True, timeout=15).stdout

        for line in out.splitlines():
            if "ESTABLISHED" not in line:
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            try:
                remote_addr = parts[2] if platform.system() == "Windows" else parts[4]
                if ":" not in remote_addr or remote_addr.startswith("["):
                    continue
                p = remote_addr.rsplit(":", 1)
                remote_ip, remote_port = p[0], int(p[1])
                if remote_ip in ("127.0.0.1", "::1") or remote_ip.startswith("169.254"):
                    continue
                key    = (remote_ip, remote_port)
                now_t  = time.time()
                if now_t - _seen_connections.get(key, 0) < _SEEN_CONNECTION_TTL:
                    continue
                if remote_port in _SUSPICIOUS_PORTS:
                    _seen_connections[key] = now_t
                    logs.append({
                        "source_name": "network_monitor",
                        "timestamp":   _utc_iso(),
                        "raw_message": f"SUSPICIOUS NETWORK CONNECTION: remote={remote_ip}:{remote_port} proto=TCP state=ESTABLISHED",
                    })
            except (ValueError, IndexError):
                continue
    except Exception as exc:
        print(f"[{_now()}] [NET] {exc}")
    return logs

# -- Process monitor -----------------------------------------------------------


def _collect_suspicious_processes():
    logs = []
    try:
        if platform.system() == "Windows":
            out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                                 capture_output=True, text=True, timeout=15).stdout
            for line in out.splitlines():
                cols = [c.strip('"') for c in line.strip().split('","')]
                if not cols:
                    continue
                name = cols[0].lower()
                pid  = cols[1] if len(cols) > 1 else "?"
                if name in _SUSPICIOUS_PROC_NAMES:
                    logs.append({
                        "source_name": "process_monitor",
                        "timestamp":   _utc_iso(),
                        "raw_message": f"SUSPICIOUS PROCESS DETECTED: name={cols[0]} pid={pid}",
                    })
        else:
            out = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=15).stdout
            for line in out.splitlines()[1:]:
                cols = line.split(None, 10)
                if len(cols) < 11:
                    continue
                cmd  = cols[10]
                name = cmd.split("/")[-1].split()[0].lower()
                pid  = cols[1]
                if name in _SUSPICIOUS_PROC_NAMES:
                    logs.append({
                        "source_name": "process_monitor",
                        "timestamp":   _utc_iso(),
                        "raw_message": f"SUSPICIOUS PROCESS DETECTED: name={name} pid={pid}",
                    })
    except Exception as exc:
        print(f"[{_now()}] [PROC] {exc}")
    return logs

# -- FIM -----------------------------------------------------------------------


def _sha256_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _collect_fim_events():
    logs    = []
    targets = _FIM_TARGETS_WINDOWS if platform.system() == "Windows" else _FIM_TARGETS_LINUX
    for path in targets:
        current = _sha256_file(path)
        if not current:
            continue
        prev = _fim_hashes.get(path)
        if prev is None:
            _fim_hashes[path] = current
            continue
        if current != prev:
            _fim_hashes[path] = current
            logs.append({
                "source_name": "fim_monitor",
                "timestamp":   _utc_iso(),
                "raw_message": f"FILE INTEGRITY VIOLATION: path={path} prev={prev[:16]}... curr={current[:16]}...",
            })
    return logs


def _collect_logs():
    if platform.system() == "Windows":
        return _read_windows_logs() + _read_win_modern_channels()
    return _read_linux_logs()

# ── Main loop ─────────────────────────────────────────────────────────────────

LOG_INTERVAL  = 10
NET_INTERVAL  = 300
PROC_INTERVAL = 300
FIM_INTERVAL  = 600


def main():
    print("=" * 52)
    print("  NEURASHIELD Agent v2.0")
    print(f"  Endpoint  : {API_ENDPOINT}")
    print(f"  Agent ID  : {AGENT_ID}")
    print(f"  Tenant ID : {TENANT_ID}")
    print(f"  Hostname  : {_HOSTNAME}")
    print(f"  Platform  : {platform.system()} {platform.release()}")
    print("=" * 52)

    _init_queue()

    cp = _load_checkpoint()
    _win_last_record.update(cp.get("win_last_record", {}))
    _win_modern_last_ts.update(cp.get("win_modern_last_ts", {}))
    for _cp_path, _cp_pos in cp.get("linux_positions", {}).items():
        if _cp_path not in _linux_tailers and os.path.exists(_cp_path):
            t = _FileTailer(_cp_path)
            t.pos = _cp_pos
            _linux_tailers[_cp_path] = t

    last_heartbeat = 0.0
    last_log_run   = 0.0
    last_net_run   = 0.0
    last_proc_run  = 0.0
    last_fim_run   = 0.0

    print(f"[{_now()}] Monitoring started.\n")

    while True:
        if _AGENT_REVOKED:
            time.sleep(60)
            continue

        now = time.time()

        if now - last_heartbeat >= HEARTBEAT_INTERVAL:
            ok = _heartbeat()
            if ok:
                print(f"[{_now()}] [HB] OK")
            last_heartbeat = now

        if now - last_log_run >= LOG_INTERVAL:
            logs = _collect_logs()
            if logs:
                _queue_events(logs)
                print(f"[{_now()}] [LOG] Queued {len(logs)}")
            _save_checkpoint()
            last_log_run = now

        if now - last_net_run >= NET_INTERVAL:
            net = _collect_network_connections()
            if net:
                _queue_events(net)
            last_net_run = now

        if now - last_proc_run >= PROC_INTERVAL:
            proc = _collect_suspicious_processes()
            if proc:
                _queue_events(proc)
            last_proc_run = now

        if now - last_fim_run >= FIM_INTERVAL:
            fim = _collect_fim_events()
            if fim:
                _queue_events(fim)
            last_fim_run = now

        time.sleep(5)


if __name__ == "__main__":
    # Single-instance lock
    _lock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _lock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
    try:
        _lock.bind(("127.0.0.1", 47333))
    except OSError:
        print("Already running — exiting.")
        sys.exit(0)

    while True:
        try:
            main()
            time.sleep(10)
        except KeyboardInterrupt:
            print("\nAgent stopped.")
            break
        except Exception as exc:
            import traceback
            print(f"[{_now()}] FATAL: {exc}")
            traceback.print_exc()
            time.sleep(15)
