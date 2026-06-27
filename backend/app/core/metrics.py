"""
Prometheus metrics — RED (Rate, Errors, Duration) + business counters.

All metrics are registered once at import time.  Import this module early
in main.py to ensure they are available before the first request.

Metric naming follows the Prometheus best-practices convention:
  <namespace>_<subsystem>_<name>_<unit>
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, Info

# ─── HTTP request metrics (RED) ───────────────────────────────────────────────

HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status_code"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "path"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

HTTP_REQUESTS_IN_FLIGHT = Gauge(
    "http_requests_in_flight",
    "Number of HTTP requests currently being processed",
)

# ─── Business metrics ─────────────────────────────────────────────────────────

ALERTS_CREATED_TOTAL = Counter(
    "soc_alerts_created_total",
    "Total alerts created",
    ["tenant_id", "severity"],
)

INVESTIGATIONS_CREATED_TOTAL = Counter(
    "soc_investigations_created_total",
    "Total investigations created",
    ["tenant_id"],
)

EVENTS_INGESTED_TOTAL = Counter(
    "soc_events_ingested_total",
    "Total raw events ingested",
    ["tenant_id"],
)

AGENT_HEARTBEATS_TOTAL = Counter(
    "soc_agent_heartbeats_total",
    "Total agent heartbeat events received",
    ["tenant_id"],
)

AGENTS_OFFLINE_TOTAL = Counter(
    "soc_agents_offline_total",
    "Total agent offline transitions detected",
    ["tenant_id"],
)

# ─── Infrastructure metrics ───────────────────────────────────────────────────

WORKER_STREAM_LAG = Gauge(
    "soc_worker_stream_lag_messages",
    "Unacknowledged messages in Redis stream consumer group",
    ["tenant_id", "stream", "group"],
)

# ─── Build info ───────────────────────────────────────────────────────────────

BUILD_INFO = Info("soc_build", "SOC SaaS v2 build information")
