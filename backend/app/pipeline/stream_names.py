from __future__ import annotations

"""
Stream name constants and helpers for the Redis Streams topology.

Topology (per-tenant):
  raw_events       → ingestion_worker reads, normalization_worker publishes
  normalized_events → normalization_worker reads, detection_worker publishes
  alert_events      → detection_worker reads, websocket broadcaster publishes

Each stream key is a SUFFIX — TenantRedisClient prepends `tenant:{id}:{subsystem}:`.
The subsystem for all pipeline streams is "pipeline".
"""

# ─── Stream suffixes (relative to subsystem prefix) ─────────────────────────

RAW_EVENTS = "stream:raw_events"
NORMALIZED_EVENTS = "stream:normalized_events"
ALERT_EVENTS = "stream:alert_events"

# ─── Stream suffixes (continued) ─────────────────────────────────────────────

CORRELATED_EVENTS = "stream:correlated_events"
INVESTIGATION_RESULTS = "stream:investigation_results"

# ─── Consumer group names ─────────────────────────────────────────────────────

GROUP_NORMALIZE = "normalize_workers"
GROUP_DETECT = "detect_workers"
GROUP_CORRELATE = "correlate_workers"
GROUP_INVESTIGATE = "investigate_workers"
GROUP_ALERT_FAN = "alert_fanout"

# ─── Subsystem label used by TenantRedisClient ───────────────────────────────

SUBSYSTEM = "pipeline"

# ─── PubSub channel suffix for WebSocket fanout ──────────────────────────────

ALERTS_PUBSUB_CHANNEL = "ws:alerts"
EVENTS_PUBSUB_CHANNEL = "ws:events"

# ─── Stream trim caps (approximate MAXLEN passed to XADD) ────────────────────
# Sized to keep total Redis memory under ~50 MB across all streams per tenant.
# raw + normalized events are trimmed most aggressively — they are transient
# buffers; once consumed they are no longer needed in the stream.

RAW_STREAM_MAX_LEN = 10_000  # ~5 MB per tenant at ~500 B/msg
NORMALIZED_STREAM_MAX_LEN = 10_000  # ~8 MB per tenant at ~800 B/msg
ALERT_STREAM_MAX_LEN = 5_000  # alerts are small; 5k is plenty
CORRELATED_STREAM_MAX_LEN = 2_000  # correlation results are larger JSON
INVESTIGATION_STREAM_MAX_LEN = 500  # investigation payloads are large (~5–50 KB each)
REALTIME_STREAM_MAX_LEN = 5_000  # ws notifications are tiny (~200 B)
