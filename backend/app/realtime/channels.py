from __future__ import annotations

"""
Channel name constants and factory helpers for the realtime system.

Redis pub/sub channel naming convention:
  tenant:{tenant_id}:realtime:{channel}

Examples:
  tenant:abc:realtime:alerts
  tenant:abc:realtime:investigations
  tenant:abc:realtime:presence
"""

# ─── Channel constants ────────────────────────────────────────────────────────

ALERTS = "alerts"
INVESTIGATIONS = "investigations"
CASES = "cases"
ACTIVITY = "activity"
HUNTS = "hunts"
PRESENCE = "presence"
EVENTS = "events"

# All valid channel names (used for validation)
ALL_CHANNELS: frozenset[str] = frozenset(
    {
        ALERTS,
        INVESTIGATIONS,
        CASES,
        ACTIVITY,
        HUNTS,
        PRESENCE,
        EVENTS,
    }
)

# The subsystem label used with TenantRedisClient for realtime streams/pubsub
REALTIME_SUBSYSTEM = "realtime"

# Redis Streams
REALTIME_EVENTS_STREAM = "stream:realtime_events"

# Consumer group for realtime worker
GROUP_REALTIME = "realtime_workers"

# Pub/sub pattern that matches all realtime channels for all tenants
PUBSUB_PATTERN = "tenant:*:realtime:*"

# ─── Key/channel factories ────────────────────────────────────────────────────


def pubsub_channel(tenant_id: str, channel: str) -> str:
    """Full Redis pub/sub channel name for a tenant/channel pair."""
    return f"tenant:{tenant_id}:realtime:{channel}"


def presence_key(analyst_id: str) -> str:
    """Redis key suffix for a single analyst's presence state (used within TenantRedisClient)."""
    return f"presence:{analyst_id}"


def presence_set_key() -> str:
    """Redis set key suffix tracking all online analysts (used within TenantRedisClient)."""
    return "presence_online"


def lock_key(investigation_id: str) -> str:
    """Redis key suffix for an investigation edit lock (used within TenantRedisClient)."""
    return f"lock:inv:{investigation_id}"


def subscription_channel_suffix(channel: str) -> str:
    """The suffix passed to TenantRedisClient.publish() for a given channel."""
    return f"realtime:{channel}"


def is_valid_channel(channel: str) -> bool:
    """Returns True if `channel` is a recognized channel name."""
    return channel in ALL_CHANNELS


def extract_tenant_from_pubsub(full_channel: str) -> str | None:
    """
    Given a full pub/sub channel like 'tenant:abc:realtime:alerts',
    extract the tenant_id part ('abc').
    Returns None if the format doesn't match.
    """
    parts = full_channel.split(":")
    if len(parts) >= 4 and parts[0] == "tenant" and parts[2] == "realtime":
        return parts[1]
    return None


def extract_channel_from_pubsub(full_channel: str) -> str | None:
    """
    Given a full pub/sub channel like 'tenant:abc:realtime:alerts',
    extract the channel part ('alerts').
    """
    parts = full_channel.split(":")
    if len(parts) >= 4 and parts[0] == "tenant" and parts[2] == "realtime":
        return parts[3]
    return None
