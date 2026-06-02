from __future__ import annotations

"""
Generic correlation rules for the SOC SaaS v2 correlation engine.

Rules are NOT attack-specific. They describe structural/behavioral patterns
in event streams that may warrant grouping into an investigation context.
Each rule has a name, a weight (1–25), and a window_seconds hint for temporal
correlation. Weights sum to the investigation score (capped at 100).

DO NOT add lateral-movement / ransomware / phishing / persistence / ATT&CK
technique IDs here. This layer is universal and technique-agnostic.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CorrelationRule:
    """Immutable descriptor for a single correlation rule."""

    name: str
    description: str
    weight: int
    window_seconds: int
    tags: tuple[str, ...] = field(default_factory=tuple)


# ─── Rules ────────────────────────────────────────────────────────────────────

# Temporal proximity — multiple events from the same host within a short window.
SAME_HOST_BURST = CorrelationRule(
    name="same_host_burst",
    description="Multiple events from the same host within a short time window.",
    weight=10,
    window_seconds=300,
    tags=("temporal", "host"),
)

# Same logon session — events sharing a logon session ID on the same host.
SAME_LOGON_SESSION = CorrelationRule(
    name="same_logon_session",
    description="Events sharing the same host/logon-session identifier.",
    weight=15,
    window_seconds=900,
    tags=("session", "host"),
)

# Process tree — events belonging to the same process lineage (ProcessGuid chain).
SAME_PROCESS_TREE = CorrelationRule(
    name="same_process_tree",
    description="Events linked through the same process-tree identifier.",
    weight=20,
    window_seconds=3600,
    tags=("process", "lineage"),
)

# Process event chain — multiple events sharing the same event_chain_id.
SAME_EVENT_CHAIN = CorrelationRule(
    name="same_event_chain",
    description="Events sharing the same process event-chain identifier.",
    weight=12,
    window_seconds=900,
    tags=("process", "chain"),
)

# Shared source IP — events sharing a source network IP across hosts.
SHARED_SOURCE_IP = CorrelationRule(
    name="shared_source_ip",
    description="Multiple events involving the same source IP address.",
    weight=8,
    window_seconds=900,
    tags=("network", "ip"),
)

# Shared destination IP — events targeting the same destination IP.
SHARED_DEST_IP = CorrelationRule(
    name="shared_dest_ip",
    description="Multiple events targeting the same destination IP address.",
    weight=8,
    window_seconds=900,
    tags=("network", "ip"),
)

# Shared domain — multiple events involving the same FQDN.
SHARED_DOMAIN = CorrelationRule(
    name="shared_domain",
    description="Multiple events referencing the same domain name.",
    weight=7,
    window_seconds=3600,
    tags=("network", "domain"),
)

# Same user across hosts — the same user account active on multiple hosts.
SAME_USER_MULTI_HOST = CorrelationRule(
    name="same_user_multi_host",
    description="The same user account observed on more than one host.",
    weight=15,
    window_seconds=3600,
    tags=("user", "host"),
)

# Shared file hash — events involving the same file hash (IOC breadcrumb).
SHARED_FILE_HASH = CorrelationRule(
    name="shared_file_hash",
    description="Events sharing a file hash value.",
    weight=18,
    window_seconds=3600,
    tags=("file", "hash"),
)

# High-frequency single source — unusually high event rate from one entity.
HIGH_FREQUENCY_SOURCE = CorrelationRule(
    name="high_frequency_source",
    description="Unusually high event rate from a single source entity in a short window.",
    weight=10,
    window_seconds=300,
    tags=("temporal", "frequency"),
)


# ─── Registry ─────────────────────────────────────────────────────────────────

ALL_RULES: tuple[CorrelationRule, ...] = (
    SAME_HOST_BURST,
    SAME_LOGON_SESSION,
    SAME_PROCESS_TREE,
    SAME_EVENT_CHAIN,
    SHARED_SOURCE_IP,
    SHARED_DEST_IP,
    SHARED_DOMAIN,
    SAME_USER_MULTI_HOST,
    SHARED_FILE_HASH,
    HIGH_FREQUENCY_SOURCE,
)

RULES_BY_NAME: dict[str, CorrelationRule] = {r.name: r for r in ALL_RULES}
