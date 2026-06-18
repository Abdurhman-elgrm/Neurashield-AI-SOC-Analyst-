from __future__ import annotations

from typing import Any

from app.normalization.models import NormalizedEvent


def build_alert_title(rule_name: str, event: NormalizedEvent) -> str:
    """Generates a human-readable alert title with contextual detail."""
    host = event.hostname or "unknown host"
    proc = event.process_name
    user = event.username

    suffix_parts: list[str] = [f"on {host}"]
    if proc:
        suffix_parts.append(f"by {proc}")
    if user:
        suffix_parts.append(f"({user})")

    return f"{rule_name} — " + " ".join(suffix_parts)


def build_alert_evidence(
    event: NormalizedEvent,
    stream_id: str | None = None,
    count: int | None = None,
    window_event_ids: list[str] | None = None,
) -> dict[str, Any]:
    """
    Bundles the triggering event details into the alert evidence JSONB.

    For threshold rules, window_event_ids contains the IDs of ALL events that
    contributed to the threshold breach — giving analysts full context instead
    of just the final triggering event.
    """
    import dataclasses

    evidence: dict[str, Any] = {
        "event_id": event.event_id,
        "event_timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "category": event.category,
        "severity": event.severity,
        "hostname": event.hostname,
        "stream_id": stream_id,
    }

    if event.process:
        evidence["process"] = dataclasses.asdict(event.process)
    if event.network:
        evidence["network"] = dataclasses.asdict(event.network)
    if event.file:
        evidence["file"] = dataclasses.asdict(event.file)
    if event.user:
        evidence["user"] = dataclasses.asdict(event.user)
    if count is not None:
        evidence["threshold_count"] = count
    if window_event_ids:
        evidence["window_event_ids"] = window_event_ids

    return evidence
