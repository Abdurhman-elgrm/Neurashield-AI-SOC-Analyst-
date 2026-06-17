"""
Combines behavioral baseline flags and attack-chain indicators into a
unified anomaly score (0.0–1.0) using additive weighted scoring.
"""
from __future__ import annotations

from dataclasses import dataclass, field

_WEIGHTS: dict[str, float] = {
    "after_hours":          0.20,
    "new_source_ip":        0.20,
    "new_process_on_host":  0.20,
    "privileged_user":      0.10,
    "impossible_travel":    0.80,
    "threat_ip_confirmed":  0.35,
    "brute_force":          0.40,
    "brute_force_success":  0.70,
    "lateral_movement":     0.60,
    "credential_stuffing":  0.50,
}

_ANOMALY_THRESHOLD = 0.50


@dataclass
class AnomalyResult:
    anomaly_score: float = 0.0
    is_anomaly: bool = False
    ueba_flags: list[str] = field(default_factory=list)
    ueba_reasons: dict[str, str] = field(default_factory=dict)


def compute_anomaly(
    baseline_flags: list[str],
    attack_chain_flags: list[str],
    is_threat_ip: bool = False,
    reasons: dict[str, str] | None = None,
) -> AnomalyResult:
    active = list(baseline_flags) + list(attack_chain_flags)
    if is_threat_ip:
        active.append("threat_ip_confirmed")

    score = min(1.0, sum(_WEIGHTS.get(f, 0.0) for f in active))

    all_reasons: dict[str, str] = dict(reasons or {})
    if is_threat_ip:
        all_reasons.setdefault(
            "threat_ip_confirmed",
            "Source IP matched a known threat intelligence database",
        )

    return AnomalyResult(
        anomaly_score=round(score, 4),
        is_anomaly=score >= _ANOMALY_THRESHOLD,
        ueba_flags=active,
        ueba_reasons=all_reasons,
    )
