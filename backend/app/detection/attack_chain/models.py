"""
Attack chain models — multi-stage attack sequence definitions.

A ChainStage matches when ANY of its keywords appear in an alert title
(case-insensitive). An AttackChainRule fires when enough stages are
satisfied by different alerts within the time window.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID


@dataclass(frozen=True)
class ChainStage:
    name: str
    keywords: tuple[str, ...]   # ANY keyword match → stage satisfied
    required: bool = True       # False = optional boost stage


@dataclass(frozen=True)
class AttackChainRule:
    name: str
    description: str
    stages: tuple[ChainStage, ...]
    window_secs: int
    final_severity: str             # severity of the generated chain alert
    mitre_tactics: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    min_stages: int = 2             # minimum required stages that must match


@dataclass
class ChainMatch:
    rule: AttackChainRule
    matched_alert_ids: list[UUID]
    matched_stage_names: list[str]
    host: str
