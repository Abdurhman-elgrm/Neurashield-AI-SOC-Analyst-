"""Enum of valid playbook step action_type values and privileged action gating."""

from __future__ import annotations

from enum import Enum


class PlaybookActionType(str, Enum):
    INVESTIGATION = "investigation"
    REMEDIATION = "remediation"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    NOTIFICATION = "notification"
    EVIDENCE_COLLECTION = "evidence_collection"
    THREAT_HUNTING = "threat_hunting"
    APPROVAL = "approval"
    CUSTOM = "custom"
    # Privileged — automatically require human approval
    ISOLATE_HOST = "isolate_host"
    KILL_PROCESS = "kill_process"
    BLOCK_IP = "block_ip"
    DISABLE_ACCOUNT = "disable_account"


PRIVILEGED_ACTION_TYPES: frozenset[PlaybookActionType] = frozenset(
    {
        PlaybookActionType.ISOLATE_HOST,
        PlaybookActionType.KILL_PROCESS,
        PlaybookActionType.BLOCK_IP,
        PlaybookActionType.DISABLE_ACCOUNT,
    }
)

VALID_ACTION_TYPE_VALUES: frozenset[str] = frozenset(a.value for a in PlaybookActionType)
