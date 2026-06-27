from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ── Template schemas ──────────────────────────────────────────────────────────


class PlaybookTemplateStepResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    template_id: UUID
    step_order: int
    category: str
    title: str
    description_template: str | None
    command_windows: str | None
    command_linux: str | None
    expected_result: str | None
    can_run_parallel: bool
    requires_human_approval: bool
    is_critical: bool
    hint: str | None
    mitre_reference: str | None
    action_type: str | None
    step_order_dependencies: list[Any]


class PlaybookTemplateResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID | None
    name: str
    description: str | None
    tactic: str | None
    technique: str | None
    category: str | None
    is_system: bool
    version: int
    enabled: bool
    created_at: datetime
    updated_at: datetime
    steps: list[PlaybookTemplateStepResponse] = []


class CreateTemplateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    tactic: str | None = Field(default=None, max_length=128)
    technique: str | None = Field(default=None, max_length=128)
    category: str | None = Field(default=None, max_length=128)
    steps: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("steps")
    @classmethod
    def validate_step_action_types(cls, steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
        from app.models.playbook_action_types import (
            PRIVILEGED_ACTION_TYPES,
            VALID_ACTION_TYPE_VALUES,
            PlaybookActionType,
        )

        for i, step in enumerate(steps):
            action_type = step.get("action_type")
            if action_type is not None:
                if action_type not in VALID_ACTION_TYPE_VALUES:
                    raise ValueError(
                        f"Step {i + 1}: invalid action_type '{action_type}'. "
                        f"Allowed values: {sorted(VALID_ACTION_TYPE_VALUES)}"
                    )
                if PlaybookActionType(action_type) in PRIVILEGED_ACTION_TYPES:
                    step["requires_human_approval"] = True
        return steps


# ── Playbook schemas ──────────────────────────────────────────────────────────


class PlaybookStepResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    playbook_id: UUID
    step_order: int
    category: str
    title: str
    description: str | None
    command_windows: str | None
    command_linux: str | None
    expected_result: str | None
    status: str
    requires_human_approval: bool
    is_critical: bool
    can_run_parallel: bool
    action_type: str | None
    action_target_id: str | None
    completed_at: datetime | None
    completed_by_id: UUID | None
    notes: str | None
    result: str | None
    created_at: datetime


class PlaybookResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    template_id: UUID | None
    alert_id: UUID | None
    investigation_id: UUID | None
    incident_id: str
    title: str
    severity: str
    source_host: str | None
    status: str
    variables: dict[str, Any]
    generated_by: str
    assigned_to_id: UUID | None
    created_by_id: UUID | None
    created_at: datetime
    updated_at: datetime
    steps: list[PlaybookStepResponse] = []


class GeneratePlaybookRequest(BaseModel):
    alert_id: UUID | None = None
    investigation_id: UUID | None = None
    # Manual fields used when alert_id is not provided
    tactic: str | None = None
    technique: str | None = None
    severity: str = "high"
    source_host: str | None = None


class CompleteStepRequest(BaseModel):
    notes: str | None = Field(default=None, max_length=5000)
    result: str | None = Field(default=None, max_length=2000)


class PlaybookRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    playbook_id: UUID
    tenant_id: UUID
    mode: str
    status: str
    steps_completed: int
    steps_total: int
    actor_id: UUID | None
    started_at: datetime
    completed_at: datetime | None
    failure_reason: str | None


# ── Containment schemas ───────────────────────────────────────────────────────


class ContainmentRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=1000)
    alert_id: UUID | None = None


class ContainmentStatusResponse(BaseModel):
    agent_id: UUID
    hostname: str
    containment_state: str
    containment_reason: str | None
    contained_at: datetime | None
    contained_by_id: UUID | None


# ── Response action schemas ───────────────────────────────────────────────────


class ResponseActionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    agent_id: UUID | None
    alert_id: UUID | None
    actor_id: UUID | None
    action_type: str
    target_type: str
    target_id: str | None
    target_name: str | None
    status: str
    result: str | None
    action_metadata: dict[str, Any]
    created_at: datetime
