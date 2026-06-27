"""Ticketing & external integrations stubs.

These endpoints handle Jira / ServiceNow / PagerDuty ticket creation and
retrieval. When no integration is configured for the tenant, they return
graceful empty responses rather than 404.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Query
from pydantic import BaseModel

from app.core.dependencies import require_permission
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse

router = APIRouter(prefix="/integrations", tags=["integrations"])


# ─── Schemas ─────────────────────────────────────────────────────────────────


class TicketFieldsIn(BaseModel):
    summary: str
    description: str = ""
    severity: str = "medium"
    assignee: str | None = None
    project_key: str | None = None
    priority: str | None = None


class CreateTicketRequest(BaseModel):
    provider: str
    investigation_id: str
    fields: TicketFieldsIn


class TicketOut(BaseModel):
    id: str
    provider: str
    ticket_key: str
    url: str
    created_at: str


# ─── In-memory ticket store (per-process, resets on restart) ────────────────
# Real implementation would persist to DB. For now this gives the UI a working
# round-trip without an external integration configured.

_TICKET_STORE: dict[str, list[TicketOut]] = {}


@router.get("/tickets", response_model=APIResponse[list])
async def list_tickets(
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    investigation_id: str = Query(default=""),
) -> APIResponse[list]:
    tickets = _TICKET_STORE.get(investigation_id, [])
    return APIResponse.ok([t.model_dump() for t in tickets])


@router.post("/tickets", response_model=APIResponse[TicketOut])
async def create_ticket(
    payload: CreateTicketRequest,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_MANAGE)],
) -> APIResponse[TicketOut]:
    provider = payload.provider
    inv_id = payload.investigation_id
    ticket_num = len(_TICKET_STORE.get(inv_id, [])) + 1

    prefix_map = {"jira": "SOC", "servicenow": "INC", "pagerduty": "PD"}
    prefix = prefix_map.get(provider, "TKT")
    ticket_key = f"{prefix}-{ticket_num:04d}"

    ticket = TicketOut(
        id=str(uuid4()),
        provider=provider,
        ticket_key=ticket_key,
        url=f"https://{provider}.example.com/browse/{ticket_key}",
        created_at=datetime.now(tz=UTC).isoformat(),
    )

    _TICKET_STORE.setdefault(inv_id, []).append(ticket)
    return APIResponse.ok(ticket)


# ─── Integration config (stub — always returns "not configured") ─────────────


class IntegrationConfig(BaseModel):
    provider: str
    enabled: bool = False
    configured: bool = False
    api_token: str = ""
    base_url: str = ""
    project_key: str | None = None
    default_assignee: str | None = None


@router.get("/config", response_model=APIResponse[list])
async def list_configs(
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
) -> APIResponse[list]:
    return APIResponse.ok([])


@router.get("/config/{provider}", response_model=APIResponse[IntegrationConfig])
async def get_config(
    provider: str,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
) -> APIResponse[IntegrationConfig]:
    return APIResponse.ok(IntegrationConfig(provider=provider))


@router.put("/config/{provider}", response_model=APIResponse[IntegrationConfig])
async def save_config(
    provider: str,
    config: IntegrationConfig,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_MANAGE)],
) -> APIResponse[IntegrationConfig]:
    config.provider = provider
    config.configured = bool(config.api_token and config.base_url)
    return APIResponse.ok(config)
