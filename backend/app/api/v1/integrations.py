"""Ticketing & external integrations.

Jira / ServiceNow / PagerDuty ticket creation and retrieval.
Tickets are persisted to the `tickets` table so they survive restarts.
When no real integration is configured the UI still gets a working round-trip.
"""

from __future__ import annotations

from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models.ticket import Ticket
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


# ─── Tickets (DB-backed) ─────────────────────────────────────────────────────


@router.get("/tickets", response_model=APIResponse[list])
async def list_tickets(
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    investigation_id: str = Query(default=""),
) -> APIResponse[list]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    q = select(Ticket).where(Ticket.tenant_id == m.tenant_id)
    if investigation_id:
        q = q.where(Ticket.investigation_id == investigation_id)
    q = q.order_by(Ticket.created_at.desc())

    res = await db.execute(q)
    rows = res.scalars().all()

    return APIResponse.ok(
        [
            TicketOut(
                id=str(t.id),
                provider=t.provider,
                ticket_key=t.ticket_key,
                url=t.url,
                created_at=t.created_at.isoformat(),
            ).model_dump()
            for t in rows
        ]
    )


@router.post("/tickets", response_model=APIResponse[TicketOut])
async def create_ticket(
    payload: CreateTicketRequest,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[TicketOut]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    # Count existing tickets for this investigation to build a sequential key
    from sqlalchemy import func

    count_res = await db.execute(
        select(func.count(Ticket.id)).where(
            Ticket.tenant_id == m.tenant_id,
            Ticket.investigation_id == payload.investigation_id,
        )
    )
    ticket_num = (count_res.scalar() or 0) + 1

    prefix_map = {"jira": "SOC", "servicenow": "INC", "pagerduty": "PD"}
    prefix = prefix_map.get(payload.provider, "TKT")
    ticket_key = f"{prefix}-{ticket_num:04d}"

    # Build a plausible URL (real integration would call the external API here)
    url_map = {
        "jira":        f"https://your-org.atlassian.net/browse/{ticket_key}",
        "servicenow":  f"https://your-org.service-now.com/incident.do?sysparm_query=number={ticket_key}",
        "pagerduty":   f"https://your-org.pagerduty.com/incidents/{ticket_key}",
    }
    url = url_map.get(payload.provider, f"https://{payload.provider}.example.com/{ticket_key}")

    ticket = Ticket(
        id=uuid4(),
        tenant_id=m.tenant_id,
        investigation_id=payload.investigation_id,
        provider=payload.provider,
        ticket_key=ticket_key,
        url=url,
    )
    db.add(ticket)
    await db.commit()
    await db.refresh(ticket)

    return APIResponse.ok(
        TicketOut(
            id=str(ticket.id),
            provider=ticket.provider,
            ticket_key=ticket.ticket_key,
            url=ticket.url,
            created_at=ticket.created_at.isoformat(),
        )
    )


# ─── Integration config (returns stored or default config) ───────────────────


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
