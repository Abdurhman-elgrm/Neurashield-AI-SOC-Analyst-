from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse

router = APIRouter(tags=["iocs"])


# ─── Response schemas ─────────────────────────────────────────────────────────


class IOCEnrichment(BaseModel):
    indicator: str
    type: str
    vt_malicious: int | None
    vt_suspicious: int | None
    vt_total: int | None
    vt_verdict: str | None
    abuseipdb_confidence: int | None
    abuseipdb_country: str | None
    first_seen: str | None
    last_seen: str | None
    tags: list[str]


class InvestigationIOCsResponse(BaseModel):
    ips: list[IOCEnrichment]
    domains: list[IOCEnrichment]
    hashes: list[IOCEnrichment]
    processes: list[IOCEnrichment]
    raw_count: int


class EnrichRequest(BaseModel):
    indicator: str
    type: str


# ─── Helpers ──────────────────────────────────────────────────────────────────


async def _enrich_ip(indicator: str) -> IOCEnrichment:
    from app.core.redis import redis_manager
    from app.threat_intel.service import ThreatIntelService

    try:
        redis = redis_manager.get_client()
        result = await ThreatIntelService.enrich_ip(indicator, redis)
        return IOCEnrichment(
            indicator=indicator,
            type="ip",
            vt_malicious=None,
            vt_suspicious=None,
            vt_total=None,
            vt_verdict=None,
            abuseipdb_confidence=result.abuse_confidence if result.abuse_confidence else None,
            abuseipdb_country=result.geo_country,
            first_seen=None,
            last_seen=None,
            tags=result.threat_intel_flags,
        )
    except Exception:
        return IOCEnrichment(
            indicator=indicator,
            type="ip",
            vt_malicious=None,
            vt_suspicious=None,
            vt_total=None,
            vt_verdict=None,
            abuseipdb_confidence=None,
            abuseipdb_country=None,
            first_seen=None,
            last_seen=None,
            tags=[],
        )


async def _enrich_hash(indicator: str) -> IOCEnrichment:
    from app.core.redis import redis_manager
    from app.threat_intel.hash_ioc import check_file_hash

    try:
        redis = redis_manager.get_client()
        result = await check_file_hash(indicator, redis)
        verdict = "malicious" if result.found else "unknown"
        return IOCEnrichment(
            indicator=indicator,
            type="hash",
            vt_malicious=1 if result.found else 0,
            vt_suspicious=0,
            vt_total=1 if result.found else 0,
            vt_verdict=verdict,
            abuseipdb_confidence=None,
            abuseipdb_country=None,
            first_seen=None,
            last_seen=None,
            tags=result.to_flags(),
        )
    except Exception:
        return IOCEnrichment(
            indicator=indicator,
            type="hash",
            vt_malicious=None,
            vt_suspicious=None,
            vt_total=None,
            vt_verdict=None,
            abuseipdb_confidence=None,
            abuseipdb_country=None,
            first_seen=None,
            last_seen=None,
            tags=[],
        )


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.post("/iocs/enrich", response_model=APIResponse[IOCEnrichment])
async def enrich_ioc(
    payload: EnrichRequest,
    member: Annotated[object, require_permission(Permission.IOC_ENRICH)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[IOCEnrichment]:
    indicator = payload.indicator.strip()
    ioc_type = payload.type.strip().lower()

    if not indicator:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="indicator must not be empty",
        )

    if ioc_type == "ip":
        return APIResponse.ok(await _enrich_ip(indicator))
    if ioc_type == "hash":
        return APIResponse.ok(await _enrich_hash(indicator))

    # Domain / URL / email: return metadata only (no external call for now)
    return APIResponse.ok(
        IOCEnrichment(
            indicator=indicator,
            type=ioc_type,
            vt_malicious=None,
            vt_suspicious=None,
            vt_total=None,
            vt_verdict="unknown",
            abuseipdb_confidence=None,
            abuseipdb_country=None,
            first_seen=None,
            last_seen=None,
            tags=[],
        )
    )


@router.get(
    "/investigations/{investigation_id}/iocs", response_model=APIResponse[InvestigationIOCsResponse]
)
async def get_investigation_iocs(
    investigation_id: UUID,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[InvestigationIOCsResponse]:
    from app.models.investigation import Investigation
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    inv = (
        await db.execute(
            select(Investigation).where(
                Investigation.id == investigation_id,
                Investigation.tenant_id == m.tenant_id,
            )
        )
    ).scalar_one_or_none()

    if inv is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    # Extract unique IPs, domains, hashes, processes from linked events
    rows = (
        await db.execute(
            text("""
            SELECT DISTINCT
                e.source_ip,
                e.dest_ip,
                e.host_name,
                e.username,
                (e.process->>'name')     AS proc_name,
                (e.file->>'sha256')      AS file_hash,
                (e.network->>'domain')   AS domain
            FROM events e
            JOIN alerts a
              ON a.triggering_event_id = e.id
             AND a.tenant_id           = e.tenant_id
            WHERE e.tenant_id     = CAST(:tid AS uuid)
              AND a.id = ANY(
                  SELECT jsonb_array_elements_text(triggering_alert_ids)::uuid
                  FROM investigations
                  WHERE id = CAST(:inv_id AS uuid)
              )
            LIMIT 500
        """),
            {"tid": str(m.tenant_id), "inv_id": str(investigation_id)},
        )
    ).all()

    seen_ips: set[str] = set()
    seen_domains: set[str] = set()
    seen_hashes: set[str] = set()
    seen_processes: set[str] = set()

    for r in rows:
        if r.source_ip:
            seen_ips.add(r.source_ip)
        if r.dest_ip:
            seen_ips.add(r.dest_ip)
        if r.domain:
            seen_domains.add(r.domain)
        if r.file_hash:
            seen_hashes.add(r.file_hash)
        if r.proc_name:
            seen_processes.add(r.proc_name)

    raw_count = len(seen_ips) + len(seen_domains) + len(seen_hashes) + len(seen_processes)

    import asyncio

    ip_enrichments = await asyncio.gather(*[_enrich_ip(ip) for ip in list(seen_ips)[:20]])
    hash_enrichments = await asyncio.gather(*[_enrich_hash(h) for h in list(seen_hashes)[:10]])

    domain_list = [
        IOCEnrichment(
            indicator=d,
            type="domain",
            vt_malicious=None,
            vt_suspicious=None,
            vt_total=None,
            vt_verdict="unknown",
            abuseipdb_confidence=None,
            abuseipdb_country=None,
            first_seen=None,
            last_seen=None,
            tags=[],
        )
        for d in list(seen_domains)[:20]
    ]
    process_list = [
        IOCEnrichment(
            indicator=p,
            type="process",
            vt_malicious=None,
            vt_suspicious=None,
            vt_total=None,
            vt_verdict="unknown",
            abuseipdb_confidence=None,
            abuseipdb_country=None,
            first_seen=None,
            last_seen=None,
            tags=[],
        )
        for p in list(seen_processes)[:20]
    ]

    return APIResponse.ok(
        InvestigationIOCsResponse(
            ips=list(ip_enrichments),
            domains=domain_list,
            hashes=list(hash_enrichments),
            processes=process_list,
            raw_count=raw_count,
        )
    )
