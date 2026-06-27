from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models.detection_rule import DetectionRule, RuleType
from app.models.event import Event
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse, EmptyResponse, PaginatedResponse
from app.schemas.detection import (
    DetectionRuleCreateRequest,
    DetectionRuleResponse,
    DetectionRuleUpdateRequest,
)
from app.services.audit_service import AuditService
from app.services.detection_service import DetectionService

router = APIRouter(prefix="/rules", tags=["detection-rules"])


class RuleTestRequest(BaseModel):
    from_hours: int = Field(
        default=24, ge=1, le=168, description="Hours of history to test against"
    )
    max_events: int = Field(default=1000, ge=1, le=5000, description="Maximum events to scan")


class RuleTestMatch(BaseModel):
    event_id: str
    occurred_at: str
    category: str
    hostname: str | None
    username: str | None
    process_name: str | None
    source_ip: str | None


class RuleTestResult(BaseModel):
    rule_id: str
    rule_name: str
    rule_type: str
    events_scanned: int
    matches: list[RuleTestMatch]
    match_count: int
    dry_run: bool = True


def _event_to_normalized(event: Event) -> Any:
    """Reconstruct a NormalizedEvent from stored DB event data."""
    from app.normalization.models import (
        NormalizedEvent,
        NormalizedFile,
        NormalizedNetwork,
        NormalizedProcess,
        NormalizedUser,
    )

    proc_data = event.process or {}
    net_data = event.network or {}
    user_data = event.user or {}
    file_data = event.file or {}
    raw = event.raw_payload or {}

    proc = (
        NormalizedProcess(
            name=proc_data.get("name"),
            pid=proc_data.get("pid"),
            ppid=proc_data.get("ppid"),
            executable=proc_data.get("executable"),
            command_line=proc_data.get("command_line"),
            hash_md5=proc_data.get("hash_md5"),
            hash_sha256=proc_data.get("hash_sha256"),
        )
        if proc_data
        else None
    )

    net = (
        NormalizedNetwork(
            src_ip=net_data.get("src_ip"),
            src_port=net_data.get("src_port"),
            dst_ip=net_data.get("dst_ip"),
            dst_port=net_data.get("dst_port"),
            protocol=net_data.get("protocol"),
        )
        if net_data
        else None
    )

    user = (
        NormalizedUser(
            name=user_data.get("name"),
            domain=user_data.get("domain"),
            id=user_data.get("id"),
            is_privileged=bool(user_data.get("is_privileged", False)),
        )
        if user_data
        else None
    )

    file_ = (
        NormalizedFile(
            path=file_data.get("path"),
            name=file_data.get("name"),
            extension=file_data.get("extension"),
            action=file_data.get("action"),
        )
        if file_data
        else None
    )

    return NormalizedEvent(
        event_id=str(event.id),
        timestamp=event.event_timestamp,
        category=event.category.value if event.category else "other",
        severity=event.severity or 1,
        hostname=event.host_name or "",
        agent_id=str(event.agent_id) if event.agent_id else "",
        tenant_id=str(event.tenant_id),
        process=proc,
        network=net,
        user=user,
        file=file_,
        tags=list(event.tags or []),
        raw=raw,
    )


@router.get("", response_model=PaginatedResponse[DetectionRuleResponse])
async def list_rules(
    member: Annotated[object, require_permission(Permission.RULES_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=25, ge=1, le=100),
    enabled_only: bool = Query(default=False),
) -> PaginatedResponse[DetectionRuleResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    rules, total = await DetectionService.list_rules(
        db, m.tenant_id, page=page, limit=limit, enabled_only=enabled_only
    )
    return PaginatedResponse[DetectionRuleResponse].offset(
        data=[DetectionRuleResponse.model_validate(r) for r in rules],
        page=page,
        limit=limit,
        total=total,
    )


@router.post("", response_model=APIResponse[DetectionRuleResponse], status_code=201)
async def create_rule(
    payload: DetectionRuleCreateRequest,
    member: Annotated[object, require_permission(Permission.RULES_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[DetectionRuleResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    rule = await DetectionService.create_rule(db, m.tenant_id, payload, m.user_id)
    await AuditService.log(
        db,
        action="rule.created",
        actor_id=m.user_id,
        actor_role=m.role,
        tenant_id=m.tenant_id,
        resource_type="detection_rule",
        resource_id=rule.id,
    )
    await db.commit()
    return APIResponse.ok(DetectionRuleResponse.model_validate(rule))


@router.get("/{rule_id}", response_model=APIResponse[DetectionRuleResponse])
async def get_rule(
    rule_id: UUID,
    member: Annotated[object, require_permission(Permission.RULES_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[DetectionRuleResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    rule = await DetectionService.require_by_id(db, m.tenant_id, rule_id)
    return APIResponse.ok(DetectionRuleResponse.model_validate(rule))


@router.patch("/{rule_id}", response_model=APIResponse[DetectionRuleResponse])
async def update_rule(
    rule_id: UUID,
    payload: DetectionRuleUpdateRequest,
    member: Annotated[object, require_permission(Permission.RULES_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[DetectionRuleResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    rule = await DetectionService.update_rule(db, m.tenant_id, rule_id, payload, m.user_id)
    await AuditService.log(
        db,
        action="rule.updated",
        actor_id=m.user_id,
        actor_role=m.role,
        tenant_id=m.tenant_id,
        resource_type="detection_rule",
        resource_id=rule_id,
    )
    await db.commit()
    return APIResponse.ok(DetectionRuleResponse.model_validate(rule))


@router.delete("/{rule_id}", response_model=APIResponse[EmptyResponse])
async def delete_rule(
    rule_id: UUID,
    member: Annotated[object, require_permission(Permission.RULES_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[EmptyResponse]:
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]
    await DetectionService.delete_rule(db, m.tenant_id, rule_id)
    await AuditService.log(
        db,
        action="rule.deleted",
        actor_id=m.user_id,
        actor_role=m.role,
        tenant_id=m.tenant_id,
        resource_type="detection_rule",
        resource_id=rule_id,
    )
    await db.commit()
    return APIResponse.ok(EmptyResponse())


@router.post("/{rule_id}/test", response_model=APIResponse[RuleTestResult])
async def test_rule_dry_run(
    rule_id: UUID,
    body: RuleTestRequest,
    member: Annotated[object, require_permission(Permission.RULES_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[RuleTestResult]:
    """
    Dry-run a detection rule against historical events.
    No alerts are created. Returns matched event IDs and counts.

    PATTERN rules: each event is evaluated independently against the rule conditions.
    THRESHOLD rules: simulated in-memory by counting events matching the base
                     conditions in a sliding window — no Redis state is touched.
    """
    from app.detection.patterns import evaluate_conditions
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    rule = await DetectionService.require_by_id(db, m.tenant_id, rule_id)

    from datetime import timedelta as _timedelta

    from_ts = datetime.now(tz=UTC) - _timedelta(hours=body.from_hours)
    events_result = await db.execute(
        select(Event)
        .where(
            Event.tenant_id == m.tenant_id,
            Event.event_timestamp >= from_ts,
        )
        .order_by(Event.event_timestamp.desc())
        .limit(body.max_events)
    )
    events = list(events_result.scalars().all())

    matches: list[RuleTestMatch] = []

    if rule.rule_type == RuleType.PATTERN:
        conditions: list[dict[str, Any]] = (
            rule.conditions if isinstance(rule.conditions, list) else []
        )
        for ev in events:
            normalized = _event_to_normalized(ev)
            if evaluate_conditions(conditions, normalized):
                matches.append(
                    RuleTestMatch(
                        event_id=str(ev.id),
                        occurred_at=ev.event_timestamp.isoformat() if ev.event_timestamp else "",
                        category=ev.category.value if ev.category else "",
                        hostname=ev.host_name,
                        username=ev.username,
                        process_name=ev.process_name,
                        source_ip=ev.source_ip,
                    )
                )

    elif rule.rule_type == RuleType.THRESHOLD:
        # Simulate threshold rule in-memory.
        # The threshold conditions include: field, operator, value (for base match),
        # plus threshold_count and window_seconds.
        conds = rule.conditions if isinstance(rule.conditions, dict) else {}
        threshold_count = int(conds.get("threshold", conds.get("count", 5)))
        window_seconds = int(conds.get("window_seconds", conds.get("window", 300)))
        # Base conditions are the filter that must match for an event to count
        base_conds: list[dict[str, Any]] = conds.get("conditions", [])

        # Sort events oldest-first to slide the window forward
        _epoch = datetime(1970, 1, 1)
        sorted_events = sorted(events, key=lambda e: e.event_timestamp or _epoch)
        # Sliding window: for each event that matches base conditions, count how many
        # prior matching events are within window_seconds. If count >= threshold, it fires.
        matching_timestamps: list[tuple[datetime, Event]] = []
        for ev in sorted_events:
            normalized = _event_to_normalized(ev)
            if not base_conds or evaluate_conditions(base_conds, normalized):
                ts = ev.event_timestamp
                if ts:
                    matching_timestamps.append((ts, ev))

        # Find windows where threshold is breached
        seen_match_ids: set[str] = set()
        for i, (ts_i, ev_i) in enumerate(matching_timestamps):
            window_start = ts_i - _timedelta(seconds=window_seconds)
            count_in_window = sum(
                1 for ts_j, _ in matching_timestamps[: i + 1] if ts_j >= window_start
            )
            if count_in_window >= threshold_count:
                eid = str(ev_i.id)
                if eid not in seen_match_ids:
                    seen_match_ids.add(eid)
                    matches.append(
                        RuleTestMatch(
                            event_id=eid,
                            occurred_at=ts_i.isoformat(),
                            category=ev_i.category.value if ev_i.category else "",
                            hostname=ev_i.host_name,
                            username=ev_i.username,
                            process_name=ev_i.process_name,
                            source_ip=ev_i.source_ip,
                        )
                    )

    result = RuleTestResult(
        rule_id=str(rule.id),
        rule_name=rule.name,
        rule_type=rule.rule_type.value,
        events_scanned=len(events),
        matches=matches[:200],  # cap response size
        match_count=len(matches),
    )
    return APIResponse.ok(result)


# ─── /rules/coverage ─────────────────────────────────────────────────────────


@router.get("/coverage", response_model=APIResponse[dict])
async def get_rules_coverage(
    member: Annotated[object, require_permission(Permission.RULES_READ)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[dict]:
    """Return MITRE ATT&CK technique coverage score based on active detection rules."""
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    result = await db.execute(
        select(DetectionRule.mitre_techniques).where(
            DetectionRule.tenant_id == m.tenant_id,
            DetectionRule.enabled == True,  # noqa: E712
        )
    )
    technique_lists = result.scalars().all()

    covered: set[str] = set()
    for tech_list in technique_lists:
        if not isinstance(tech_list, list):
            continue
        for item in tech_list:
            tid = item.get("technique_id") if isinstance(item, dict) else str(item)
            if tid:
                covered.add(tid)

    # ATT&CK Enterprise v14 has ~200 techniques; use 200 as denominator
    total = 200
    covered_count = len(covered)
    score_pct = min(100, round((covered_count / total) * 100))

    return APIResponse.ok(
        {
            "score_pct": score_pct,
            "covered_techniques": covered_count,
            "total_techniques": total,
            "trend_delta": 0,
        }
    )
