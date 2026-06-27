from __future__ import annotations

import base64
from datetime import UTC, datetime
from uuid import UUID

import structlog
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError, ValidationError
from app.core.utils import create_task_safe
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.schemas.alert import AlertFilterParams, AlertUpdateRequest

logger = structlog.get_logger(__name__)

# TTL for per-tenant per-flag FP counters (30-day rolling window)
_FP_COUNTER_TTL = 86400 * 30


async def _enrich_assignee_names(db: AsyncSession, alerts: list[Alert]) -> None:
    """Populate ._assignee_name on each alert via a single User lookup."""
    ids = {a.assignee_id for a in alerts if a.assignee_id}
    if not ids:
        return
    from app.models.user import User

    result = await db.execute(select(User.id, User.full_name, User.email).where(User.id.in_(ids)))
    name_map = {row.id: row.full_name or row.email for row in result.all()}
    for alert in alerts:
        if alert.assignee_id and alert.assignee_id in name_map:
            alert._assignee_name = name_map[alert.assignee_id]  # type: ignore[attr-defined]


async def _invalidate_dashboard_cache_async(tenant_id: str) -> None:
    """Delete cached dashboard KPIs for this tenant after an alert write."""
    try:
        from app.api.v1.dashboard import _invalidate_dashboard_cache

        await _invalidate_dashboard_cache(tenant_id)
    except Exception:
        pass


async def _record_fp_signal_async(tenant_id: str, evidence: dict) -> None:
    """Increment Redis FP counters for each UEBA flag present in a false-positive alert."""
    try:
        from app.core.redis import TenantRedisClient, redis_manager

        redis = redis_manager.get_client()
        client = TenantRedisClient(redis, tenant_id, "ueba")
        ueba_flags: list[str] = evidence.get("ueba_flags", [])
        for flag in ueba_flags:
            key = f"fp:{flag}"
            await client.incr(key)
            await client.expire(key, _FP_COUNTER_TTL)
        if ueba_flags:
            logger.info("fp_signal_recorded", tenant_id=tenant_id, flags=ueba_flags)
    except Exception as exc:
        logger.warning("fp_signal_record_failed", error=str(exc))


class AlertService:
    @staticmethod
    async def get_by_id(
        db: AsyncSession,
        tenant_id: UUID,
        alert_id: UUID,
    ) -> Alert | None:
        result = await db.execute(
            select(Alert).where(
                Alert.id == alert_id,
                Alert.tenant_id == tenant_id,
                Alert.deleted_at.is_(None),
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def require_by_id(
        db: AsyncSession,
        tenant_id: UUID,
        alert_id: UUID,
    ) -> Alert:
        alert = await AlertService.get_by_id(db, tenant_id, alert_id)
        if alert is None:
            raise NotFoundError(f"Alert {alert_id} not found")
        await _enrich_assignee_names(db, [alert])
        return alert

    @staticmethod
    async def list_alerts(
        db: AsyncSession,
        tenant_id: UUID,
        params: AlertFilterParams,
    ) -> tuple[list[Alert], str | None]:
        conditions = [
            Alert.tenant_id == tenant_id,
            Alert.deleted_at.is_(None),
        ]

        if params.status:
            try:
                conditions.append(Alert.status == AlertStatus(params.status))
            except ValueError:
                pass

        if params.severity:
            try:
                conditions.append(Alert.severity == AlertSeverity(params.severity))
            except ValueError:
                pass

        if params.source_host:
            conditions.append(Alert.source_host == params.source_host)

        if params.rule_id:
            conditions.append(Alert.rule_id == params.rule_id)

        if params.assignee_id:
            conditions.append(Alert.assignee_id == params.assignee_id)

        if params.from_ts:
            conditions.append(Alert.created_at >= params.from_ts)

        if params.to_ts:
            conditions.append(Alert.created_at <= params.to_ts)

        if params.cursor:
            try:
                ts_str, id_str = _decode_cursor(params.cursor)
                ts = datetime.fromisoformat(ts_str)
                # Keyset pagination for ORDER BY (created_at DESC, id DESC):
                # "next page" means rows that come AFTER the cursor in descending order,
                # i.e. strictly older timestamp OR same timestamp with a lower UUID.
                conditions.append(
                    or_(
                        Alert.created_at < ts,
                        and_(
                            Alert.created_at == ts,
                            Alert.id < UUID(id_str),
                        ),
                    )
                )
            except Exception:
                pass

        limit = min(params.limit, 200)

        result = await db.execute(
            select(Alert)
            .where(*conditions)
            .order_by(Alert.created_at.desc(), Alert.id.desc())
            .limit(limit + 1)
        )
        alerts = list(result.scalars().all())

        next_cursor: str | None = None
        if len(alerts) > limit:
            last = alerts[limit - 1]
            next_cursor = _decode_cursor_encode(last.created_at.isoformat(), str(last.id))
            alerts = alerts[:limit]

        await _enrich_assignee_names(db, alerts)
        return alerts, next_cursor

    @staticmethod
    async def update_alert(
        db: AsyncSession,
        tenant_id: UUID,
        alert_id: UUID,
        payload: AlertUpdateRequest,
        actor_id: UUID,
    ) -> Alert:
        alert = await AlertService.require_by_id(db, tenant_id, alert_id)
        now = datetime.now(tz=UTC)

        if payload.status is not None:
            try:
                new_status = AlertStatus(payload.status)
            except ValueError:
                raise ValidationError(
                    f"Invalid status: {payload.status}",
                    details={"allowed": [s.value for s in AlertStatus]},
                ) from None

            if new_status == AlertStatus.ACKNOWLEDGED and alert.acknowledged_at is None:
                alert.acknowledged_at = now
                alert.acknowledged_by_id = actor_id

            if new_status in (AlertStatus.CLOSED, AlertStatus.FALSE_POSITIVE):
                alert.closed_at = now
                alert.closed_by_id = actor_id

            if new_status == AlertStatus.FALSE_POSITIVE:
                # Record UEBA flags as FP signals for weight adjustment (non-blocking)
                create_task_safe(
                    _record_fp_signal_async(str(tenant_id), alert.evidence or {}),
                    name="record_fp_signal",
                )

            alert.status = new_status

        if payload.notes is not None:
            alert.notes = payload.notes

        if payload.assignee_id is not None:
            # Ensure the assignee is a member of the same tenant.
            from sqlalchemy import exists as _exists

            from app.models.tenant_member import TenantMember

            is_member = await db.scalar(
                select(
                    _exists().where(
                        TenantMember.user_id == payload.assignee_id,
                        TenantMember.tenant_id == tenant_id,
                        TenantMember.deleted_at.is_(None),
                    )
                )
            )
            if not is_member:
                raise ValidationError("Assignee is not a member of this tenant")
            alert.assignee_id = payload.assignee_id

        await db.flush()
        await _enrich_assignee_names(db, [alert])
        create_task_safe(
            _invalidate_dashboard_cache_async(str(tenant_id)),
            name="invalidate_dashboard_cache",
        )
        logger.info(
            "alert_updated",
            alert_id=str(alert_id),
            tenant_id=str(tenant_id),
            actor_id=str(actor_id),
            new_status=alert.status.value,
        )
        return alert

    @staticmethod
    async def delete_alert(
        db: AsyncSession,
        tenant_id: UUID,
        alert_id: UUID,
        actor_id: UUID,
    ) -> None:
        alert = await AlertService.require_by_id(db, tenant_id, alert_id)
        alert.soft_delete()
        await db.flush()
        logger.info("alert_deleted", alert_id=str(alert_id), actor_id=str(actor_id))


def _decode_cursor_encode(ts: str, id_str: str) -> str:
    raw = f"{ts}|{id_str}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _decode_cursor(cursor: str) -> tuple[str, str]:
    raw = base64.urlsafe_b64decode(cursor.encode()).decode()
    ts, _, id_str = raw.partition("|")
    return ts, id_str
