from __future__ import annotations

import base64
from datetime import datetime, timezone
from uuid import UUID

import structlog
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError, ValidationError
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.schemas.alert import AlertFilterParams, AlertUpdateRequest

logger = structlog.get_logger(__name__)


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
                conditions.append(
                    and_(
                        Alert.created_at <= ts,
                        Alert.id < UUID(id_str),
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
        now = datetime.now(tz=timezone.utc)

        if payload.status is not None:
            try:
                new_status = AlertStatus(payload.status)
            except ValueError:
                raise ValidationError(
                    f"Invalid status: {payload.status}",
                    details={"allowed": [s.value for s in AlertStatus]},
                )

            if new_status == AlertStatus.ACKNOWLEDGED and alert.acknowledged_at is None:
                alert.acknowledged_at = now
                alert.acknowledged_by_id = actor_id

            if new_status in (AlertStatus.CLOSED, AlertStatus.FALSE_POSITIVE):
                alert.closed_at = now
                alert.closed_by_id = actor_id

            alert.status = new_status

        if payload.notes is not None:
            alert.notes = payload.notes

        if payload.assignee_id is not None:
            alert.assignee_id = payload.assignee_id

        await db.flush()
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
