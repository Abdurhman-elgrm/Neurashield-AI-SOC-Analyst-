"""
Alert escalation worker.

Periodically scans for HIGH/CRITICAL open alerts that have not been
acknowledged within the configured window and marks them as escalated
by appending a system note to their notes field.

One global instance — all tenants are covered in a single sweep.
"""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy import or_, select, update

from app.core.database import database_manager
from app.models.alert import Alert, AlertSeverity, AlertStatus

logger = structlog.get_logger(__name__)

# How long an unacknowledged HIGH/CRITICAL alert can stay open before escalation.
_ESCALATION_WINDOW_SECS = int(os.getenv("ALERT_ESCALATION_WINDOW_SECS", "3600"))  # 1 hour
_CHECK_INTERVAL_SECS    = int(os.getenv("ALERT_ESCALATION_CHECK_SECS",  "300"))   # 5 minutes

_ESCALATION_SEVERITIES = {AlertSeverity.HIGH, AlertSeverity.CRITICAL}
_ESCALATION_NOTE = (
    "[AUTO-ESCALATED] This alert has been open for over "
    "{minutes} minute(s) without acknowledgment. "
    "Immediate analyst review required."
)


class AlertEscalationWorker:
    """
    Globally scans all tenants every _CHECK_INTERVAL_SECS seconds for
    unacknowledged HIGH/CRITICAL alerts past the escalation window.
    Appends a system note and logs the escalation for downstream alerting hooks.
    """

    async def run(self, stop_event: asyncio.Event) -> None:
        logger.info(
            "escalation_worker_started",
            window_secs=_ESCALATION_WINDOW_SECS,
            check_interval_secs=_CHECK_INTERVAL_SECS,
        )
        while not stop_event.is_set():
            try:
                count = await self._sweep()
                if count:
                    logger.info("escalation_sweep_complete", escalated=count)
            except Exception as exc:
                logger.error("escalation_sweep_error", error=str(exc), exc_info=True)

            try:
                await asyncio.wait_for(stop_event.wait(), timeout=_CHECK_INTERVAL_SECS)
            except asyncio.TimeoutError:
                pass

        logger.info("escalation_worker_stopped")

    async def _sweep(self) -> int:
        cutoff = datetime.now(tz=timezone.utc) - timedelta(seconds=_ESCALATION_WINDOW_SECS)
        minutes_elapsed = _ESCALATION_WINDOW_SECS // 60
        note_text = _ESCALATION_NOTE.format(minutes=minutes_elapsed)

        async with database_manager.session() as db:
            # Find candidates: open, high/critical, no acknowledgment, older than cutoff.
            result = await db.execute(
                select(Alert.id, Alert.tenant_id, Alert.severity, Alert.notes, Alert.created_at)
                .where(
                    Alert.status == AlertStatus.OPEN,
                    Alert.severity.in_([AlertSeverity.HIGH, AlertSeverity.CRITICAL]),
                    Alert.acknowledged_at.is_(None),
                    Alert.created_at <= cutoff,
                    Alert.deleted_at.is_(None),
                    # Only escalate once — skip if the note is already present
                    or_(Alert.notes.is_(None), ~Alert.notes.like("%AUTO-ESCALATED%")),
                )
            )
            rows = result.fetchall()
            if not rows:
                return 0

            alert_ids = [row.id for row in rows]

            # Append escalation note. Concatenate with existing notes if present.
            # Using Python-side update to safely concat (avoids per-row SQL concat complexity).
            for row in rows:
                existing_notes = row.notes or ""
                new_notes = f"{existing_notes}\n\n{note_text}".strip()
                await db.execute(
                    update(Alert)
                    .where(Alert.id == row.id)
                    .values(notes=new_notes, updated_at=datetime.now(tz=timezone.utc))
                )
                created = row.created_at
                if created and created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                age_minutes = (
                    (datetime.now(tz=timezone.utc) - created).seconds // 60
                    if created else "unknown"
                )
                logger.warning(
                    "alert_auto_escalated",
                    alert_id=str(row.id),
                    tenant_id=str(row.tenant_id),
                    severity=row.severity.value,
                    age_minutes=age_minutes,
                )

            await db.commit()
            return len(alert_ids)
