from __future__ import annotations

"""
Notes service — analyst notes on investigations.

Rules:
  - Any analyst can create notes.
  - Only the original author can edit / delete their own notes.
  - Any analyst can pin / unpin any note (collaboration feature).
  - Deletion is soft (sets deleted_at).
  - List returns pinned notes first, then by created_at desc.
"""

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ForbiddenError, NotFoundError
from app.models.analyst import InvestigationNote
from app.analyst.schemas import NoteCreate, NoteUpdate

logger = structlog.get_logger(__name__)


class NoteService:

    @staticmethod
    async def create(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        analyst_id: UUID,
        payload: NoteCreate,
    ) -> InvestigationNote:
        note = InvestigationNote(
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            content=payload.content,
            pinned=payload.pinned,
        )
        db.add(note)
        await db.flush([note])
        logger.info(
            "note_created",
            note_id=str(note.id),
            investigation_id=investigation_id,
            tenant_id=str(tenant_id),
        )
        return note

    @staticmethod
    async def get_by_id(
        db: AsyncSession,
        tenant_id: UUID,
        note_id: UUID,
    ) -> InvestigationNote | None:
        result = await db.execute(
            select(InvestigationNote).where(
                InvestigationNote.id == note_id,
                InvestigationNote.tenant_id == tenant_id,
                InvestigationNote.deleted_at.is_(None),
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def require_by_id(
        db: AsyncSession,
        tenant_id: UUID,
        note_id: UUID,
    ) -> InvestigationNote:
        note = await NoteService.get_by_id(db, tenant_id, note_id)
        if note is None:
            raise NotFoundError(f"Note {note_id} not found")
        return note

    @staticmethod
    async def update(
        db: AsyncSession,
        tenant_id: UUID,
        note_id: UUID,
        analyst_id: UUID,
        payload: NoteUpdate,
        is_admin: bool = False,
    ) -> InvestigationNote:
        note = await NoteService.require_by_id(db, tenant_id, note_id)

        if note.analyst_id != analyst_id and not is_admin:
            raise ForbiddenError("Only the note author can edit this note")

        if payload.content is not None:
            note.content = payload.content
        if payload.pinned is not None:
            note.pinned = payload.pinned

        note.updated_at = datetime.now(tz=timezone.utc)
        await db.flush([note])
        return note

    @staticmethod
    async def delete(
        db: AsyncSession,
        tenant_id: UUID,
        note_id: UUID,
        analyst_id: UUID,
        is_admin: bool = False,
    ) -> None:
        note = await NoteService.require_by_id(db, tenant_id, note_id)

        if note.analyst_id != analyst_id and not is_admin:
            raise ForbiddenError("Only the note author can delete this note")

        note.soft_delete()
        await db.flush([note])
        logger.info(
            "note_deleted",
            note_id=str(note_id),
            tenant_id=str(tenant_id),
            deleted_by=str(analyst_id),
        )

    @staticmethod
    async def set_pin(
        db: AsyncSession,
        tenant_id: UUID,
        note_id: UUID,
        pinned: bool,
    ) -> InvestigationNote:
        note = await NoteService.require_by_id(db, tenant_id, note_id)
        note.pinned = pinned
        note.updated_at = datetime.now(tz=timezone.utc)
        await db.flush([note])
        return note

    @staticmethod
    async def list_for_investigation(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        page: int = 1,
        limit: int = 50,
    ) -> tuple[list[InvestigationNote], int]:
        """Return (notes, total) ordered pinned-first then newest-first."""
        limit = min(limit, 200)
        base = [
            InvestigationNote.tenant_id == tenant_id,
            InvestigationNote.investigation_id == investigation_id,
            InvestigationNote.deleted_at.is_(None),
        ]

        total_result = await db.execute(
            select(func.count()).select_from(InvestigationNote).where(*base)
        )
        total = total_result.scalar_one()

        offset = (page - 1) * limit
        rows_result = await db.execute(
            select(InvestigationNote)
            .where(*base)
            .order_by(
                InvestigationNote.pinned.desc(),
                InvestigationNote.created_at.desc(),
            )
            .offset(offset)
            .limit(limit)
        )
        rows = list(rows_result.scalars().all())
        return rows, total

    @staticmethod
    async def count_for_investigation(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
    ) -> int:
        result = await db.execute(
            select(func.count()).select_from(InvestigationNote).where(
                InvestigationNote.tenant_id == tenant_id,
                InvestigationNote.investigation_id == investigation_id,
                InvestigationNote.deleted_at.is_(None),
            )
        )
        return result.scalar_one()
