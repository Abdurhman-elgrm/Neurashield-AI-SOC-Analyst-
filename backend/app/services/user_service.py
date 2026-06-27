from __future__ import annotations

from datetime import UTC
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User

logger = structlog.get_logger(__name__)


class UserService:
    @staticmethod
    async def get_by_id(db: AsyncSession, user_id: UUID) -> User | None:
        result = await db.execute(select(User).where(User.id == user_id, User.deleted_at.is_(None)))
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_email(db: AsyncSession, email: str) -> User | None:
        result = await db.execute(
            select(User).where(User.email == email.lower(), User.deleted_at.is_(None))
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_verification_token(db: AsyncSession, token: str) -> User | None:
        result = await db.execute(
            select(User).where(
                User.email_verification_token == token,
                User.deleted_at.is_(None),
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def email_exists(db: AsyncSession, email: str) -> bool:
        result = await db.execute(
            select(User.id).where(User.email == email.lower(), User.deleted_at.is_(None))
        )
        return result.scalar_one_or_none() is not None

    @staticmethod
    async def create(
        db: AsyncSession,
        email: str,
        password_hash: str,
        full_name: str,
        email_verified: bool = False,
        email_verification_token: str | None = None,
    ) -> User:
        from datetime import datetime

        user = User(
            email=email.lower().strip(),
            password_hash=password_hash,
            full_name=full_name.strip(),
            email_verified=email_verified,
            email_verification_token=email_verification_token,
            email_verification_sent_at=datetime.now(tz=UTC) if email_verification_token else None,
        )
        db.add(user)
        await db.flush([user])
        logger.info("user_created", user_id=str(user.id), email=user.email)
        return user

    @staticmethod
    async def update_profile(
        db: AsyncSession,
        user: User,
        full_name: str | None = None,
        timezone: str | None = None,
        avatar_url: str | None = None,
        job_title: str | None = None,
        bio: str | None = None,
    ) -> User:
        if full_name is not None:
            user.full_name = full_name.strip()
        if timezone is not None:
            user.timezone = timezone
        if avatar_url is not None:
            user.avatar_url = avatar_url or None
        if job_title is not None:
            user.job_title = job_title.strip() or None
        if bio is not None:
            user.bio = bio.strip() or None
        await db.flush([user])
        return user

    @staticmethod
    async def update_password(
        db: AsyncSession,
        user: User,
        new_password_hash: str,
    ) -> User:
        user.password_hash = new_password_hash
        await db.flush([user])
        return user
