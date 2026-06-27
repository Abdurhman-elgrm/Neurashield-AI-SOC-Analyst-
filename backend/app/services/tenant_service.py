from __future__ import annotations

import re
from datetime import UTC, datetime
from uuid import UUID

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ConflictError, ForbiddenError, NotFoundError
from app.detection.default_rules import seed_default_rules
from app.detection.sigma import bulk_import_defaults
from app.models.tenant import Tenant
from app.models.tenant_member import TenantMember
from app.models.user import User
from app.rbac.roles import ROLE_HIERARCHY, Role
from app.services.audit_service import AuditService

logger = structlog.get_logger(__name__)


class TenantService:
    @staticmethod
    async def create(
        db: AsyncSession,
        name: str,
        slug: str | None,
        owner: User,
    ) -> Tenant:
        """
        Creates a new tenant and makes the creator its OWNER.
        Generates a URL-safe slug from the name if not provided.
        """
        resolved_slug = slug or TenantService._generate_slug(name)

        if await TenantService._slug_exists(db, resolved_slug):
            raise ConflictError(f"A tenant with slug '{resolved_slug}' already exists")

        tenant = Tenant(name=name.strip(), slug=resolved_slug)
        db.add(tenant)
        await db.flush([tenant])

        member = TenantMember(
            tenant_id=tenant.id,
            user_id=owner.id,
            role=Role.OWNER.value,
            joined_at=datetime.now(tz=UTC),
        )
        db.add(member)
        await db.flush([member])

        await seed_default_rules(db, tenant.id)
        await bulk_import_defaults(db, tenant.id)

        await AuditService.log(
            db,
            action="tenant.created",
            actor_id=owner.id,
            tenant_id=tenant.id,
            resource_type="tenant",
            resource_id=tenant.id,
            changes={"after": {"name": tenant.name, "slug": tenant.slug}},
        )

        logger.info("tenant_created", tenant_id=str(tenant.id), slug=tenant.slug)
        return tenant

    @staticmethod
    async def get_by_id(db: AsyncSession, tenant_id: UUID) -> Tenant | None:
        result = await db.execute(
            select(Tenant).where(
                Tenant.id == tenant_id,
                Tenant.deleted_at.is_(None),
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def get_user_tenants(db: AsyncSession, user_id: UUID) -> list[Tenant]:
        """Returns all active tenants the user is an active member of."""
        result = await db.execute(
            select(Tenant)
            .join(TenantMember, TenantMember.tenant_id == Tenant.id)
            .where(
                TenantMember.user_id == user_id,
                TenantMember.deleted_at.is_(None),
                Tenant.deleted_at.is_(None),
                Tenant.is_active.is_(True),
            )
            .order_by(Tenant.name)
        )
        return list(result.scalars().all())

    @staticmethod
    async def get_user_tenants_with_role(
        db: AsyncSession, user_id: UUID
    ) -> list[tuple[Tenant, str]]:
        """Returns (tenant, role) pairs for all active tenants the user belongs to."""
        result = await db.execute(
            select(Tenant, TenantMember.role)
            .join(TenantMember, TenantMember.tenant_id == Tenant.id)
            .where(
                TenantMember.user_id == user_id,
                TenantMember.deleted_at.is_(None),
                Tenant.deleted_at.is_(None),
                Tenant.is_active.is_(True),
            )
            .order_by(Tenant.name)
        )
        return [(row.Tenant, row.role) for row in result.all()]

    @staticmethod
    async def update(
        db: AsyncSession,
        tenant: Tenant,
        actor: TenantMember,
        name: str | None = None,
        timezone: str | None = None,
        logo_url: str | None | type[...] = ...,
        event_retention_days: int | None = None,
        alert_retention_days: int | None = None,
    ) -> Tenant:
        before = {
            "name": tenant.name,
            "timezone": tenant.timezone,
            "event_retention_days": tenant.event_retention_days,
            "alert_retention_days": tenant.alert_retention_days,
        }
        if name is not None:
            tenant.name = name.strip()
        if timezone is not None:
            tenant.timezone = timezone
        if logo_url is not ...:
            tenant.logo_url = logo_url  # type: ignore[assignment]
        if event_retention_days is not None:
            tenant.event_retention_days = event_retention_days
        if alert_retention_days is not None:
            tenant.alert_retention_days = alert_retention_days
        await db.flush([tenant])

        await AuditService.log(
            db,
            action="tenant.updated",
            actor_id=actor.user_id,
            actor_role=actor.role,
            tenant_id=tenant.id,
            resource_type="tenant",
            resource_id=tenant.id,
            changes={
                "before": before,
                "after": {
                    "name": tenant.name,
                    "timezone": tenant.timezone,
                    "event_retention_days": tenant.event_retention_days,
                    "alert_retention_days": tenant.alert_retention_days,
                },
            },
        )
        return tenant

    # ─── Member management ────────────────────────────────────────────────────

    @staticmethod
    async def get_active_member(
        db: AsyncSession, tenant_id: UUID, user_id: UUID
    ) -> TenantMember | None:
        """Returns the active (non-deleted) membership for a user in a tenant."""
        result = await db.execute(
            select(TenantMember).where(
                TenantMember.tenant_id == tenant_id,
                TenantMember.user_id == user_id,
                TenantMember.deleted_at.is_(None),
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def get_members(
        db: AsyncSession,
        tenant_id: UUID,
        page: int = 1,
        limit: int = 25,
    ) -> tuple[list[dict], int]:
        """Returns paginated member list with user details joined."""
        offset = (page - 1) * limit

        count_result = await db.execute(
            select(func.count(TenantMember.id)).where(
                TenantMember.tenant_id == tenant_id,
                TenantMember.deleted_at.is_(None),
            )
        )
        total = count_result.scalar_one()

        result = await db.execute(
            select(TenantMember, User)
            .join(User, User.id == TenantMember.user_id)
            .where(
                TenantMember.tenant_id == tenant_id,
                TenantMember.deleted_at.is_(None),
            )
            .order_by(TenantMember.created_at)
            .offset(offset)
            .limit(limit)
        )
        rows = result.all()

        members = [
            {
                "id": m.id,
                "tenant_id": m.tenant_id,
                "user_id": m.user_id,
                "role": m.role,
                "joined_at": m.joined_at,
                "created_at": m.created_at,
                "email": u.email,
                "full_name": u.full_name,
            }
            for m, u in rows
        ]
        return members, total

    @staticmethod
    async def remove_member(
        db: AsyncSession,
        tenant_id: UUID,
        target_user_id: UUID,
        actor: TenantMember,
    ) -> None:
        """
        Soft-removes a member from a tenant.
        Cannot remove the last OWNER.
        Cannot remove yourself if you are the only OWNER.
        """
        target = await TenantService.get_active_member(db, tenant_id, target_user_id)
        if target is None:
            raise NotFoundError("Member not found in this tenant")

        if target.role == Role.OWNER.value:
            owner_count_result = await db.execute(
                select(func.count(TenantMember.id)).where(
                    TenantMember.tenant_id == tenant_id,
                    TenantMember.role == Role.OWNER.value,
                    TenantMember.deleted_at.is_(None),
                )
            )
            if (owner_count_result.scalar_one() or 0) <= 1:
                raise ForbiddenError("Cannot remove the last owner of a tenant")

        target.soft_delete()
        await db.flush([target])

        await AuditService.log(
            db,
            action="member.removed",
            actor_id=actor.user_id,
            actor_role=actor.role,
            tenant_id=tenant_id,
            resource_type="tenant_member",
            resource_id=target.id,
            permission_used="members:manage",
            changes={"before": {"user_id": str(target_user_id), "role": target.role}},
        )

    @staticmethod
    async def update_member_role(
        db: AsyncSession,
        tenant_id: UUID,
        target_user_id: UUID,
        new_role: Role,
        actor: TenantMember,
    ) -> TenantMember:
        """Changes a member's role. Cannot demote the last owner. Actor cannot promote above own level."""
        target = await TenantService.get_active_member(db, tenant_id, target_user_id)
        if target is None:
            raise NotFoundError("Member not found")

        # Prevent privilege escalation — actors below OWNER cannot assign a role >= their own.
        # OWNER (the highest role) is explicitly allowed to promote others to OWNER so that
        # ownership can be transferred without requiring a super-admin bypass.
        actor_level = ROLE_HIERARCHY.get(Role(actor.role), -1)
        target_level = ROLE_HIERARCHY.get(new_role, -1)
        if target_level > actor_level:
            raise ForbiddenError("You cannot assign a role higher than your own")

        if target.role == Role.OWNER.value and new_role != Role.OWNER:
            owner_count_result = await db.execute(
                select(func.count(TenantMember.id)).where(
                    TenantMember.tenant_id == tenant_id,
                    TenantMember.role == Role.OWNER.value,
                    TenantMember.deleted_at.is_(None),
                )
            )
            if (owner_count_result.scalar_one() or 0) <= 1:
                raise ForbiddenError("Cannot demote the last owner")

        before_role = target.role
        target.role = new_role.value
        await db.flush([target])

        await AuditService.log(
            db,
            action="member.role_changed",
            actor_id=actor.user_id,
            actor_role=actor.role,
            tenant_id=tenant_id,
            resource_type="tenant_member",
            resource_id=target.id,
            changes={"before": {"role": before_role}, "after": {"role": new_role.value}},
        )
        return target

    # ─── Private helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _generate_slug(name: str) -> str:
        slug = name.lower().strip()
        slug = re.sub(r"[^a-z0-9\s-]", "", slug)
        slug = re.sub(r"[\s]+", "-", slug)
        slug = re.sub(r"-+", "-", slug)
        slug = slug.strip("-")
        return slug[:100] or "tenant"

    @staticmethod
    async def _slug_exists(db: AsyncSession, slug: str) -> bool:
        result = await db.execute(select(Tenant.id).where(Tenant.slug == slug))
        return result.scalar_one_or_none() is not None
