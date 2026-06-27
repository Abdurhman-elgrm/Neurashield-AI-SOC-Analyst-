"""
Invitations API
---------------
POST   /invitations           — send invitation (requires INVITATIONS_MANAGE)
GET    /invitations           — list pending invitations (requires INVITATIONS_MANAGE)
DELETE /invitations/{id}      — revoke invitation (requires INVITATIONS_MANAGE)
POST   /invitations/accept    — exchange token for membership + auth (public)
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.dependencies import CurrentUser, require_permission
from app.core.exceptions import ConflictError, ForbiddenError, NotFoundError, ValidationError
from app.models.invitation import Invitation
from app.models.tenant_member import TenantMember
from app.models.user import User
from app.rbac.permissions import Permission
from app.rbac.roles import ROLE_HIERARCHY, Role
from app.schemas.common import APIResponse, EmptyResponse
from app.services.email_service import send_invitation_email

log = structlog.get_logger(__name__)
router = APIRouter(prefix="/invitations", tags=["Invitations"])

INVITE_EXPIRY_HOURS = 48


# ─── Schemas ──────────────────────────────────────────────────────────────────


class InviteCreateRequest(BaseModel):
    email: EmailStr
    role: str = "analyst"


class InviteResponse(BaseModel):
    id: str
    email: str
    role: str
    expires_at: str
    created_at: str
    is_valid: bool
    invited_by_name: str | None = None


class AcceptInviteRequest(BaseModel):
    token: str
    # New user flow
    full_name: str | None = None
    password: str | None = None
    # Existing user flow
    existing_email: EmailStr | None = None
    existing_password: str | None = None


class AcceptInviteResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    tenant_id: str
    message: str


# ─── Send invitation ──────────────────────────────────────────────────────────


@router.post("", response_model=APIResponse[InviteResponse], status_code=201)
async def send_invitation(
    payload: InviteCreateRequest,
    actor: Annotated[object, require_permission(Permission.INVITATIONS_MANAGE)],
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[InviteResponse]:
    m: TenantMember = actor  # type: ignore[assignment]

    # Validate role
    try:
        invited_role = Role(payload.role)
    except ValueError:
        raise ValidationError(
            f"Invalid role: {payload.role!r}. Must be one of: {[r.value for r in Role]}"
        ) from None

    # Prevent privilege escalation — actor can only invite at a strictly lower level
    actor_level = ROLE_HIERARCHY.get(Role(m.role), -1)
    invited_level = ROLE_HIERARCHY.get(invited_role, -1)
    if invited_level >= actor_level:
        raise ForbiddenError(
            "You cannot invite a member with a role equal to or higher than your own"
        )

    # Check if email is already a member
    existing_member = await db.execute(
        select(TenantMember)
        .join(User, TenantMember.user_id == User.id)
        .where(
            TenantMember.tenant_id == m.tenant_id,
            User.email == payload.email.lower(),
            TenantMember.deleted_at.is_(None),
        )
    )
    if existing_member.scalar_one_or_none():
        raise ConflictError("This user is already a member of this tenant")

    # Check for existing active invitation for this email
    existing_invite = await db.execute(
        select(Invitation).where(
            Invitation.tenant_id == m.tenant_id,
            Invitation.email == payload.email.lower(),
            Invitation.accepted_at.is_(None),
            Invitation.revoked_at.is_(None),
            Invitation.expires_at > datetime.now(tz=UTC),
        )
    )
    if existing_invite.scalar_one_or_none():
        raise ConflictError("A pending invitation already exists for this email address")

    # Generate token
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    invitation = Invitation(
        tenant_id=m.tenant_id,
        invited_by=current_user.id,
        email=payload.email.lower(),
        role=payload.role,
        token_hash=token_hash,
        expires_at=datetime.now(tz=UTC) + timedelta(hours=INVITE_EXPIRY_HOURS),
    )
    db.add(invitation)
    await db.flush()

    # Load tenant name for the email
    from app.models.tenant import Tenant

    tenant_result = await db.execute(select(Tenant).where(Tenant.id == m.tenant_id))
    tenant = tenant_result.scalar_one()

    accept_url = f"{settings.FRONTEND_URL}/accept-invite?token={raw_token}"

    await send_invitation_email(
        to_email=payload.email,
        invited_by_name=current_user.full_name or current_user.email,
        tenant_name=tenant.name,
        accept_url=accept_url,
        role=payload.role,
        expires_hours=INVITE_EXPIRY_HOURS,
    )

    await db.commit()

    log.info(
        "invitation_sent",
        invitation_id=str(invitation.id),
        email=payload.email,
        tenant_id=str(m.tenant_id),
    )

    return APIResponse.ok(
        InviteResponse(
            id=str(invitation.id),
            email=invitation.email,
            role=invitation.role,
            expires_at=invitation.expires_at.isoformat(),
            created_at=invitation.created_at.isoformat(),
            is_valid=invitation.is_valid,
            invited_by_name=current_user.full_name,
        )
    )


# ─── List pending invitations ─────────────────────────────────────────────────


@router.get("", response_model=APIResponse[list[InviteResponse]])
async def list_invitations(
    actor: Annotated[object, require_permission(Permission.INVITATIONS_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[list[InviteResponse]]:
    m: TenantMember = actor  # type: ignore[assignment]

    result = await db.execute(
        select(Invitation)
        .where(
            Invitation.tenant_id == m.tenant_id,
            Invitation.accepted_at.is_(None),
            Invitation.revoked_at.is_(None),
            Invitation.expires_at > datetime.now(tz=UTC),
        )
        .order_by(Invitation.created_at.desc())
    )
    invitations = result.scalars().all()

    return APIResponse.ok(
        [
            InviteResponse(
                id=str(inv.id),
                email=inv.email,
                role=inv.role,
                expires_at=inv.expires_at.isoformat(),
                created_at=inv.created_at.isoformat(),
                is_valid=inv.is_valid,
            )
            for inv in invitations
        ]
    )


# ─── Revoke invitation ────────────────────────────────────────────────────────


@router.delete("/{invitation_id}", response_model=APIResponse[EmptyResponse])
async def revoke_invitation(
    invitation_id: UUID,
    actor: Annotated[object, require_permission(Permission.INVITATIONS_MANAGE)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[EmptyResponse]:
    m: TenantMember = actor  # type: ignore[assignment]

    result = await db.execute(
        select(Invitation).where(
            Invitation.id == invitation_id,
            Invitation.tenant_id == m.tenant_id,
        )
    )
    invitation = result.scalar_one_or_none()
    if not invitation:
        raise NotFoundError("Invitation not found")

    invitation.revoked_at = datetime.now(tz=UTC)
    await db.commit()
    return APIResponse.ok(EmptyResponse())


# ─── Accept invitation (public — no auth required) ────────────────────────────


@router.post("/accept", response_model=APIResponse[AcceptInviteResponse])
async def accept_invitation(
    payload: AcceptInviteRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[AcceptInviteResponse]:
    """
    Exchange an invitation token for membership + auth tokens.

    New user flow:    provide full_name + password (creates account)
    Existing user:    provide existing_email + existing_password (joins tenant)
    """
    from app.core.security import (
        create_access_token,
        create_refresh_token,
        hash_password,
        verify_password,
    )
    from app.models.refresh_token import RefreshToken

    # Look up and validate the token
    token_hash = hashlib.sha256(payload.token.encode()).hexdigest()
    result = await db.execute(select(Invitation).where(Invitation.token_hash == token_hash))
    invitation = result.scalar_one_or_none()

    if not invitation or not invitation.is_valid:
        raise ValidationError("Invitation is invalid, expired, or already used")

    user: User | None = None

    if payload.existing_email and payload.existing_password:
        # Existing user flow — verify credentials
        user_result = await db.execute(
            select(User).where(User.email == payload.existing_email.lower())
        )
        user = user_result.scalar_one_or_none()
        if not user or not verify_password(payload.existing_password, user.password_hash):
            raise ValidationError("Invalid email or password")
        if user.email.lower() != invitation.email.lower():
            raise ValidationError("This invitation was sent to a different email address")

    elif payload.full_name and payload.password:
        # New user flow — create account
        existing = await db.execute(select(User).where(User.email == invitation.email))
        if existing.scalar_one_or_none():
            raise ConflictError("An account with this email already exists. Please log in instead.")
        user = User(
            email=invitation.email,
            full_name=payload.full_name.strip(),
            password_hash=hash_password(payload.password),
            email_verified=True,  # clicking the invite link proves email ownership
        )
        db.add(user)
        await db.flush()
    else:
        raise ValidationError(
            "Provide either (full_name + password) for a new account, "
            "or (existing_email + existing_password) to use an existing account"
        )

    # Add to tenant
    member = TenantMember(
        tenant_id=invitation.tenant_id,
        user_id=user.id,
        role=invitation.role,
        invited_by=invitation.invited_by,
        joined_at=datetime.now(tz=UTC),
    )
    db.add(member)

    # Mark invitation accepted
    invitation.accepted_at = datetime.now(tz=UTC)
    await db.flush()

    # Issue token pair (same pattern as AuthService._issue_token_pair)
    access_token = create_access_token(subject=str(user.id))
    refresh_token_str, jti = create_refresh_token(subject=str(user.id))
    expire = datetime.now(tz=UTC) + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_obj = RefreshToken(
        user_id=user.id,
        jti=jti,
        expires_at=expire,
    )
    db.add(refresh_obj)
    await db.commit()

    log.info(
        "invitation_accepted",
        invitation_id=str(invitation.id),
        user_id=str(user.id),
        tenant_id=str(invitation.tenant_id),
    )

    return APIResponse.ok(
        AcceptInviteResponse(
            access_token=access_token,
            refresh_token=refresh_token_str,
            expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            tenant_id=str(invitation.tenant_id),
            message="Welcome to NEURASHIELD!",
        )
    )
