from __future__ import annotations

from enum import Enum

from app.rbac.permissions import Permission

# ─── Role definitions ─────────────────────────────────────────────────────────

class Role(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"
    OWNER = "owner"


# ─── Permission sets ──────────────────────────────────────────────────────────

_VIEWER_PERMISSIONS: frozenset[Permission] = frozenset({
    Permission.ALERTS_READ,
    Permission.EVENTS_READ,
    Permission.AGENTS_READ,
    Permission.RULES_READ,
    Permission.MEMBERS_READ,
})

_ANALYST_PERMISSIONS: frozenset[Permission] = _VIEWER_PERMISSIONS | frozenset({
    Permission.ALERTS_UPDATE,
    Permission.EVENTS_EXPORT,
    Permission.INVESTIGATIONS_READ,
    Permission.INVESTIGATIONS_UPDATE,
    Permission.HUNT_QUERY,
    Permission.PLAYBOOKS_READ,
    Permission.PLAYBOOKS_MANAGE,   # generate, execute, complete steps
})

_ADMIN_PERMISSIONS: frozenset[Permission] = _ANALYST_PERMISSIONS | frozenset({
    Permission.ALERTS_DELETE,
    Permission.AGENTS_MANAGE,
    Permission.AGENTS_VIEW_TOKEN,
    Permission.RULES_MANAGE,
    Permission.MEMBERS_MANAGE,
    Permission.INVITATIONS_MANAGE,
    Permission.TENANT_SETTINGS,
    Permission.AUDIT_READ,
    Permission.INVESTIGATIONS_MANAGE,
    Permission.PLAYBOOKS_ADMIN,    # manage templates
    Permission.RESPONSE_EXECUTE,   # quarantine / isolate agents
})

_OWNER_PERMISSIONS: frozenset[Permission] = _ADMIN_PERMISSIONS | frozenset({
    Permission.TENANT_DELETE,
})

# ─── Canonical mapping — single source of truth ───────────────────────────────

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: _VIEWER_PERMISSIONS,
    Role.ANALYST: _ANALYST_PERMISSIONS,
    Role.ADMIN: _ADMIN_PERMISSIONS,
    Role.OWNER: _OWNER_PERMISSIONS,
}

# Role hierarchy — used for "at minimum this role" checks
ROLE_HIERARCHY: dict[Role, int] = {
    Role.VIEWER: 0,
    Role.ANALYST: 1,
    Role.ADMIN: 2,
    Role.OWNER: 3,
}


# ─── Helper functions ─────────────────────────────────────────────────────────

def get_role_permissions(role: Role | str) -> frozenset[Permission]:
    """Return the permission set for a built-in role."""
    if isinstance(role, str):
        role = Role(role)
    return ROLE_PERMISSIONS.get(role, frozenset())


def has_permission(role: Role | str, permission: Permission) -> bool:
    """Check if a role includes a specific permission."""
    return permission in get_role_permissions(role)


def has_minimum_role(role: Role | str, minimum: Role) -> bool:
    """Check if a role is at least as privileged as the minimum required."""
    if isinstance(role, str):
        role = Role(role)
    return ROLE_HIERARCHY.get(role, -1) >= ROLE_HIERARCHY.get(minimum, 999)


def role_from_string(value: str) -> Role:
    """Safe conversion from string, raises ValueError on invalid."""
    try:
        return Role(value)
    except ValueError:
        valid = [r.value for r in Role]
        raise ValueError(f"Invalid role '{value}'. Must be one of: {valid}")


def get_effective_permissions(
    role: Role | str,
    custom_permissions: dict | None = None,
) -> frozenset[Permission]:
    """
    Compute effective permissions = role_base + granted - revoked.
    custom_permissions format: {"grant": ["alerts:delete"], "revoke": ["events:export"]}
    """
    base = get_role_permissions(role)
    if not custom_permissions:
        return base

    try:
        granted = frozenset(
            Permission(p) for p in custom_permissions.get("grant", [])
            if p in Permission._value2member_map_
        )
        revoked = frozenset(
            Permission(p) for p in custom_permissions.get("revoke", [])
            if p in Permission._value2member_map_
        )
    except Exception:
        return base

    return (base | granted) - revoked
