from __future__ import annotations

from enum import Enum


class Permission(str, Enum):
    """
    Atomic capability strings in the format resource:action.
    Routes and services check these directly — never raw role strings.
    Adding a new permission here is the only code change needed
    before assigning it to roles.
    """

    # ─── Alerts ───────────────────────────────────────────────────────────────
    ALERTS_READ = "alerts:read"
    ALERTS_UPDATE = "alerts:update"        # acknowledge, close, add notes
    ALERTS_DELETE = "alerts:delete"        # admin-only hard remove (soft delete)

    # ─── Events ───────────────────────────────────────────────────────────────
    EVENTS_READ = "events:read"
    EVENTS_EXPORT = "events:export"

    # ─── Agents ───────────────────────────────────────────────────────────────
    AGENTS_READ = "agents:read"
    AGENTS_MANAGE = "agents:manage"        # register, delete, update config
    AGENTS_VIEW_TOKEN = "agents:view_token"  # see enrollment tokens

    # ─── Detection Rules ──────────────────────────────────────────────────────
    RULES_READ = "rules:read"
    RULES_MANAGE = "rules:manage"          # create, update, delete, enable/disable

    # ─── Team Management ──────────────────────────────────────────────────────
    MEMBERS_READ = "members:read"
    MEMBERS_MANAGE = "members:manage"      # change roles, remove members
    INVITATIONS_MANAGE = "invitations:manage"

    # ─── Tenant ───────────────────────────────────────────────────────────────
    TENANT_SETTINGS = "tenant:settings"    # update tenant name, config
    TENANT_DELETE = "tenant:delete"        # owner only

    # ─── Audit ────────────────────────────────────────────────────────────────
    AUDIT_READ = "audit:read"              # view audit log entries

    # ─── Investigations (Phase 3.4) ───────────────────────────────────────────
    INVESTIGATIONS_READ   = "investigations:read"
    INVESTIGATIONS_UPDATE = "investigations:update"   # notes, status, verdict, assign
    INVESTIGATIONS_MANAGE = "investigations:manage"   # merge, split, force-close
    HUNT_QUERY            = "hunt:query"             # threat hunting queries
