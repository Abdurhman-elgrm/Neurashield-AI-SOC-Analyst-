"""Add investigations table chain + manual creation columns

Revision ID: 005_investigation_manual
Revises: 004_events_explorer
Create Date: 2026-06-04

This migration is idempotent.  It handles two scenarios:

1. Fresh Railway deployment — the investigations table was never created
   because migrations/003_investigations.py and migrations/004_analyst_workspace.py
   lived outside the versions/ directory and were never run by Alembic.
   All CREATE TABLE / CREATE INDEX statements use IF NOT EXISTS.

2. Existing deployment where the table already exists — the
   ALTER TABLE ... ADD COLUMN IF NOT EXISTS statements are no-ops,
   so the migration completes cleanly without touching existing data.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "005_investigation_manual"
down_revision: Union[str, None] = "004_events_explorer"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. investigations (base table from 003_investigations.py) ─────────────
    op.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            id                     UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id              UUID        NOT NULL,
            investigation_group_id VARCHAR(64) NOT NULL,
            threat_score           INTEGER     NOT NULL DEFAULT 0,
            confidence             VARCHAR(16) NOT NULL DEFAULT 'low',
            tp_probability         FLOAT       NOT NULL DEFAULT 0.0,
            fp_probability         FLOAT       NOT NULL DEFAULT 1.0,
            executive_summary      TEXT        NOT NULL DEFAULT '',
            technical_summary      TEXT        NOT NULL DEFAULT '',
            attack_progression     JSONB       NOT NULL DEFAULT '[]'::jsonb,
            recommended_actions    JSONB       NOT NULL DEFAULT '[]'::jsonb,
            status                 VARCHAR(20) NOT NULL DEFAULT 'new',
            created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_investigation_group          ON investigations (investigation_group_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_investigation_tenant_score   ON investigations (tenant_id, threat_score)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_investigation_tenant_created ON investigations (tenant_id, created_at)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_investigation_tenant_status  ON investigations (tenant_id, status)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_investigation_tenant_id      ON investigations (tenant_id)")

    # ── 2. Analyst-workspace columns (from 004_analyst_workspace.py) ──────────
    op.execute("ALTER TABLE investigations ADD COLUMN IF NOT EXISTS assigned_to   UUID")
    op.execute("ALTER TABLE investigations ADD COLUMN IF NOT EXISTS verdict        VARCHAR(32)")
    op.execute("ALTER TABLE investigations ADD COLUMN IF NOT EXISTS verdict_set_at TIMESTAMPTZ")
    op.execute("ALTER TABLE investigations ADD COLUMN IF NOT EXISTS verdict_set_by UUID")
    op.execute("ALTER TABLE investigations ADD COLUMN IF NOT EXISTS timeline_json  JSONB")
    op.execute("ALTER TABLE investigations ADD COLUMN IF NOT EXISTS graph_json     JSONB")
    op.execute("ALTER TABLE investigations ADD COLUMN IF NOT EXISTS behaviors_json JSONB")
    op.execute("ALTER TABLE investigations ADD COLUMN IF NOT EXISTS context_json   JSONB")
    op.execute("CREATE INDEX IF NOT EXISTS idx_investigation_tenant_assigned ON investigations (tenant_id, assigned_to)")

    # ── 3. Workspace support tables (from 004_analyst_workspace.py) ───────────
    op.execute("""
        CREATE TABLE IF NOT EXISTS investigation_notes (
            id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id        UUID        NOT NULL,
            investigation_id VARCHAR(64) NOT NULL,
            analyst_id       UUID        NOT NULL,
            content          TEXT        NOT NULL,
            pinned           BOOLEAN     NOT NULL DEFAULT FALSE,
            created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            deleted_at       TIMESTAMPTZ
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_note_tenant_inv ON investigation_notes (tenant_id, investigation_id)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS investigation_assignments (
            id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id         UUID        NOT NULL,
            investigation_id  VARCHAR(64) NOT NULL,
            assigned_to       UUID        NOT NULL,
            assigned_by       UUID        NOT NULL,
            assigned_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            unassigned_at     TIMESTAMPTZ,
            escalated         BOOLEAN     NOT NULL DEFAULT FALSE,
            escalation_reason TEXT,
            severity          VARCHAR(32),
            is_active         BOOLEAN     NOT NULL DEFAULT TRUE,
            created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_assign_tenant_inv_active ON investigation_assignments (tenant_id, investigation_id, is_active)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS investigation_activity (
            id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id        UUID        NOT NULL,
            investigation_id VARCHAR(64) NOT NULL,
            analyst_id       UUID        NOT NULL,
            action           VARCHAR(100) NOT NULL,
            target_id        VARCHAR(64),
            metadata         JSONB       NOT NULL DEFAULT '{}'::jsonb,
            created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_activity_tenant_inv ON investigation_activity (tenant_id, investigation_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_activity_tenant_ts  ON investigation_activity (tenant_id, created_at)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS investigation_evidence (
            id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id        UUID        NOT NULL,
            investigation_id VARCHAR(64) NOT NULL,
            analyst_id       UUID        NOT NULL,
            evidence_type    VARCHAR(32) NOT NULL,
            reference_id     VARCHAR(255),
            title            VARCHAR(500) NOT NULL,
            description      TEXT,
            metadata         JSONB       NOT NULL DEFAULT '{}'::jsonb,
            created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_evidence_tenant_inv ON investigation_evidence (tenant_id, investigation_id)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS investigation_verdicts (
            id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id          UUID        NOT NULL,
            investigation_id   VARCHAR(64) NOT NULL,
            analyst_id         UUID        NOT NULL,
            previous_verdict   VARCHAR(32),
            new_verdict        VARCHAR(32) NOT NULL,
            reasoning          TEXT,
            containment_status VARCHAR(64),
            created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_verdict_tenant_inv ON investigation_verdicts (tenant_id, investigation_id)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS saved_hunts (
            id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id    UUID         NOT NULL,
            analyst_id   UUID         NOT NULL,
            name         VARCHAR(200) NOT NULL,
            description  TEXT,
            query_params JSONB        NOT NULL DEFAULT '{}'::jsonb,
            run_count    INTEGER      NOT NULL DEFAULT 0,
            created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
            updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_saved_hunt_tenant_analyst ON saved_hunts (tenant_id, analyst_id)")

    # ── 4. New columns for manual investigation creation (this PR) ────────────
    op.execute("ALTER TABLE investigations ADD COLUMN IF NOT EXISTS title      VARCHAR(500) DEFAULT ''")
    op.execute("ALTER TABLE investigations ADD COLUMN IF NOT EXISTS source     VARCHAR(32)  DEFAULT 'auto'")
    op.execute("ALTER TABLE investigations ADD COLUMN IF NOT EXISTS created_by UUID")
    op.execute("CREATE INDEX IF NOT EXISTS idx_investigation_tenant_source ON investigations (tenant_id, source)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_investigation_tenant_source")
    op.execute("ALTER TABLE investigations DROP COLUMN IF EXISTS created_by")
    op.execute("ALTER TABLE investigations DROP COLUMN IF EXISTS source")
    op.execute("ALTER TABLE investigations DROP COLUMN IF EXISTS title")
