"""feat: playbook generator, agent containment, response actions

Revision ID: 023
Revises: 022
Create Date: 2026-06-19
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "023"
down_revision = "022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── 1. Agent containment state ──────────────────────────────────────────────
    op.execute(sa.text("""
        DO $$ BEGIN
            CREATE TYPE agent_containment_state_enum AS ENUM (
                'none', 'quarantined', 'isolated', 'muted'
            );
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$
    """))
    op.execute(sa.text("""
        ALTER TABLE agents
          ADD COLUMN IF NOT EXISTS containment_state
              agent_containment_state_enum NOT NULL DEFAULT 'none',
          ADD COLUMN IF NOT EXISTS containment_reason TEXT,
          ADD COLUMN IF NOT EXISTS contained_at       TIMESTAMPTZ,
          ADD COLUMN IF NOT EXISTS contained_by_id    UUID REFERENCES users(id) ON DELETE SET NULL
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_agent_containment "
        "ON agents (tenant_id, containment_state) WHERE deleted_at IS NULL"
    ))

    # ── 2. playbook_templates ────────────────────────────────────────────────────
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS playbook_templates (
            id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE,
            name            VARCHAR(255) NOT NULL,
            description     TEXT,
            tactic          VARCHAR(128),
            technique       VARCHAR(128),
            category        VARCHAR(128),
            is_system       BOOLEAN NOT NULL DEFAULT FALSE,
            version         INTEGER NOT NULL DEFAULT 1,
            enabled         BOOLEAN NOT NULL DEFAULT TRUE,
            created_by_id   UUID REFERENCES users(id) ON DELETE SET NULL,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            deleted_at      TIMESTAMPTZ
        )
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_pt_tenant ON playbook_templates (tenant_id)"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_pt_technique ON playbook_templates (technique)"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_pt_tactic ON playbook_templates (tactic)"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_pt_category ON playbook_templates (category)"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_pt_system ON playbook_templates (is_system) WHERE is_system = TRUE"
    ))

    # ── 3. playbook_template_steps ───────────────────────────────────────────────
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS playbook_template_steps (
            id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            template_id             UUID NOT NULL
                REFERENCES playbook_templates(id) ON DELETE CASCADE,
            step_order              INTEGER NOT NULL,
            category                VARCHAR(128) NOT NULL DEFAULT 'investigation',
            title                   VARCHAR(512) NOT NULL,
            description_template    TEXT,
            command_windows         TEXT,
            command_linux           TEXT,
            expected_result         TEXT,
            can_run_parallel        BOOLEAN NOT NULL DEFAULT FALSE,
            requires_human_approval BOOLEAN NOT NULL DEFAULT TRUE,
            is_critical             BOOLEAN NOT NULL DEFAULT FALSE,
            hint                    TEXT,
            mitre_reference         VARCHAR(128),
            action_type             VARCHAR(64),
            step_order_dependencies JSONB NOT NULL DEFAULT '[]',
            created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_pts_template "
        "ON playbook_template_steps (template_id, step_order)"
    ))

    # ── 4. playbooks (instantiated per alert/incident) ───────────────────────────
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS playbooks (
            id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            template_id      UUID REFERENCES playbook_templates(id) ON DELETE SET NULL,
            alert_id         UUID REFERENCES alerts(id) ON DELETE SET NULL,
            investigation_id UUID REFERENCES investigations(id) ON DELETE SET NULL,
            incident_id      VARCHAR(64) NOT NULL,
            title            VARCHAR(512) NOT NULL,
            severity         VARCHAR(32) NOT NULL DEFAULT 'medium',
            source_host      VARCHAR(255),
            status           VARCHAR(32) NOT NULL DEFAULT 'pending',
            variables        JSONB NOT NULL DEFAULT '{}',
            generated_by     VARCHAR(64) NOT NULL DEFAULT 'fallback',
            assigned_to_id   UUID REFERENCES users(id) ON DELETE SET NULL,
            created_by_id    UUID REFERENCES users(id) ON DELETE SET NULL,
            created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            deleted_at       TIMESTAMPTZ
        )
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_pb_tenant ON playbooks (tenant_id)"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_pb_alert ON playbooks (alert_id)"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_pb_incident ON playbooks (tenant_id, incident_id)"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_pb_status ON playbooks (tenant_id, status)"
    ))

    # ── 5. playbook_steps ────────────────────────────────────────────────────────
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS playbook_steps (
            id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            playbook_id             UUID NOT NULL
                REFERENCES playbooks(id) ON DELETE CASCADE,
            step_order              INTEGER NOT NULL,
            category                VARCHAR(128) NOT NULL DEFAULT 'investigation',
            title                   VARCHAR(512) NOT NULL,
            description             TEXT,
            command_windows         TEXT,
            command_linux           TEXT,
            expected_result         TEXT,
            status                  VARCHAR(32) NOT NULL DEFAULT 'pending',
            requires_human_approval BOOLEAN NOT NULL DEFAULT TRUE,
            is_critical             BOOLEAN NOT NULL DEFAULT FALSE,
            can_run_parallel        BOOLEAN NOT NULL DEFAULT FALSE,
            action_type             VARCHAR(64),
            action_target_id        VARCHAR(255),
            completed_at            TIMESTAMPTZ,
            completed_by_id         UUID REFERENCES users(id) ON DELETE SET NULL,
            notes                   TEXT,
            result                  TEXT,
            created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_pbs_playbook "
        "ON playbook_steps (playbook_id, step_order)"
    ))

    # ── 6. playbook_runs ─────────────────────────────────────────────────────────
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS playbook_runs (
            id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            playbook_id     UUID NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
            tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            mode            VARCHAR(32) NOT NULL DEFAULT 'manual',
            status          VARCHAR(32) NOT NULL DEFAULT 'running',
            steps_completed INTEGER NOT NULL DEFAULT 0,
            steps_total     INTEGER NOT NULL DEFAULT 0,
            actor_id        UUID REFERENCES users(id) ON DELETE SET NULL,
            started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            completed_at    TIMESTAMPTZ,
            failure_reason  TEXT
        )
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_pr_playbook ON playbook_runs (playbook_id)"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_pr_tenant ON playbook_runs (tenant_id)"
    ))

    # ── 7. response_actions ──────────────────────────────────────────────────────
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS response_actions (
            id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            playbook_id      UUID REFERENCES playbooks(id) ON DELETE SET NULL,
            playbook_step_id UUID REFERENCES playbook_steps(id) ON DELETE SET NULL,
            agent_id         UUID REFERENCES agents(id) ON DELETE SET NULL,
            alert_id         UUID REFERENCES alerts(id) ON DELETE SET NULL,
            actor_id         UUID REFERENCES users(id) ON DELETE SET NULL,
            action_type      VARCHAR(64) NOT NULL,
            target_type      VARCHAR(64) NOT NULL DEFAULT 'agent',
            target_id        VARCHAR(255),
            target_name      VARCHAR(255),
            status           VARCHAR(32) NOT NULL DEFAULT 'pending',
            result           TEXT,
            action_metadata  JSONB NOT NULL DEFAULT '{}',
            created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_ra_tenant ON response_actions (tenant_id)"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_ra_agent ON response_actions (agent_id)"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_ra_alert ON response_actions (alert_id)"
    ))


def downgrade() -> None:
    op.execute(sa.text("DROP TABLE IF EXISTS response_actions CASCADE"))
    op.execute(sa.text("DROP TABLE IF EXISTS playbook_runs CASCADE"))
    op.execute(sa.text("DROP TABLE IF EXISTS playbook_steps CASCADE"))
    op.execute(sa.text("DROP TABLE IF EXISTS playbooks CASCADE"))
    op.execute(sa.text("DROP TABLE IF EXISTS playbook_template_steps CASCADE"))
    op.execute(sa.text("DROP TABLE IF EXISTS playbook_templates CASCADE"))
    op.execute(sa.text("""
        ALTER TABLE agents
          DROP COLUMN IF EXISTS containment_state,
          DROP COLUMN IF EXISTS containment_reason,
          DROP COLUMN IF EXISTS contained_at,
          DROP COLUMN IF EXISTS contained_by_id
    """))
    op.execute(sa.text("DROP TYPE IF EXISTS agent_containment_state_enum"))
