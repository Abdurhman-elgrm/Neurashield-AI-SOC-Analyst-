"""perf: GIN indexes on events.ueba_flags and events.tags for event-level threat hunt

Revision ID: 024
Revises: 023
Create Date: 2026-06-19

Why
---
Event Hunt queries filter events by JSONB array containment, e.g.:

    WHERE ueba_flags @> '["brute_force"]'::jsonb
    WHERE tags       @> '["PowerShell Script Block Logged"]'::jsonb

Without a GIN index these become full sequential scans over what can be
hundreds of millions of rows.  With GIN + jsonb_path_ops the planner uses
an index-only scan that is O(log n + k).

Operator class
--------------
jsonb_path_ops is chosen over the default jsonb_ops because:
  - Event Hunt only uses the @> containment operator (never ?, ?|, ?&, @?)
  - jsonb_path_ops produces a ~30 % smaller index with faster lookups for @>
  - It does not support key-existence operators, but we do not need them here

Operational notes
-----------------
  - Both indexes are built CONCURRENTLY so the events table is never locked.
    Reads and writes continue normally during the entire build.
  - Build time: typically 1–10 minutes depending on the events table row count.
    The migration will appear to hang during this period — this is expected.
  - CONCURRENTLY performs TWO full table scans.  CPU and I/O will spike.
    Schedule this migration during a low-traffic window on large deployments.
  - If the migration is killed mid-build, PostgreSQL leaves an INVALID index.
    Detect it with:
        SELECT indexname FROM pg_indexes
        WHERE tablename = 'events'
          AND indexname LIKE 'idx_event_%_gin'
        INTERSECT
        SELECT indexrelid::regclass::text FROM pg_index WHERE indisvalid = false;
    Then recover with:
        DROP INDEX CONCURRENTLY idx_event_ueba_flags_gin;
        DROP INDEX CONCURRENTLY idx_event_tags_gin;
    and re-run alembic upgrade.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "024"
down_revision = "023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # CREATE INDEX CONCURRENTLY is prohibited inside a transaction block.
    # autocommit_block() commits the enclosing Alembic transaction, switches
    # the connection to autocommit mode, executes the DDL, then returns control
    # to Alembic so subsequent migrations run normally.
    # Requires Alembic >= 1.7.0 (project uses >= 1.14.0).
    with op.get_context().autocommit_block():
        op.execute(sa.text(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_event_ueba_flags_gin "
            "ON events USING gin(ueba_flags jsonb_path_ops)"
        ))
        op.execute(sa.text(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_event_tags_gin "
            "ON events USING gin(tags jsonb_path_ops)"
        ))


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute(sa.text(
            "DROP INDEX CONCURRENTLY IF EXISTS idx_event_ueba_flags_gin"
        ))
        op.execute(sa.text(
            "DROP INDEX CONCURRENTLY IF EXISTS idx_event_tags_gin"
        ))
