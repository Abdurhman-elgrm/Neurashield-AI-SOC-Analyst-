"""Events Explorer — correlation columns + performance indexes + FTS GIN index

Revision ID: 004_events_explorer
Revises: 003_installer_tokens
Create Date: 2026-05-25

Adds:
  - events.correlation_id, session_id, process_tree_id, event_chain_id (nullable)
  - Composite B-tree indexes for: severity, username, source_ip, dest_ip,
    process_name, correlation_id, session_id, process_tree_id, event_chain_id
  - GIN functional full-text search index on (host_name || username || process_name
    || source_ip || dest_ip) using English dictionary
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "004_events_explorer"
down_revision: Union[str, None] = "003_installer_tokens"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ─── New correlation / session / chain columns ────────────────────────────
    op.add_column("events", sa.Column("correlation_id", sa.String(255), nullable=True))
    op.add_column("events", sa.Column("session_id", sa.String(255), nullable=True))
    op.add_column("events", sa.Column("process_tree_id", sa.String(255), nullable=True))
    op.add_column("events", sa.Column("event_chain_id", sa.String(255), nullable=True))

    # ─── B-tree composite indexes ─────────────────────────────────────────────
    op.create_index(
        "idx_event_tenant_severity", "events", ["tenant_id", "severity"],
    )
    op.create_index(
        "idx_event_tenant_username", "events", ["tenant_id", "username"],
    )
    op.create_index(
        "idx_event_tenant_source_ip", "events", ["tenant_id", "source_ip"],
    )
    op.create_index(
        "idx_event_tenant_dest_ip", "events", ["tenant_id", "dest_ip"],
    )
    op.create_index(
        "idx_event_tenant_process_name", "events", ["tenant_id", "process_name"],
    )
    op.create_index(
        "idx_event_tenant_correlation_id", "events", ["tenant_id", "correlation_id"],
    )
    op.create_index(
        "idx_event_tenant_session_id", "events", ["tenant_id", "session_id"],
    )
    op.create_index(
        "idx_event_tenant_process_tree_id", "events", ["tenant_id", "process_tree_id"],
    )
    op.create_index(
        "idx_event_tenant_event_chain_id", "events", ["tenant_id", "event_chain_id"],
    )

    # ─── GIN full-text search index ───────────────────────────────────────────
    # Matches the to_tsvector expression used in EventSearchService._fts_clause
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_event_fts
        ON events
        USING GIN (
            to_tsvector(
                'english',
                coalesce(host_name, '') || ' ' ||
                coalesce(username, '') || ' ' ||
                coalesce(process_name, '') || ' ' ||
                coalesce(source_ip, '') || ' ' ||
                coalesce(dest_ip, '')
            )
        )
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_event_fts")

    op.drop_index("idx_event_tenant_event_chain_id", table_name="events")
    op.drop_index("idx_event_tenant_process_tree_id", table_name="events")
    op.drop_index("idx_event_tenant_session_id", table_name="events")
    op.drop_index("idx_event_tenant_correlation_id", table_name="events")
    op.drop_index("idx_event_tenant_process_name", table_name="events")
    op.drop_index("idx_event_tenant_dest_ip", table_name="events")
    op.drop_index("idx_event_tenant_source_ip", table_name="events")
    op.drop_index("idx_event_tenant_username", table_name="events")
    op.drop_index("idx_event_tenant_severity", table_name="events")

    op.drop_column("events", "event_chain_id")
    op.drop_column("events", "process_tree_id")
    op.drop_column("events", "session_id")
    op.drop_column("events", "correlation_id")
