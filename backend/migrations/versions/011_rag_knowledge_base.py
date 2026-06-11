"""Create RAG knowledge base table

Revision ID: 011_rag_knowledge_base
Revises: 010_user_timezone
Create Date: 2026-06-11
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "011_rag_knowledge_base"
down_revision: Union[str, None] = "010_user_timezone"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "rag_knowledge_base",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("source",   sa.String(64),  nullable=False),
        sa.Column("chunk_id", sa.String(256), nullable=False),
        sa.Column("title",    sa.Text(),      nullable=False),
        sa.Column("content",  sa.Text(),      nullable=False),
        sa.Column(
            "tags",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("chunk_id", name="uq_rag_chunk_id"),
    )

    op.create_index("idx_rag_source", "rag_knowledge_base", ["source"])
    op.create_index(
        "idx_rag_tags_gin",
        "rag_knowledge_base",
        ["tags"],
        postgresql_using="gin",
    )
    op.execute(
        "CREATE INDEX idx_rag_content_fts ON rag_knowledge_base "
        "USING gin(to_tsvector('english', content))"
    )


def downgrade() -> None:
    op.drop_index("idx_rag_content_fts", table_name="rag_knowledge_base")
    op.drop_index("idx_rag_tags_gin",   table_name="rag_knowledge_base")
    op.drop_index("idx_rag_source",     table_name="rag_knowledge_base")
    op.drop_table("rag_knowledge_base")
