"""Add ai_analysis_json column to investigations table

Revision ID: 012_investigation_ai_analysis
Revises: 011_rag_knowledge_base
Create Date: 2026-06-12
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "012_investigation_ai_analysis"
down_revision: Union[str, None] = "011_rag_knowledge_base"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "investigations",
        sa.Column(
            "ai_analysis_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("investigations", "ai_analysis_json")
