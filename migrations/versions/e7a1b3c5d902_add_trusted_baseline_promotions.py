"""add trusted baseline promotion history

Revision ID: e7a1b3c5d902
Revises: d6f9b2c7a104
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e7a1b3c5d902"
down_revision: str | Sequence[str] | None = "d6f9b2c7a104"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "source_trusted_baseline_promotions",
        sa.Column("baseline_id", sa.String(36), nullable=False),
        sa.Column("lineage_id", sa.String(36), nullable=False),
        sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("actor_type", sa.String(32), nullable=False),
        sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "revision >= 1",
            name="ck_source_trusted_baseline_promotions_revision",
        ),
        sa.CheckConstraint(
            "actor_type = 'LOCAL_OPERATOR'",
            name="ck_source_trusted_baseline_promotions_actor",
        ),
        sa.ForeignKeyConstraint(
            ["lineage_id"],
            ["source_target_lineages.lineage_id"],
            name="fk_source_trusted_baseline_promotions_lineage",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["lineage_id", "run_id"],
            ["source_lineage_runs.lineage_id", "source_lineage_runs.run_id"],
            name="fk_source_trusted_baseline_promotions_run",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("baseline_id"),
        sa.UniqueConstraint(
            "lineage_id",
            "revision",
            name="uq_source_trusted_baseline_promotions_revision",
        ),
    )
    op.create_index(
        "ix_source_trusted_baseline_promotions_history",
        "source_trusted_baseline_promotions",
        ["lineage_id", "revision"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_source_trusted_baseline_promotions_history",
        table_name="source_trusted_baseline_promotions",
    )
    op.drop_table("source_trusted_baseline_promotions")
