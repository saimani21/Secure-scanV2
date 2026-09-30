"""add deterministic trusted policy definitions and evaluations

Revision ID: f8c2d6e1a305
Revises: e7a1b3c5d902
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f8c2d6e1a305"
down_revision: str | Sequence[str] | None = "e7a1b3c5d902"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "source_policy_definitions",
        sa.Column("lineage_id", sa.String(36), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("policy_id", sa.String(36), nullable=False),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("definition_json", sa.JSON(), nullable=False),
        sa.Column("actor_type", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("version >= 2", name="ck_source_policy_definitions_version"),
        sa.CheckConstraint(
            "actor_type = 'LOCAL_OPERATOR'", name="ck_source_policy_definitions_actor"
        ),
        sa.CheckConstraint("length(digest) = 64", name="ck_source_policy_definitions_digest"),
        sa.ForeignKeyConstraint(
            ["lineage_id"],
            ["source_target_lineages.lineage_id"],
            name="fk_source_policy_definitions_lineage",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("lineage_id", "version"),
    )
    op.create_table(
        "source_policy_evaluations",
        sa.Column("evaluation_id", sa.String(36), nullable=False),
        sa.Column("lineage_id", sa.String(36), nullable=False),
        sa.Column("candidate_run_id", sa.String(36), nullable=False),
        sa.Column("baseline_id", sa.String(36), nullable=True),
        sa.Column("baseline_revision", sa.Integer(), nullable=True),
        sa.Column("policy_id", sa.String(36), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("policy_digest", sa.String(64), nullable=False),
        sa.Column("result", sa.String(8), nullable=False),
        sa.Column("decisions_json", sa.JSON(), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "result IN ('PASS', 'FAIL', 'ERROR')", name="ck_source_policy_evaluations_result"
        ),
        sa.CheckConstraint(
            "(baseline_id IS NULL) = (baseline_revision IS NULL)",
            name="ck_source_policy_evaluations_baseline_pair",
        ),
        sa.CheckConstraint(
            "policy_version >= 1", name="ck_source_policy_evaluations_policy_version"
        ),
        sa.ForeignKeyConstraint(
            ["lineage_id"],
            ["source_target_lineages.lineage_id"],
            name="fk_source_policy_evaluations_lineage",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["lineage_id", "candidate_run_id"],
            ["source_lineage_runs.lineage_id", "source_lineage_runs.run_id"],
            name="fk_source_policy_evaluations_candidate",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["baseline_id"],
            ["source_trusted_baseline_promotions.baseline_id"],
            name="fk_source_policy_evaluations_baseline",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("evaluation_id"),
    )
    op.create_index(
        "ix_source_policy_evaluations_lineage",
        "source_policy_evaluations",
        ["lineage_id", "evaluated_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_source_policy_evaluations_lineage", table_name="source_policy_evaluations")
    op.drop_table("source_policy_evaluations")
    op.drop_table("source_policy_definitions")
