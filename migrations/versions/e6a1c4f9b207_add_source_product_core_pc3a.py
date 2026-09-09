"""add Source Product Core PC3A durable submission intent

Revision ID: e6a1c4f9b207
Revises: d5e9f2a3b014

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e6a1c4f9b207"
down_revision: str | Sequence[str] | None = "d5e9f2a3b014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "source_scan_submissions",
        sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column("lineage_id", sa.String(36), nullable=False),
        sa.Column("submission_sequence_number", sa.Integer(), nullable=False),
        sa.Column("predecessor_run_id", sa.String(36)),
        sa.Column("predecessor_sequence_number", sa.Integer()),
        sa.Column("intake_kind", sa.String(32), nullable=False),
        sa.Column("intake_ref", sa.String(69), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finalized_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "submission_sequence_number >= 1",
            name="ck_source_scan_submissions_sequence_positive",
        ),
        sa.CheckConstraint(
            "(submission_sequence_number = 1 AND predecessor_run_id IS NULL "
            "AND predecessor_sequence_number IS NULL) OR "
            "(submission_sequence_number > 1 AND predecessor_run_id IS NOT NULL "
            "AND predecessor_sequence_number IS NOT NULL "
            "AND predecessor_sequence_number = submission_sequence_number - 1)",
            name="ck_source_scan_submissions_predecessor_pair",
        ),
        sa.CheckConstraint(
            "intake_kind = 'MANAGED_WORKSPACE_V1'",
            name="ck_source_scan_submissions_intake_kind",
        ),
        sa.CheckConstraint(
            "intake_ref LIKE 'securescan-workspace-%'",
            name="ck_source_scan_submissions_intake_ref",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"], ["analysis_runs.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["lineage_id"], ["source_target_lineages.lineage_id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["predecessor_run_id"], ["analysis_runs.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("run_id"),
        sa.UniqueConstraint(
            "lineage_id",
            "submission_sequence_number",
            name="uq_source_scan_submissions_sequence",
        ),
    )
    op.create_index(
        "ix_source_scan_submissions_lineage",
        "source_scan_submissions",
        ["lineage_id", "submission_sequence_number"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_source_scan_submissions_lineage",
        table_name="source_scan_submissions",
    )
    op.drop_table("source_scan_submissions")
