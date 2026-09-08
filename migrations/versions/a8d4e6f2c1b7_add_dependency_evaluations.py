"""add Source dependency evaluations

Revision ID: a8d4e6f2c1b7
Revises: 7c91e2a4b6d8

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a8d4e6f2c1b7"
down_revision: str | Sequence[str] | None = "7c91e2a4b6d8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "source_orchestration_nodes",
        sa.Column("terminal_reason_code", sa.String(length=128), nullable=True),
    )
    with op.batch_alter_table("source_orchestration_nodes") as batch_op:
        batch_op.create_check_constraint(
            "ck_source_node_terminal_reason",
            "lifecycle_state = 'TERMINAL' OR terminal_reason_code IS NULL",
        )
    with op.batch_alter_table("source_orchestration_scanner_jobs") as batch_op:
        batch_op.create_unique_constraint(
            "uq_source_scanner_job_dependency_identity",
            ["job_id", "run_id", "node_id"],
        )
    op.create_table(
        "source_orchestration_dependency_evaluations",
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("osv_node_id", sa.String(length=64), nullable=False),
        sa.Column("syft_node_id", sa.String(length=64), nullable=False),
        sa.Column("syft_job_id", sa.String(length=36), nullable=False),
        sa.Column("syft_selected_attempt_number", sa.Integer(), nullable=False),
        sa.Column("syft_native_result_sha256", sa.String(length=64), nullable=False),
        sa.Column("scope_digest", sa.String(length=64), nullable=False),
        sa.Column("evaluation_artifact_sha256", sa.String(length=64), nullable=False),
        sa.Column("evaluation_artifact_size_bytes", sa.Integer(), nullable=False),
        sa.Column("evaluation_artifact_media_type", sa.String(length=128), nullable=False),
        sa.Column("evaluation_schema_version", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "syft_selected_attempt_number >= 1",
            name="ck_source_dependency_evaluation_attempt",
        ),
        sa.CheckConstraint(
            "evaluation_artifact_size_bytes >= 1",
            name="ck_source_dependency_evaluation_size",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["source_orchestrations.run_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["osv_node_id", "run_id"],
            ["source_orchestration_nodes.node_id", "source_orchestration_nodes.run_id"],
            name="fk_source_dependency_evaluation_osv_node",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["syft_node_id", "run_id"],
            ["source_orchestration_nodes.node_id", "source_orchestration_nodes.run_id"],
            name="fk_source_dependency_evaluation_syft_node",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["syft_job_id", "run_id", "syft_node_id"],
            [
                "source_orchestration_scanner_jobs.job_id",
                "source_orchestration_scanner_jobs.run_id",
                "source_orchestration_scanner_jobs.node_id",
            ],
            name="fk_source_dependency_evaluation_syft_job",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["syft_job_id", "syft_selected_attempt_number"],
            [
                "source_orchestration_attempts.job_id",
                "source_orchestration_attempts.attempt_number",
            ],
            name="fk_source_dependency_evaluation_syft_attempt",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("run_id", "osv_node_id"),
    )


def downgrade() -> None:
    op.drop_table("source_orchestration_dependency_evaluations")
    with op.batch_alter_table("source_orchestration_scanner_jobs") as batch_op:
        batch_op.drop_constraint("uq_source_scanner_job_dependency_identity", type_="unique")
    with op.batch_alter_table("source_orchestration_nodes") as batch_op:
        batch_op.drop_constraint("ck_source_node_terminal_reason", type_="check")
        batch_op.drop_column("terminal_reason_code")
