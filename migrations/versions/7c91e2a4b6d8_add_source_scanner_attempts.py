"""add Source scanner jobs and attempts

Revision ID: 7c91e2a4b6d8
Revises: 3a6f1c8e2d90

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "7c91e2a4b6d8"
down_revision: str | Sequence[str] | None = "3a6f1c8e2d90"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "source_orchestration_scanner_jobs",
        sa.Column("job_id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("node_id", sa.String(length=64), nullable=False),
        sa.Column("authority", sa.String(length=64), nullable=False),
        sa.Column("capability", sa.String(length=64), nullable=False),
        sa.Column("analyzer_id", sa.String(length=128), nullable=False),
        sa.Column("contract_digest", sa.String(length=64), nullable=False),
        sa.Column("context_digest", sa.String(length=64), nullable=False),
        sa.Column("context_artifact_sha256", sa.String(length=64), nullable=False),
        sa.Column("context_artifact_size_bytes", sa.Integer(), nullable=False),
        sa.Column("context_artifact_storage_path", sa.Text(), nullable=False),
        sa.Column("projection_id", sa.String(length=96), nullable=False),
        sa.Column("projection_digest", sa.String(length=64), nullable=False),
        sa.Column("selected_attempt_number", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["jobs.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["node_id", "run_id"],
            ["source_orchestration_nodes.node_id", "source_orchestration_nodes.run_id"],
            name="fk_source_scanner_job_node_run",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "authority", "capability"],
            [
                "source_orchestration_authorities.run_id",
                "source_orchestration_authorities.authority",
                "source_orchestration_authorities.capability",
            ],
            name="fk_source_scanner_job_authority",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("job_id"),
        sa.CheckConstraint(
            "selected_attempt_number IS NULL OR selected_attempt_number >= 1",
            name="ck_source_scanner_job_selected_attempt",
        ),
        sa.UniqueConstraint("node_id", name="uq_source_scanner_job_node"),
    )
    op.create_table(
        "source_orchestration_attempts",
        sa.Column("job_id", sa.String(length=36), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("node_id", sa.String(length=64), nullable=False),
        sa.Column("attempt_token", sa.String(length=36), nullable=False),
        sa.Column("worker_id", sa.String(length=200), nullable=False),
        sa.Column("lease_token", sa.String(length=36), nullable=False),
        sa.Column("containment_state", sa.String(length=32), nullable=False),
        sa.Column("acceptance_state", sa.String(length=16), nullable=False),
        sa.Column("supervisor_identity", sa.String(length=64), nullable=True),
        sa.Column("supervisor_pid", sa.Integer(), nullable=True),
        sa.Column("supervisor_start_ticks", sa.Integer(), nullable=True),
        sa.Column("scanner_pid", sa.Integer(), nullable=True),
        sa.Column("scanner_pgid", sa.Integer(), nullable=True),
        sa.Column("scanner_start_ticks", sa.Integer(), nullable=True),
        sa.Column("cleanup_receipt_sha256", sa.String(length=64), nullable=True),
        sa.Column("cleanup_receipt_json", sa.JSON(), nullable=True),
        sa.Column("tool_execution_id", sa.String(length=36), nullable=True),
        sa.Column("native_result_sha256", sa.String(length=64), nullable=True),
        sa.Column("native_result_size_bytes", sa.Integer(), nullable=True),
        sa.Column("native_result_media_type", sa.String(length=128), nullable=True),
        sa.Column("native_result_schema_version", sa.String(length=128), nullable=True),
        sa.Column("native_result_storage_path", sa.Text(), nullable=True),
        sa.Column("projection_revalidated", sa.Boolean(), nullable=True),
        sa.Column("failure_code", sa.String(length=64), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("attempt_number >= 1", name="ck_source_attempt_number"),
        sa.CheckConstraint(
            "containment_state IN ('ACTIVE', 'RECONCILIATION_REQUIRED', 'CLEAN')",
            name="ck_source_attempt_containment",
        ),
        sa.CheckConstraint(
            "acceptance_state IN ('PENDING', 'ACCEPTED', 'REJECTED')",
            name="ck_source_attempt_acceptance",
        ),
        sa.CheckConstraint(
            "(acceptance_state = 'ACCEPTED') = (native_result_sha256 IS NOT NULL)",
            name="ck_source_attempt_accepted_result",
        ),
        sa.CheckConstraint(
            "(native_result_sha256 IS NULL AND native_result_size_bytes IS NULL "
            "AND native_result_media_type IS NULL "
            "AND native_result_schema_version IS NULL "
            "AND native_result_storage_path IS NULL AND accepted_at IS NULL) OR "
            "(native_result_sha256 IS NOT NULL "
            "AND native_result_size_bytes IS NOT NULL "
            "AND native_result_media_type IS NOT NULL "
            "AND native_result_schema_version IS NOT NULL "
            "AND native_result_storage_path IS NOT NULL AND accepted_at IS NOT NULL)",
            name="ck_source_attempt_result_reference",
        ),
        sa.CheckConstraint(
            "acceptance_state <> 'ACCEPTED' OR "
            "(containment_state = 'CLEAN' AND projection_revalidated = true "
            "AND tool_execution_id IS NOT NULL)",
            name="ck_source_attempt_acceptance_proof",
        ),
        sa.CheckConstraint(
            "cleanup_receipt_sha256 IS NULL OR cleanup_receipt_json IS NOT NULL",
            name="ck_source_attempt_receipt_pair",
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["source_orchestration_scanner_jobs.job_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["node_id", "run_id"],
            ["source_orchestration_nodes.node_id", "source_orchestration_nodes.run_id"],
            name="fk_source_attempt_node_run",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tool_execution_id"],
            ["tool_executions.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("job_id", "attempt_number"),
        sa.UniqueConstraint("attempt_token", name="uq_source_attempt_token"),
        sa.UniqueConstraint(
            "tool_execution_id", name="uq_source_attempt_tool_execution"
        ),
    )
    op.create_index(
        "uq_source_attempt_selected_node",
        "source_orchestration_attempts",
        ["node_id"],
        unique=True,
        sqlite_where=sa.text("acceptance_state = 'ACCEPTED'"),
        postgresql_where=sa.text("acceptance_state = 'ACCEPTED'"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_source_attempt_selected_node",
        table_name="source_orchestration_attempts",
    )
    op.drop_table("source_orchestration_attempts")
    op.drop_table("source_orchestration_scanner_jobs")
