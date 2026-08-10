"""create initial securescan schema

Revision ID: 9eba1941b4ac
Revises:
Create Date: 2026-07-23 19:24:03.680385

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "9eba1941b4ac"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "projects",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "targets",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("target_type", sa.String(length=64), nullable=False),
        sa.Column("content_digest", sa.String(length=64), nullable=False),
        sa.Column("source_path", sa.Text(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_targets_project_id"),
        "targets",
        ["project_id"],
        unique=False,
    )
    op.create_table(
        "analysis_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("report_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_analysis_runs_target_id"),
        "analysis_runs",
        ["target_id"],
        unique=False,
    )
    op.create_table(
        "jobs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("adapter_id", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("leased_by", sa.String(length=200), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("priority >= 0", name="ck_jobs_priority_nonnegative"),
        sa.CheckConstraint(
            "attempt_count >= 0",
            name="ck_jobs_attempt_count_nonnegative",
        ),
        sa.CheckConstraint(
            "max_attempts >= 1",
            name="ck_jobs_max_attempts_positive",
        ),
        sa.CheckConstraint(
            "attempt_count <= max_attempts",
            name="ck_jobs_attempt_count_within_limit",
        ),
        sa.CheckConstraint(
            "status IN ("
            "'submitted', 'queued', 'leased', 'running', 'retry_pending', "
            "'succeeded', 'partial', 'failed', 'cancelled'"
            ")",
            name="ck_jobs_status",
        ),
        sa.ForeignKeyConstraint(["run_id"], ["analysis_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key", name="uq_jobs_idempotency_key"),
    )
    op.create_index(
        "ix_jobs_claim",
        "jobs",
        ["status", "available_at", "priority", "created_at"],
        unique=False,
    )
    op.create_index(op.f("ix_jobs_run_id"), "jobs", ["run_id"], unique=False)
    op.create_table(
        "tool_executions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("adapter_id", sa.String(length=100), nullable=False),
        sa.Column("tool_version", sa.String(length=64), nullable=False),
        sa.Column("adapter_version", sa.String(length=64), nullable=False),
        sa.Column("outcome", sa.String(length=100), nullable=False),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("warning_json", sa.JSON(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["run_id"], ["analysis_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_tool_executions_run_id"),
        "tool_executions",
        ["run_id"],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(
        op.f("ix_tool_executions_run_id"),
        table_name="tool_executions",
    )
    op.drop_table("tool_executions")
    op.drop_index(op.f("ix_jobs_run_id"), table_name="jobs")
    op.drop_index("ix_jobs_claim", table_name="jobs")
    op.drop_table("jobs")
    op.drop_index(
        op.f("ix_analysis_runs_target_id"),
        table_name="analysis_runs",
    )
    op.drop_table("analysis_runs")
    op.drop_index(op.f("ix_targets_project_id"), table_name="targets")
    op.drop_table("targets")
    op.drop_table("projects")
