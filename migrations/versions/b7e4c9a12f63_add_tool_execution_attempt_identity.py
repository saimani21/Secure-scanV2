"""add tool execution attempt identity

Revision ID: b7e4c9a12f63
Revises: 4c7d2e91a6bf

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b7e4c9a12f63"
down_revision: str | Sequence[str] | None = "4c7d2e91a6bf"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("tool_executions") as batch_op:
        batch_op.add_column(
            sa.Column(
                "job_id",
                sa.String(length=36),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "attempt_number",
                sa.Integer(),
                nullable=True,
            )
        )
        batch_op.create_foreign_key(
            "fk_tool_executions_job_id_jobs",
            "jobs",
            ["job_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_check_constraint(
            "ck_tool_executions_attempt_positive",
            "attempt_number IS NULL OR attempt_number >= 1",
        )
        batch_op.create_unique_constraint(
            "uq_tool_executions_job_attempt",
            ["job_id", "attempt_number"],
        )
        batch_op.create_index(
            "ix_tool_executions_job_id",
            ["job_id"],
            unique=False,
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("tool_executions") as batch_op:
        batch_op.drop_index("ix_tool_executions_job_id")
        batch_op.drop_constraint(
            "uq_tool_executions_job_attempt",
            type_="unique",
        )
        batch_op.drop_constraint(
            "ck_tool_executions_attempt_positive",
            type_="check",
        )
        batch_op.drop_constraint(
            "fk_tool_executions_job_id_jobs",
            type_="foreignkey",
        )
        batch_op.drop_column("attempt_number")
        batch_op.drop_column("job_id")
