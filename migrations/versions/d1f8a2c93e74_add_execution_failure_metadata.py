"""add execution failure metadata

Revision ID: d1f8a2c93e74
Revises: b7e4c9a12f63

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d1f8a2c93e74"
down_revision: str | Sequence[str] | None = "b7e4c9a12f63"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

FAILURE_CATEGORY_SQL = ", ".join(
    [
        "'retryable_infrastructure'",
        "'non_retryable_input'",
        "'non_retryable_parser'",
        "'non_retryable_policy'",
        "'timeout'",
        "'output_limit'",
        "'worker_crash'",
        "'cancelled'",
    ]
)


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("tool_executions") as batch_op:
        batch_op.add_column(
            sa.Column(
                "failure_category",
                sa.String(length=64),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "retryable",
                sa.Boolean(),
                nullable=True,
            )
        )
        batch_op.create_check_constraint(
            "ck_tool_executions_failure_category",
            f"failure_category IS NULL OR failure_category IN ({FAILURE_CATEGORY_SQL})",
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("tool_executions") as batch_op:
        batch_op.drop_constraint(
            "ck_tool_executions_failure_category",
            type_="check",
        )
        batch_op.drop_column("retryable")
        batch_op.drop_column("failure_category")
