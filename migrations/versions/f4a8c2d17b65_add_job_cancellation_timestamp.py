"""Add job cancellation timestamp.

Revision ID: f4a8c2d17b65
Revises: d1f8a2c93e74
Create Date: 2026-07-24

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f4a8c2d17b65"
down_revision: str | None = "d1f8a2c93e74"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("jobs") as batch_op:
        batch_op.add_column(
            sa.Column(
                "cancel_requested_at",
                sa.DateTime(timezone=True),
                nullable=True,
            )
        )
        batch_op.create_check_constraint(
            "ck_jobs_cancel_timestamp_requires_flag",
            "cancel_requested_at IS NULL OR cancel_requested = true",
        )
        batch_op.create_index(
            "ix_jobs_cancel_reap",
            ["cancel_requested", "status", "lease_expires_at"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("jobs") as batch_op:
        batch_op.drop_index("ix_jobs_cancel_reap")
        batch_op.drop_constraint(
            "ck_jobs_cancel_timestamp_requires_flag",
            type_="check",
        )
        batch_op.drop_column("cancel_requested_at")
