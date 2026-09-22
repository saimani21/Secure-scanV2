"""add bounded Source assembly failure state

Revision ID: f7c2d4e8a901
Revises: e6a1c4f9b207

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f7c2d4e8a901"
down_revision: str | Sequence[str] | None = "e6a1c4f9b207"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("source_orchestrations") as batch_op:
        batch_op.add_column(
            sa.Column(
                "assembly_attempt_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            )
        )
        batch_op.add_column(
            sa.Column("assembly_failure_code", sa.String(length=128), nullable=True)
        )
        batch_op.add_column(
            sa.Column("assembly_failure_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.create_check_constraint(
            "ck_source_orchestrations_assembly_attempt_count",
            "assembly_attempt_count >= 0",
        )
        batch_op.create_check_constraint(
            "ck_source_orchestrations_assembly_failure_pair",
            "(assembly_failure_code IS NULL) = (assembly_failure_at IS NULL)",
        )
        batch_op.alter_column("assembly_attempt_count", server_default=None)


def downgrade() -> None:
    with op.batch_alter_table("source_orchestrations") as batch_op:
        batch_op.drop_constraint(
            "ck_source_orchestrations_assembly_failure_pair", type_="check"
        )
        batch_op.drop_constraint(
            "ck_source_orchestrations_assembly_attempt_count", type_="check"
        )
        batch_op.drop_column("assembly_failure_at")
        batch_op.drop_column("assembly_failure_code")
        batch_op.drop_column("assembly_attempt_count")
