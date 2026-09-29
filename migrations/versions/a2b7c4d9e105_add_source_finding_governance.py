"""add Source finding governance core

Revision ID: a2b7c4d9e105
Revises: f7c2d4e8a901
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a2b7c4d9e105"
down_revision: str | Sequence[str] | None = "f7c2d4e8a901"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "source_finding_governance",
        sa.Column("lineage_id", sa.String(36), nullable=False),
        sa.Column("finding_id", sa.String(64), nullable=False),
        sa.Column("disposition", sa.String(32), nullable=False),
        sa.Column("reason", sa.Text()),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("actor_type", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "disposition IN ('UNREVIEWED', 'FALSE_POSITIVE', 'ACCEPTED_RISK')",
            name="ck_source_finding_governance_disposition",
        ),
        sa.CheckConstraint(
            "(disposition = 'UNREVIEWED' AND reason IS NULL AND expires_at IS NULL) OR "
            "(disposition = 'FALSE_POSITIVE' AND reason IS NOT NULL AND expires_at IS NULL) OR "
            "(disposition = 'ACCEPTED_RISK' AND reason IS NOT NULL AND expires_at IS NOT NULL)",
            name="ck_source_finding_governance_material",
        ),
        sa.CheckConstraint(
            "reason IS NULL OR (length(reason) >= 1 AND length(reason) <= 1000)",
            name="ck_source_finding_governance_reason",
        ),
        sa.CheckConstraint("revision >= 1", name="ck_source_finding_governance_revision"),
        sa.CheckConstraint(
            "actor_type = 'LOCAL_OPERATOR'",
            name="ck_source_finding_governance_actor",
        ),
        sa.CheckConstraint(
            "created_at <= updated_at",
            name="ck_source_finding_governance_time_order",
        ),
        sa.ForeignKeyConstraint(
            ["lineage_id", "finding_id"],
            ["source_finding_lifecycles.lineage_id", "source_finding_lifecycles.finding_id"],
            name="fk_source_finding_governance_lifecycle",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("lineage_id", "finding_id"),
    )
    op.create_index(
        "ix_source_finding_governance_lineage_disposition",
        "source_finding_governance",
        ["lineage_id", "disposition"],
    )
    op.create_table(
        "source_finding_governance_events",
        sa.Column("event_id", sa.String(36), nullable=False),
        sa.Column("lineage_id", sa.String(36), nullable=False),
        sa.Column("finding_id", sa.String(64), nullable=False),
        sa.Column("operation", sa.String(16), nullable=False),
        sa.Column("previous_disposition", sa.String(32), nullable=False),
        sa.Column("new_disposition", sa.String(32), nullable=False),
        sa.Column("previous_reason", sa.Text()),
        sa.Column("new_reason", sa.Text()),
        sa.Column("previous_expires_at", sa.DateTime(timezone=True)),
        sa.Column("new_expires_at", sa.DateTime(timezone=True)),
        sa.Column("actor_type", sa.String(32), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resulting_revision", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "operation IN ('SET', 'CLEAR')", name="ck_source_finding_governance_events_operation"
        ),
        sa.CheckConstraint(
            "previous_disposition IN ('UNREVIEWED', 'FALSE_POSITIVE', 'ACCEPTED_RISK')",
            name="ck_source_finding_governance_events_previous",
        ),
        sa.CheckConstraint(
            "new_disposition IN ('UNREVIEWED', 'FALSE_POSITIVE', 'ACCEPTED_RISK')",
            name="ck_source_finding_governance_events_new",
        ),
        sa.CheckConstraint(
            "previous_reason IS NULL OR "
            "(length(previous_reason) >= 1 AND length(previous_reason) <= 1000)",
            name="ck_source_finding_governance_events_previous_reason",
        ),
        sa.CheckConstraint(
            "new_reason IS NULL OR (length(new_reason) >= 1 AND length(new_reason) <= 1000)",
            name="ck_source_finding_governance_events_new_reason",
        ),
        sa.CheckConstraint(
            "resulting_revision >= 1", name="ck_source_finding_governance_events_revision"
        ),
        sa.CheckConstraint(
            "actor_type = 'LOCAL_OPERATOR'", name="ck_source_finding_governance_events_actor"
        ),
        sa.ForeignKeyConstraint(
            ["lineage_id", "finding_id"],
            ["source_finding_lifecycles.lineage_id", "source_finding_lifecycles.finding_id"],
            name="fk_source_finding_governance_events_lifecycle",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("event_id"),
        sa.UniqueConstraint(
            "lineage_id",
            "finding_id",
            "resulting_revision",
            name="uq_source_finding_governance_events_revision",
        ),
    )
    op.create_index(
        "ix_source_finding_governance_events_history",
        "source_finding_governance_events",
        ["lineage_id", "finding_id", "resulting_revision"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_source_finding_governance_events_history", table_name="source_finding_governance_events"
    )
    op.drop_table("source_finding_governance_events")
    op.drop_index(
        "ix_source_finding_governance_lineage_disposition", table_name="source_finding_governance"
    )
    op.drop_table("source_finding_governance")
