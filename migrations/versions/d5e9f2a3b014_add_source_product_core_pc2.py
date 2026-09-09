"""add Source Product Core PC2 lifecycle and priority

Revision ID: d5e9f2a3b014
Revises: c4d8e1f2a903

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d5e9f2a3b014"
down_revision: str | Sequence[str] | None = "c4d8e1f2a903"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("source_lineage_runs") as batch_op:
        batch_op.add_column(sa.Column("lifecycle_evaluated_at", sa.DateTime(timezone=True)))
        batch_op.add_column(sa.Column("lifecycle_evaluation_sha256", sa.String(64)))
        batch_op.add_column(sa.Column("lifecycle_event_count", sa.Integer()))
        batch_op.create_check_constraint(
            "ck_source_lineage_runs_lifecycle_marker",
            "(lifecycle_evaluated_at IS NULL AND lifecycle_evaluation_sha256 IS NULL "
            "AND lifecycle_event_count IS NULL) OR "
            "(lifecycle_evaluated_at IS NOT NULL "
            "AND lifecycle_evaluation_sha256 IS NOT NULL "
            "AND lifecycle_event_count IS NOT NULL)",
        )
        batch_op.create_check_constraint(
            "ck_source_lineage_runs_lifecycle_event_count",
            "lifecycle_event_count IS NULL OR lifecycle_event_count >= 0",
        )
        batch_op.create_check_constraint(
            "ck_source_lineage_runs_lifecycle_sha",
            "lifecycle_evaluation_sha256 IS NULL OR "
            "(length(lifecycle_evaluation_sha256) = 64 "
            "AND lifecycle_evaluation_sha256 = lower(lifecycle_evaluation_sha256))",
        )
    with op.batch_alter_table("source_finding_occurrences") as batch_op:
        batch_op.add_column(sa.Column("priority_band", sa.String(16)))
        batch_op.add_column(sa.Column("priority_reason_codes_json", sa.JSON()))
        batch_op.create_check_constraint(
            "ck_source_finding_occurrences_priority_pair",
            "(priority_band IS NULL AND priority_reason_codes_json IS NULL) OR "
            "(priority_band IN "
            "('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNRANKED') "
            "AND priority_reason_codes_json IS NOT NULL)",
        )
    op.create_table(
        "source_finding_lifecycles",
        sa.Column("lineage_id", sa.String(36), nullable=False),
        sa.Column("finding_id", sa.String(64), nullable=False),
        sa.Column("authority", sa.String(32), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("native_identity_schema", sa.String(512), nullable=False),
        sa.Column("current_state", sa.String(16), nullable=False),
        sa.Column("first_seen_run_id", sa.String(36), nullable=False),
        sa.Column("last_seen_run_id", sa.String(36), nullable=False),
        sa.Column("resolved_run_id", sa.String(36)),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.Column("transition_version", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "current_state IN ('NEW', 'EXISTING', 'RESOLVED', 'REOPENED')",
            name="ck_source_finding_lifecycles_state",
        ),
        sa.CheckConstraint(
            "transition_version >= 1",
            name="ck_source_finding_lifecycles_version",
        ),
        sa.CheckConstraint(
            "(current_state = 'RESOLVED') = "
            "(resolved_run_id IS NOT NULL AND resolved_at IS NOT NULL)",
            name="ck_source_finding_lifecycles_resolved_pair",
        ),
        sa.CheckConstraint(
            "first_seen_at <= last_seen_at",
            name="ck_source_finding_lifecycles_seen_order",
        ),
        sa.CheckConstraint(
            "resolved_at IS NULL OR last_seen_at <= resolved_at",
            name="ck_source_finding_lifecycles_resolved_order",
        ),
        sa.ForeignKeyConstraint(
            ["lineage_id"],
            ["source_target_lineages.lineage_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["lineage_id", "first_seen_run_id"],
            ["source_lineage_runs.lineage_id", "source_lineage_runs.run_id"],
            name="fk_source_finding_lifecycles_first_run",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["lineage_id", "last_seen_run_id"],
            ["source_lineage_runs.lineage_id", "source_lineage_runs.run_id"],
            name="fk_source_finding_lifecycles_last_run",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["lineage_id", "resolved_run_id"],
            ["source_lineage_runs.lineage_id", "source_lineage_runs.run_id"],
            name="fk_source_finding_lifecycles_resolved_run",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("lineage_id", "finding_id"),
    )
    op.create_index(
        "ix_source_finding_lifecycles_lineage_state",
        "source_finding_lifecycles",
        ["lineage_id", "current_state"],
    )
    op.create_table(
        "source_finding_lifecycle_events",
        sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column("finding_id", sa.String(64), nullable=False),
        sa.Column("lineage_id", sa.String(36), nullable=False),
        sa.Column("event_kind", sa.String(32), nullable=False),
        sa.Column("previous_state", sa.String(16)),
        sa.Column("resulting_state", sa.String(16), nullable=False),
        sa.Column("reason_codes_json", sa.JSON(), nullable=False),
        sa.Column("transition_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "event_kind IN ('TRANSITION', 'RESOLUTION_WITHHELD')",
            name="ck_source_finding_lifecycle_events_kind",
        ),
        sa.CheckConstraint(
            "previous_state IS NULL OR previous_state IN "
            "('NEW', 'EXISTING', 'RESOLVED', 'REOPENED')",
            name="ck_source_finding_lifecycle_events_previous_state",
        ),
        sa.CheckConstraint(
            "resulting_state IN ('NEW', 'EXISTING', 'RESOLVED', 'REOPENED')",
            name="ck_source_finding_lifecycle_events_resulting_state",
        ),
        sa.CheckConstraint(
            "transition_version >= 1",
            name="ck_source_finding_lifecycle_events_version",
        ),
        sa.CheckConstraint(
            "event_kind = 'TRANSITION' OR "
            "(previous_state IS NOT NULL AND previous_state = resulting_state)",
            name="ck_source_finding_lifecycle_events_withheld_state",
        ),
        sa.ForeignKeyConstraint(
            ["lineage_id", "run_id"],
            ["source_lineage_runs.lineage_id", "source_lineage_runs.run_id"],
            name="fk_source_finding_lifecycle_events_run",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["lineage_id", "finding_id"],
            ["source_finding_lifecycles.lineage_id", "source_finding_lifecycles.finding_id"],
            name="fk_source_finding_lifecycle_events_finding",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("run_id", "finding_id"),
    )
    op.create_index(
        "ix_source_finding_lifecycle_events_lineage_run",
        "source_finding_lifecycle_events",
        ["lineage_id", "run_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_source_finding_lifecycle_events_lineage_run",
        table_name="source_finding_lifecycle_events",
    )
    op.drop_table("source_finding_lifecycle_events")
    op.drop_index(
        "ix_source_finding_lifecycles_lineage_state",
        table_name="source_finding_lifecycles",
    )
    op.drop_table("source_finding_lifecycles")
    with op.batch_alter_table("source_finding_occurrences") as batch_op:
        batch_op.drop_constraint(
            "ck_source_finding_occurrences_priority_pair", type_="check"
        )
        batch_op.drop_column("priority_reason_codes_json")
        batch_op.drop_column("priority_band")
    with op.batch_alter_table("source_lineage_runs") as batch_op:
        batch_op.drop_constraint(
            "ck_source_lineage_runs_lifecycle_event_count", type_="check"
        )
        batch_op.drop_constraint(
            "ck_source_lineage_runs_lifecycle_sha", type_="check"
        )
        batch_op.drop_constraint(
            "ck_source_lineage_runs_lifecycle_marker", type_="check"
        )
        batch_op.drop_column("lifecycle_event_count")
        batch_op.drop_column("lifecycle_evaluation_sha256")
        batch_op.drop_column("lifecycle_evaluated_at")
