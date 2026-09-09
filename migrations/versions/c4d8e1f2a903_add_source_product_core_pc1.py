"""add Source Product Core PC1 lineage and finding index

Revision ID: c4d8e1f2a903
Revises: b6c3d9e8f120

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c4d8e1f2a903"
down_revision: str | Sequence[str] | None = "b6c3d9e8f120"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "source_target_lineages",
        sa.Column("lineage_id", sa.String(36), nullable=False),
        sa.Column("project_id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("lineage_id"),
    )
    op.create_index(
        "ix_source_target_lineages_project_id",
        "source_target_lineages",
        ["project_id"],
    )
    op.create_table(
        "source_lineage_runs",
        sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column("lineage_id", sa.String(36), nullable=False),
        sa.Column("sequence_number", sa.Integer(), nullable=False),
        sa.Column("predecessor_run_id", sa.String(36), nullable=True),
        sa.Column("predecessor_sequence_number", sa.Integer(), nullable=True),
        sa.Column("report_artifact_sha256", sa.String(64), nullable=False),
        sa.Column("report_artifact_size_bytes", sa.Integer(), nullable=False),
        sa.Column("report_schema_version", sa.String(128), nullable=False),
        sa.Column("indexing_state", sa.String(16), nullable=False),
        sa.Column("indexed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "sequence_number >= 1",
            name="ck_source_lineage_runs_sequence_positive",
        ),
        sa.CheckConstraint(
            "(sequence_number = 1 AND predecessor_run_id IS NULL "
            "AND predecessor_sequence_number IS NULL) OR "
            "(sequence_number > 1 AND predecessor_run_id IS NOT NULL "
            "AND predecessor_sequence_number IS NOT NULL "
            "AND predecessor_sequence_number < sequence_number)",
            name="ck_source_lineage_runs_predecessor_pair",
        ),
        sa.CheckConstraint(
            "indexing_state IN ('ATTACHED', 'INDEXED')",
            name="ck_source_lineage_runs_indexing_state",
        ),
        sa.CheckConstraint(
            "(indexing_state = 'INDEXED') = (indexed_at IS NOT NULL)",
            name="ck_source_lineage_runs_indexed_pair",
        ),
        sa.CheckConstraint(
            "length(report_artifact_sha256) = 64 "
            "AND report_artifact_sha256 = lower(report_artifact_sha256)",
            name="ck_source_lineage_runs_report_sha",
        ),
        sa.CheckConstraint(
            "report_artifact_size_bytes >= 1",
            name="ck_source_lineage_runs_report_size",
        ),
        sa.CheckConstraint(
            "report_schema_version = 'securescan-unified-evidence-s4-v1'",
            name="ck_source_lineage_runs_report_schema",
        ),
        sa.ForeignKeyConstraint(
            ["lineage_id"],
            ["source_target_lineages.lineage_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(["run_id"], ["analysis_runs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["lineage_id", "predecessor_run_id", "predecessor_sequence_number"],
            [
                "source_lineage_runs.lineage_id",
                "source_lineage_runs.run_id",
                "source_lineage_runs.sequence_number",
            ],
            name="fk_source_lineage_runs_predecessor",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("run_id"),
        sa.UniqueConstraint(
            "lineage_id",
            "run_id",
            name="uq_source_lineage_runs_membership",
        ),
        sa.UniqueConstraint(
            "lineage_id",
            "run_id",
            "sequence_number",
            name="uq_source_lineage_runs_ordered_membership",
        ),
        sa.UniqueConstraint(
            "lineage_id",
            "run_id",
            "report_artifact_sha256",
            name="uq_source_lineage_runs_report_membership",
        ),
        sa.UniqueConstraint(
            "lineage_id",
            "sequence_number",
            name="uq_source_lineage_runs_sequence",
        ),
    )
    op.create_table(
        "source_finding_occurrences",
        sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column("finding_id", sa.String(64), nullable=False),
        sa.Column("lineage_id", sa.String(36), nullable=False),
        sa.Column("authority", sa.String(32), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("native_identity_schema", sa.String(512), nullable=False),
        sa.Column("severity", sa.String(32), nullable=True),
        sa.Column("subject_kind", sa.String(64), nullable=False),
        sa.Column("subject_summary_json", sa.JSON(), nullable=False),
        sa.Column("primary_location_json", sa.JSON(), nullable=True),
        sa.Column("report_artifact_sha256", sa.String(64), nullable=False),
        sa.Column("finding_ordinal", sa.Integer(), nullable=False),
        sa.Column("indexed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "finding_ordinal >= 0",
            name="ck_source_finding_occurrences_ordinal",
        ),
        sa.CheckConstraint(
            "length(finding_id) = 64 AND finding_id = lower(finding_id)",
            name="ck_source_finding_occurrences_finding_id",
        ),
        sa.CheckConstraint(
            "length(report_artifact_sha256) = 64 "
            "AND report_artifact_sha256 = lower(report_artifact_sha256)",
            name="ck_source_finding_occurrences_report_sha",
        ),
        sa.CheckConstraint(
            "(authority = 'semgrep-ce' AND category = 'CODE_SECURITY' "
            "AND subject_kind = 'SOURCE_CODE' "
            "AND (severity IS NULL OR severity IN "
            "('HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'))) OR "
            "(authority = 'gitleaks' AND category = 'SECRET_EXPOSURE' "
            "AND subject_kind = 'SECRET_EXPOSURE' AND severity IS NULL) OR "
            "(authority = 'osv.dev' AND category = 'DEPENDENCY_VULNERABILITY' "
            "AND subject_kind = 'PACKAGE' AND severity IS NULL) OR "
            "(authority = 'checkov' AND category = 'CONFIGURATION_SECURITY' "
            "AND subject_kind = 'CONFIGURATION_RESOURCE' "
            "AND (severity IS NULL OR severity IN "
            "('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN')))",
            name="ck_source_finding_occurrences_s4_kind",
        ),
        sa.ForeignKeyConstraint(
            ["lineage_id", "run_id", "report_artifact_sha256"],
            [
                "source_lineage_runs.lineage_id",
                "source_lineage_runs.run_id",
                "source_lineage_runs.report_artifact_sha256",
            ],
            name="fk_source_finding_occurrences_report_membership",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("run_id", "finding_id"),
        sa.UniqueConstraint(
            "run_id",
            "finding_ordinal",
            name="uq_source_finding_occurrences_ordinal",
        ),
    )
    op.create_index(
        "ix_source_finding_occurrences_lineage_authority",
        "source_finding_occurrences",
        ["lineage_id", "authority", "category"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_source_finding_occurrences_lineage_authority",
        table_name="source_finding_occurrences",
    )
    op.drop_table("source_finding_occurrences")
    op.drop_table("source_lineage_runs")
    op.drop_index(
        "ix_source_target_lineages_project_id",
        table_name="source_target_lineages",
    )
    op.drop_table("source_target_lineages")
