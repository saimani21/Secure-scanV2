from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import Boolean, DateTime, Integer, String, create_engine, inspect

from securescan.config import get_settings

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI_PATH = REPOSITORY_ROOT / "alembic.ini"
MIGRATIONS_PATH = REPOSITORY_ROOT / "migrations"
HEAD_REVISION = "a8d4e6f2c1b7"

APPLICATION_TABLES = {
    "projects",
    "targets",
    "analysis_runs",
    "jobs",
    "tool_executions",
    "source_orchestrations",
    "source_orchestration_authorities",
    "source_orchestration_nodes",
    "source_orchestration_dependencies",
    "source_orchestration_scanner_jobs",
    "source_orchestration_attempts",
    "source_orchestration_dependency_evaluations",
}
EXPECTED_TABLES = APPLICATION_TABLES | {"alembic_version"}
EXPECTED_JOB_CHECK_CONSTRAINTS = {
    "ck_jobs_priority_nonnegative",
    "ck_jobs_attempt_count_nonnegative",
    "ck_jobs_max_attempts_positive",
    "ck_jobs_attempt_count_within_limit",
    "ck_jobs_status",
    "ck_jobs_cancel_timestamp_requires_flag",
}
EXPECTED_JOB_INDEXES = {
    "ix_jobs_claim",
    "ix_jobs_cancel_reap",
    "ix_jobs_run_id",
}
EXPECTED_ORCHESTRATION_TABLES = {
    "source_orchestrations",
    "source_orchestration_authorities",
    "source_orchestration_nodes",
    "source_orchestration_dependencies",
    "source_orchestration_scanner_jobs",
    "source_orchestration_attempts",
    "source_orchestration_dependency_evaluations",
}


def _assert_lease_token_column(database_inspector) -> None:
    columns = {column["name"]: column for column in database_inspector.get_columns("jobs")}
    lease_token = columns["lease_token"]
    assert isinstance(lease_token["type"], String)
    assert lease_token["type"].length == 36
    assert lease_token["nullable"] is True


def _assert_cancellation_timestamp_column(database_inspector) -> None:
    columns = {column["name"]: column for column in database_inspector.get_columns("jobs")}
    cancel_requested_at = columns["cancel_requested_at"]
    assert isinstance(cancel_requested_at["type"], DateTime)
    assert cancel_requested_at["nullable"] is True


def _assert_tool_execution_attempt_identity(database_inspector) -> None:
    columns = {
        column["name"]: column for column in database_inspector.get_columns("tool_executions")
    }
    assert {
        "id",
        "run_id",
        "job_id",
        "attempt_number",
        "adapter_id",
        "tool_version",
        "adapter_version",
        "outcome",
        "exit_code",
        "duration_ms",
        "warning_json",
        "error",
        "failure_category",
        "retryable",
    } <= columns.keys()
    assert isinstance(columns["job_id"]["type"], String)
    assert columns["job_id"]["type"].length == 36
    assert columns["job_id"]["nullable"] is True
    assert isinstance(columns["attempt_number"]["type"], Integer)
    assert columns["attempt_number"]["nullable"] is True
    assert isinstance(columns["failure_category"]["type"], String)
    assert columns["failure_category"]["type"].length == 64
    assert columns["failure_category"]["nullable"] is True
    assert isinstance(columns["retryable"]["type"], Boolean)
    assert columns["retryable"]["nullable"] is True

    foreign_keys = {
        foreign_key["name"]: foreign_key
        for foreign_key in database_inspector.get_foreign_keys("tool_executions")
    }
    job_foreign_key = foreign_keys["fk_tool_executions_job_id_jobs"]
    assert job_foreign_key["constrained_columns"] == ["job_id"]
    assert job_foreign_key["referred_table"] == "jobs"
    assert job_foreign_key["referred_columns"] == ["id"]
    assert job_foreign_key.get("options", {}).get("ondelete") == "CASCADE"

    checks = {
        constraint["name"]
        for constraint in database_inspector.get_check_constraints("tool_executions")
    }
    assert "ck_tool_executions_attempt_positive" in checks
    assert "ck_tool_executions_failure_category" in checks
    unique_constraints = {
        constraint["name"]
        for constraint in database_inspector.get_unique_constraints("tool_executions")
    }
    assert "uq_tool_executions_job_attempt" in unique_constraints
    indexes = {index["name"] for index in database_inspector.get_indexes("tool_executions")}
    assert indexes >= {"ix_tool_executions_job_id", "ix_tool_executions_run_id"}


def _assert_source_orchestration_schema(database_inspector) -> None:
    assert set(database_inspector.get_table_names()) >= EXPECTED_ORCHESTRATION_TABLES
    parent_columns = {
        column["name"] for column in database_inspector.get_columns("source_orchestrations")
    }
    assert parent_columns == {
        "run_id",
        "idempotency_key",
        "creation_request_digest",
        "repository_digest",
        "profile_digest",
        "plan_digest",
        "roster_digest",
        "planning_snapshot_sha256",
        "snapshot_size_bytes",
        "snapshot_media_type",
        "snapshot_schema_version",
        "snapshot_storage_path",
        "lifecycle_state",
        "terminal_outcome",
        "cancel_requested",
        "cancel_requested_at",
        "state_version",
        "deadline_at",
        "created_at",
        "updated_at",
    }
    assert {column["name"] for column in database_inspector.get_columns("jobs")} == {
        "id",
        "run_id",
        "adapter_id",
        "status",
        "priority",
        "attempt_count",
        "max_attempts",
        "available_at",
        "leased_by",
        "lease_token",
        "lease_expires_at",
        "heartbeat_at",
        "cancel_requested",
        "cancel_requested_at",
        "created_at",
        "updated_at",
        "started_at",
        "finished_at",
        "idempotency_key",
        "payload_json",
        "last_error",
    }
    scanner_job_columns = {
        column["name"]
        for column in database_inspector.get_columns("source_orchestration_scanner_jobs")
    }
    assert {
        "job_id",
        "run_id",
        "node_id",
        "authority",
        "capability",
        "analyzer_id",
        "contract_digest",
        "context_digest",
        "projection_id",
        "projection_digest",
        "selected_attempt_number",
    } <= scanner_job_columns
    attempt_columns = {
        column["name"] for column in database_inspector.get_columns("source_orchestration_attempts")
    }
    assert {
        "job_id",
        "attempt_number",
        "attempt_token",
        "containment_state",
        "acceptance_state",
        "cleanup_receipt_sha256",
        "tool_execution_id",
        "native_result_sha256",
        "projection_revalidated",
    } <= attempt_columns
    node_columns = {
        column["name"]: column
        for column in database_inspector.get_columns("source_orchestration_nodes")
    }
    assert "terminal_reason_code" in node_columns
    assert isinstance(node_columns["terminal_reason_code"]["type"], String)
    assert node_columns["terminal_reason_code"]["type"].length == 128
    assert node_columns["terminal_reason_code"]["nullable"] is True
    node_checks = {
        item["name"]
        for item in database_inspector.get_check_constraints("source_orchestration_nodes")
    }
    assert "ck_source_node_terminal_reason" in node_checks
    evaluation_columns = {
        column["name"]
        for column in database_inspector.get_columns("source_orchestration_dependency_evaluations")
    }
    assert evaluation_columns == {
        "run_id",
        "osv_node_id",
        "syft_node_id",
        "syft_job_id",
        "syft_selected_attempt_number",
        "syft_native_result_sha256",
        "scope_digest",
        "evaluation_artifact_sha256",
        "evaluation_artifact_size_bytes",
        "evaluation_artifact_media_type",
        "evaluation_schema_version",
        "created_at",
    }
    assert database_inspector.get_pk_constraint("source_orchestration_dependency_evaluations")[
        "constrained_columns"
    ] == ["run_id", "osv_node_id"]
    evaluation_foreign_keys = {
        item["name"]
        for item in database_inspector.get_foreign_keys(
            "source_orchestration_dependency_evaluations"
        )
    }
    assert evaluation_foreign_keys >= {
        "fk_source_dependency_evaluation_osv_node",
        "fk_source_dependency_evaluation_syft_node",
        "fk_source_dependency_evaluation_syft_job",
        "fk_source_dependency_evaluation_syft_attempt",
    }
    scanner_job_uniques = {
        item["name"]
        for item in database_inspector.get_unique_constraints("source_orchestration_scanner_jobs")
    }
    assert "uq_source_scanner_job_dependency_identity" in scanner_job_uniques
    assert "source_authority_results" not in database_inspector.get_table_names()


@pytest.fixture
def migration_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[Config, str]]:
    database_path = tmp_path / "migrations.db"
    database_url = f"sqlite:///{database_path}"

    monkeypatch.setenv("SECURESCAN_DATABASE_URL", database_url)
    get_settings.cache_clear()

    config = Config(str(ALEMBIC_INI_PATH))
    config.set_main_option("script_location", str(MIGRATIONS_PATH))

    try:
        yield config, database_url
    finally:
        get_settings.cache_clear()


def test_initial_migration_upgrade_creates_expected_schema(
    migration_environment: tuple[Config, str],
) -> None:
    config, database_url = migration_environment

    command.upgrade(config, "head")

    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)

        assert set(inspector.get_table_names()) == EXPECTED_TABLES
        _assert_lease_token_column(inspector)
        _assert_cancellation_timestamp_column(inspector)
        _assert_tool_execution_attempt_identity(inspector)
        _assert_source_orchestration_schema(inspector)

        job_check_constraints = {
            constraint["name"] for constraint in inspector.get_check_constraints("jobs")
        }
        assert job_check_constraints >= EXPECTED_JOB_CHECK_CONSTRAINTS

        job_unique_constraints = {
            constraint["name"] for constraint in inspector.get_unique_constraints("jobs")
        }
        assert "uq_jobs_idempotency_key" in job_unique_constraints

        job_indexes = {index["name"] for index in inspector.get_indexes("jobs")}
        assert job_indexes >= EXPECTED_JOB_INDEXES
    finally:
        engine.dispose()


def test_initial_migration_has_no_pending_model_changes(
    migration_environment: tuple[Config, str],
) -> None:
    config, _ = migration_environment

    command.upgrade(config, "head")
    command.check(config)


def test_initial_migration_downgrade_and_reupgrade_round_trip(
    migration_environment: tuple[Config, str],
) -> None:
    config, database_url = migration_environment
    engine = create_engine(database_url)

    try:
        command.upgrade(config, "head")
        inspector = inspect(engine)
        assert set(inspector.get_table_names()) == EXPECTED_TABLES
        _assert_lease_token_column(inspector)
        _assert_cancellation_timestamp_column(inspector)
        _assert_tool_execution_attempt_identity(inspector)
        _assert_source_orchestration_schema(inspector)
        command.check(config)

        command.downgrade(config, "base")
        remaining_tables = set(inspect(engine).get_table_names())
        assert remaining_tables <= {"alembic_version"}
        assert remaining_tables.isdisjoint(APPLICATION_TABLES)

        command.upgrade(config, "head")
        inspector = inspect(engine)
        assert set(inspector.get_table_names()) == EXPECTED_TABLES
        _assert_lease_token_column(inspector)
        _assert_cancellation_timestamp_column(inspector)
        _assert_tool_execution_attempt_identity(inspector)
        _assert_source_orchestration_schema(inspector)
        command.check(config)

        with engine.connect() as connection:
            migration_context = MigrationContext.configure(connection)
            assert migration_context.get_current_revision() == HEAD_REVISION
    finally:
        engine.dispose()
