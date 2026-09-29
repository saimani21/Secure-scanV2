from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import Boolean, DateTime, Integer, String, create_engine, inspect, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import ArgumentError

from securescan.config import get_settings

pytestmark = pytest.mark.postgres

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI_PATH = REPOSITORY_ROOT / "alembic.ini"
MIGRATIONS_PATH = REPOSITORY_ROOT / "migrations"
V11_HEAD_REVISION = "f7c2d4e8a901"
HEAD_REVISION = "a2b7c4d9e105"

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
    "source_osv_request_permits",
    "source_target_lineages",
    "source_lineage_runs",
    "source_finding_occurrences",
    "source_finding_lifecycles",
    "source_finding_lifecycle_events",
    "source_scan_submissions",
    "source_finding_governance",
    "source_finding_governance_events",
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


def _assert_lease_token_column(database_inspector) -> None:
    columns = {
        column["name"]: column for column in database_inspector.get_columns("jobs")
    }
    lease_token = columns["lease_token"]
    assert isinstance(lease_token["type"], String)
    assert lease_token["type"].length == 36
    assert lease_token["nullable"] is True


def _assert_cancellation_timestamp_column(database_inspector) -> None:
    columns = {
        column["name"]: column for column in database_inspector.get_columns("jobs")
    }
    cancel_requested_at = columns["cancel_requested_at"]
    assert isinstance(cancel_requested_at["type"], DateTime)
    assert cancel_requested_at["type"].timezone is True
    assert cancel_requested_at["nullable"] is True


def _assert_tool_execution_attempt_identity(database_inspector) -> None:
    columns = {
        column["name"]: column
        for column in database_inspector.get_columns("tool_executions")
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
    indexes = {
        index["name"] for index in database_inspector.get_indexes("tool_executions")
    }
    assert indexes >= {"ix_tool_executions_job_id", "ix_tool_executions_run_id"}


def _assert_governance_schema(database_inspector) -> None:
    current_columns = {
        item["name"]: item for item in database_inspector.get_columns("source_finding_governance")
    }
    assert set(current_columns) == {
        "lineage_id",
        "finding_id",
        "disposition",
        "reason",
        "expires_at",
        "revision",
        "actor_type",
        "created_at",
        "updated_at",
    }
    current_checks = {
        item["name"]
        for item in database_inspector.get_check_constraints("source_finding_governance")
    }
    assert current_checks >= {
        "ck_source_finding_governance_disposition",
        "ck_source_finding_governance_material",
        "ck_source_finding_governance_reason",
        "ck_source_finding_governance_revision",
        "ck_source_finding_governance_actor",
        "ck_source_finding_governance_time_order",
    }
    event_columns = {
        item["name"] for item in database_inspector.get_columns("source_finding_governance_events")
    }
    assert event_columns == {
        "event_id",
        "lineage_id",
        "finding_id",
        "operation",
        "previous_disposition",
        "new_disposition",
        "previous_reason",
        "new_reason",
        "previous_expires_at",
        "new_expires_at",
        "actor_type",
        "occurred_at",
        "resulting_revision",
    }
    event_uniques = {
        item["name"]
        for item in database_inspector.get_unique_constraints("source_finding_governance_events")
    }
    assert "uq_source_finding_governance_events_revision" in event_uniques


def _validated_test_database_url() -> str:
    database_url = os.environ.get("SECURESCAN_TEST_POSTGRES_URL")
    if database_url is None:
        pytest.skip(
            "SECURESCAN_TEST_POSTGRES_URL is not configured; "
            "skipping PostgreSQL migration integration test"
        )

    try:
        parsed_url = make_url(database_url)
    except ArgumentError as exc:
        pytest.fail(f"Unsafe SECURESCAN_TEST_POSTGRES_URL: URL could not be parsed: {exc}")

    backend_name = parsed_url.get_backend_name()
    if not backend_name.startswith("postgresql"):
        pytest.fail("Unsafe SECURESCAN_TEST_POSTGRES_URL: backend must be PostgreSQL")

    database_name = parsed_url.database
    if not database_name:
        pytest.fail("Unsafe SECURESCAN_TEST_POSTGRES_URL: database name is required")

    if not database_name.endswith("_test"):
        pytest.fail("Unsafe SECURESCAN_TEST_POSTGRES_URL: database name must end with _test")

    return database_url


def _reset_public_schema(database_url: str) -> None:
    engine = create_engine(
        database_url,
        isolation_level="AUTOCOMMIT",
    )
    try:
        with engine.connect() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
    finally:
        engine.dispose()


def _current_revision(engine: Engine) -> str | None:
    with engine.connect() as connection:
        migration_context = MigrationContext.configure(connection)
        return migration_context.get_current_revision()


@pytest.fixture
def postgres_migration_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[Config, str]]:
    database_url = _validated_test_database_url()

    config = Config(str(ALEMBIC_INI_PATH))
    config.set_main_option("script_location", str(MIGRATIONS_PATH))

    monkeypatch.setenv("SECURESCAN_DATABASE_URL", database_url)
    get_settings.cache_clear()

    try:
        _reset_public_schema(database_url)
        yield config, database_url
    finally:
        try:
            _reset_public_schema(database_url)
        finally:
            get_settings.cache_clear()


def test_postgres_migration_round_trip_and_schema_contract(
    postgres_migration_environment: tuple[Config, str],
) -> None:
    config, database_url = postgres_migration_environment
    engine = create_engine(database_url)

    try:
        assert engine.dialect.name == "postgresql"

        command.upgrade(config, "head")
        command.check(config)

        assert _current_revision(engine) == HEAD_REVISION
        assert set(inspect(engine).get_table_names()) == EXPECTED_TABLES

        inspector = inspect(engine)
        parent_columns = {
            column["name"]: column
            for column in inspector.get_columns("source_orchestrations")
        }
        assert isinstance(parent_columns["max_active_jobs"]["type"], Integer)
        assert parent_columns["max_active_jobs"]["nullable"] is False
        assert isinstance(parent_columns["assembly_attempt_count"]["type"], Integer)
        assert parent_columns["assembly_attempt_count"]["nullable"] is False
        assert isinstance(parent_columns["assembly_failure_code"]["type"], String)
        assert parent_columns["assembly_failure_code"]["type"].length == 128
        assert parent_columns["assembly_failure_code"]["nullable"] is True
        assert isinstance(parent_columns["assembly_failure_at"]["type"], DateTime)
        orchestration_checks = {
            constraint["name"]
            for constraint in inspector.get_check_constraints(
                "source_orchestrations"
            )
        }
        assert orchestration_checks >= {
            "ck_source_orchestrations_max_active_jobs",
            "ck_source_orchestrations_assembly_attempt_count",
            "ck_source_orchestrations_assembly_failure_pair",
        }
        _assert_lease_token_column(inspector)
        _assert_cancellation_timestamp_column(inspector)
        _assert_tool_execution_attempt_identity(inspector)
        _assert_governance_schema(inspector)
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
        _assert_governance_schema(inspector)
        assert _current_revision(engine) == HEAD_REVISION
        command.check(config)
    finally:
        engine.dispose()


def test_postgres_upgrade_from_v11_head_preserves_existing_data(
    postgres_migration_environment: tuple[Config, str],
) -> None:
    config, database_url = postgres_migration_environment
    engine = create_engine(database_url)
    project_id = "11111111-1111-4111-8111-111111111111"
    try:
        command.upgrade(config, V11_HEAD_REVISION)
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO projects (id, name, created_at) VALUES (:id, :name, :created_at)"
                ),
                {
                    "id": project_id,
                    "name": "v11-upgrade-proof",
                    "created_at": "2026-09-29T00:00:00+00:00",
                },
            )
        command.upgrade(config, "head")
        with engine.connect() as connection:
            assert (
                connection.scalar(
                    text("SELECT name FROM projects WHERE id = :id"),
                    {"id": project_id},
                )
                == "v11-upgrade-proof"
            )
        inspector = inspect(engine)
        _assert_governance_schema(inspector)
        assert _current_revision(engine) == HEAD_REVISION
    finally:
        engine.dispose()
