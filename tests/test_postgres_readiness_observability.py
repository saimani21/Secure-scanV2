from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from securescan.api.main import app
from securescan.config import get_settings
from securescan.domain.enums import (
    ExecutionOutcome,
    JobFailureCategory,
    JobStatus,
    RunStatus,
    TargetType,
)
from securescan.jobs import JobSubmissionRequest, JobSubmissionService
from securescan.observability.metrics import OperationalMetricsService
from securescan.observability.readiness import DatabaseReadinessService, ReadinessReason
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    ProjectRow,
    TargetRow,
    ToolExecutionRow,
    create_session_factory,
)

pytestmark = pytest.mark.postgres

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI_PATH = REPOSITORY_ROOT / "alembic.ini"
MIGRATIONS_PATH = REPOSITORY_ROOT / "migrations"
GENERATED_AT = datetime(2053, 2, 3, 4, 5, 6, tzinfo=UTC)


def _validated_test_database_url() -> str:
    database_url = os.environ.get("SECURESCAN_TEST_POSTGRES_URL")
    if database_url is None:
        pytest.skip(
            "SECURESCAN_TEST_POSTGRES_URL is not configured; "
            "skipping PostgreSQL readiness observability test"
        )
    try:
        parsed_url = make_url(database_url)
    except ArgumentError as exc:
        pytest.fail(f"Unsafe SECURESCAN_TEST_POSTGRES_URL: URL could not be parsed: {exc}")
    if not parsed_url.get_backend_name().startswith("postgresql"):
        pytest.fail("Unsafe SECURESCAN_TEST_POSTGRES_URL: backend must be PostgreSQL")
    if not parsed_url.database:
        pytest.fail("Unsafe SECURESCAN_TEST_POSTGRES_URL: database name is required")
    if not parsed_url.database.endswith("_test"):
        pytest.fail("Unsafe SECURESCAN_TEST_POSTGRES_URL: database name must end with _test")
    return database_url


def _reset_public_schema(database_url: str) -> None:
    engine = create_engine(database_url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
    finally:
        engine.dispose()


def _alembic_config() -> Config:
    config = Config(str(ALEMBIC_INI_PATH))
    config.set_main_option("script_location", str(MIGRATIONS_PATH))
    return config


@pytest.fixture
def postgres_observability_database(
    monkeypatch: pytest.MonkeyPatch,
    initialized_api_runtime_storage: None,
) -> Iterator[str]:
    database_url = _validated_test_database_url()
    monkeypatch.setenv("SECURESCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("SECURESCAN_ALLOW_SQLITE_SCHEMA_BOOTSTRAP", "true")
    get_settings.cache_clear()
    try:
        _reset_public_schema(database_url)
        yield database_url
    finally:
        try:
            _reset_public_schema(database_url)
        finally:
            get_settings.cache_clear()


def test_postgres_empty_schema_is_unready_and_startup_does_not_create_tables(
    postgres_observability_database: str,
) -> None:
    with TestClient(app) as client:
        response = client.get("/health/ready")

    inspection_engine = create_engine(postgres_observability_database)
    try:
        tables = set(inspect(inspection_engine).get_table_names())
    finally:
        inspection_engine.dispose()

    assert response.status_code == 503
    assert response.json()["reason"] == ReadinessReason.SCHEMA_UNVERSIONED.value
    assert response.json()["database_reachable"] is True
    assert tables == set()


def test_postgres_migrated_schema_is_ready(
    postgres_observability_database: str,
) -> None:
    command.upgrade(_alembic_config(), "head")
    engine = create_engine(postgres_observability_database)
    try:
        snapshot = DatabaseReadinessService(engine, ALEMBIC_INI_PATH).check()
    finally:
        engine.dispose()

    assert snapshot.ready is True
    assert snapshot.schema_at_head is True
    assert snapshot.reason is ReadinessReason.READY
    assert snapshot.checked_at.utcoffset() == timedelta(0)


def test_postgres_operational_metrics_match_real_job_states(
    postgres_observability_database: str,
) -> None:
    command.upgrade(_alembic_config(), "head")
    engine, factory = create_session_factory(get_settings())
    try:
        with factory.begin() as session:
            project = ProjectRow(name="PostgreSQL observability")
            target = TargetRow(
                project=project,
                target_type=TargetType.SOURCE_REPOSITORY.value,
                content_digest="d" * 64,
                source_path="/tmp/postgres-observability",
            )
            session.add(target)
            session.flush()
            target_id = target.id

        submission_service = JobSubmissionService(factory)
        first = submission_service.submit(
            JobSubmissionRequest(
                target_id=target_id,
                adapter_id="scanner",
                idempotency_key="1" * 64,
            )
        )
        second = submission_service.submit(
            JobSubmissionRequest(
                target_id=target_id,
                adapter_id="scanner",
                idempotency_key="2" * 64,
            )
        )

        with factory.begin() as session:
            first_job = session.get(JobRow, first.job_id)
            first_run = session.get(AnalysisRunRow, first.run_id)
            second_job = session.get(JobRow, second.job_id)
            second_run = session.get(AnalysisRunRow, second.run_id)
            assert first_job is not None
            assert first_run is not None
            assert second_job is not None
            assert second_run is not None

            first_job.status = JobStatus.LEASED.value
            first_job.leased_by = "worker-private"
            first_job.lease_token = str(uuid4())
            first_job.lease_expires_at = GENERATED_AT - timedelta(seconds=1)
            first_job.cancel_requested = True
            first_run.status = RunStatus.RUNNING.value

            second_job.status = JobStatus.FAILED.value
            second_job.finished_at = GENERATED_AT
            second_run.status = RunStatus.FAILED.value

            session.add_all(
                [
                    ToolExecutionRow(
                        run_id=first.run_id,
                        job_id=first.job_id,
                        attempt_number=1,
                        adapter_id="scanner",
                        tool_version="1",
                        adapter_version="1",
                        outcome=ExecutionOutcome.TIMEOUT.value,
                        duration_ms=10,
                        failure_category=JobFailureCategory.TIMEOUT.value,
                        retryable=True,
                    ),
                    ToolExecutionRow(
                        run_id=second.run_id,
                        job_id=second.job_id,
                        attempt_number=1,
                        adapter_id="scanner",
                        tool_version="1",
                        adapter_version="1",
                        outcome=ExecutionOutcome.INVALID_OUTPUT.value,
                        duration_ms=20,
                        failure_category=JobFailureCategory.NON_RETRYABLE_PARSER.value,
                        retryable=False,
                    ),
                ]
            )

        snapshot = OperationalMetricsService(
            factory,
            clock=lambda: GENERATED_AT,
        ).collect()

        assert snapshot.total_runs == 2
        assert snapshot.active_runs == 1
        assert snapshot.total_jobs == 2
        assert snapshot.leased_jobs == 1
        assert snapshot.failed_jobs == 1
        assert snapshot.expired_active_leases == 1
        assert snapshot.cancellation_requested_jobs == 1
        assert snapshot.total_tool_executions == 2
        assert snapshot.retryable_tool_failures == 1
        assert snapshot.permanent_tool_failures == 1
        assert snapshot.average_execution_duration_ms == 15.0
        assert snapshot.maximum_execution_duration_ms == 20
        assert snapshot.generated_at == GENERATED_AT
        assert snapshot.generated_at.utcoffset() == timedelta(0)
    finally:
        engine.dispose()
