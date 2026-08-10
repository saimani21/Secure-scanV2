from __future__ import annotations

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.orm import Session, sessionmaker

from securescan.config import get_settings
from securescan.domain.enums import JobStatus, TargetType
from securescan.jobs import (
    JobExecutionService,
    JobLeaseTokenMismatchError,
    JobLeasingService,
    JobRecord,
    JobStateConflictError,
    JobSubmissionRequest,
    JobSubmissionService,
)
from securescan.persistence.database import (
    JobRow,
    ProjectRow,
    TargetRow,
    create_session_factory,
)

pytestmark = pytest.mark.postgres

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI_PATH = REPOSITORY_ROOT / "alembic.ini"
MIGRATIONS_PATH = REPOSITORY_ROOT / "migrations"


@dataclass(frozen=True, slots=True)
class _PostgresExecutionContext:
    session_factory: sessionmaker[Session]
    target_id: str


def _validated_test_database_url() -> str:
    database_url = os.environ.get("SECURESCAN_TEST_POSTGRES_URL")
    if database_url is None:
        pytest.skip(
            "SECURESCAN_TEST_POSTGRES_URL is not configured; "
            "skipping PostgreSQL job execution integration test"
        )

    try:
        parsed_url = make_url(database_url)
    except ArgumentError as exc:
        pytest.fail(f"Unsafe SECURESCAN_TEST_POSTGRES_URL: URL could not be parsed: {exc}")

    if not parsed_url.get_backend_name().startswith("postgresql"):
        pytest.fail("Unsafe SECURESCAN_TEST_POSTGRES_URL: backend must be PostgreSQL")

    database_name = parsed_url.database
    if not database_name:
        pytest.fail("Unsafe SECURESCAN_TEST_POSTGRES_URL: database name is required")
    if not database_name.endswith("_test"):
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


@pytest.fixture
def postgres_execution_context(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_PostgresExecutionContext]:
    database_url = _validated_test_database_url()
    alembic_config = Config(str(ALEMBIC_INI_PATH))
    alembic_config.set_main_option("script_location", str(MIGRATIONS_PATH))

    monkeypatch.setenv("SECURESCAN_DATABASE_URL", database_url)
    get_settings.cache_clear()
    engine: Engine | None = None

    try:
        _reset_public_schema(database_url)
        command.upgrade(alembic_config, "head")

        settings = get_settings()
        engine, session_factory = create_session_factory(settings)
        with session_factory.begin() as session:
            project = ProjectRow(name="PostgreSQL job execution test")
            target = TargetRow(
                project=project,
                target_type=TargetType.SOURCE_REPOSITORY.value,
                content_digest="4" * 64,
                source_path="/tmp/postgres-job-execution-target",
            )
            session.add(target)
            session.flush()
            target_id = target.id

        yield _PostgresExecutionContext(
            session_factory=session_factory,
            target_id=target_id,
        )
    finally:
        if engine is not None:
            engine.dispose()
        try:
            _reset_public_schema(database_url)
        finally:
            get_settings.cache_clear()


def _submit_job(
    context: _PostgresExecutionContext,
    idempotency_key: str,
) -> str:
    result = JobSubmissionService(context.session_factory).submit(
        JobSubmissionRequest(
            target_id=context.target_id,
            adapter_id="fake-scanner",
            idempotency_key=idempotency_key,
            payload_json={"idempotency_key": idempotency_key},
        )
    )
    return result.job_id


def test_postgres_lease_owner_starts_job(
    postgres_execution_context: _PostgresExecutionContext,
) -> None:
    lease_time = datetime(2035, 6, 7, 8, 9, 10, tzinfo=UTC)
    execution_time = lease_time + timedelta(seconds=10)
    worker_id = "postgres-worker"
    job_id = _submit_job(postgres_execution_context, "5" * 64)

    leased = JobLeasingService(
        postgres_execution_context.session_factory,
        clock=lambda: lease_time,
    ).lease_next_job(worker_id, lease_seconds=60)
    assert leased is not None
    assert leased.lease_token is not None
    original_lease_expiry = leased.lease_expires_at

    started = JobExecutionService(
        postgres_execution_context.session_factory,
        clock=lambda: execution_time,
    ).start_job(job_id, worker_id, leased.lease_token)

    assert started.status is JobStatus.RUNNING
    assert started.leased_by == worker_id
    assert started.lease_token == leased.lease_token
    assert started.attempt_count == 1
    assert started.heartbeat_at == execution_time
    assert started.started_at == execution_time
    assert started.lease_expires_at == original_lease_expiry

    with postgres_execution_context.session_factory() as session:
        persisted = session.get(JobRow, job_id)
        assert persisted is not None
        assert persisted.status == started.status.value
        assert persisted.leased_by == started.leased_by
        assert persisted.lease_token == started.lease_token
        assert persisted.attempt_count == started.attempt_count
        assert persisted.heartbeat_at == started.heartbeat_at
        assert persisted.started_at == started.started_at
        assert persisted.lease_expires_at == started.lease_expires_at


def test_concurrent_start_calls_transition_only_once(
    postgres_execution_context: _PostgresExecutionContext,
) -> None:
    lease_time = datetime(2035, 7, 8, 9, 10, 11, tzinfo=UTC)
    execution_time = lease_time + timedelta(seconds=10)
    worker_id = "concurrent-worker"
    job_id = _submit_job(postgres_execution_context, "6" * 64)

    leased = JobLeasingService(
        postgres_execution_context.session_factory,
        clock=lambda: lease_time,
    ).lease_next_job(worker_id, lease_seconds=60)
    assert leased is not None
    assert leased.lease_token is not None

    services = [
        JobExecutionService(
            postgres_execution_context.session_factory,
            clock=lambda: execution_time,
        )
        for _ in range(2)
    ]
    outcomes: list[JobRecord | JobStateConflictError] = []

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                service.start_job,
                job_id,
                worker_id,
                leased.lease_token,
            )
            for service in services
        ]
        for future in futures:
            try:
                outcomes.append(future.result(timeout=5))
            except JobStateConflictError as exc:
                outcomes.append(exc)

    successful = [outcome for outcome in outcomes if isinstance(outcome, JobRecord)]
    conflicts = [outcome for outcome in outcomes if isinstance(outcome, JobStateConflictError)]
    assert len(successful) == 1
    assert len(conflicts) == 1
    assert conflicts[0].expected_status is JobStatus.LEASED
    assert conflicts[0].actual_status is JobStatus.RUNNING

    with postgres_execution_context.session_factory() as session:
        persisted = session.get(JobRow, job_id)
        assert persisted is not None
        assert persisted.status == JobStatus.RUNNING.value
        assert persisted.started_at == execution_time
        assert persisted.attempt_count == 1
        assert persisted.leased_by == worker_id
        assert persisted.lease_token == leased.lease_token


def test_stale_token_cannot_start_new_lease_for_same_worker(
    postgres_execution_context: _PostgresExecutionContext,
) -> None:
    first_lease_time = datetime(2035, 8, 9, 10, 11, 12, tzinfo=UTC)
    second_lease_time = first_lease_time + timedelta(seconds=30)
    execution_time = second_lease_time + timedelta(seconds=10)
    worker_id = "worker-reused"
    job_id = _submit_job(postgres_execution_context, "7" * 64)
    first_token = UUID("00000000-0000-4000-8000-000000000020")
    second_token = UUID("00000000-0000-4000-8000-000000000021")

    first_lease = JobLeasingService(
        postgres_execution_context.session_factory,
        clock=lambda: first_lease_time,
        token_factory=lambda: first_token,
    ).lease_next_job(worker_id, lease_seconds=60)
    assert first_lease is not None
    assert first_lease.lease_token == str(first_token)
    assert first_lease.attempt_count == 1

    with postgres_execution_context.session_factory.begin() as session:
        row = session.get(JobRow, job_id)
        assert row is not None
        row.status = JobStatus.QUEUED.value
        row.leased_by = None
        row.lease_token = None
        row.lease_expires_at = None
        row.heartbeat_at = None
        row.available_at = second_lease_time

    second_lease = JobLeasingService(
        postgres_execution_context.session_factory,
        clock=lambda: second_lease_time,
        token_factory=lambda: second_token,
    ).lease_next_job(worker_id, lease_seconds=60)
    assert second_lease is not None
    assert second_lease.lease_token == str(second_token)
    assert second_lease.lease_token != first_lease.lease_token
    assert second_lease.attempt_count == 2

    service = JobExecutionService(
        postgres_execution_context.session_factory,
        clock=lambda: execution_time,
    )
    with pytest.raises(JobLeaseTokenMismatchError):
        service.start_job(job_id, worker_id, first_lease.lease_token)

    with postgres_execution_context.session_factory() as session:
        persisted = session.get(JobRow, job_id)
        assert persisted is not None
        assert persisted.status == JobStatus.LEASED.value
        assert persisted.lease_token == second_lease.lease_token
        assert persisted.attempt_count == 2

    started = service.start_job(job_id, worker_id, second_lease.lease_token)
    assert started.status is JobStatus.RUNNING
    assert started.lease_token == second_lease.lease_token
    assert started.attempt_count == 2

    with postgres_execution_context.session_factory() as session:
        persisted = session.get(JobRow, job_id)
        assert persisted is not None
        assert persisted.status == JobStatus.RUNNING.value
        assert persisted.lease_token == second_lease.lease_token
        assert persisted.attempt_count == 2
