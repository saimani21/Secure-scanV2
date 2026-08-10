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
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.orm import Session, sessionmaker

from securescan.config import get_settings
from securescan.domain.enums import JobStatus, RunStatus, TargetType
from securescan.jobs import (
    JobLeasingService,
    JobRecord,
    JobSubmissionRequest,
    JobSubmissionResult,
    JobSubmissionService,
)
from securescan.persistence.database import (
    AnalysisRunRow,
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
class _PostgresLeasingContext:
    session_factory: sessionmaker[Session]
    target_id: str


def _validated_test_database_url() -> str:
    database_url = os.environ.get("SECURESCAN_TEST_POSTGRES_URL")
    if database_url is None:
        pytest.skip(
            "SECURESCAN_TEST_POSTGRES_URL is not configured; "
            "skipping PostgreSQL job leasing integration test"
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
def postgres_leasing_context(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_PostgresLeasingContext]:
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
            project = ProjectRow(name="PostgreSQL job leasing test")
            target = TargetRow(
                project=project,
                target_type=TargetType.SOURCE_REPOSITORY.value,
                content_digest="1" * 64,
                source_path="/tmp/postgres-job-leasing-target",
            )
            session.add(target)
            session.flush()
            target_id = target.id

        yield _PostgresLeasingContext(
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
    context: _PostgresLeasingContext,
    idempotency_key: str,
    *,
    priority: int = 100,
    max_attempts: int = 3,
) -> JobSubmissionResult:
    return JobSubmissionService(context.session_factory).submit(
        JobSubmissionRequest(
            target_id=context.target_id,
            adapter_id="fake-scanner",
            idempotency_key=idempotency_key,
            payload_json={"idempotency_key": idempotency_key},
            priority=priority,
            max_attempts=max_attempts,
        )
    )


def test_empty_queue_returns_none(
    postgres_leasing_context: _PostgresLeasingContext,
) -> None:
    generated_tokens: list[UUID] = []

    def token_factory() -> UUID:
        token = UUID("00000000-0000-4000-8000-000000000001")
        generated_tokens.append(token)
        return token

    service = JobLeasingService(
        postgres_leasing_context.session_factory,
        token_factory=token_factory,
    )

    assert service.lease_next_job("worker-empty") is None
    assert generated_tokens == []


def test_ready_job_is_leased_and_persisted(
    postgres_leasing_context: _PostgresLeasingContext,
) -> None:
    operation_timestamp = datetime(2035, 1, 2, 3, 4, 5, tzinfo=UTC)
    expected_token = UUID("00000000-0000-4000-8000-000000000002")
    submitted = _submit_job(
        postgres_leasing_context,
        "b" * 64,
        priority=25,
        max_attempts=5,
    )

    with postgres_leasing_context.session_factory() as session:
        original = session.get(JobRow, submitted.job_id)
        assert original is not None
        original_available_at = original.available_at
        original_created_at = original.created_at

    service = JobLeasingService(
        postgres_leasing_context.session_factory,
        clock=lambda: operation_timestamp,
        token_factory=lambda: expected_token,
    )
    leased = service.lease_next_job("  worker-1  ")

    assert isinstance(leased, JobRecord)
    assert leased.id == submitted.job_id
    assert leased.run_id == submitted.run_id
    assert leased.status is JobStatus.LEASED
    assert leased.leased_by == "worker-1"
    assert leased.lease_token == str(expected_token)
    assert leased.lease_token == str(UUID(leased.lease_token))
    assert leased.heartbeat_at == operation_timestamp
    assert leased.lease_expires_at == operation_timestamp + timedelta(seconds=30)
    assert leased.attempt_count == 1
    assert leased.updated_at == operation_timestamp
    assert leased.started_at is None
    assert leased.finished_at is None
    assert leased.priority == 25
    assert leased.max_attempts == 5
    assert leased.available_at == original_available_at
    assert leased.created_at == original_created_at

    with postgres_leasing_context.session_factory() as session:
        persisted = session.get(JobRow, submitted.job_id)
        run = session.get(AnalysisRunRow, submitted.run_id)
        assert persisted is not None
        assert run is not None
        assert persisted.status == JobStatus.LEASED.value
        assert run.status == RunStatus.RUNNING.value
        assert persisted.leased_by == leased.leased_by
        assert persisted.lease_token == leased.lease_token
        assert persisted.heartbeat_at == leased.heartbeat_at
        assert persisted.lease_expires_at == leased.lease_expires_at
        assert persisted.attempt_count == leased.attempt_count
        assert persisted.updated_at == leased.updated_at


def test_leasing_respects_eligibility_and_priority(
    postgres_leasing_context: _PostgresLeasingContext,
) -> None:
    operation_timestamp = datetime(2035, 2, 3, 4, 5, 6, tzinfo=UTC)
    ready_low_priority = _submit_job(
        postgres_leasing_context,
        "c" * 64,
        priority=100,
    )
    ready_high_priority = _submit_job(
        postgres_leasing_context,
        "d" * 64,
        priority=10,
    )
    future = _submit_job(postgres_leasing_context, "e" * 64, priority=0)
    cancelled = _submit_job(postgres_leasing_context, "f" * 64, priority=1)
    exhausted = _submit_job(
        postgres_leasing_context,
        "g" * 64,
        priority=2,
        max_attempts=2,
    )

    with postgres_leasing_context.session_factory.begin() as session:
        future_row = session.get(JobRow, future.job_id)
        cancelled_row = session.get(JobRow, cancelled.job_id)
        exhausted_row = session.get(JobRow, exhausted.job_id)
        assert future_row is not None
        assert cancelled_row is not None
        assert exhausted_row is not None
        future_row.available_at = operation_timestamp + timedelta(seconds=1)
        cancelled_row.cancel_requested = True
        exhausted_row.attempt_count = exhausted_row.max_attempts

    service = JobLeasingService(
        postgres_leasing_context.session_factory,
        clock=lambda: operation_timestamp,
    )
    leased = service.lease_next_job("worker-priority")

    assert leased is not None
    assert leased.id == ready_high_priority.job_id
    assert leased.priority == 10

    with postgres_leasing_context.session_factory() as session:
        low_priority_row = session.get(JobRow, ready_low_priority.job_id)
        assert low_priority_row is not None
        assert low_priority_row.status == JobStatus.QUEUED.value


def test_locked_highest_priority_job_is_skipped(
    postgres_leasing_context: _PostgresLeasingContext,
) -> None:
    operation_timestamp = datetime(2035, 3, 4, 5, 6, 7, tzinfo=UTC)
    first = _submit_job(postgres_leasing_context, "h" * 64, priority=1)
    second = _submit_job(postgres_leasing_context, "i" * 64, priority=2)
    service = JobLeasingService(
        postgres_leasing_context.session_factory,
        clock=lambda: operation_timestamp,
    )

    lock_session = postgres_leasing_context.session_factory()
    lock_transaction = lock_session.begin()
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        locked = lock_session.scalar(
            select(JobRow).where(JobRow.id == first.job_id).with_for_update()
        )
        assert locked is not None

        future = executor.submit(service.lease_next_job, "worker-skip-locked")
        leased = future.result(timeout=5)

        assert leased is not None
        assert leased.id == second.job_id
        assert locked.status == JobStatus.QUEUED.value
    finally:
        lock_transaction.rollback()
        lock_session.close()
        executor.shutdown(wait=True, cancel_futures=True)

    with postgres_leasing_context.session_factory() as session:
        first_row = session.get(JobRow, first.job_id)
        second_row = session.get(JobRow, second.job_id)
        assert first_row is not None
        assert second_row is not None
        assert first_row.status == JobStatus.QUEUED.value
        assert second_row.status == JobStatus.LEASED.value


def test_concurrent_workers_lease_each_job_at_most_once(
    postgres_leasing_context: _PostgresLeasingContext,
) -> None:
    operation_timestamp = datetime(2035, 4, 5, 6, 7, 8, tzinfo=UTC)
    submitted = [
        _submit_job(postgres_leasing_context, character * 64, priority=priority)
        for character, priority in zip("jklm", range(4), strict=True)
    ]
    service = JobLeasingService(
        postgres_leasing_context.session_factory,
        clock=lambda: operation_timestamp,
    )
    worker_ids = [f"worker-{index}" for index in range(8)]

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(service.lease_next_job, worker_id) for worker_id in worker_ids]
        results = [future.result(timeout=5) for future in futures]

    leased_records = [result for result in results if result is not None]
    assert len(leased_records) == 4
    assert sum(result is None for result in results) == 4
    assert len({record.id for record in leased_records}) == 4
    assert all(record.lease_token is not None for record in leased_records)
    assert len({record.lease_token for record in leased_records}) == 4
    assert all(
        record.lease_token == str(UUID(record.lease_token))
        for record in leased_records
        if record.lease_token is not None
    )
    assert {record.id for record in leased_records} == {
        submission.job_id for submission in submitted
    }

    with postgres_leasing_context.session_factory() as session:
        persisted_jobs = list(session.scalars(select(JobRow)))

    assert len(persisted_jobs) == 4
    assert all(job.status == JobStatus.LEASED.value for job in persisted_jobs)
    assert all(job.attempt_count == 1 for job in persisted_jobs)
    assert len({job.leased_by for job in persisted_jobs}) == 4
    assert {job.lease_token for job in persisted_jobs} == {
        record.lease_token for record in leased_records
    }
