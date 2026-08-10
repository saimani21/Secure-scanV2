from __future__ import annotations

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.orm import Session, sessionmaker

from securescan.config import get_settings
from securescan.domain.enums import (
    ExecutionOutcome,
    JobFailureCategory,
    JobStatus,
    TargetType,
)
from securescan.jobs import (
    FailedToolExecutionCommit,
    JobExecutionService,
    JobFailureCommitRequest,
    JobFailureCommitService,
    JobLeasingService,
    JobRecord,
    JobRepository,
    JobRetryPromotionService,
    JobSubmissionRequest,
    JobSubmissionService,
)
from securescan.persistence.database import (
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
LIFECYCLE_TIME = datetime(2039, 2, 3, 4, 5, 6, tzinfo=UTC)
PROMOTION_TIME = LIFECYCLE_TIME + timedelta(seconds=100)


@dataclass(frozen=True, slots=True)
class _PostgresPromotionContext:
    session_factory: sessionmaker[Session]
    target_id: str


@dataclass(frozen=True, slots=True)
class _RetryJob:
    job_id: str
    run_id: str
    record: JobRecord


def _validated_test_database_url() -> str:
    database_url = os.environ.get("SECURESCAN_TEST_POSTGRES_URL")
    if database_url is None:
        pytest.skip(
            "SECURESCAN_TEST_POSTGRES_URL is not configured; "
            "skipping PostgreSQL retry-promotion integration test"
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


@pytest.fixture
def postgres_promotion_context(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_PostgresPromotionContext]:
    database_url = _validated_test_database_url()
    alembic_config = Config(str(ALEMBIC_INI_PATH))
    alembic_config.set_main_option("script_location", str(MIGRATIONS_PATH))
    monkeypatch.setenv("SECURESCAN_DATABASE_URL", database_url)
    get_settings.cache_clear()
    engine: Engine | None = None

    try:
        _reset_public_schema(database_url)
        command.upgrade(alembic_config, "head")
        engine, session_factory = create_session_factory(get_settings())
        with session_factory.begin() as session:
            project = ProjectRow(name="PostgreSQL retry promotion test")
            target = TargetRow(
                project=project,
                target_type=TargetType.SOURCE_REPOSITORY.value,
                content_digest="e" * 64,
                source_path="/tmp/postgres-retry-promotion",
            )
            session.add(target)
            session.flush()
            target_id = target.id
        yield _PostgresPromotionContext(session_factory, target_id)
    finally:
        if engine is not None:
            engine.dispose()
        try:
            _reset_public_schema(database_url)
        finally:
            get_settings.cache_clear()


def _create_retry_job(
    context: _PostgresPromotionContext,
    idempotency_key: str,
    worker_id: str,
) -> _RetryJob:
    submitted = JobSubmissionService(context.session_factory).submit(
        JobSubmissionRequest(
            target_id=context.target_id,
            adapter_id="fake-scanner",
            idempotency_key=idempotency_key,
        )
    )
    leased = JobLeasingService(
        context.session_factory,
        clock=lambda: LIFECYCLE_TIME,
    ).lease_next_job(worker_id, lease_seconds=60)
    assert leased is not None
    assert leased.id == submitted.job_id
    assert leased.lease_token is not None
    JobExecutionService(
        context.session_factory,
        clock=lambda: LIFECYCLE_TIME + timedelta(seconds=1),
    ).start_job(submitted.job_id, worker_id, leased.lease_token)
    failed = JobFailureCommitService(
        context.session_factory,
        clock=lambda: LIFECYCLE_TIME + timedelta(seconds=2),
        retry_delay_seconds=lambda _attempt: 5,
    ).commit_failure(
        JobFailureCommitRequest(
            job_id=submitted.job_id,
            worker_id=worker_id,
            lease_token=leased.lease_token,
            tool_execution=FailedToolExecutionCommit(
                tool_version="1.0.0",
                adapter_version="1.0.0",
                outcome=ExecutionOutcome.INTERNAL_ERROR.value,
                exit_code=2,
                duration_ms=10,
                warning_json=[],
                error=f"Failure evidence for {worker_id}",
                failure_category=JobFailureCategory.RETRYABLE_INFRASTRUCTURE,
                retryable=True,
            ),
        )
    )
    assert failed.retry_scheduled is True
    return _RetryJob(submitted.job_id, submitted.run_id, failed.job)


def _execution_count(context: _PostgresPromotionContext) -> int:
    with context.session_factory() as session:
        count = session.scalar(select(func.count()).select_from(ToolExecutionRow))
        assert count is not None
        return count


def test_promotion_returns_empty_list_when_no_retry_is_due(
    postgres_promotion_context: _PostgresPromotionContext,
) -> None:
    future = _create_retry_job(
        postgres_promotion_context,
        "5" * 64,
        "future-empty-worker",
    )
    with postgres_promotion_context.session_factory.begin() as session:
        row = session.get(JobRow, future.job_id)
        assert row is not None
        row.available_at = PROMOTION_TIME + timedelta(seconds=1)
    before = JobRepository(postgres_promotion_context.session_factory).get_job(future.job_id)

    promoted = JobRetryPromotionService(
        postgres_promotion_context.session_factory,
        clock=lambda: PROMOTION_TIME,
    ).promote_due_retries()

    assert promoted == []
    assert JobRepository(postgres_promotion_context.session_factory).get_job(
        future.job_id
    ) == before


def test_due_retry_is_promoted_and_ineligible_rows_are_skipped(
    postgres_promotion_context: _PostgresPromotionContext,
) -> None:
    retry_jobs = [
        _create_retry_job(
            postgres_promotion_context,
            character * 64,
            f"eligibility-worker-{character}",
        )
        for character in "6789a"
    ]
    due, future, cancelled, exhausted, owned = retry_jobs
    with postgres_promotion_context.session_factory.begin() as session:
        rows = {
            row.id: row
            for row in session.scalars(
                select(JobRow).where(JobRow.id.in_([job.job_id for job in retry_jobs]))
            )
        }
        rows[due.job_id].available_at = PROMOTION_TIME - timedelta(seconds=5)
        rows[future.job_id].available_at = PROMOTION_TIME + timedelta(seconds=1)
        rows[cancelled.job_id].cancel_requested = True
        rows[exhausted.job_id].attempt_count = rows[exhausted.job_id].max_attempts
        rows[owned.job_id].leased_by = "invalid-retry-owner"

    repository = JobRepository(postgres_promotion_context.session_factory)
    due_before = repository.get_job(due.job_id)
    assert due_before is not None
    execution_count_before = _execution_count(postgres_promotion_context)
    promoted = JobRetryPromotionService(
        postgres_promotion_context.session_factory,
        clock=lambda: PROMOTION_TIME,
    ).promote_due_retries(limit=10)

    assert [record.id for record in promoted] == [due.job_id]
    promoted_due = promoted[0]
    assert promoted_due.status is JobStatus.QUEUED
    assert promoted_due.available_at == due_before.available_at
    assert promoted_due.attempt_count == due_before.attempt_count
    assert promoted_due.last_error == due_before.last_error
    assert promoted_due.heartbeat_at == due_before.heartbeat_at
    persisted_due = repository.get_job(due.job_id)
    assert persisted_due == promoted_due
    assert _execution_count(postgres_promotion_context) == execution_count_before
    for ineligible in (future, cancelled, exhausted, owned):
        persisted = repository.get_job(ineligible.job_id)
        assert persisted is not None
        assert persisted.status is JobStatus.RETRY_PENDING


def test_promotion_respects_due_time_priority_and_limit(
    postgres_promotion_context: _PostgresPromotionContext,
) -> None:
    retry_jobs = [
        _create_retry_job(
            postgres_promotion_context,
            character * 64,
            f"ordering-worker-{character}",
        )
        for character in "bcd"
    ]
    first, second, third = retry_jobs
    with postgres_promotion_context.session_factory.begin() as session:
        rows = {
            row.id: row
            for row in session.scalars(
                select(JobRow).where(JobRow.id.in_([job.job_id for job in retry_jobs]))
            )
        }
        rows[first.job_id].available_at = PROMOTION_TIME - timedelta(seconds=20)
        rows[first.job_id].priority = 500
        rows[second.job_id].available_at = PROMOTION_TIME - timedelta(seconds=10)
        rows[second.job_id].priority = 10
        rows[third.job_id].available_at = PROMOTION_TIME - timedelta(seconds=10)
        rows[third.job_id].priority = 20
    attempt_counts = {
        job.job_id: job.record.attempt_count
        for job in retry_jobs
    }
    service = JobRetryPromotionService(
        postgres_promotion_context.session_factory,
        clock=lambda: PROMOTION_TIME,
    )

    first_batch = service.promote_due_retries(limit=2)
    assert [record.id for record in first_batch] == [first.job_id, second.job_id]
    remaining = JobRepository(postgres_promotion_context.session_factory).get_job(
        third.job_id
    )
    assert remaining is not None
    assert remaining.status is JobStatus.RETRY_PENDING

    second_batch = service.promote_due_retries(limit=2)
    assert [record.id for record in second_batch] == [third.job_id]
    with postgres_promotion_context.session_factory() as session:
        rows = session.scalars(
            select(JobRow).where(JobRow.id.in_([job.job_id for job in retry_jobs]))
        ).all()
        assert {
            row.id: row.attempt_count for row in rows
        } == attempt_counts


def test_locked_first_retry_is_skipped(
    postgres_promotion_context: _PostgresPromotionContext,
) -> None:
    first = _create_retry_job(
        postgres_promotion_context,
        "e" * 64,
        "locked-first-worker",
    )
    second = _create_retry_job(
        postgres_promotion_context,
        "f" * 64,
        "locked-second-worker",
    )
    with postgres_promotion_context.session_factory.begin() as session:
        first_row = session.get(JobRow, first.job_id)
        second_row = session.get(JobRow, second.job_id)
        assert first_row is not None
        assert second_row is not None
        first_row.available_at = PROMOTION_TIME - timedelta(seconds=2)
        second_row.available_at = PROMOTION_TIME - timedelta(seconds=1)

    lock_session = postgres_promotion_context.session_factory()
    lock_transaction = lock_session.begin()
    try:
        locked = lock_session.scalar(
            select(JobRow)
            .where(JobRow.id == first.job_id)
            .with_for_update()
        )
        assert locked is not None
        service = JobRetryPromotionService(
            postgres_promotion_context.session_factory,
            clock=lambda: PROMOTION_TIME,
        )
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(service.promote_due_retries, 1)
            promoted = future.result(timeout=5)

        assert [record.id for record in promoted] == [second.job_id]
        lock_session.refresh(locked)
        assert locked.status == JobStatus.RETRY_PENDING.value
    finally:
        lock_transaction.rollback()
        lock_session.close()

    second_persisted = JobRepository(
        postgres_promotion_context.session_factory
    ).get_job(second.job_id)
    assert second_persisted is not None
    assert second_persisted.status is JobStatus.QUEUED


def test_concurrent_promoters_never_promote_the_same_job_twice(
    postgres_promotion_context: _PostgresPromotionContext,
) -> None:
    retry_jobs = [
        _create_retry_job(
            postgres_promotion_context,
            character * 64,
            f"concurrent-promotion-worker-{character}",
        )
        for character in "ghij"
    ]
    with postgres_promotion_context.session_factory.begin() as session:
        for offset, retry_job in enumerate(retry_jobs):
            row = session.get(JobRow, retry_job.job_id)
            assert row is not None
            row.available_at = PROMOTION_TIME - timedelta(seconds=10 - offset)
    attempt_counts = {
        job.job_id: job.record.attempt_count
        for job in retry_jobs
    }
    execution_count_before = _execution_count(postgres_promotion_context)
    services = [
        JobRetryPromotionService(
            postgres_promotion_context.session_factory,
            clock=lambda: PROMOTION_TIME,
        )
        for _ in range(2)
    ]

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(service.promote_due_retries, 2)
            for service in services
        ]
        batches = [future.result(timeout=5) for future in futures]

    promoted = [record for batch in batches for record in batch]
    promoted_ids = [record.id for record in promoted]
    assert len(promoted_ids) == 4
    assert len(set(promoted_ids)) == 4
    with postgres_promotion_context.session_factory() as session:
        rows = session.scalars(
            select(JobRow).where(JobRow.id.in_([job.job_id for job in retry_jobs]))
        ).all()
        assert all(row.status == JobStatus.QUEUED.value for row in rows)
        assert {
            row.id: row.attempt_count for row in rows
        } == attempt_counts
    assert _execution_count(postgres_promotion_context) == execution_count_before
    assert JobRetryPromotionService(
        postgres_promotion_context.session_factory,
        clock=lambda: PROMOTION_TIME,
    ).promote_due_retries(limit=2) == []
