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
from sqlalchemy import create_engine, event, func, select, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import ArgumentError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.config import get_settings
from securescan.domain.enums import JobStatus, RunStatus, TargetType
from securescan.jobs import (
    ExpiredLeaseRecoveryResult,
    JobExecutionService,
    JobLeaseRecoveryError,
    JobLeaseRecoveryService,
    JobLeaseTokenMismatchError,
    JobLeasingService,
    JobRecord,
    JobRepository,
    JobRetryPromotionService,
    JobSubmissionRequest,
    JobSubmissionService,
)
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
LEASE_TIME = datetime(2040, 2, 3, 4, 5, 6, tzinfo=UTC)
RECOVERY_TIME = LEASE_TIME + timedelta(seconds=100)


@dataclass(frozen=True, slots=True)
class _PostgresRecoveryContext:
    session_factory: sessionmaker[Session]
    target_id: str


@dataclass(frozen=True, slots=True)
class _LeasedJob:
    job_id: str
    run_id: str
    worker_id: str
    lease_token: str
    record: JobRecord


def _validated_test_database_url() -> str:
    database_url = os.environ.get("SECURESCAN_TEST_POSTGRES_URL")
    if database_url is None:
        pytest.skip(
            "SECURESCAN_TEST_POSTGRES_URL is not configured; "
            "skipping PostgreSQL lease-recovery integration test"
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
def postgres_recovery_context(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_PostgresRecoveryContext]:
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
            project = ProjectRow(name="PostgreSQL lease recovery test")
            target = TargetRow(
                project=project,
                target_type=TargetType.SOURCE_REPOSITORY.value,
                content_digest="1" * 64,
                source_path="/tmp/postgres-lease-recovery",
            )
            session.add(target)
            session.flush()
            target_id = target.id
        yield _PostgresRecoveryContext(session_factory, target_id)
    finally:
        if engine is not None:
            engine.dispose()
        try:
            _reset_public_schema(database_url)
        finally:
            get_settings.cache_clear()


def _create_leased_job(
    context: _PostgresRecoveryContext,
    idempotency_key: str,
    worker_id: str,
    *,
    max_attempts: int = 3,
    lease_seconds: int = 30,
) -> _LeasedJob:
    submitted = JobSubmissionService(context.session_factory).submit(
        JobSubmissionRequest(
            target_id=context.target_id,
            adapter_id="fake-scanner",
            idempotency_key=idempotency_key,
            max_attempts=max_attempts,
        )
    )
    leased = JobLeasingService(
        context.session_factory,
        clock=lambda: LEASE_TIME,
    ).lease_next_job(worker_id, lease_seconds=lease_seconds)
    assert leased is not None
    assert leased.id == submitted.job_id
    assert leased.lease_token is not None
    return _LeasedJob(
        job_id=submitted.job_id,
        run_id=submitted.run_id,
        worker_id=worker_id,
        lease_token=leased.lease_token,
        record=leased,
    )


def _start_job(
    context: _PostgresRecoveryContext,
    leased: _LeasedJob,
) -> JobRecord:
    return JobExecutionService(
        context.session_factory,
        clock=lambda: LEASE_TIME + timedelta(seconds=1),
    ).start_job(
        leased.job_id,
        leased.worker_id,
        leased.lease_token,
    )


def _execution_count(context: _PostgresRecoveryContext) -> int:
    with context.session_factory() as session:
        count = session.scalar(select(func.count()).select_from(ToolExecutionRow))
        assert count is not None
        return count


def test_recovery_returns_empty_when_no_lease_is_expired(
    postgres_recovery_context: _PostgresRecoveryContext,
) -> None:
    unexpired = _create_leased_job(
        postgres_recovery_context,
        "2" * 64,
        "unexpired-worker",
        lease_seconds=200,
    )
    before = JobRepository(postgres_recovery_context.session_factory).get_job(
        unexpired.job_id
    )

    def unexpected_retry_policy(_attempt_number: int) -> int:
        pytest.fail("retry policy must not be called when no lease is expired")

    recovered = JobLeaseRecoveryService(
        postgres_recovery_context.session_factory,
        clock=lambda: RECOVERY_TIME,
        retry_delay_seconds=unexpected_retry_policy,
    ).recover_expired_jobs()

    assert recovered == []
    assert JobRepository(postgres_recovery_context.session_factory).get_job(
        unexpired.job_id
    ) == before


def test_expired_running_recovery_updates_job_and_run_atomically(
    postgres_recovery_context: _PostgresRecoveryContext,
) -> None:
    leased = _create_leased_job(
        postgres_recovery_context,
        "1" * 64,
        "atomic-recovery-worker",
    )
    running = _start_job(postgres_recovery_context, leased)
    attempt_count = running.attempt_count
    heartbeat_at = running.heartbeat_at

    recovered = JobLeaseRecoveryService(
        postgres_recovery_context.session_factory,
        clock=lambda: RECOVERY_TIME,
        retry_delay_seconds=lambda _attempt: 5,
    ).recover_expired_jobs(limit=1)

    assert len(recovered) == 1
    assert recovered[0].job.id == leased.job_id
    with postgres_recovery_context.session_factory() as session:
        job = session.get(JobRow, leased.job_id)
        run = session.get(AnalysisRunRow, leased.run_id)
        executions = list(
            session.scalars(
                select(ToolExecutionRow).where(ToolExecutionRow.job_id == leased.job_id)
            )
        )
        assert job is not None
        assert run is not None
        assert job.status == JobStatus.RETRY_PENDING.value
        assert run.status == RunStatus.QUEUED.value
        assert job.leased_by is None
        assert job.lease_token is None
        assert job.lease_expires_at is None
        assert job.attempt_count == attempt_count
        assert job.heartbeat_at == heartbeat_at
        assert executions == []


def test_recovery_rolls_back_job_and_run_when_commit_fails(
    postgres_recovery_context: _PostgresRecoveryContext,
) -> None:
    leased = _create_leased_job(
        postgres_recovery_context,
        "0" * 64,
        "rollback-recovery-worker",
    )
    running = _start_job(postgres_recovery_context, leased)

    def fail_before_commit(_session: Session) -> None:
        raise SQLAlchemyError("injected recovery commit failure")

    event.listen(
        postgres_recovery_context.session_factory,
        "before_commit",
        fail_before_commit,
    )
    try:
        with pytest.raises(JobLeaseRecoveryError):
            JobLeaseRecoveryService(
                postgres_recovery_context.session_factory,
                clock=lambda: RECOVERY_TIME,
            ).recover_expired_jobs(limit=1)
    finally:
        event.remove(
            postgres_recovery_context.session_factory,
            "before_commit",
            fail_before_commit,
        )

    with postgres_recovery_context.session_factory() as session:
        job = session.get(JobRow, leased.job_id)
        run = session.get(AnalysisRunRow, leased.run_id)
        executions = list(
            session.scalars(
                select(ToolExecutionRow).where(ToolExecutionRow.job_id == leased.job_id)
            )
        )
        assert job is not None
        assert run is not None
        assert job.status == JobStatus.RUNNING.value
        assert run.status == RunStatus.RUNNING.value
        assert job.leased_by == running.leased_by
        assert job.lease_token == running.lease_token
        assert job.lease_expires_at == running.lease_expires_at
        assert job.attempt_count == running.attempt_count
        assert executions == []


def test_expired_leased_job_schedules_retry(
    postgres_recovery_context: _PostgresRecoveryContext,
) -> None:
    leased = _create_leased_job(
        postgres_recovery_context,
        "3" * 64,
        "expired-leased-worker",
    )
    existing_report = {"lease_evidence": {"preserved": True}}
    with postgres_recovery_context.session_factory.begin() as session:
        run = session.get(AnalysisRunRow, leased.run_id)
        assert run is not None
        run.report_json = existing_report
    heartbeat_before = leased.record.heartbeat_at

    recovered = JobLeaseRecoveryService(
        postgres_recovery_context.session_factory,
        clock=lambda: RECOVERY_TIME,
        retry_delay_seconds=lambda attempt: attempt * 7,
    ).recover_expired_jobs(limit=1)

    assert len(recovered) == 1
    result = recovered[0]
    assert isinstance(result, ExpiredLeaseRecoveryResult)
    assert result.previous_status is JobStatus.LEASED
    assert result.retry_scheduled is True
    assert result.retry_delay_seconds == 7
    assert result.job.status is JobStatus.RETRY_PENDING
    assert result.job.available_at == RECOVERY_TIME + timedelta(seconds=7)
    assert result.job.finished_at is None
    assert result.job.leased_by is None
    assert result.job.lease_token is None
    assert result.job.lease_expires_at is None
    assert result.job.attempt_count == 1
    assert result.job.heartbeat_at == heartbeat_before
    assert result.job.last_error == "Worker lease expired before execution started."
    with postgres_recovery_context.session_factory() as session:
        run = session.get(AnalysisRunRow, leased.run_id)
        assert run is not None
        assert run.status == RunStatus.QUEUED.value
        assert run.report_json == existing_report
    assert _execution_count(postgres_recovery_context) == 0


def test_expired_running_job_at_attempt_limit_becomes_failed(
    postgres_recovery_context: _PostgresRecoveryContext,
) -> None:
    leased = _create_leased_job(
        postgres_recovery_context,
        "4" * 64,
        "expired-running-worker",
        max_attempts=1,
    )
    running = _start_job(postgres_recovery_context, leased)
    existing_report = {"running_evidence": ["preserved"]}
    with postgres_recovery_context.session_factory.begin() as session:
        run = session.get(AnalysisRunRow, leased.run_id)
        assert run is not None
        run.report_json = existing_report

    def unexpected_retry_policy(_attempt_number: int) -> int:
        pytest.fail("retry policy must not be called at the attempt limit")

    recovered = JobLeaseRecoveryService(
        postgres_recovery_context.session_factory,
        clock=lambda: RECOVERY_TIME,
        retry_delay_seconds=unexpected_retry_policy,
    ).recover_expired_jobs(limit=1)

    result = recovered[0]
    assert result.previous_status is JobStatus.RUNNING
    assert result.retry_scheduled is False
    assert result.retry_delay_seconds is None
    assert result.job.status is JobStatus.FAILED
    assert result.job.finished_at == RECOVERY_TIME
    assert result.job.leased_by is None
    assert result.job.lease_token is None
    assert result.job.lease_expires_at is None
    assert result.job.attempt_count == 1
    assert result.job.heartbeat_at == running.heartbeat_at
    assert result.job.last_error == "Worker lease expired during execution."
    with postgres_recovery_context.session_factory() as session:
        run = session.get(AnalysisRunRow, leased.run_id)
        assert run is not None
        assert run.status == RunStatus.FAILED.value
        assert run.report_json == existing_report
    assert _execution_count(postgres_recovery_context) == 0


def test_unexpired_cancelled_and_missing_expiry_jobs_are_skipped(
    postgres_recovery_context: _PostgresRecoveryContext,
) -> None:
    unexpired = _create_leased_job(
        postgres_recovery_context,
        "5" * 64,
        "skipped-unexpired-worker",
        lease_seconds=200,
    )
    cancelled = _create_leased_job(
        postgres_recovery_context,
        "6" * 64,
        "skipped-cancelled-worker",
    )
    missing_expiry = _create_leased_job(
        postgres_recovery_context,
        "7" * 64,
        "skipped-missing-expiry-worker",
    )
    valid = _create_leased_job(
        postgres_recovery_context,
        "8" * 64,
        "valid-expired-worker",
    )
    with postgres_recovery_context.session_factory.begin() as session:
        cancelled_row = session.get(JobRow, cancelled.job_id)
        missing_expiry_row = session.get(JobRow, missing_expiry.job_id)
        valid_row = session.get(JobRow, valid.job_id)
        assert cancelled_row is not None
        assert missing_expiry_row is not None
        assert valid_row is not None
        cancelled_row.cancel_requested = True
        missing_expiry_row.lease_expires_at = None
        valid_row.lease_token = None
    repository = JobRepository(postgres_recovery_context.session_factory)
    skipped_before = {
        job.job_id: repository.get_job(job.job_id)
        for job in (unexpired, cancelled, missing_expiry)
    }

    recovered = JobLeaseRecoveryService(
        postgres_recovery_context.session_factory,
        clock=lambda: RECOVERY_TIME,
    ).recover_expired_jobs(limit=10)

    assert [result.job.id for result in recovered] == [valid.job_id]
    for job in (unexpired, cancelled, missing_expiry):
        assert repository.get_job(job.job_id) == skipped_before[job.job_id]


def test_locked_first_expired_job_is_skipped(
    postgres_recovery_context: _PostgresRecoveryContext,
) -> None:
    first = _create_leased_job(
        postgres_recovery_context,
        "9" * 64,
        "locked-first-recovery-worker",
    )
    second = _create_leased_job(
        postgres_recovery_context,
        "a" * 64,
        "locked-second-recovery-worker",
    )
    with postgres_recovery_context.session_factory.begin() as session:
        first_row = session.get(JobRow, first.job_id)
        second_row = session.get(JobRow, second.job_id)
        assert first_row is not None
        assert second_row is not None
        first_row.lease_expires_at = RECOVERY_TIME - timedelta(seconds=2)
        second_row.lease_expires_at = RECOVERY_TIME - timedelta(seconds=1)

    lock_session = postgres_recovery_context.session_factory()
    lock_transaction = lock_session.begin()
    try:
        locked = lock_session.scalar(
            select(JobRow)
            .where(JobRow.id == first.job_id)
            .with_for_update()
        )
        assert locked is not None
        service = JobLeaseRecoveryService(
            postgres_recovery_context.session_factory,
            clock=lambda: RECOVERY_TIME,
        )
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(service.recover_expired_jobs, 1)
            recovered = future.result(timeout=5)

        assert [result.job.id for result in recovered] == [second.job_id]
        lock_session.refresh(locked)
        assert locked.status == JobStatus.LEASED.value
        assert locked.lease_token == first.lease_token
    finally:
        lock_transaction.rollback()
        lock_session.close()

    second_persisted = JobRepository(
        postgres_recovery_context.session_factory
    ).get_job(second.job_id)
    assert second_persisted is not None
    assert second_persisted.status is JobStatus.RETRY_PENDING


def test_concurrent_recovery_services_never_recover_the_same_job_twice(
    postgres_recovery_context: _PostgresRecoveryContext,
) -> None:
    leased_jobs = [
        _create_leased_job(
            postgres_recovery_context,
            character * 64,
            f"concurrent-recovery-worker-{character}",
        )
        for character in "bcde"
    ]
    _start_job(postgres_recovery_context, leased_jobs[1])
    _start_job(postgres_recovery_context, leased_jobs[3])
    with postgres_recovery_context.session_factory.begin() as session:
        for offset, leased in enumerate(leased_jobs):
            row = session.get(JobRow, leased.job_id)
            assert row is not None
            row.lease_expires_at = RECOVERY_TIME - timedelta(seconds=10 - offset)
    attempt_counts = {
        leased.job_id: leased.record.attempt_count
        for leased in leased_jobs
    }
    services = [
        JobLeaseRecoveryService(
            postgres_recovery_context.session_factory,
            clock=lambda: RECOVERY_TIME,
        )
        for _ in range(2)
    ]

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(service.recover_expired_jobs, 2)
            for service in services
        ]
        batches = [future.result(timeout=5) for future in futures]

    recovered = [result for batch in batches for result in batch]
    recovered_ids = [result.job.id for result in recovered]
    assert len(recovered_ids) == 4
    assert len(set(recovered_ids)) == 4
    with postgres_recovery_context.session_factory() as session:
        rows = session.scalars(
            select(JobRow).where(
                JobRow.id.in_([leased.job_id for leased in leased_jobs])
            )
        ).all()
        assert all(
            row.status not in {
                JobStatus.LEASED.value,
                JobStatus.RUNNING.value,
            }
            for row in rows
        )
        assert {
            row.id: row.attempt_count for row in rows
        } == attempt_counts
    assert _execution_count(postgres_recovery_context) == 0
    assert JobLeaseRecoveryService(
        postgres_recovery_context.session_factory,
        clock=lambda: RECOVERY_TIME,
    ).recover_expired_jobs(limit=2) == []


def test_recovery_retry_promotion_and_new_lease_fence_stale_worker(
    postgres_recovery_context: _PostgresRecoveryContext,
) -> None:
    worker_id = "worker-reused"
    leased = _create_leased_job(
        postgres_recovery_context,
        "f" * 64,
        worker_id,
        max_attempts=3,
    )
    token_a = leased.lease_token
    _start_job(postgres_recovery_context, leased)
    recovery_time = LEASE_TIME + timedelta(seconds=31)
    recovered = JobLeaseRecoveryService(
        postgres_recovery_context.session_factory,
        clock=lambda: recovery_time,
        retry_delay_seconds=lambda _attempt: 5,
    ).recover_expired_jobs(limit=1)
    assert recovered[0].job.status is JobStatus.RETRY_PENDING

    promoted = JobRetryPromotionService(
        postgres_recovery_context.session_factory,
        clock=lambda: recovery_time + timedelta(seconds=5),
    ).promote_due_retries(limit=1)
    assert promoted[0].id == leased.job_id
    assert promoted[0].status is JobStatus.QUEUED

    leased_again = JobLeasingService(
        postgres_recovery_context.session_factory,
        clock=lambda: recovery_time + timedelta(seconds=6),
    ).lease_next_job(worker_id, lease_seconds=60)
    assert leased_again is not None
    assert leased_again.lease_token is not None
    token_b = leased_again.lease_token
    assert token_b != token_a
    assert leased_again.attempt_count == 2

    execution_service = JobExecutionService(
        postgres_recovery_context.session_factory,
        clock=lambda: recovery_time + timedelta(seconds=7),
    )
    with pytest.raises(JobLeaseTokenMismatchError):
        execution_service.start_job(leased.job_id, worker_id, token_a)

    persisted = JobRepository(postgres_recovery_context.session_factory).get_job(
        leased.job_id
    )
    assert persisted is not None
    assert persisted.status is JobStatus.LEASED
    assert persisted.lease_token == token_b

    started = execution_service.start_job(leased.job_id, worker_id, token_b)
    assert started.status is JobStatus.RUNNING
