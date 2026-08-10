from __future__ import annotations

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

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
    RunStatus,
    TargetType,
)
from securescan.domain.models import ScanReport, TargetProfile
from securescan.jobs import (
    FailedToolExecutionCommit,
    JobCancellationRequestedError,
    JobCancellationService,
    JobExecutionService,
    JobFailureCommitRequest,
    JobFailureCommitService,
    JobLeasingService,
    JobRecord,
    JobResultCommitRequest,
    JobResultCommitService,
    JobSubmissionRequest,
    JobSubmissionService,
    ToolExecutionCommit,
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
LEASE_TIME = datetime(2042, 2, 3, 4, 5, 6, tzinfo=UTC)
START_TIME = LEASE_TIME + timedelta(seconds=2)
REQUEST_TIME = LEASE_TIME + timedelta(seconds=5)
ACK_TIME = LEASE_TIME + timedelta(seconds=10)
EXPIRED_TIME = LEASE_TIME + timedelta(seconds=100)


@dataclass(frozen=True, slots=True)
class _PostgresCancellationContext:
    session_factory: sessionmaker[Session]
    target_id: str


@dataclass(frozen=True, slots=True)
class _ActiveJob:
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
            "skipping PostgreSQL cancellation integration test"
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
def postgres_cancellation_context(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_PostgresCancellationContext]:
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
            project = ProjectRow(name="PostgreSQL job cancellation test")
            target = TargetRow(
                project=project,
                target_type=TargetType.SOURCE_REPOSITORY.value,
                content_digest="e" * 64,
                source_path="/tmp/postgres-job-cancellation",
            )
            session.add(target)
            session.flush()
            target_id = target.id
        yield _PostgresCancellationContext(session_factory, target_id)
    finally:
        if engine is not None:
            engine.dispose()
        try:
            _reset_public_schema(database_url)
        finally:
            get_settings.cache_clear()


def _submit(
    context: _PostgresCancellationContext,
    idempotency_key: str,
) -> tuple[str, str]:
    result = JobSubmissionService(context.session_factory).submit(
        JobSubmissionRequest(
            target_id=context.target_id,
            adapter_id="fake-scanner",
            idempotency_key=idempotency_key,
        )
    )
    return result.job_id, result.run_id


def _prepare_active_job(
    context: _PostgresCancellationContext,
    idempotency_key: str,
    worker_id: str,
    *,
    running: bool = True,
    lease_seconds: int = 30,
) -> _ActiveJob:
    job_id, run_id = _submit(context, idempotency_key)
    leased = JobLeasingService(
        context.session_factory,
        clock=lambda: LEASE_TIME,
    ).lease_next_job(worker_id, lease_seconds=lease_seconds)
    assert leased is not None
    assert leased.id == job_id
    assert leased.lease_token is not None
    record = leased
    if running:
        record = JobExecutionService(
            context.session_factory,
            clock=lambda: START_TIME,
        ).start_job(job_id, worker_id, leased.lease_token)
    with context.session_factory.begin() as session:
        run = session.get(AnalysisRunRow, run_id)
        assert run is not None
        run.status = RunStatus.RUNNING.value
    return _ActiveJob(job_id, run_id, worker_id, leased.lease_token, record)


def _execution_count(context: _PostgresCancellationContext) -> int:
    with context.session_factory() as session:
        count = session.scalar(select(func.count()).select_from(ToolExecutionRow))
        assert count is not None
        return count


def _report_json(run_id: str) -> dict[str, Any]:
    return ScanReport(
        run_id=UUID(run_id),
        target=TargetProfile(
            target_type=TargetType.SOURCE_REPOSITORY,
            path=Path("/tmp/postgres-job-cancellation"),
            content_digest="e" * 64,
        ),
        status=RunStatus.COMPLETED,
        executions=[],
        observations=[],
        generated_at=ACK_TIME,
    ).model_dump(mode="json")


def test_postgres_queued_job_is_cancelled_immediately(
    postgres_cancellation_context: _PostgresCancellationContext,
) -> None:
    job_id, run_id = _submit(postgres_cancellation_context, "1" * 64)

    result = JobCancellationService(
        postgres_cancellation_context.session_factory,
        clock=lambda: REQUEST_TIME,
    ).request_cancellation(job_id)

    assert result.immediate is True
    assert result.already_requested is False
    assert result.job.status is JobStatus.CANCELLED
    assert result.job.cancel_requested_at == REQUEST_TIME
    with postgres_cancellation_context.session_factory() as session:
        run = session.get(AnalysisRunRow, run_id)
        assert run is not None
        assert run.status == RunStatus.CANCELLED.value
    assert _execution_count(postgres_cancellation_context) == 0


def test_postgres_running_job_request_and_owner_acknowledgement(
    postgres_cancellation_context: _PostgresCancellationContext,
) -> None:
    active = _prepare_active_job(
        postgres_cancellation_context,
        "2" * 64,
        "owner-worker",
        lease_seconds=60,
    )
    cancellation = JobCancellationService(
        postgres_cancellation_context.session_factory,
        clock=lambda: REQUEST_TIME,
    ).request_cancellation(active.job_id)

    assert cancellation.job.status is JobStatus.RUNNING
    assert cancellation.job.cancel_requested is True
    assert cancellation.job.cancel_requested_at == REQUEST_TIME

    result_request = JobResultCommitRequest(
        job_id=active.job_id,
        worker_id=active.worker_id,
        lease_token=active.lease_token,
        final_status=JobStatus.SUCCEEDED,
        report_json=_report_json(active.run_id),
        tool_execution=ToolExecutionCommit(
            tool_version="1.0",
            adapter_version="1.0",
            outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS.value,
            exit_code=0,
            duration_ms=20,
            warning_json=[],
        ),
    )
    with pytest.raises(JobCancellationRequestedError):
        JobResultCommitService(
            postgres_cancellation_context.session_factory,
            clock=lambda: ACK_TIME,
        ).commit_result(result_request)

    failure_request = JobFailureCommitRequest(
        job_id=active.job_id,
        worker_id=active.worker_id,
        lease_token=active.lease_token,
        tool_execution=FailedToolExecutionCommit(
            tool_version="1.0",
            adapter_version="1.0",
            outcome=ExecutionOutcome.INTERNAL_ERROR.value,
            exit_code=1,
            duration_ms=20,
            warning_json=[],
            error="must not commit",
            failure_category=JobFailureCategory.RETRYABLE_INFRASTRUCTURE,
            retryable=True,
        ),
    )
    with pytest.raises(JobCancellationRequestedError):
        JobFailureCommitService(
            postgres_cancellation_context.session_factory,
            clock=lambda: ACK_TIME,
        ).commit_failure(failure_request)

    acknowledged = JobCancellationService(
        postgres_cancellation_context.session_factory,
        clock=lambda: ACK_TIME,
    ).acknowledge_cancellation(
        active.job_id,
        active.worker_id,
        active.lease_token,
    )

    assert acknowledged.status is JobStatus.CANCELLED
    assert acknowledged.leased_by is None
    assert acknowledged.lease_token is None
    assert acknowledged.lease_expires_at is None
    assert acknowledged.heartbeat_at == ACK_TIME
    with postgres_cancellation_context.session_factory() as session:
        run = session.get(AnalysisRunRow, active.run_id)
        assert run is not None
        assert run.status == RunStatus.CANCELLED.value
    assert _execution_count(postgres_cancellation_context) == 0


def test_concurrent_cancellation_requests_are_idempotent(
    postgres_cancellation_context: _PostgresCancellationContext,
) -> None:
    active = _prepare_active_job(
        postgres_cancellation_context,
        "3" * 64,
        "concurrent-request-worker",
        lease_seconds=60,
    )
    services = [
        JobCancellationService(
            postgres_cancellation_context.session_factory,
            clock=lambda: REQUEST_TIME,
        )
        for _ in range(2)
    ]

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(service.request_cancellation, active.job_id)
            for service in services
        ]
        results = [future.result(timeout=5) for future in futures]

    assert sorted(result.already_requested for result in results) == [False, True]
    assert {result.job.cancel_requested_at for result in results} == {REQUEST_TIME}
    with postgres_cancellation_context.session_factory() as session:
        row = session.get(JobRow, active.job_id)
        assert row is not None
        assert row.cancel_requested is True
        assert row.cancel_requested_at == REQUEST_TIME
        assert row.status == JobStatus.RUNNING.value
    assert _execution_count(postgres_cancellation_context) == 0


def test_expired_requested_cancellation_is_finalized(
    postgres_cancellation_context: _PostgresCancellationContext,
) -> None:
    active = _prepare_active_job(
        postgres_cancellation_context,
        "4" * 64,
        "expired-cancellation-worker",
    )
    JobCancellationService(
        postgres_cancellation_context.session_factory,
        clock=lambda: REQUEST_TIME,
    ).request_cancellation(active.job_id)
    heartbeat_before = active.record.heartbeat_at

    results = JobCancellationService(
        postgres_cancellation_context.session_factory,
        clock=lambda: EXPIRED_TIME,
    ).finalize_expired_cancellations()

    assert len(results) == 1
    assert results[0].previous_status is JobStatus.RUNNING
    assert results[0].job.status is JobStatus.CANCELLED
    assert results[0].job.heartbeat_at == heartbeat_before
    assert results[0].job.leased_by is None
    assert results[0].job.lease_token is None
    assert results[0].job.lease_expires_at is None
    with postgres_cancellation_context.session_factory() as session:
        run = session.get(AnalysisRunRow, active.run_id)
        assert run is not None
        assert run.status == RunStatus.CANCELLED.value
    assert _execution_count(postgres_cancellation_context) == 0


def test_locked_first_cancellation_is_skipped(
    postgres_cancellation_context: _PostgresCancellationContext,
) -> None:
    first = _prepare_active_job(
        postgres_cancellation_context,
        "5" * 64,
        "locked-cancellation-worker",
    )
    second = _prepare_active_job(
        postgres_cancellation_context,
        "6" * 64,
        "available-cancellation-worker",
    )
    JobCancellationService(
        postgres_cancellation_context.session_factory,
        clock=lambda: REQUEST_TIME,
    ).request_cancellation(first.job_id)
    JobCancellationService(
        postgres_cancellation_context.session_factory,
        clock=lambda: REQUEST_TIME + timedelta(seconds=1),
    ).request_cancellation(second.job_id)

    locker = postgres_cancellation_context.session_factory()
    transaction = locker.begin()
    try:
        locked = locker.scalar(
            select(JobRow)
            .where(JobRow.id == first.job_id)
            .with_for_update()
        )
        assert locked is not None

        service = JobCancellationService(
            postgres_cancellation_context.session_factory,
            clock=lambda: EXPIRED_TIME,
        )
        with ThreadPoolExecutor(max_workers=1) as executor:
            result = executor.submit(
                service.finalize_expired_cancellations,
                1,
            ).result(timeout=5)

        assert [item.job.id for item in result] == [second.job_id]
        with postgres_cancellation_context.session_factory() as session:
            first_row = session.get(JobRow, first.job_id)
            second_row = session.get(JobRow, second.job_id)
            assert first_row is not None
            assert second_row is not None
            assert first_row.status == JobStatus.RUNNING.value
            assert second_row.status == JobStatus.CANCELLED.value
    finally:
        transaction.rollback()
        locker.close()


def test_concurrent_finalizers_never_finalize_same_job_twice(
    postgres_cancellation_context: _PostgresCancellationContext,
) -> None:
    active_jobs = [
        _prepare_active_job(
            postgres_cancellation_context,
            character * 64,
            f"finalizer-worker-{character}",
        )
        for character in ("7", "8", "9", "a")
    ]
    for active in active_jobs:
        JobCancellationService(
            postgres_cancellation_context.session_factory,
            clock=lambda: REQUEST_TIME,
        ).request_cancellation(active.job_id)

    services = [
        JobCancellationService(
            postgres_cancellation_context.session_factory,
            clock=lambda: EXPIRED_TIME,
        )
        for _ in range(2)
    ]
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(service.finalize_expired_cancellations, 2)
            for service in services
        ]
        result_groups = [future.result(timeout=5) for future in futures]

    results = [result for group in result_groups for result in group]
    result_ids = [result.job.id for result in results]
    assert len(result_ids) == 4
    assert len(set(result_ids)) == 4
    assert {result.job.attempt_count for result in results} == {1}
    with postgres_cancellation_context.session_factory() as session:
        rows = list(
            session.scalars(
                select(JobRow).where(
                    JobRow.id.in_([active.job_id for active in active_jobs])
                )
            )
        )
        assert {row.status for row in rows} == {JobStatus.CANCELLED.value}
        assert {row.attempt_count for row in rows} == {1}
    assert _execution_count(postgres_cancellation_context) == 0
    assert (
        JobCancellationService(
            postgres_cancellation_context.session_factory,
            clock=lambda: EXPIRED_TIME,
        ).finalize_expired_cancellations()
        == []
    )
