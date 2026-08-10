from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy.orm import Session, sessionmaker

from securescan.config import Settings
from securescan.domain.enums import JobStatus, TargetType
from securescan.jobs import (
    InvalidWorkerRequestError,
    JobCancellationRequestedError,
    JobExecutionService,
    JobLeaseExpiredError,
    JobLeaseOwnershipError,
    JobLeaseTokenMismatchError,
    JobNotFoundError,
    JobRecord,
    JobRepository,
    JobStateConflictError,
    JobSubmissionRequest,
    JobSubmissionService,
)
from securescan.persistence.database import (
    JobRow,
    ProjectRow,
    TargetRow,
    create_session_factory,
    initialize_database,
)

OPERATION_TIME = datetime(2035, 5, 6, 7, 8, 9, tzinfo=UTC)
LEASE_WORKER_ID = "worker-owner"
LEASE_TOKEN = str(UUID("00000000-0000-4000-8000-000000000010"))
OTHER_LEASE_TOKEN = str(UUID("00000000-0000-4000-8000-000000000011"))


@dataclass(frozen=True, slots=True)
class _SqliteExecutionContext:
    session_factory: sessionmaker[Session]
    repository: JobRepository
    job_id: str


@pytest.fixture
def sqlite_execution_context(
    tmp_path: Path,
) -> Iterator[_SqliteExecutionContext]:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'job-execution.db'}",
        artifact_root=tmp_path / "artifacts",
    )
    initialize_database(settings)
    engine, session_factory = create_session_factory(settings)

    with session_factory.begin() as session:
        project = ProjectRow(name="Job execution test")
        target = TargetRow(
            project=project,
            target_type=TargetType.SOURCE_REPOSITORY.value,
            content_digest="2" * 64,
            source_path="/tmp/job-execution-target",
        )
        session.add(target)
        session.flush()
        target_id = target.id

    submitted = JobSubmissionService(session_factory).submit(
        JobSubmissionRequest(
            target_id=target_id,
            adapter_id="fake-scanner",
            idempotency_key="3" * 64,
        )
    )

    try:
        yield _SqliteExecutionContext(
            session_factory=session_factory,
            repository=JobRepository(session_factory),
            job_id=submitted.job_id,
        )
    finally:
        engine.dispose()


def _prepare_lease(
    context: _SqliteExecutionContext,
    *,
    worker_id: str = LEASE_WORKER_ID,
    lease_expires_at: datetime | None = None,
    cancel_requested: bool = False,
) -> datetime:
    context.repository.transition_job(
        job_id=context.job_id,
        expected_status=JobStatus.QUEUED,
        requested_status=JobStatus.LEASED,
    )
    expiry = lease_expires_at or OPERATION_TIME + timedelta(seconds=60)

    with context.session_factory.begin() as session:
        row = session.get(JobRow, context.job_id)
        assert row is not None
        row.leased_by = worker_id
        row.lease_token = LEASE_TOKEN
        row.lease_expires_at = expiry
        row.heartbeat_at = OPERATION_TIME - timedelta(seconds=10)
        row.attempt_count = 1
        row.cancel_requested = cancel_requested

    return expiry


def _without_timezone(timestamp: datetime | None) -> datetime | None:
    if timestamp is None:
        return None
    return timestamp.replace(tzinfo=None)


def test_blank_worker_id_is_rejected(
    sqlite_execution_context: _SqliteExecutionContext,
) -> None:
    service = JobExecutionService(sqlite_execution_context.session_factory)

    with pytest.raises(InvalidWorkerRequestError, match="worker_id"):
        service.start_job(sqlite_execution_context.job_id, " \t ", LEASE_TOKEN)


def test_overlong_worker_id_is_rejected(
    sqlite_execution_context: _SqliteExecutionContext,
) -> None:
    service = JobExecutionService(sqlite_execution_context.session_factory)

    with pytest.raises(InvalidWorkerRequestError, match="200"):
        service.start_job(sqlite_execution_context.job_id, "w" * 201, LEASE_TOKEN)


def test_unknown_job_raises_not_found(
    sqlite_execution_context: _SqliteExecutionContext,
) -> None:
    service = JobExecutionService(
        sqlite_execution_context.session_factory,
        clock=lambda: OPERATION_TIME,
    )
    job_id = str(uuid4())

    with pytest.raises(JobNotFoundError) as error:
        service.start_job(job_id, LEASE_WORKER_ID, LEASE_TOKEN)

    assert error.value.job_id == job_id


def test_nonleased_job_raises_state_conflict(
    sqlite_execution_context: _SqliteExecutionContext,
) -> None:
    service = JobExecutionService(
        sqlite_execution_context.session_factory,
        clock=lambda: OPERATION_TIME,
    )

    with pytest.raises(JobStateConflictError) as error:
        service.start_job(
            sqlite_execution_context.job_id,
            LEASE_WORKER_ID,
            LEASE_TOKEN,
        )

    assert error.value.expected_status is JobStatus.LEASED
    assert error.value.actual_status is JobStatus.QUEUED


def test_wrong_worker_cannot_start_leased_job(
    sqlite_execution_context: _SqliteExecutionContext,
) -> None:
    _prepare_lease(sqlite_execution_context)
    service = JobExecutionService(
        sqlite_execution_context.session_factory,
        clock=lambda: OPERATION_TIME,
    )

    with pytest.raises(JobLeaseOwnershipError) as error:
        service.start_job(
            sqlite_execution_context.job_id,
            "  worker-other  ",
            LEASE_TOKEN,
        )

    assert error.value.job_id == sqlite_execution_context.job_id
    assert error.value.requested_worker_id == "worker-other"
    assert error.value.leased_by == LEASE_WORKER_ID

    persisted = sqlite_execution_context.repository.get_job(sqlite_execution_context.job_id)
    assert persisted is not None
    assert persisted.status is JobStatus.LEASED
    assert persisted.leased_by == LEASE_WORKER_ID


def test_wrong_lease_token_cannot_start_job(
    sqlite_execution_context: _SqliteExecutionContext,
) -> None:
    _prepare_lease(sqlite_execution_context)
    service = JobExecutionService(
        sqlite_execution_context.session_factory,
        clock=lambda: OPERATION_TIME,
    )

    with pytest.raises(JobLeaseTokenMismatchError) as error:
        service.start_job(
            sqlite_execution_context.job_id,
            LEASE_WORKER_ID,
            OTHER_LEASE_TOKEN,
        )

    assert error.value.job_id == sqlite_execution_context.job_id
    persisted = sqlite_execution_context.repository.get_job(sqlite_execution_context.job_id)
    assert persisted is not None
    assert persisted.status is JobStatus.LEASED
    assert persisted.leased_by == LEASE_WORKER_ID
    assert persisted.lease_token == LEASE_TOKEN
    assert persisted.started_at is None


def test_expired_lease_cannot_start_job(
    sqlite_execution_context: _SqliteExecutionContext,
) -> None:
    _prepare_lease(
        sqlite_execution_context,
        lease_expires_at=OPERATION_TIME,
    )
    service = JobExecutionService(
        sqlite_execution_context.session_factory,
        clock=lambda: OPERATION_TIME,
    )

    with pytest.raises(JobLeaseExpiredError) as error:
        service.start_job(
            sqlite_execution_context.job_id,
            LEASE_WORKER_ID,
            LEASE_TOKEN,
        )

    assert error.value.job_id == sqlite_execution_context.job_id
    assert error.value.operation_time == OPERATION_TIME
    assert _without_timezone(error.value.lease_expires_at) == _without_timezone(OPERATION_TIME)

    persisted = sqlite_execution_context.repository.get_job(sqlite_execution_context.job_id)
    assert persisted is not None
    assert persisted.status is JobStatus.LEASED


def test_cancel_requested_job_cannot_start(
    sqlite_execution_context: _SqliteExecutionContext,
) -> None:
    _prepare_lease(
        sqlite_execution_context,
        cancel_requested=True,
    )
    service = JobExecutionService(
        sqlite_execution_context.session_factory,
        clock=lambda: OPERATION_TIME,
    )

    with pytest.raises(JobCancellationRequestedError) as error:
        service.start_job(
            sqlite_execution_context.job_id,
            LEASE_WORKER_ID,
            LEASE_TOKEN,
        )

    assert error.value.job_id == sqlite_execution_context.job_id

    persisted = sqlite_execution_context.repository.get_job(sqlite_execution_context.job_id)
    assert persisted is not None
    assert persisted.status is JobStatus.LEASED


def test_lease_owner_starts_job_and_sets_timestamps(
    sqlite_execution_context: _SqliteExecutionContext,
) -> None:
    lease_expires_at = _prepare_lease(sqlite_execution_context)
    service = JobExecutionService(
        sqlite_execution_context.session_factory,
        clock=lambda: OPERATION_TIME,
    )

    started = service.start_job(
        sqlite_execution_context.job_id,
        f"  {LEASE_WORKER_ID}  ",
        f"  {LEASE_TOKEN}  ",
    )

    assert isinstance(started, JobRecord)
    assert started.status is JobStatus.RUNNING
    assert started.leased_by == LEASE_WORKER_ID
    assert started.lease_token == LEASE_TOKEN
    assert started.attempt_count == 1
    assert _without_timezone(started.started_at) == _without_timezone(OPERATION_TIME)
    assert _without_timezone(started.heartbeat_at) == _without_timezone(OPERATION_TIME)
    assert started.finished_at is None
    assert _without_timezone(started.lease_expires_at) == _without_timezone(lease_expires_at)

    with pytest.raises(JobStateConflictError):
        service.start_job(
            sqlite_execution_context.job_id,
            LEASE_WORKER_ID,
            LEASE_TOKEN,
        )

    persisted = sqlite_execution_context.repository.get_job(sqlite_execution_context.job_id)
    assert persisted is not None
    assert persisted.status is JobStatus.RUNNING
    assert persisted.leased_by == started.leased_by
    assert persisted.lease_token == started.lease_token
    assert persisted.attempt_count == started.attempt_count
    assert persisted.started_at == started.started_at
    assert persisted.heartbeat_at == started.heartbeat_at
    assert persisted.lease_expires_at == started.lease_expires_at
