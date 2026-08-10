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
    InvalidJobFinalStatusError,
    JobCancellationRequestedError,
    JobExecutionService,
    JobFinalizationService,
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

T0 = datetime(2036, 1, 2, 3, 4, 5, tzinfo=UTC)
FINALIZATION_TIME = T0 + timedelta(seconds=10)
WORKER_ID = "finalization-worker"
LEASE_TOKEN = str(UUID("00000000-0000-4000-8000-000000000050"))
OTHER_LEASE_TOKEN = str(UUID("00000000-0000-4000-8000-000000000051"))


@dataclass(frozen=True, slots=True)
class _SqliteFinalizationContext:
    session_factory: sessionmaker[Session]
    repository: JobRepository
    job_id: str


@pytest.fixture
def sqlite_finalization_context(
    tmp_path: Path,
) -> Iterator[_SqliteFinalizationContext]:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'job-finalization.db'}",
        artifact_root=tmp_path / "artifacts",
    )
    initialize_database(settings)
    engine, session_factory = create_session_factory(settings)

    with session_factory.begin() as session:
        project = ProjectRow(name="Job finalization test")
        target = TargetRow(
            project=project,
            target_type=TargetType.SOURCE_REPOSITORY.value,
            content_digest="b" * 64,
            source_path="/tmp/job-finalization-target",
        )
        session.add(target)
        session.flush()
        target_id = target.id

    submitted = JobSubmissionService(session_factory).submit(
        JobSubmissionRequest(
            target_id=target_id,
            adapter_id="fake-scanner",
            idempotency_key="c" * 64,
        )
    )

    try:
        yield _SqliteFinalizationContext(
            session_factory=session_factory,
            repository=JobRepository(session_factory),
            job_id=submitted.job_id,
        )
    finally:
        engine.dispose()


def _prepare_leased_job(context: _SqliteFinalizationContext) -> JobRecord:
    context.repository.transition_job(
        job_id=context.job_id,
        expected_status=JobStatus.QUEUED,
        requested_status=JobStatus.LEASED,
    )
    with context.session_factory.begin() as session:
        row = session.get(JobRow, context.job_id)
        assert row is not None
        row.leased_by = WORKER_ID
        row.lease_token = LEASE_TOKEN
        row.heartbeat_at = T0 - timedelta(seconds=5)
        row.lease_expires_at = T0 + timedelta(seconds=60)
        row.attempt_count = 1
        row.last_error = "previous transient error"

    leased = context.repository.get_job(context.job_id)
    assert leased is not None
    return leased


def _prepare_running_job(context: _SqliteFinalizationContext) -> JobRecord:
    _prepare_leased_job(context)
    return JobExecutionService(
        context.session_factory,
        clock=lambda: T0,
    ).start_job(context.job_id, WORKER_ID, LEASE_TOKEN)


def _without_timezone(timestamp: datetime | None) -> datetime | None:
    if timestamp is None:
        return None
    return timestamp.replace(tzinfo=None)


def _assert_terminal_record(
    record: JobRecord,
    expected_status: JobStatus,
    started_at: datetime | None,
) -> None:
    assert record.status is expected_status
    assert _without_timezone(record.finished_at) == _without_timezone(FINALIZATION_TIME)
    assert _without_timezone(record.heartbeat_at) >= _without_timezone(FINALIZATION_TIME)
    assert _without_timezone(record.updated_at) >= _without_timezone(FINALIZATION_TIME)
    assert record.leased_by is None
    assert record.lease_token is None
    assert record.lease_expires_at is None
    assert record.attempt_count == 1
    assert record.started_at == started_at
    assert record.cancel_requested is False
    assert record.last_error is None


def test_invalid_final_status_is_rejected(
    sqlite_finalization_context: _SqliteFinalizationContext,
) -> None:
    before = _prepare_running_job(sqlite_finalization_context)
    service = JobFinalizationService(sqlite_finalization_context.session_factory)

    with pytest.raises(InvalidJobFinalStatusError) as error:
        service.finalize_job(
            sqlite_finalization_context.job_id,
            WORKER_ID,
            LEASE_TOKEN,
            JobStatus.FAILED,
        )

    assert error.value.requested_status is JobStatus.FAILED
    assert (
        sqlite_finalization_context.repository.get_job(sqlite_finalization_context.job_id) == before
    )


def test_unknown_job_raises_not_found(
    sqlite_finalization_context: _SqliteFinalizationContext,
) -> None:
    service = JobFinalizationService(
        sqlite_finalization_context.session_factory,
        clock=lambda: FINALIZATION_TIME,
    )
    job_id = str(uuid4())

    with pytest.raises(JobNotFoundError) as error:
        service.finalize_job(
            job_id,
            WORKER_ID,
            LEASE_TOKEN,
            JobStatus.SUCCEEDED,
        )

    assert error.value.job_id == job_id


def test_nonrunning_job_raises_state_conflict(
    sqlite_finalization_context: _SqliteFinalizationContext,
) -> None:
    _prepare_leased_job(sqlite_finalization_context)
    service = JobFinalizationService(
        sqlite_finalization_context.session_factory,
        clock=lambda: FINALIZATION_TIME,
    )

    with pytest.raises(JobStateConflictError) as error:
        service.finalize_job(
            sqlite_finalization_context.job_id,
            WORKER_ID,
            LEASE_TOKEN,
            JobStatus.SUCCEEDED,
        )

    assert error.value.expected_status is JobStatus.RUNNING
    assert error.value.actual_status is JobStatus.LEASED


def test_wrong_worker_cannot_finalize_job(
    sqlite_finalization_context: _SqliteFinalizationContext,
) -> None:
    _prepare_running_job(sqlite_finalization_context)
    service = JobFinalizationService(
        sqlite_finalization_context.session_factory,
        clock=lambda: FINALIZATION_TIME,
    )

    with pytest.raises(JobLeaseOwnershipError):
        service.finalize_job(
            sqlite_finalization_context.job_id,
            "worker-other",
            LEASE_TOKEN,
            JobStatus.SUCCEEDED,
        )

    persisted = sqlite_finalization_context.repository.get_job(sqlite_finalization_context.job_id)
    assert persisted is not None
    assert persisted.status is JobStatus.RUNNING
    assert persisted.leased_by == WORKER_ID
    assert persisted.lease_token == LEASE_TOKEN


def test_wrong_token_cannot_finalize_job(
    sqlite_finalization_context: _SqliteFinalizationContext,
) -> None:
    _prepare_running_job(sqlite_finalization_context)
    service = JobFinalizationService(
        sqlite_finalization_context.session_factory,
        clock=lambda: FINALIZATION_TIME,
    )

    with pytest.raises(JobLeaseTokenMismatchError):
        service.finalize_job(
            sqlite_finalization_context.job_id,
            WORKER_ID,
            OTHER_LEASE_TOKEN,
            JobStatus.SUCCEEDED,
        )

    persisted = sqlite_finalization_context.repository.get_job(sqlite_finalization_context.job_id)
    assert persisted is not None
    assert persisted.status is JobStatus.RUNNING
    assert persisted.lease_token == LEASE_TOKEN


def test_expired_lease_cannot_finalize_job(
    sqlite_finalization_context: _SqliteFinalizationContext,
) -> None:
    _prepare_running_job(sqlite_finalization_context)
    with sqlite_finalization_context.session_factory.begin() as session:
        row = session.get(JobRow, sqlite_finalization_context.job_id)
        assert row is not None
        row.lease_expires_at = FINALIZATION_TIME

    service = JobFinalizationService(
        sqlite_finalization_context.session_factory,
        clock=lambda: FINALIZATION_TIME,
    )
    with pytest.raises(JobLeaseExpiredError):
        service.finalize_job(
            sqlite_finalization_context.job_id,
            WORKER_ID,
            LEASE_TOKEN,
            JobStatus.SUCCEEDED,
        )

    persisted = sqlite_finalization_context.repository.get_job(sqlite_finalization_context.job_id)
    assert persisted is not None
    assert persisted.status is JobStatus.RUNNING
    assert persisted.finished_at is None


def test_cancel_requested_job_cannot_finalize_successfully(
    sqlite_finalization_context: _SqliteFinalizationContext,
) -> None:
    before = _prepare_running_job(sqlite_finalization_context)
    with sqlite_finalization_context.session_factory.begin() as session:
        row = session.get(JobRow, sqlite_finalization_context.job_id)
        assert row is not None
        row.cancel_requested = True

    service = JobFinalizationService(
        sqlite_finalization_context.session_factory,
        clock=lambda: FINALIZATION_TIME,
    )
    with pytest.raises(JobCancellationRequestedError):
        service.finalize_job(
            sqlite_finalization_context.job_id,
            WORKER_ID,
            LEASE_TOKEN,
            JobStatus.SUCCEEDED,
        )

    persisted = sqlite_finalization_context.repository.get_job(sqlite_finalization_context.job_id)
    assert persisted is not None
    assert persisted.status is JobStatus.RUNNING
    assert persisted.leased_by == before.leased_by
    assert persisted.lease_token == before.lease_token
    assert persisted.lease_expires_at == before.lease_expires_at
    assert persisted.finished_at is None


def test_owner_finalizes_job_as_succeeded(
    sqlite_finalization_context: _SqliteFinalizationContext,
) -> None:
    running = _prepare_running_job(sqlite_finalization_context)
    finalized = JobFinalizationService(
        sqlite_finalization_context.session_factory,
        clock=lambda: FINALIZATION_TIME,
    ).finalize_job(
        sqlite_finalization_context.job_id,
        WORKER_ID,
        LEASE_TOKEN,
        JobStatus.SUCCEEDED,
    )

    assert isinstance(finalized, JobRecord)
    _assert_terminal_record(finalized, JobStatus.SUCCEEDED, running.started_at)
    assert (
        sqlite_finalization_context.repository.get_job(sqlite_finalization_context.job_id)
        == finalized
    )


def test_owner_finalizes_job_as_partial(
    sqlite_finalization_context: _SqliteFinalizationContext,
) -> None:
    running = _prepare_running_job(sqlite_finalization_context)
    finalized = JobFinalizationService(
        sqlite_finalization_context.session_factory,
        clock=lambda: FINALIZATION_TIME,
    ).finalize_job(
        sqlite_finalization_context.job_id,
        WORKER_ID,
        LEASE_TOKEN,
        JobStatus.PARTIAL,
    )

    _assert_terminal_record(finalized, JobStatus.PARTIAL, running.started_at)
    assert (
        sqlite_finalization_context.repository.get_job(sqlite_finalization_context.job_id)
        == finalized
    )


def test_second_finalization_is_rejected_and_terminal_state_is_unchanged(
    sqlite_finalization_context: _SqliteFinalizationContext,
) -> None:
    _prepare_running_job(sqlite_finalization_context)
    service = JobFinalizationService(
        sqlite_finalization_context.session_factory,
        clock=lambda: FINALIZATION_TIME,
    )
    first = service.finalize_job(
        sqlite_finalization_context.job_id,
        WORKER_ID,
        LEASE_TOKEN,
        JobStatus.SUCCEEDED,
    )

    with pytest.raises(JobStateConflictError) as error:
        service.finalize_job(
            sqlite_finalization_context.job_id,
            WORKER_ID,
            LEASE_TOKEN,
            JobStatus.PARTIAL,
        )

    assert error.value.expected_status is JobStatus.RUNNING
    assert error.value.actual_status is JobStatus.SUCCEEDED
    persisted = sqlite_finalization_context.repository.get_job(sqlite_finalization_context.job_id)
    assert persisted is not None
    assert persisted.status is JobStatus.SUCCEEDED
    assert persisted.finished_at == first.finished_at
    assert persisted.leased_by is None
    assert persisted.lease_token is None
    assert persisted.lease_expires_at is None
