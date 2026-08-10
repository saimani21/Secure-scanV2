from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from securescan.config import Settings
from securescan.domain.enums import JobStatus, RunStatus, TargetType
from securescan.domain.job_state import InvalidJobTransition
from securescan.jobs import (
    DuplicateJobError,
    JobCreate,
    JobNotFoundError,
    JobRecord,
    JobRepository,
    JobRepositoryError,
    JobStateConflictError,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    ProjectRow,
    TargetRow,
    create_session_factory,
    initialize_database,
)


@pytest.fixture
def repository_context(
    tmp_path: Path,
) -> Iterator[tuple[JobRepository, sessionmaker[Session], str]]:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'job-repository.db'}",
        artifact_root=tmp_path / "artifacts",
    )
    initialize_database(settings)
    engine, session_factory = create_session_factory(settings)

    with session_factory.begin() as session:
        project = ProjectRow(name="Job repository test")
        target = TargetRow(
            project=project,
            target_type=TargetType.SOURCE_REPOSITORY.value,
            content_digest="a" * 64,
            source_path="/tmp/repository",
        )
        run = AnalysisRunRow(
            target=target,
            status=RunStatus.QUEUED.value,
        )
        session.add(run)
        session.flush()
        run_id = run.id

    try:
        yield JobRepository(session_factory), session_factory, run_id
    finally:
        engine.dispose()


def test_create_job_persists_submitted_job(
    repository_context: tuple[JobRepository, sessionmaker[Session], str],
) -> None:
    repository, session_factory, run_id = repository_context
    payload = {
        "mode": "findings",
        "options": {"depth": 2},
    }

    record = repository.create_job(
        JobCreate(
            run_id=run_id,
            adapter_id="fake-scanner",
            idempotency_key="1" * 64,
            payload_json=payload,
        )
    )

    assert isinstance(record, JobRecord)
    assert record.status is JobStatus.SUBMITTED
    assert record.attempt_count == 0
    assert record.cancel_requested is False
    assert record.priority == 100
    assert record.max_attempts == 3
    assert record.payload_json == payload
    assert str(UUID(record.id)) == record.id
    assert record.available_at is not None
    assert record.created_at is not None
    assert record.updated_at is not None

    payload["options"]["depth"] = 99
    assert record.payload_json["options"]["depth"] == 2
    record.payload_json["options"]["depth"] = 7

    with session_factory() as session:
        row = session.get(JobRow, record.id)
        assert row is not None
        assert row.payload_json["options"]["depth"] == 2


def test_get_job_returns_detached_record(
    repository_context: tuple[JobRepository, sessionmaker[Session], str],
) -> None:
    repository, _, run_id = repository_context
    created = repository.create_job(
        JobCreate(
            run_id=run_id,
            adapter_id="fake-scanner",
            idempotency_key="2" * 64,
            payload_json={"mode": "detached"},
        )
    )

    retrieved = repository.get_job(created.id)

    assert isinstance(retrieved, JobRecord)
    assert retrieved == created
    assert retrieved.status is JobStatus.SUBMITTED
    assert retrieved.payload_json == {"mode": "detached"}


def test_get_job_returns_none_for_unknown_id(
    repository_context: tuple[JobRepository, sessionmaker[Session], str],
) -> None:
    repository, _, _ = repository_context

    assert repository.get_job(str(uuid4())) is None


def test_get_by_idempotency_key_returns_created_job(
    repository_context: tuple[JobRepository, sessionmaker[Session], str],
) -> None:
    repository, _, run_id = repository_context
    idempotency_key = "3" * 64
    created = repository.create_job(
        JobCreate(
            run_id=run_id,
            adapter_id="fake-scanner",
            idempotency_key=idempotency_key,
        )
    )

    retrieved = repository.get_by_idempotency_key(idempotency_key)

    assert retrieved == created


def test_duplicate_idempotency_key_raises_domain_error(
    repository_context: tuple[JobRepository, sessionmaker[Session], str],
) -> None:
    repository, session_factory, run_id = repository_context
    idempotency_key = "4" * 64
    job = JobCreate(
        run_id=run_id,
        adapter_id="fake-scanner",
        idempotency_key=idempotency_key,
    )
    repository.create_job(job)

    with pytest.raises(DuplicateJobError) as error:
        repository.create_job(job)

    assert error.value.idempotency_key == idempotency_key

    with session_factory() as session:
        matching_jobs = session.scalar(
            select(func.count())
            .select_from(JobRow)
            .where(JobRow.idempotency_key == idempotency_key)
        )
        assert matching_jobs == 1


def test_failed_create_rolls_back_and_repository_remains_usable(
    repository_context: tuple[JobRepository, sessionmaker[Session], str],
) -> None:
    repository, session_factory, run_id = repository_context
    idempotency_key = "5" * 64
    invalid_job = JobCreate(
        run_id="00000000-0000-0000-0000-000000000000",
        adapter_id="fake-scanner",
        idempotency_key=idempotency_key,
    )

    with pytest.raises(JobRepositoryError) as error:
        repository.create_job(invalid_job)

    assert not isinstance(error.value, DuplicateJobError)

    with session_factory() as session:
        invalid_jobs = session.scalar(
            select(func.count())
            .select_from(JobRow)
            .where(JobRow.idempotency_key == idempotency_key)
        )
        assert invalid_jobs == 0

    created = repository.create_job(
        JobCreate(
            run_id=run_id,
            adapter_id="fake-scanner",
            idempotency_key=idempotency_key,
        )
    )

    assert created.status is JobStatus.SUBMITTED


def test_transition_job_updates_submitted_to_queued(
    repository_context: tuple[JobRepository, sessionmaker[Session], str],
) -> None:
    repository, _, run_id = repository_context
    created = repository.create_job(
        JobCreate(
            run_id=run_id,
            adapter_id="fake-scanner",
            idempotency_key="6" * 64,
        )
    )

    transitioned = repository.transition_job(
        job_id=created.id,
        expected_status=JobStatus.SUBMITTED,
        requested_status=JobStatus.QUEUED,
    )

    assert isinstance(transitioned, JobRecord)
    assert transitioned.status is JobStatus.QUEUED
    assert transitioned.updated_at is not None

    retrieved = repository.get_job(created.id)
    assert retrieved is not None
    assert retrieved.status is JobStatus.QUEUED


def test_transition_job_supports_legal_execution_chain(
    repository_context: tuple[JobRepository, sessionmaker[Session], str],
) -> None:
    repository, _, run_id = repository_context
    record = repository.create_job(
        JobCreate(
            run_id=run_id,
            adapter_id="fake-scanner",
            idempotency_key="7" * 64,
        )
    )

    for expected_status, requested_status in (
        (JobStatus.SUBMITTED, JobStatus.QUEUED),
        (JobStatus.QUEUED, JobStatus.LEASED),
        (JobStatus.LEASED, JobStatus.RUNNING),
        (JobStatus.RUNNING, JobStatus.SUCCEEDED),
    ):
        record = repository.transition_job(
            job_id=record.id,
            expected_status=expected_status,
            requested_status=requested_status,
        )

    assert record.status is JobStatus.SUCCEEDED


def test_transition_job_rejects_illegal_transition(
    repository_context: tuple[JobRepository, sessionmaker[Session], str],
) -> None:
    repository, _, run_id = repository_context
    created = repository.create_job(
        JobCreate(
            run_id=run_id,
            adapter_id="fake-scanner",
            idempotency_key="8" * 64,
        )
    )

    with pytest.raises(InvalidJobTransition):
        repository.transition_job(
            job_id=created.id,
            expected_status=JobStatus.SUBMITTED,
            requested_status=JobStatus.RUNNING,
        )

    persisted = repository.get_job(created.id)
    assert persisted is not None
    assert persisted.status is JobStatus.SUBMITTED


def test_transition_job_rejects_stale_expected_status(
    repository_context: tuple[JobRepository, sessionmaker[Session], str],
) -> None:
    repository, _, run_id = repository_context
    created = repository.create_job(
        JobCreate(
            run_id=run_id,
            adapter_id="fake-scanner",
            idempotency_key="9" * 64,
        )
    )
    repository.transition_job(
        job_id=created.id,
        expected_status=JobStatus.SUBMITTED,
        requested_status=JobStatus.QUEUED,
    )

    with pytest.raises(JobStateConflictError) as error:
        repository.transition_job(
            job_id=created.id,
            expected_status=JobStatus.SUBMITTED,
            requested_status=JobStatus.CANCELLED,
        )

    assert error.value.job_id == created.id
    assert error.value.expected_status is JobStatus.SUBMITTED
    assert error.value.actual_status is JobStatus.QUEUED

    persisted = repository.get_job(created.id)
    assert persisted is not None
    assert persisted.status is JobStatus.QUEUED


def test_transition_job_raises_not_found_for_unknown_job(
    repository_context: tuple[JobRepository, sessionmaker[Session], str],
) -> None:
    repository, _, _ = repository_context
    job_id = str(uuid4())

    with pytest.raises(JobNotFoundError) as error:
        repository.transition_job(
            job_id=job_id,
            expected_status=JobStatus.SUBMITTED,
            requested_status=JobStatus.QUEUED,
        )

    assert error.value.job_id == job_id


def test_transition_job_sets_lifecycle_timestamps(
    repository_context: tuple[JobRepository, sessionmaker[Session], str],
) -> None:
    repository, _, run_id = repository_context
    record = repository.create_job(
        JobCreate(
            run_id=run_id,
            adapter_id="fake-scanner",
            idempotency_key="a" * 64,
        )
    )
    record = repository.transition_job(
        job_id=record.id,
        expected_status=JobStatus.SUBMITTED,
        requested_status=JobStatus.QUEUED,
    )
    record = repository.transition_job(
        job_id=record.id,
        expected_status=JobStatus.QUEUED,
        requested_status=JobStatus.LEASED,
    )
    running = repository.transition_job(
        job_id=record.id,
        expected_status=JobStatus.LEASED,
        requested_status=JobStatus.RUNNING,
    )

    assert running.started_at is not None
    assert running.finished_at is None
    started_at = running.started_at

    succeeded = repository.transition_job(
        job_id=running.id,
        expected_status=JobStatus.RUNNING,
        requested_status=JobStatus.SUCCEEDED,
    )

    assert succeeded.started_at == started_at
    assert succeeded.finished_at is not None


def test_terminal_job_cannot_transition_again(
    repository_context: tuple[JobRepository, sessionmaker[Session], str],
) -> None:
    repository, _, run_id = repository_context
    record = repository.create_job(
        JobCreate(
            run_id=run_id,
            adapter_id="fake-scanner",
            idempotency_key="b" * 64,
        )
    )

    for expected_status, requested_status in (
        (JobStatus.SUBMITTED, JobStatus.QUEUED),
        (JobStatus.QUEUED, JobStatus.LEASED),
        (JobStatus.LEASED, JobStatus.RUNNING),
        (JobStatus.RUNNING, JobStatus.SUCCEEDED),
    ):
        record = repository.transition_job(
            job_id=record.id,
            expected_status=expected_status,
            requested_status=requested_status,
        )

    with pytest.raises(InvalidJobTransition):
        repository.transition_job(
            job_id=record.id,
            expected_status=JobStatus.SUCCEEDED,
            requested_status=JobStatus.QUEUED,
        )

    persisted = repository.get_job(record.id)
    assert persisted is not None
    assert persisted.status is JobStatus.SUCCEEDED
