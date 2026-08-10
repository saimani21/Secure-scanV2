from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from securescan.config import Settings
from securescan.domain.enums import JobStatus, RunStatus, TargetType
from securescan.jobs import (
    IdempotencyConflictError,
    JobSubmissionError,
    JobSubmissionRequest,
    JobSubmissionResult,
    JobSubmissionService,
    TargetNotFoundError,
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
def submission_context(
    tmp_path: Path,
) -> Iterator[tuple[JobSubmissionService, sessionmaker[Session], str]]:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'job-submission.db'}",
        artifact_root=tmp_path / "artifacts",
    )
    initialize_database(settings)
    engine, session_factory = create_session_factory(settings)

    with session_factory.begin() as session:
        project = ProjectRow(name="Job submission test")
        target = TargetRow(
            project=project,
            target_type=TargetType.SOURCE_REPOSITORY.value,
            content_digest="b" * 64,
            source_path="/tmp/submission-target",
        )
        session.add(target)
        session.flush()
        target_id = target.id

    try:
        yield JobSubmissionService(session_factory), session_factory, target_id
    finally:
        engine.dispose()


def test_submit_creates_queued_run_and_job_atomically(
    submission_context: tuple[JobSubmissionService, sessionmaker[Session], str],
) -> None:
    service, session_factory, target_id = submission_context
    request = JobSubmissionRequest(
        target_id=target_id,
        adapter_id="fake-scanner",
        idempotency_key="c" * 64,
        payload_json={"mode": "findings"},
        priority=25,
        max_attempts=5,
    )

    result = service.submit(request)

    assert isinstance(result, JobSubmissionResult)
    assert result.created is True
    assert result.status is JobStatus.QUEUED

    with session_factory() as session:
        runs = list(session.scalars(select(AnalysisRunRow)))
        jobs = list(session.scalars(select(JobRow)))

        assert len(runs) == 1
        assert len(jobs) == 1

        run = runs[0]
        job = jobs[0]
        assert run.id == result.run_id
        assert run.target_id == target_id
        assert run.status == RunStatus.QUEUED.value
        assert job.id == result.job_id
        assert job.run_id == run.id
        assert job.status == JobStatus.QUEUED.value
        assert job.adapter_id == request.adapter_id
        assert job.priority == request.priority
        assert job.max_attempts == request.max_attempts
        assert job.idempotency_key == request.idempotency_key
        assert job.payload_json == request.payload_json


def test_repeated_identical_submission_returns_existing_job(
    submission_context: tuple[JobSubmissionService, sessionmaker[Session], str],
) -> None:
    service, session_factory, target_id = submission_context
    request = JobSubmissionRequest(
        target_id=target_id,
        adapter_id="fake-scanner",
        idempotency_key="d" * 64,
        payload_json={"mode": "findings"},
    )

    first = service.submit(request)
    second = service.submit(request)

    assert first.created is True
    assert second.created is False
    assert second.run_id == first.run_id
    assert second.job_id == first.job_id

    with session_factory() as session:
        run_count = session.scalar(select(func.count()).select_from(AnalysisRunRow))
        job_count = session.scalar(select(func.count()).select_from(JobRow))
        assert run_count == 1
        assert job_count == 1


def test_reused_key_with_different_payload_raises_conflict(
    submission_context: tuple[JobSubmissionService, sessionmaker[Session], str],
) -> None:
    service, session_factory, target_id = submission_context
    idempotency_key = "e" * 64
    service.submit(
        JobSubmissionRequest(
            target_id=target_id,
            adapter_id="fake-scanner",
            idempotency_key=idempotency_key,
            payload_json={"mode": "original"},
        )
    )

    with pytest.raises(IdempotencyConflictError) as error:
        service.submit(
            JobSubmissionRequest(
                target_id=target_id,
                adapter_id="fake-scanner",
                idempotency_key=idempotency_key,
                payload_json={"mode": "different"},
            )
        )

    assert error.value.idempotency_key == idempotency_key

    with session_factory() as session:
        run_count = session.scalar(select(func.count()).select_from(AnalysisRunRow))
        jobs = list(session.scalars(select(JobRow)))
        assert run_count == 1
        assert len(jobs) == 1
        assert jobs[0].payload_json == {"mode": "original"}


def test_unknown_target_is_rejected_without_partial_rows(
    submission_context: tuple[JobSubmissionService, sessionmaker[Session], str],
) -> None:
    service, session_factory, _ = submission_context
    target_id = str(uuid4())

    with pytest.raises(TargetNotFoundError) as error:
        service.submit(
            JobSubmissionRequest(
                target_id=target_id,
                adapter_id="fake-scanner",
                idempotency_key="f" * 64,
            )
        )

    assert error.value.target_id == target_id

    with session_factory() as session:
        run_count = session.scalar(select(func.count()).select_from(AnalysisRunRow))
        job_count = session.scalar(select(func.count()).select_from(JobRow))
        assert run_count == 0
        assert job_count == 0


def test_failed_job_insert_rolls_back_created_run(
    submission_context: tuple[JobSubmissionService, sessionmaker[Session], str],
) -> None:
    service, session_factory, target_id = submission_context
    idempotency_key = "0" * 64

    with pytest.raises(JobSubmissionError):
        service.submit(
            JobSubmissionRequest(
                target_id=target_id,
                adapter_id="fake-scanner",
                idempotency_key=idempotency_key,
                priority=-1,
            )
        )

    with session_factory() as session:
        run_count = session.scalar(select(func.count()).select_from(AnalysisRunRow))
        job_count = session.scalar(select(func.count()).select_from(JobRow))
        assert run_count == 0
        assert job_count == 0

    result = service.submit(
        JobSubmissionRequest(
            target_id=target_id,
            adapter_id="fake-scanner",
            idempotency_key=idempotency_key,
        )
    )
    assert result.created is True
    assert result.status is JobStatus.QUEUED


def test_submission_defensively_copies_payload(
    submission_context: tuple[JobSubmissionService, sessionmaker[Session], str],
) -> None:
    service, session_factory, target_id = submission_context
    payload = {
        "mode": "findings",
        "options": {"depth": 2},
    }
    result = service.submit(
        JobSubmissionRequest(
            target_id=target_id,
            adapter_id="fake-scanner",
            idempotency_key="1" * 64,
            payload_json=payload,
        )
    )

    payload["options"]["depth"] = 99

    with session_factory() as session:
        job = session.get(JobRow, result.job_id)
        assert job is not None
        assert job.payload_json["options"]["depth"] == 2
