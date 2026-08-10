from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.domain.enums import JobStatus, RunStatus
from securescan.domain.job_state import InvalidJobTransition, validate_job_transition
from securescan.jobs.models import JobSubmissionRequest, JobSubmissionResult
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    TargetRow,
    utc_now,
)


class JobSubmissionError(RuntimeError):
    """Raised when a job submission persistence operation fails."""


class TargetNotFoundError(JobSubmissionError):
    """Raised when a submission target does not exist."""

    def __init__(self, target_id: str) -> None:
        self.target_id = target_id
        super().__init__(f"Target {target_id!r} was not found")


class IdempotencyConflictError(JobSubmissionError):
    """Raised when an idempotency key is reused for a different submission."""

    def __init__(self, idempotency_key: str) -> None:
        self.idempotency_key = idempotency_key
        super().__init__(
            f"Idempotency key {idempotency_key!r} was reused for a different submission"
        )


@dataclass(frozen=True, slots=True)
class _PersistedSubmission:
    run_id: str
    job_id: str
    status: JobStatus
    target_id: str
    adapter_id: str
    payload_json: dict[str, Any]
    priority: int
    max_attempts: int


def _find_submission(
    session: Session,
    idempotency_key: str,
) -> _PersistedSubmission | None:
    row = session.execute(
        select(
            JobRow.id,
            JobRow.run_id,
            JobRow.status,
            AnalysisRunRow.target_id,
            JobRow.adapter_id,
            JobRow.payload_json,
            JobRow.priority,
            JobRow.max_attempts,
        )
        .join(
            AnalysisRunRow,
            JobRow.run_id == AnalysisRunRow.id,
        )
        .where(JobRow.idempotency_key == idempotency_key)
    ).one_or_none()

    if row is None:
        return None

    (
        job_id,
        run_id,
        status,
        target_id,
        adapter_id,
        payload_json,
        priority,
        max_attempts,
    ) = row

    return _PersistedSubmission(
        run_id=run_id,
        job_id=job_id,
        status=JobStatus(status),
        target_id=target_id,
        adapter_id=adapter_id,
        payload_json=deepcopy(payload_json),
        priority=priority,
        max_attempts=max_attempts,
    )


def _result_for_existing_submission(
    request: JobSubmissionRequest,
    existing: _PersistedSubmission,
) -> JobSubmissionResult:
    matches = (
        existing.target_id == request.target_id
        and existing.adapter_id == request.adapter_id
        and existing.payload_json == deepcopy(request.payload_json)
        and existing.priority == request.priority
        and existing.max_attempts == request.max_attempts
    )
    if not matches:
        raise IdempotencyConflictError(request.idempotency_key)

    return JobSubmissionResult(
        run_id=existing.run_id,
        job_id=existing.job_id,
        status=existing.status,
        idempotency_key=request.idempotency_key,
        created=False,
    )


class JobSubmissionService:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def submit(self, request: JobSubmissionRequest) -> JobSubmissionResult:
        try:
            with self._session_factory.begin() as session:
                existing = _find_submission(session, request.idempotency_key)
                if existing is not None:
                    result = _result_for_existing_submission(request, existing)
                else:
                    target = session.get(TargetRow, request.target_id)
                    if target is None:
                        raise TargetNotFoundError(request.target_id)

                    run = AnalysisRunRow(
                        target_id=request.target_id,
                        status=RunStatus.QUEUED.value,
                    )
                    session.add(run)
                    session.flush()

                    job = JobRow(
                        run_id=run.id,
                        adapter_id=request.adapter_id,
                        idempotency_key=request.idempotency_key,
                        payload_json=deepcopy(request.payload_json),
                        priority=request.priority,
                        max_attempts=request.max_attempts,
                    )
                    session.add(job)
                    session.flush()

                    validate_job_transition(
                        JobStatus.SUBMITTED,
                        JobStatus.QUEUED,
                    )
                    operation_timestamp = utc_now()
                    job.status = JobStatus.QUEUED.value
                    job.updated_at = operation_timestamp
                    session.flush()

                    result = JobSubmissionResult(
                        run_id=run.id,
                        job_id=job.id,
                        status=JobStatus(job.status),
                        idempotency_key=job.idempotency_key,
                        created=True,
                    )
        except (TargetNotFoundError, IdempotencyConflictError, InvalidJobTransition):
            raise
        except IntegrityError as exc:
            try:
                with self._session_factory() as session:
                    existing = _find_submission(session, request.idempotency_key)
                    if existing is None:
                        raise JobSubmissionError("Failed to submit job") from exc

                    return _result_for_existing_submission(request, existing)
            except IdempotencyConflictError:
                raise
            except SQLAlchemyError:
                raise JobSubmissionError("Failed to submit job") from exc
        except SQLAlchemyError as exc:
            raise JobSubmissionError("Failed to submit job") from exc

        return result
