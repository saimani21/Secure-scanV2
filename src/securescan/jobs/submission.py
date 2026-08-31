from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.domain.enums import JobStatus, RunStatus
from securescan.domain.job_state import InvalidJobTransition, validate_job_transition
from securescan.jobs.models import (
    RESERVED_INTERNAL_JOB_PAYLOAD_PREFIX,
    JobSubmissionRequest,
    JobSubmissionResult,
    ServerOwnedJobSubmissionRequest,
)
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


class ReservedJobPayloadError(JobSubmissionError, ValueError):
    def __init__(self) -> None:
        super().__init__("Reserved internal job payload is not allowed")


class TargetContentDigestMismatchError(JobSubmissionError):
    def __init__(self) -> None:
        super().__init__("Target content identity does not match the trusted submission")


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
    request: JobSubmissionRequest | ServerOwnedJobSubmissionRequest,
    existing: _PersistedSubmission,
) -> JobSubmissionResult:
    matches = (
        existing.target_id == request.target_id
        and existing.adapter_id == request.adapter_id
        and existing.payload_json == deepcopy(request.payload_json)
        and existing.priority == request.priority
        and existing.max_attempts == request.max_attempts
    )
    if isinstance(request, ServerOwnedJobSubmissionRequest):
        matches = (
            matches
            and existing.run_id == request.run_id
            and existing.job_id == request.job_id
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


def _contains_reserved_payload_key(payload: object) -> bool:
    pending = [payload]
    visited: set[int] = set()
    while pending:
        value = pending.pop()
        if id(value) in visited:
            continue
        visited.add(id(value))
        if isinstance(value, dict):
            for key, child in value.items():
                if isinstance(key, str) and key.startswith(
                    RESERVED_INTERNAL_JOB_PAYLOAD_PREFIX
                ):
                    return True
                pending.append(child)
        elif isinstance(value, list):
            pending.extend(value)
    return False


def _canonical_uuid(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 36 or value != value.lower():
        return False
    try:
        return str(UUID(value)) == value
    except ValueError:
        return False


class JobSubmissionService:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def submit(self, request: JobSubmissionRequest) -> JobSubmissionResult:
        if not isinstance(request, JobSubmissionRequest):
            raise JobSubmissionError("Job submission request is invalid")
        if _contains_reserved_payload_key(request.payload_json):
            raise ReservedJobPayloadError
        return self._submit(request)

    def submit_server_owned(
        self,
        request: ServerOwnedJobSubmissionRequest,
    ) -> JobSubmissionResult:
        if (
            not isinstance(request, ServerOwnedJobSubmissionRequest)
            or not _canonical_uuid(request.run_id)
            or not _canonical_uuid(request.job_id)
            or not isinstance(request.payload_json, dict)
            or not request.payload_json
            or any(
                not isinstance(key, str)
                or not key.startswith(RESERVED_INTERNAL_JOB_PAYLOAD_PREFIX)
                for key in request.payload_json
            )
        ):
            raise JobSubmissionError("Server-owned job submission request is invalid")
        return self._submit(request)

    def _submit(
        self,
        request: JobSubmissionRequest | ServerOwnedJobSubmissionRequest,
    ) -> JobSubmissionResult:
        try:
            with self._session_factory.begin() as session:
                existing = _find_submission(session, request.idempotency_key)
                if existing is not None:
                    result = _result_for_existing_submission(request, existing)
                else:
                    target = session.get(TargetRow, request.target_id)
                    if target is None:
                        raise TargetNotFoundError(request.target_id)
                    if (
                        isinstance(request, ServerOwnedJobSubmissionRequest)
                        and target.content_digest
                        != request.expected_target_content_digest
                    ):
                        raise TargetContentDigestMismatchError

                    if isinstance(request, ServerOwnedJobSubmissionRequest):
                        run = AnalysisRunRow(
                            id=request.run_id,
                            target_id=request.target_id,
                            status=RunStatus.QUEUED.value,
                        )
                    else:
                        run = AnalysisRunRow(
                            target_id=request.target_id,
                            status=RunStatus.QUEUED.value,
                        )
                    session.add(run)
                    session.flush()

                    if isinstance(request, ServerOwnedJobSubmissionRequest):
                        job = JobRow(
                            id=request.job_id,
                            run_id=run.id,
                            adapter_id=request.adapter_id,
                            idempotency_key=request.idempotency_key,
                            payload_json=deepcopy(request.payload_json),
                            priority=request.priority,
                            max_attempts=request.max_attempts,
                        )
                    else:
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
        except (
            TargetNotFoundError,
            TargetContentDigestMismatchError,
            IdempotencyConflictError,
            InvalidJobTransition,
        ):
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
