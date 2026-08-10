from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import case, func, or_, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.domain.enums import JobStatus
from securescan.domain.job_state import InvalidJobTransition, validate_job_transition
from securescan.jobs.execution import (
    InvalidLeaseTokenError,
    InvalidWorkerRequestError,
    JobLeaseExpiredError,
    JobLeaseOwnershipError,
    JobLeaseTokenMismatchError,
    _comparable_timestamp,
    _normalize_lease_token,
    _normalize_worker_id,
)
from securescan.jobs.leasing import UnsupportedQueueDatabaseError
from securescan.jobs.mappers import job_record_from_row
from securescan.jobs.models import JobRecord
from securescan.jobs.repository import JobNotFoundError
from securescan.jobs.result_commit import AnalysisRunNotFoundError
from securescan.persistence.database import AnalysisRunRow, JobRow, utc_now
from securescan.runs.aggregation import recompute_analysis_run_status

_ACTIVE_STATUSES = frozenset({JobStatus.LEASED, JobStatus.RUNNING})
_COMPLETED_STATUSES = frozenset(
    {
        JobStatus.SUCCEEDED,
        JobStatus.PARTIAL,
        JobStatus.FAILED,
    }
)
_IMMEDIATE_STATUSES = frozenset(
    {
        JobStatus.SUBMITTED,
        JobStatus.QUEUED,
        JobStatus.RETRY_PENDING,
    }
)
_UNSET = object()


@dataclass(frozen=True, slots=True)
class JobCancellationRequestResult:
    job: JobRecord
    immediate: bool
    already_requested: bool


@dataclass(frozen=True, slots=True)
class ExpiredCancellationResult:
    job: JobRecord
    previous_status: JobStatus


class JobCancellationError(RuntimeError):
    """Raised when a cooperative cancellation operation fails."""


class InvalidCancellationRequestError(JobCancellationError):
    """Raised when a cancellation job ID or finalizer limit is invalid."""

    def __init__(
        self,
        *,
        job_id: object = _UNSET,
        limit: object = _UNSET,
    ) -> None:
        self.job_id = None if job_id is _UNSET else job_id
        self.limit = None if limit is _UNSET else limit
        if limit is not _UNSET:
            message = "Cancellation finalizer limit must be an integer from 1 through 1000"
        else:
            message = "Cancellation job ID must be a canonical UUID string"
        super().__init__(message)


class JobCancellationConflictError(JobCancellationError):
    """Raised when a job cannot be cancelled from its current state."""

    def __init__(self, job_id: str, actual_status: JobStatus) -> None:
        self.job_id = job_id
        self.actual_status = actual_status
        super().__init__(f"Job {job_id!r} cannot be cancelled from status {actual_status.value!r}")


class JobCancellationNotRequestedError(JobCancellationError):
    """Raised when a worker acknowledges a cancellation that was not requested."""

    def __init__(self, job_id: str) -> None:
        self.job_id = job_id
        super().__init__(f"Job {job_id!r} does not have cancellation requested")


def _normalize_job_id(job_id: str) -> str:
    if not isinstance(job_id, str):
        raise InvalidCancellationRequestError(job_id=job_id)
    normalized_job_id = job_id.strip()
    if len(normalized_job_id) != 36 or normalized_job_id != normalized_job_id.lower():
        raise InvalidCancellationRequestError(job_id=job_id)
    try:
        parsed_job_id = UUID(normalized_job_id)
    except ValueError as exc:
        raise InvalidCancellationRequestError(job_id=job_id) from exc
    if str(parsed_job_id) != normalized_job_id:
        raise InvalidCancellationRequestError(job_id=job_id)
    return normalized_job_id


def _monotonic_timestamp(current: datetime, requested: datetime) -> datetime:
    if _comparable_timestamp(current) < _comparable_timestamp(requested):
        return requested
    return current


def _monotonic_update(column, operation_timestamp: datetime):
    return case(
        (column.is_(None), operation_timestamp),
        (column < operation_timestamp, operation_timestamp),
        else_=column,
    )


class JobCancellationService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._session_factory = session_factory
        self._clock = clock

    def request_cancellation(
        self,
        job_id: str,
    ) -> JobCancellationRequestResult:
        normalized_job_id = _normalize_job_id(job_id)
        operation_timestamp = self._clock()

        try:
            with self._session_factory.begin() as session:
                row = session.scalar(
                    select(JobRow).where(JobRow.id == normalized_job_id).with_for_update()
                )
                if row is None:
                    raise JobNotFoundError(normalized_job_id)

                status = JobStatus(row.status)
                if status is JobStatus.CANCELLED:
                    result = JobCancellationRequestResult(
                        job=job_record_from_row(row),
                        immediate=True,
                        already_requested=True,
                    )
                elif status in _COMPLETED_STATUSES:
                    raise JobCancellationConflictError(normalized_job_id, status)
                elif row.cancel_requested:
                    result = JobCancellationRequestResult(
                        job=job_record_from_row(row),
                        immediate=False,
                        already_requested=True,
                    )
                else:
                    run = session.get(AnalysisRunRow, row.run_id)
                    if run is None:
                        raise AnalysisRunNotFoundError(row.run_id)

                    row.cancel_requested = True
                    if row.cancel_requested_at is None:
                        row.cancel_requested_at = operation_timestamp
                    row.updated_at = _monotonic_timestamp(
                        row.updated_at,
                        operation_timestamp,
                    )

                    immediate = status in _IMMEDIATE_STATUSES
                    if immediate:
                        validate_job_transition(status, JobStatus.CANCELLED)
                        row.status = JobStatus.CANCELLED.value
                        row.finished_at = operation_timestamp
                        row.leased_by = None
                        row.lease_token = None
                        row.lease_expires_at = None
                        recompute_analysis_run_status(
                            session,
                            row.run_id,
                            changed_at=operation_timestamp,
                        )
                    elif status not in _ACTIVE_STATUSES:
                        raise JobCancellationConflictError(normalized_job_id, status)

                    session.flush()
                    result = JobCancellationRequestResult(
                        job=job_record_from_row(row),
                        immediate=immediate,
                        already_requested=False,
                    )
        except (
            JobNotFoundError,
            AnalysisRunNotFoundError,
            InvalidJobTransition,
            JobCancellationError,
        ):
            raise
        except SQLAlchemyError:
            raise JobCancellationError("Failed to request job cancellation") from None

        return result

    def acknowledge_cancellation(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
    ) -> JobRecord:
        normalized_job_id = _normalize_job_id(job_id)
        normalized_worker_id = _normalize_worker_id(worker_id)
        normalized_lease_token = _normalize_lease_token(lease_token)
        validate_job_transition(JobStatus.LEASED, JobStatus.CANCELLED)
        validate_job_transition(JobStatus.RUNNING, JobStatus.CANCELLED)
        operation_timestamp = self._clock()

        try:
            with self._session_factory.begin() as session:
                result = session.execute(
                    update(JobRow)
                    .where(
                        JobRow.id == normalized_job_id,
                        JobRow.status.in_(
                            [
                                JobStatus.LEASED.value,
                                JobStatus.RUNNING.value,
                            ]
                        ),
                        JobRow.leased_by == normalized_worker_id,
                        JobRow.lease_token == normalized_lease_token,
                        JobRow.lease_expires_at.is_not(None),
                        JobRow.lease_expires_at > operation_timestamp,
                        JobRow.cancel_requested.is_(True),
                    )
                    .values(
                        status=JobStatus.CANCELLED.value,
                        finished_at=operation_timestamp,
                        leased_by=None,
                        lease_token=None,
                        lease_expires_at=None,
                        heartbeat_at=_monotonic_update(
                            JobRow.heartbeat_at,
                            operation_timestamp,
                        ),
                        updated_at=_monotonic_update(
                            JobRow.updated_at,
                            operation_timestamp,
                        ),
                    )
                )

                if result.rowcount == 0:
                    self._classify_acknowledgement_failure(
                        session,
                        normalized_job_id,
                        normalized_worker_id,
                        normalized_lease_token,
                        operation_timestamp,
                    )
                    raise JobCancellationError(
                        "Cancellation acknowledgement failed due to a lifecycle conflict"
                    )
                if result.rowcount != 1:
                    raise JobCancellationError(
                        "Cancellation acknowledgement affected an unexpected number of jobs"
                    )

                row = session.get(JobRow, normalized_job_id)
                if row is None:
                    raise JobNotFoundError(normalized_job_id)
                recompute_analysis_run_status(
                    session,
                    row.run_id,
                    changed_at=operation_timestamp,
                )
                session.flush()
                record = job_record_from_row(row)
        except (
            InvalidWorkerRequestError,
            InvalidLeaseTokenError,
            JobNotFoundError,
            JobLeaseOwnershipError,
            JobLeaseTokenMismatchError,
            JobLeaseExpiredError,
            AnalysisRunNotFoundError,
            InvalidJobTransition,
            JobCancellationError,
        ):
            raise
        except SQLAlchemyError:
            raise JobCancellationError("Failed to acknowledge job cancellation") from None

        return record

    def finalize_expired_cancellations(
        self,
        limit: int = 100,
    ) -> list[ExpiredCancellationResult]:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise InvalidCancellationRequestError(limit=limit)
        validate_job_transition(JobStatus.LEASED, JobStatus.CANCELLED)
        validate_job_transition(JobStatus.RUNNING, JobStatus.CANCELLED)

        try:
            with self._session_factory.begin() as session:
                dialect_name = session.get_bind().dialect.name
                if dialect_name != "postgresql":
                    raise UnsupportedQueueDatabaseError(dialect_name)

                operation_timestamp = self._clock()
                rows = list(
                    session.scalars(
                        select(JobRow)
                        .where(
                            JobRow.status.in_(
                                [
                                    JobStatus.LEASED.value,
                                    JobStatus.RUNNING.value,
                                ]
                            ),
                            JobRow.cancel_requested.is_(True),
                            or_(
                                JobRow.lease_expires_at.is_(None),
                                JobRow.lease_expires_at <= operation_timestamp,
                            ),
                        )
                        .order_by(
                            func.coalesce(
                                JobRow.cancel_requested_at,
                                JobRow.created_at,
                            ).asc(),
                            JobRow.priority.asc(),
                            JobRow.created_at.asc(),
                            JobRow.id.asc(),
                        )
                        .limit(limit)
                        .with_for_update(skip_locked=True)
                    )
                )

                results: list[ExpiredCancellationResult] = []
                for row in rows:
                    previous_status = JobStatus(row.status)
                    validate_job_transition(previous_status, JobStatus.CANCELLED)
                    row.status = JobStatus.CANCELLED.value
                    row.finished_at = operation_timestamp
                    row.leased_by = None
                    row.lease_token = None
                    row.lease_expires_at = None
                    row.updated_at = _monotonic_timestamp(
                        row.updated_at,
                        operation_timestamp,
                    )
                    recompute_analysis_run_status(
                        session,
                        row.run_id,
                        changed_at=operation_timestamp,
                    )
                    results.append(
                        ExpiredCancellationResult(
                            job=job_record_from_row(row),
                            previous_status=previous_status,
                        )
                    )

                session.flush()
        except (
            UnsupportedQueueDatabaseError,
            AnalysisRunNotFoundError,
            InvalidJobTransition,
            JobCancellationError,
        ):
            raise
        except SQLAlchemyError:
            raise JobCancellationError("Failed to finalize expired cancellations") from None

        return results

    @staticmethod
    def _classify_acknowledgement_failure(
        session: Session,
        job_id: str,
        worker_id: str,
        lease_token: str,
        operation_timestamp: datetime,
    ) -> None:
        row = session.get(JobRow, job_id)
        if row is None:
            raise JobNotFoundError(job_id)

        actual_status = JobStatus(row.status)
        if actual_status not in _ACTIVE_STATUSES:
            raise JobCancellationConflictError(job_id, actual_status)
        if row.leased_by != worker_id:
            raise JobLeaseOwnershipError(
                job_id=job_id,
                requested_worker_id=worker_id,
                leased_by=row.leased_by,
            )
        if row.lease_token is None or row.lease_token != lease_token:
            raise JobLeaseTokenMismatchError(job_id)
        if not row.cancel_requested:
            raise JobCancellationNotRequestedError(job_id)
        if row.lease_expires_at is None or _comparable_timestamp(
            row.lease_expires_at
        ) <= _comparable_timestamp(operation_timestamp):
            raise JobLeaseExpiredError(
                job_id=job_id,
                lease_expires_at=row.lease_expires_at,
                operation_time=operation_timestamp,
            )
