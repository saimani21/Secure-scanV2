from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.domain.enums import JobStatus
from securescan.domain.job_state import InvalidJobTransition, validate_job_transition
from securescan.jobs.mappers import job_record_from_row
from securescan.jobs.models import JobRecord
from securescan.jobs.repository import JobNotFoundError, JobStateConflictError
from securescan.persistence.database import JobRow, utc_now
from securescan.runs.aggregation import RunAggregationError, recompute_analysis_run_status


class JobExecutionError(RuntimeError):
    """Raised when a worker-owned lifecycle operation fails."""


class InvalidWorkerRequestError(JobExecutionError):
    """Raised when a worker identifier is invalid."""


class InvalidLeaseTokenError(JobExecutionError):
    """Raised when a supplied lease token is not a canonical UUID."""


class JobLeaseOwnershipError(JobExecutionError):
    """Raised when a worker attempts to use another worker's lease."""

    def __init__(
        self,
        job_id: str,
        requested_worker_id: str,
        leased_by: str | None,
    ) -> None:
        self.job_id = job_id
        self.requested_worker_id = requested_worker_id
        self.leased_by = leased_by
        super().__init__(
            f"Worker {requested_worker_id!r} does not own the lease for job {job_id!r}; "
            f"the lease is owned by {leased_by!r}"
        )


class JobLeaseExpiredError(JobExecutionError):
    """Raised when a job has no active lease."""

    def __init__(
        self,
        job_id: str,
        lease_expires_at: datetime | None,
        operation_time: datetime,
    ) -> None:
        self.job_id = job_id
        self.lease_expires_at = lease_expires_at
        self.operation_time = operation_time
        super().__init__(
            f"Job {job_id!r} lease is missing or expired at operation time "
            f"{operation_time.isoformat()}"
        )


class JobLeaseTokenMismatchError(JobExecutionError):
    """Raised when a lease token does not own the current lease."""

    def __init__(self, job_id: str) -> None:
        self.job_id = job_id
        super().__init__(
            f"The supplied lease token does not own the current lease for job {job_id!r}"
        )


class JobCancellationRequestedError(JobExecutionError):
    """Raised when a job is cancelled before execution starts."""

    def __init__(self, job_id: str) -> None:
        self.job_id = job_id
        super().__init__(f"Job {job_id!r} has cancellation requested before execution started")


def _normalize_worker_id(worker_id: str) -> str:
    normalized_worker_id = worker_id.strip()
    if not normalized_worker_id:
        raise InvalidWorkerRequestError("worker_id must not be blank")
    if len(normalized_worker_id) > 200:
        raise InvalidWorkerRequestError("worker_id must be 200 characters or fewer")
    return normalized_worker_id


def _normalize_lease_token(lease_token: str) -> str:
    normalized_lease_token = lease_token.strip()
    if not normalized_lease_token or len(normalized_lease_token) != 36:
        raise InvalidLeaseTokenError("lease_token must be a canonical UUID string")
    try:
        parsed_lease_token = UUID(normalized_lease_token)
    except ValueError as exc:
        raise InvalidLeaseTokenError("lease_token must be a canonical UUID string") from exc
    canonical_lease_token = str(parsed_lease_token)
    if canonical_lease_token != normalized_lease_token:
        raise InvalidLeaseTokenError("lease_token must be a canonical UUID string")
    return canonical_lease_token


def _comparable_timestamp(timestamp: datetime) -> datetime:
    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=UTC)
    return timestamp.astimezone(UTC)


class JobExecutionService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._session_factory = session_factory
        self._clock = clock

    def start_job(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
    ) -> JobRecord:
        normalized_worker_id = _normalize_worker_id(worker_id)
        normalized_lease_token = _normalize_lease_token(lease_token)

        validate_job_transition(
            JobStatus.LEASED,
            JobStatus.RUNNING,
        )
        operation_timestamp = self._clock()

        try:
            with self._session_factory.begin() as session:
                result = session.execute(
                    update(JobRow)
                    .where(
                        JobRow.id == job_id,
                        JobRow.status == JobStatus.LEASED.value,
                        JobRow.leased_by == normalized_worker_id,
                        JobRow.lease_token == normalized_lease_token,
                        JobRow.lease_expires_at.is_not(None),
                        JobRow.lease_expires_at > operation_timestamp,
                        JobRow.cancel_requested.is_(False),
                    )
                    .values(
                        status=JobStatus.RUNNING.value,
                        updated_at=operation_timestamp,
                        heartbeat_at=operation_timestamp,
                        started_at=func.coalesce(
                            JobRow.started_at,
                            operation_timestamp,
                        ),
                    )
                )

                if result.rowcount == 0:
                    row = session.get(JobRow, job_id)
                    if row is None:
                        raise JobNotFoundError(job_id)

                    actual_status = JobStatus(row.status)
                    if actual_status is not JobStatus.LEASED:
                        raise JobStateConflictError(
                            job_id=job_id,
                            expected_status=JobStatus.LEASED,
                            actual_status=actual_status,
                        )
                    if row.leased_by != normalized_worker_id:
                        raise JobLeaseOwnershipError(
                            job_id=job_id,
                            requested_worker_id=normalized_worker_id,
                            leased_by=row.leased_by,
                        )
                    if row.lease_token is None or row.lease_token != normalized_lease_token:
                        raise JobLeaseTokenMismatchError(job_id)
                    if row.cancel_requested:
                        raise JobCancellationRequestedError(job_id)
                    if row.lease_expires_at is None or _comparable_timestamp(
                        row.lease_expires_at
                    ) <= _comparable_timestamp(operation_timestamp):
                        raise JobLeaseExpiredError(
                            job_id=job_id,
                            lease_expires_at=row.lease_expires_at,
                            operation_time=operation_timestamp,
                        )

                    raise JobExecutionError(
                        f"Job {job_id!r} could not start due to an internal lifecycle conflict"
                    )

                if result.rowcount != 1:
                    raise JobExecutionError(
                        f"Job {job_id!r} update affected an unexpected number of rows"
                    )

                row = session.get(JobRow, job_id)
                if row is None:
                    raise JobNotFoundError(job_id)
                recompute_analysis_run_status(
                    session,
                    row.run_id,
                    changed_at=operation_timestamp,
                )
                record = job_record_from_row(row)
        except (
            InvalidWorkerRequestError,
            InvalidLeaseTokenError,
            JobNotFoundError,
            JobStateConflictError,
            JobLeaseOwnershipError,
            JobLeaseTokenMismatchError,
            JobCancellationRequestedError,
            JobLeaseExpiredError,
            InvalidJobTransition,
            JobExecutionError,
        ):
            raise
        except RunAggregationError as exc:
            raise JobExecutionError(f"Failed to start job {job_id!r}") from exc
        except SQLAlchemyError as exc:
            raise JobExecutionError(f"Failed to start job {job_id!r}") from exc

        return record
