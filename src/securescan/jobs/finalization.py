from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from sqlalchemy import case, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.domain.enums import JobStatus
from securescan.domain.job_state import InvalidJobTransition, validate_job_transition
from securescan.jobs.execution import (
    InvalidLeaseTokenError,
    InvalidWorkerRequestError,
    JobCancellationRequestedError,
    JobLeaseExpiredError,
    JobLeaseOwnershipError,
    JobLeaseTokenMismatchError,
    _comparable_timestamp,
    _normalize_lease_token,
    _normalize_worker_id,
)
from securescan.jobs.mappers import job_record_from_row
from securescan.jobs.models import JobRecord
from securescan.jobs.repository import JobNotFoundError, JobStateConflictError
from securescan.persistence.database import JobRow, utc_now
from securescan.runs.aggregation import recompute_analysis_run_status


class JobFinalizationError(RuntimeError):
    """Raised when a terminal finalization operation fails."""


class InvalidJobFinalStatusError(JobFinalizationError):
    """Raised when an unsupported terminal status is requested."""

    def __init__(self, requested_status: object) -> None:
        self.requested_status = requested_status
        super().__init__("Only JobStatus.SUCCEEDED and JobStatus.PARTIAL are accepted")


def _normalize_terminal_request(
    worker_id: str,
    lease_token: str,
    final_status: JobStatus,
) -> tuple[str, str]:
    normalized_worker_id = _normalize_worker_id(worker_id)
    normalized_lease_token = _normalize_lease_token(lease_token)
    if not isinstance(final_status, JobStatus) or final_status not in {
        JobStatus.SUCCEEDED,
        JobStatus.PARTIAL,
    }:
        raise InvalidJobFinalStatusError(final_status)

    validate_job_transition(
        JobStatus.RUNNING,
        final_status,
    )
    return normalized_worker_id, normalized_lease_token


def _build_terminal_update(
    job_id: str,
    worker_id: str,
    lease_token: str,
    final_status: JobStatus,
    operation_timestamp: datetime,
):
    return (
        update(JobRow)
        .where(
            JobRow.id == job_id,
            JobRow.status == JobStatus.RUNNING.value,
            JobRow.leased_by == worker_id,
            JobRow.lease_token == lease_token,
            JobRow.lease_expires_at.is_not(None),
            JobRow.lease_expires_at > operation_timestamp,
            JobRow.cancel_requested.is_(False),
        )
        .values(
            status=final_status.value,
            finished_at=operation_timestamp,
            leased_by=None,
            lease_token=None,
            lease_expires_at=None,
            last_error=None,
            heartbeat_at=case(
                (
                    JobRow.heartbeat_at.is_(None),
                    operation_timestamp,
                ),
                (
                    JobRow.heartbeat_at < operation_timestamp,
                    operation_timestamp,
                ),
                else_=JobRow.heartbeat_at,
            ),
            updated_at=case(
                (
                    JobRow.updated_at < operation_timestamp,
                    operation_timestamp,
                ),
                else_=JobRow.updated_at,
            ),
        )
    )


def _classify_terminal_update_failure(
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
    if actual_status is not JobStatus.RUNNING:
        raise JobStateConflictError(
            job_id=job_id,
            expected_status=JobStatus.RUNNING,
            actual_status=actual_status,
        )
    if row.leased_by != worker_id:
        raise JobLeaseOwnershipError(
            job_id=job_id,
            requested_worker_id=worker_id,
            leased_by=row.leased_by,
        )
    if row.lease_token is None or row.lease_token != lease_token:
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


class JobFinalizationService:
    """Perform legacy state-only finalization.

    Worker execution must use JobResultCommitService for SUCCEEDED and PARTIAL scanner
    outcomes so evidence and terminal state are committed atomically.
    """

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._session_factory = session_factory
        self._clock = clock

    def finalize_job(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        final_status: JobStatus,
    ) -> JobRecord:
        normalized_worker_id, normalized_lease_token = _normalize_terminal_request(
            worker_id,
            lease_token,
            final_status,
        )
        operation_timestamp = self._clock()

        try:
            with self._session_factory.begin() as session:
                result = session.execute(
                    _build_terminal_update(
                        job_id,
                        normalized_worker_id,
                        normalized_lease_token,
                        final_status,
                        operation_timestamp,
                    )
                )

                if result.rowcount == 0:
                    _classify_terminal_update_failure(
                        session,
                        job_id,
                        normalized_worker_id,
                        normalized_lease_token,
                        operation_timestamp,
                    )
                    raise JobFinalizationError(
                        f"Job {job_id!r} finalization failed due to an internal lifecycle conflict"
                    )

                if result.rowcount != 1:
                    raise JobFinalizationError(
                        f"Job {job_id!r} finalization affected an unexpected number of rows"
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
            InvalidJobFinalStatusError,
            InvalidWorkerRequestError,
            InvalidLeaseTokenError,
            JobNotFoundError,
            JobStateConflictError,
            JobLeaseOwnershipError,
            JobLeaseTokenMismatchError,
            JobCancellationRequestedError,
            JobLeaseExpiredError,
            InvalidJobTransition,
            JobFinalizationError,
        ):
            raise
        except SQLAlchemyError:
            raise JobFinalizationError(f"Failed to finalize job {job_id!r}") from None

        return record
