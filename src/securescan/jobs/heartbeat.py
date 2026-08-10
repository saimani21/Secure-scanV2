from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta

from sqlalchemy import case, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.domain.enums import JobStatus
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


class JobHeartbeatError(RuntimeError):
    """Raised when a heartbeat persistence or lifecycle operation fails."""


class InvalidHeartbeatRequestError(JobHeartbeatError):
    """Raised when a heartbeat lease duration is invalid."""

    def __init__(self, lease_seconds: int) -> None:
        self.lease_seconds = lease_seconds
        super().__init__(f"lease_seconds must be at least 1; received {lease_seconds}")


class JobHeartbeatService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._session_factory = session_factory
        self._clock = clock

    def renew_lease(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        lease_seconds: int = 30,
    ) -> JobRecord:
        normalized_worker_id = _normalize_worker_id(worker_id)
        normalized_lease_token = _normalize_lease_token(lease_token)
        if lease_seconds < 1:
            raise InvalidHeartbeatRequestError(lease_seconds)

        operation_timestamp = self._clock()
        candidate_expiry = operation_timestamp + timedelta(seconds=lease_seconds)

        try:
            with self._session_factory.begin() as session:
                result = session.execute(
                    update(JobRow)
                    .where(
                        JobRow.id == job_id,
                        JobRow.status == JobStatus.RUNNING.value,
                        JobRow.leased_by == normalized_worker_id,
                        JobRow.lease_token == normalized_lease_token,
                        JobRow.lease_expires_at.is_not(None),
                        JobRow.lease_expires_at > operation_timestamp,
                        JobRow.cancel_requested.is_(False),
                    )
                    .values(
                        lease_expires_at=case(
                            (
                                JobRow.lease_expires_at < candidate_expiry,
                                candidate_expiry,
                            ),
                            else_=JobRow.lease_expires_at,
                        ),
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

                if result.rowcount == 0:
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

                    raise JobHeartbeatError(
                        f"Job {job_id!r} heartbeat failed due to an internal lifecycle conflict"
                    )

                if result.rowcount != 1:
                    raise JobHeartbeatError(
                        f"Job {job_id!r} heartbeat affected an unexpected number of rows"
                    )

                row = session.get(JobRow, job_id)
                if row is None:
                    raise JobNotFoundError(job_id)
                record = job_record_from_row(row)
        except (
            InvalidHeartbeatRequestError,
            InvalidWorkerRequestError,
            InvalidLeaseTokenError,
            JobNotFoundError,
            JobStateConflictError,
            JobLeaseOwnershipError,
            JobLeaseTokenMismatchError,
            JobCancellationRequestedError,
            JobLeaseExpiredError,
            JobHeartbeatError,
        ):
            raise
        except SQLAlchemyError:
            raise JobHeartbeatError(f"Failed to renew heartbeat for job {job_id!r}") from None

        return record
