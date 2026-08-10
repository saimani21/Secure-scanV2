from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.domain.enums import JobStatus
from securescan.domain.job_state import InvalidJobTransition, validate_job_transition
from securescan.jobs.execution import _comparable_timestamp
from securescan.jobs.failure_commit import (
    InvalidRetryDelayError,
    default_retry_delay_seconds,
)
from securescan.jobs.leasing import UnsupportedQueueDatabaseError
from securescan.jobs.mappers import job_record_from_row
from securescan.jobs.models import JobRecord
from securescan.jobs.result_commit import AnalysisRunNotFoundError
from securescan.persistence.database import JobRow, utc_now
from securescan.runs.aggregation import recompute_analysis_run_status

_LEASE_EXPIRY_ERRORS = {
    JobStatus.LEASED: "Worker lease expired before execution started.",
    JobStatus.RUNNING: "Worker lease expired during execution.",
}


class JobLeaseRecoveryError(RuntimeError):
    """Raised when atomic expired-lease recovery fails."""


class InvalidLeaseRecoveryRequestError(JobLeaseRecoveryError):
    """Raised when the requested recovery batch size is invalid."""

    def __init__(self, limit: object) -> None:
        self.limit = limit
        super().__init__("limit must be between 1 and 1000")


@dataclass(frozen=True, slots=True)
class ExpiredLeaseRecoveryResult:
    job: JobRecord
    previous_status: JobStatus
    retry_scheduled: bool
    retry_delay_seconds: int | None


def _validated_retry_delay(
    policy: Callable[[int], int],
    attempt_number: int,
) -> int:
    returned_delay = policy(attempt_number)
    if (
        not isinstance(returned_delay, int)
        or isinstance(returned_delay, bool)
        or not 1 <= returned_delay <= 86_400
    ):
        raise InvalidRetryDelayError(attempt_number, returned_delay)
    return returned_delay


class JobLeaseRecoveryService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        clock: Callable[[], datetime] = utc_now,
        retry_delay_seconds: Callable[[int], int] = default_retry_delay_seconds,
    ) -> None:
        self._session_factory = session_factory
        self._clock = clock
        self._retry_delay_seconds = retry_delay_seconds

    def recover_expired_jobs(
        self,
        limit: int = 100,
    ) -> list[ExpiredLeaseRecoveryResult]:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise InvalidLeaseRecoveryRequestError(limit)

        for previous_status in (JobStatus.LEASED, JobStatus.RUNNING):
            validate_job_transition(previous_status, JobStatus.RETRY_PENDING)
            validate_job_transition(previous_status, JobStatus.FAILED)

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
                            JobRow.lease_expires_at.is_not(None),
                            JobRow.lease_expires_at <= operation_timestamp,
                            JobRow.cancel_requested.is_(False),
                        )
                        .order_by(
                            JobRow.lease_expires_at.asc(),
                            JobRow.priority.asc(),
                            JobRow.created_at.asc(),
                            JobRow.id.asc(),
                        )
                        .limit(limit)
                        .with_for_update(skip_locked=True)
                    )
                )

                decisions: list[tuple[JobRow, JobStatus, bool, int | None]] = []
                for row in rows:
                    previous_status = JobStatus(row.status)
                    retry_scheduled = row.attempt_count < row.max_attempts
                    requested_status = (
                        JobStatus.RETRY_PENDING if retry_scheduled else JobStatus.FAILED
                    )
                    validate_job_transition(previous_status, requested_status)
                    retry_delay = (
                        _validated_retry_delay(
                            self._retry_delay_seconds,
                            row.attempt_count,
                        )
                        if retry_scheduled
                        else None
                    )

                    row.status = requested_status.value
                    row.last_error = _LEASE_EXPIRY_ERRORS[previous_status]
                    row.leased_by = None
                    row.lease_token = None
                    row.lease_expires_at = None
                    row.finished_at = None if retry_scheduled else operation_timestamp
                    if retry_scheduled:
                        assert retry_delay is not None
                        row.available_at = operation_timestamp + timedelta(seconds=retry_delay)
                    if row.updated_at is None or _comparable_timestamp(
                        row.updated_at
                    ) < _comparable_timestamp(operation_timestamp):
                        row.updated_at = operation_timestamp
                    recompute_analysis_run_status(
                        session,
                        row.run_id,
                        changed_at=operation_timestamp,
                    )

                    decisions.append(
                        (
                            row,
                            previous_status,
                            retry_scheduled,
                            retry_delay,
                        )
                    )

                session.flush()
                results = [
                    ExpiredLeaseRecoveryResult(
                        job=job_record_from_row(row),
                        previous_status=previous_status,
                        retry_scheduled=retry_scheduled,
                        retry_delay_seconds=retry_delay,
                    )
                    for (
                        row,
                        previous_status,
                        retry_scheduled,
                        retry_delay,
                    ) in decisions
                ]
        except (
            InvalidLeaseRecoveryRequestError,
            UnsupportedQueueDatabaseError,
            InvalidRetryDelayError,
            AnalysisRunNotFoundError,
            InvalidJobTransition,
            JobLeaseRecoveryError,
        ):
            raise
        except SQLAlchemyError:
            raise JobLeaseRecoveryError("Failed to recover expired job leases") from None

        return results
