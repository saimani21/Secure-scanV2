from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.domain.enums import JobStatus
from securescan.domain.job_state import InvalidJobTransition, validate_job_transition
from securescan.jobs.mappers import job_record_from_row
from securescan.jobs.models import JobRecord
from securescan.persistence.database import JobRow, utc_now
from securescan.runs.aggregation import RunAggregationError, recompute_analysis_run_status


class JobLeasingError(RuntimeError):
    """Raised when an atomic job leasing operation fails."""


class InvalidLeaseRequestError(JobLeasingError):
    """Raised when a worker identifier or lease duration is invalid."""


class UnsupportedQueueDatabaseError(JobLeasingError):
    """Raised when job leasing is attempted on a non-PostgreSQL database."""

    def __init__(self, dialect_name: str) -> None:
        self.dialect_name = dialect_name
        super().__init__(
            "PostgreSQL is required for atomic job leasing; "
            f"received database dialect {dialect_name!r}"
        )


class JobLeasingService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        clock: Callable[[], datetime] = utc_now,
        token_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._session_factory = session_factory
        self._clock = clock
        self._token_factory = token_factory

    def lease_next_job(
        self,
        worker_id: str,
        lease_seconds: int = 30,
    ) -> JobRecord | None:
        normalized_worker_id = worker_id.strip()
        if not normalized_worker_id:
            raise InvalidLeaseRequestError("worker_id must not be blank")
        if len(normalized_worker_id) > 200:
            raise InvalidLeaseRequestError("worker_id must be 200 characters or fewer")
        if lease_seconds < 1:
            raise InvalidLeaseRequestError("lease_seconds must be at least 1")

        try:
            with self._session_factory.begin() as session:
                dialect_name = session.get_bind().dialect.name
                if dialect_name != "postgresql":
                    raise UnsupportedQueueDatabaseError(dialect_name)

                operation_timestamp = self._clock()
                row = session.scalar(
                    select(JobRow)
                    .where(
                        JobRow.status == JobStatus.QUEUED.value,
                        JobRow.available_at <= operation_timestamp,
                        JobRow.cancel_requested.is_(False),
                        JobRow.attempt_count < JobRow.max_attempts,
                    )
                    .order_by(
                        JobRow.priority.asc(),
                        JobRow.available_at.asc(),
                        JobRow.created_at.asc(),
                        JobRow.id.asc(),
                    )
                    .limit(1)
                    .with_for_update(skip_locked=True)
                )

                if row is None:
                    record = None
                else:
                    validate_job_transition(
                        JobStatus(row.status),
                        JobStatus.LEASED,
                    )
                    lease_token = str(self._token_factory())
                    row.status = JobStatus.LEASED.value
                    row.leased_by = normalized_worker_id
                    row.lease_token = lease_token
                    row.heartbeat_at = operation_timestamp
                    row.lease_expires_at = operation_timestamp + timedelta(seconds=lease_seconds)
                    row.attempt_count += 1
                    row.updated_at = operation_timestamp
                    recompute_analysis_run_status(
                        session,
                        row.run_id,
                        changed_at=operation_timestamp,
                    )
                    record = job_record_from_row(row)
        except (UnsupportedQueueDatabaseError, InvalidJobTransition):
            raise
        except RunAggregationError as exc:
            raise JobLeasingError("Failed to lease the next queued job") from exc
        except SQLAlchemyError as exc:
            raise JobLeasingError("Failed to lease the next queued job") from exc

        return record
