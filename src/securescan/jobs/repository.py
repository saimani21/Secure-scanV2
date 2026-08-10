from __future__ import annotations

from copy import deepcopy

from sqlalchemy import case, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.domain.enums import JobStatus
from securescan.domain.job_state import (
    is_terminal_job_status,
    validate_job_transition,
)
from securescan.jobs.mappers import job_record_from_row
from securescan.jobs.models import JobCreate, JobRecord
from securescan.persistence.database import JobRow, utc_now
from securescan.runs.aggregation import RunAggregationError, recompute_analysis_run_status


class JobRepositoryError(RuntimeError):
    """Raised when a job persistence operation fails."""


class DuplicateJobError(JobRepositoryError):
    """Raised when a job idempotency key already exists."""

    def __init__(self, idempotency_key: str) -> None:
        self.idempotency_key = idempotency_key
        super().__init__(f"A job with idempotency key {idempotency_key!r} already exists")


class JobNotFoundError(JobRepositoryError):
    """Raised when a requested job does not exist."""

    def __init__(self, job_id: str) -> None:
        self.job_id = job_id
        super().__init__(f"Job {job_id!r} was not found")


class JobStateConflictError(JobRepositoryError):
    """Raised when a job is not in the expected state."""

    def __init__(
        self,
        job_id: str,
        expected_status: JobStatus,
        actual_status: JobStatus,
    ) -> None:
        self.job_id = job_id
        self.expected_status = expected_status
        self.actual_status = actual_status
        super().__init__(
            f"Job {job_id!r} expected status {expected_status.value!r}, "
            f"but actual status is {actual_status.value!r}"
        )


class JobRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def create_job(self, job: JobCreate) -> JobRecord:
        try:
            with self._session_factory.begin() as session:
                row = JobRow(
                    run_id=job.run_id,
                    adapter_id=job.adapter_id,
                    idempotency_key=job.idempotency_key,
                    payload_json=deepcopy(job.payload_json),
                    priority=job.priority,
                    max_attempts=job.max_attempts,
                )
                if job.available_at is not None:
                    row.available_at = job.available_at

                session.add(row)
                session.flush()
                session.refresh(row)
                recompute_analysis_run_status(
                    session,
                    row.run_id,
                    changed_at=utc_now(),
                )
                record = job_record_from_row(row)
        except IntegrityError as exc:
            try:
                duplicate = self.get_by_idempotency_key(job.idempotency_key)
            except JobRepositoryError:
                raise JobRepositoryError("Failed to create job") from exc

            if duplicate is not None:
                raise DuplicateJobError(job.idempotency_key) from exc

            raise JobRepositoryError("Failed to create job") from exc
        except (RunAggregationError, SQLAlchemyError) as exc:
            raise JobRepositoryError("Failed to create job") from exc

        return record

    def transition_job(
        self,
        job_id: str,
        expected_status: JobStatus,
        requested_status: JobStatus,
    ) -> JobRecord:
        validate_job_transition(expected_status, requested_status)

        operation_timestamp = utc_now()
        update_values: dict[str, object] = {
            "status": requested_status.value,
            "updated_at": operation_timestamp,
        }

        if requested_status is JobStatus.RUNNING:
            update_values["started_at"] = case(
                (
                    JobRow.started_at.is_(None),
                    operation_timestamp,
                ),
                else_=JobRow.started_at,
            )

        if is_terminal_job_status(requested_status):
            update_values["finished_at"] = operation_timestamp

        try:
            with self._session_factory.begin() as session:
                result = session.execute(
                    update(JobRow)
                    .where(
                        JobRow.id == job_id,
                        JobRow.status == expected_status.value,
                    )
                    .values(**update_values)
                )

                if result.rowcount == 0:
                    row = session.get(JobRow, job_id)
                    if row is None:
                        raise JobNotFoundError(job_id)

                    raise JobStateConflictError(
                        job_id=job_id,
                        expected_status=expected_status,
                        actual_status=JobStatus(row.status),
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
        except (JobNotFoundError, JobStateConflictError):
            raise
        except (RunAggregationError, SQLAlchemyError) as exc:
            raise JobRepositoryError(f"Failed to transition job {job_id!r}") from exc

        return record

    def get_job(self, job_id: str) -> JobRecord | None:
        try:
            with self._session_factory() as session:
                row = session.get(JobRow, job_id)
                return job_record_from_row(row) if row is not None else None
        except SQLAlchemyError as exc:
            raise JobRepositoryError(f"Failed to retrieve job {job_id!r}") from exc

    def get_by_idempotency_key(
        self,
        idempotency_key: str,
    ) -> JobRecord | None:
        try:
            with self._session_factory() as session:
                row = session.scalar(
                    select(JobRow).where(JobRow.idempotency_key == idempotency_key)
                )
                return job_record_from_row(row) if row is not None else None
        except SQLAlchemyError as exc:
            raise JobRepositoryError(
                f"Failed to retrieve job with idempotency key {idempotency_key!r}"
            ) from exc
