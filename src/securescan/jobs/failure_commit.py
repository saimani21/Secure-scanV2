from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import case, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.domain.enums import ExecutionOutcome, JobFailureCategory, JobStatus
from securescan.domain.job_state import InvalidJobTransition, validate_job_transition
from securescan.jobs.execution import (
    InvalidLeaseTokenError,
    InvalidWorkerRequestError,
    JobCancellationRequestedError,
    JobLeaseExpiredError,
    JobLeaseOwnershipError,
    JobLeaseTokenMismatchError,
    _normalize_lease_token,
    _normalize_worker_id,
)
from securescan.jobs.finalization import _classify_terminal_update_failure
from securescan.jobs.mappers import job_record_from_row
from securescan.jobs.models import JobRecord
from securescan.jobs.repository import JobNotFoundError, JobStateConflictError
from securescan.jobs.result_commit import AnalysisRunNotFoundError
from securescan.jobs.transaction_retry import run_with_bounded_transaction_retry
from securescan.persistence.database import (
    JobRow,
    ToolExecutionRow,
    utc_now,
)
from securescan.runs.aggregation import recompute_analysis_run_status


class JobFailureCommitError(RuntimeError):
    """Raised when an atomic failure-commit operation fails."""


class InvalidFailedToolExecutionCommitError(JobFailureCommitError):
    """Raised when failed execution metadata is invalid."""

    def __init__(self, field_name: str) -> None:
        self.field_name = field_name
        super().__init__(f"Invalid failed tool execution field: {field_name}")


class InvalidRetryDelayError(JobFailureCommitError):
    """Raised when a retry policy produces an unsafe delay."""

    def __init__(self, attempt_number: int, returned_delay_seconds: object) -> None:
        self.attempt_number = attempt_number
        self.returned_delay_seconds = returned_delay_seconds
        super().__init__(f"Retry policy produced an invalid delay for attempt {attempt_number}")


@dataclass(frozen=True, slots=True)
class FailedToolExecutionCommit:
    tool_version: str
    adapter_version: str
    outcome: str
    exit_code: int | None
    duration_ms: int
    warning_json: list[dict[str, Any]]
    error: str
    failure_category: JobFailureCategory
    retryable: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "warning_json", deepcopy(self.warning_json))


@dataclass(frozen=True, slots=True)
class JobFailureCommitRequest:
    job_id: str
    worker_id: str
    lease_token: str
    tool_execution: FailedToolExecutionCommit


@dataclass(frozen=True, slots=True)
class JobFailureCommitResult:
    job: JobRecord
    run_id: str
    tool_execution_id: str
    attempt_number: int
    retry_scheduled: bool
    retry_delay_seconds: int | None
    failure_category: JobFailureCategory


def default_retry_delay_seconds(attempt_number: int) -> int:
    if attempt_number == 1:
        return 5
    if attempt_number == 2:
        return 30
    if attempt_number == 3:
        return 60
    if attempt_number == 4:
        return 120
    return 300


def _normalize_bounded_text(value: object, field_name: str, maximum_length: int) -> str:
    if not isinstance(value, str):
        raise InvalidFailedToolExecutionCommitError(field_name)
    normalized_value = value.strip()
    if not normalized_value or len(normalized_value) > maximum_length:
        raise InvalidFailedToolExecutionCommitError(field_name)
    return normalized_value


def _normalize_failed_execution(
    commit: FailedToolExecutionCommit,
) -> FailedToolExecutionCommit:
    if not isinstance(commit, FailedToolExecutionCommit):
        raise InvalidFailedToolExecutionCommitError("tool_execution")

    tool_version = _normalize_bounded_text(commit.tool_version, "tool_version", 64)
    adapter_version = _normalize_bounded_text(commit.adapter_version, "adapter_version", 64)
    outcome = _normalize_bounded_text(commit.outcome, "outcome", 100)
    try:
        canonical_outcome = ExecutionOutcome(outcome).value
    except ValueError as exc:
        raise InvalidFailedToolExecutionCommitError("outcome") from exc
    error = _normalize_bounded_text(commit.error, "error", 2000)

    if (
        not isinstance(commit.duration_ms, int)
        or isinstance(commit.duration_ms, bool)
        or commit.duration_ms < 0
    ):
        raise InvalidFailedToolExecutionCommitError("duration_ms")
    if commit.exit_code is not None and (
        not isinstance(commit.exit_code, int) or isinstance(commit.exit_code, bool)
    ):
        raise InvalidFailedToolExecutionCommitError("exit_code")
    if not isinstance(commit.warning_json, list) or not all(
        isinstance(warning, dict) for warning in commit.warning_json
    ):
        raise InvalidFailedToolExecutionCommitError("warning_json")
    if not isinstance(commit.failure_category, JobFailureCategory):
        raise InvalidFailedToolExecutionCommitError("failure_category")
    if not isinstance(commit.retryable, bool):
        raise InvalidFailedToolExecutionCommitError("retryable")

    return FailedToolExecutionCommit(
        tool_version=tool_version,
        adapter_version=adapter_version,
        outcome=canonical_outcome,
        exit_code=commit.exit_code,
        duration_ms=commit.duration_ms,
        warning_json=deepcopy(commit.warning_json),
        error=error,
        failure_category=commit.failure_category,
        retryable=commit.retryable,
    )


def _guarded_failure_update(
    job_id: str,
    worker_id: str,
    lease_token: str,
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
        .returning(
            JobRow.run_id,
            JobRow.adapter_id,
            JobRow.attempt_count,
            JobRow.max_attempts,
        )
    )


def _failure_decision_update(
    job_id: str,
    worker_id: str,
    lease_token: str,
    operation_timestamp: datetime,
    error: str,
    *,
    retry_scheduled: bool,
    retry_delay_seconds: int | None,
):
    values: dict[str, object] = {
        "status": (JobStatus.RETRY_PENDING.value if retry_scheduled else JobStatus.FAILED.value),
        "last_error": error,
        "leased_by": None,
        "lease_token": None,
        "lease_expires_at": None,
        "finished_at": None if retry_scheduled else operation_timestamp,
        "heartbeat_at": case(
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
        "updated_at": case(
            (
                JobRow.updated_at < operation_timestamp,
                operation_timestamp,
            ),
            else_=JobRow.updated_at,
        ),
    }
    if retry_scheduled:
        assert retry_delay_seconds is not None
        values["available_at"] = operation_timestamp + timedelta(seconds=retry_delay_seconds)

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
        .values(**values)
    )


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


class JobFailureCommitService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        clock: Callable[[], datetime] = utc_now,
        execution_id_factory: Callable[[], UUID] = uuid4,
        retry_delay_seconds: Callable[[int], int] = default_retry_delay_seconds,
    ) -> None:
        self._session_factory = session_factory
        self._clock = clock
        self._execution_id_factory = execution_id_factory
        self._retry_delay_seconds = retry_delay_seconds

    def commit_failure(
        self,
        request: JobFailureCommitRequest,
    ) -> JobFailureCommitResult:
        normalized_worker_id = _normalize_worker_id(request.worker_id)
        normalized_lease_token = _normalize_lease_token(request.lease_token)
        failed_execution = _normalize_failed_execution(request.tool_execution)

        try:
            return run_with_bounded_transaction_retry(
                lambda: self._commit_failure_once(
                    request,
                    normalized_worker_id=normalized_worker_id,
                    normalized_lease_token=normalized_lease_token,
                    failed_execution=failed_execution,
                )
            )
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
            AnalysisRunNotFoundError,
            JobFailureCommitError,
        ):
            raise
        except SQLAlchemyError:
            raise JobFailureCommitError(
                f"Failed to commit failure for job {request.job_id!r}"
            ) from None

    def _commit_failure_once(
        self,
        request: JobFailureCommitRequest,
        *,
        normalized_worker_id: str,
        normalized_lease_token: str,
        failed_execution: FailedToolExecutionCommit,
    ) -> JobFailureCommitResult:
        with self._session_factory.begin() as session:
            operation_timestamp = self._clock()
            guarded_job = session.execute(
                _guarded_failure_update(
                    request.job_id,
                    normalized_worker_id,
                    normalized_lease_token,
                    operation_timestamp,
                )
            ).one_or_none()
            if guarded_job is None:
                _classify_terminal_update_failure(
                    session,
                    request.job_id,
                    normalized_worker_id,
                    normalized_lease_token,
                    operation_timestamp,
                )
                raise JobFailureCommitError(
                    f"Job {request.job_id!r} failure commitment failed due to "
                    "an internal lifecycle conflict"
                )

            retry_scheduled = (
                failed_execution.retryable and guarded_job.attempt_count < guarded_job.max_attempts
            )
            requested_status = JobStatus.RETRY_PENDING if retry_scheduled else JobStatus.FAILED
            validate_job_transition(JobStatus.RUNNING, requested_status)
            retry_delay = (
                _validated_retry_delay(
                    self._retry_delay_seconds,
                    guarded_job.attempt_count,
                )
                if retry_scheduled
                else None
            )

            update_result = session.execute(
                _failure_decision_update(
                    request.job_id,
                    normalized_worker_id,
                    normalized_lease_token,
                    operation_timestamp,
                    failed_execution.error,
                    retry_scheduled=retry_scheduled,
                    retry_delay_seconds=retry_delay,
                )
            )
            if update_result.rowcount == 0:
                _classify_terminal_update_failure(
                    session,
                    request.job_id,
                    normalized_worker_id,
                    normalized_lease_token,
                    operation_timestamp,
                )
                raise JobFailureCommitError(
                    f"Job {request.job_id!r} failure commitment lost its lifecycle guard"
                )
            if update_result.rowcount != 1:
                raise JobFailureCommitError(
                    f"Job {request.job_id!r} failure commitment affected an "
                    "unexpected number of rows"
                )

            execution_id = str(self._execution_id_factory())
            execution_row = ToolExecutionRow(
                id=execution_id,
                run_id=guarded_job.run_id,
                job_id=request.job_id,
                attempt_number=guarded_job.attempt_count,
                adapter_id=guarded_job.adapter_id,
                tool_version=failed_execution.tool_version,
                adapter_version=failed_execution.adapter_version,
                outcome=failed_execution.outcome,
                exit_code=failed_execution.exit_code,
                duration_ms=failed_execution.duration_ms,
                warning_json=deepcopy(failed_execution.warning_json),
                error=failed_execution.error,
                failure_category=failed_execution.failure_category.value,
                retryable=failed_execution.retryable,
            )
            session.add(execution_row)
            recompute_analysis_run_status(
                session,
                guarded_job.run_id,
                changed_at=operation_timestamp,
            )
            session.flush()

            job_row = session.get(JobRow, request.job_id)
            if job_row is None:
                raise JobNotFoundError(request.job_id)
            return JobFailureCommitResult(
                job=job_record_from_row(job_row),
                run_id=guarded_job.run_id,
                tool_execution_id=execution_id,
                attempt_number=guarded_job.attempt_count,
                retry_scheduled=retry_scheduled,
                retry_delay_seconds=retry_delay,
                failure_category=failed_execution.failure_category,
            )
