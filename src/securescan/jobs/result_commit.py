from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.domain.enums import ExecutionOutcome, JobStatus
from securescan.domain.job_state import InvalidJobTransition
from securescan.domain.models import ScanReport
from securescan.jobs.execution import (
    InvalidLeaseTokenError,
    InvalidWorkerRequestError,
    JobCancellationRequestedError,
    JobLeaseExpiredError,
    JobLeaseOwnershipError,
    JobLeaseTokenMismatchError,
)
from securescan.jobs.finalization import (
    InvalidJobFinalStatusError,
    _build_terminal_update,
    _classify_terminal_update_failure,
    _normalize_terminal_request,
)
from securescan.jobs.mappers import job_record_from_row
from securescan.jobs.models import JobRecord
from securescan.jobs.repository import JobNotFoundError, JobStateConflictError
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    ToolExecutionRow,
    utc_now,
)
from securescan.runs.aggregation import recompute_analysis_run_status


class JobResultCommitError(RuntimeError):
    """Raised when an atomic result-commit operation fails."""


class InvalidToolExecutionCommitError(JobResultCommitError):
    """Raised when tool execution metadata is invalid."""

    def __init__(self, field_name: str) -> None:
        self.field_name = field_name
        super().__init__(f"Invalid tool execution field: {field_name}")


class InvalidCanonicalReportError(JobResultCommitError):
    """Raised when a report does not satisfy the canonical report contract."""

    def __init__(self) -> None:
        super().__init__("The canonical SecureScan report failed validation")


class AnalysisRunNotFoundError(JobResultCommitError):
    """Raised when the job's analysis run cannot be found."""

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        super().__init__(f"Analysis run {run_id!r} was not found")


@dataclass(frozen=True, slots=True)
class ToolExecutionCommit:
    tool_version: str
    adapter_version: str
    outcome: str
    exit_code: int | None
    duration_ms: int
    warning_json: list[dict[str, Any]]
    error: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "warning_json", deepcopy(self.warning_json))


@dataclass(frozen=True, slots=True)
class JobResultCommitRequest:
    job_id: str
    worker_id: str
    lease_token: str
    final_status: JobStatus
    report_json: dict[str, Any]
    tool_execution: ToolExecutionCommit

    def __post_init__(self) -> None:
        object.__setattr__(self, "report_json", deepcopy(self.report_json))


@dataclass(frozen=True, slots=True)
class JobResultCommitResult:
    job: JobRecord
    run_id: str
    tool_execution_id: str
    attempt_number: int
    report_json: dict[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "report_json", deepcopy(self.report_json))


def _normalize_bounded_text(value: object, field_name: str, maximum_length: int) -> str:
    if not isinstance(value, str):
        raise InvalidToolExecutionCommitError(field_name)
    normalized_value = value.strip()
    if not normalized_value or len(normalized_value) > maximum_length:
        raise InvalidToolExecutionCommitError(field_name)
    return normalized_value


def _normalize_tool_execution(commit: ToolExecutionCommit) -> ToolExecutionCommit:
    if not isinstance(commit, ToolExecutionCommit):
        raise InvalidToolExecutionCommitError("tool_execution")

    tool_version = _normalize_bounded_text(commit.tool_version, "tool_version", 64)
    adapter_version = _normalize_bounded_text(commit.adapter_version, "adapter_version", 64)
    outcome = _normalize_bounded_text(commit.outcome, "outcome", 100)
    try:
        canonical_outcome = ExecutionOutcome(outcome).value
    except ValueError as exc:
        raise InvalidToolExecutionCommitError("outcome") from exc

    if (
        not isinstance(commit.duration_ms, int)
        or isinstance(commit.duration_ms, bool)
        or commit.duration_ms < 0
    ):
        raise InvalidToolExecutionCommitError("duration_ms")
    if commit.exit_code is not None and (
        not isinstance(commit.exit_code, int) or isinstance(commit.exit_code, bool)
    ):
        raise InvalidToolExecutionCommitError("exit_code")
    if not isinstance(commit.warning_json, list) or not all(
        isinstance(warning, dict) for warning in commit.warning_json
    ):
        raise InvalidToolExecutionCommitError("warning_json")
    if commit.error is not None and not isinstance(commit.error, str):
        raise InvalidToolExecutionCommitError("error")

    return ToolExecutionCommit(
        tool_version=tool_version,
        adapter_version=adapter_version,
        outcome=canonical_outcome,
        exit_code=commit.exit_code,
        duration_ms=commit.duration_ms,
        warning_json=deepcopy(commit.warning_json),
        error=commit.error,
    )


def _canonicalize_report(report_json: dict[str, Any]) -> dict[str, Any]:
    try:
        report = ScanReport.model_validate(deepcopy(report_json))
    except ValidationError as exc:
        raise InvalidCanonicalReportError from exc
    return report.model_dump(mode="json")


class JobResultCommitService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        clock: Callable[[], datetime] = utc_now,
        execution_id_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._session_factory = session_factory
        self._clock = clock
        self._execution_id_factory = execution_id_factory

    def commit_result(
        self,
        request: JobResultCommitRequest,
    ) -> JobResultCommitResult:
        normalized_worker_id, normalized_lease_token = _normalize_terminal_request(
            request.worker_id,
            request.lease_token,
            request.final_status,
        )
        tool_execution = _normalize_tool_execution(request.tool_execution)
        canonical_report = _canonicalize_report(request.report_json)

        try:
            with self._session_factory.begin() as session:
                operation_timestamp = self._clock()
                update_result = session.execute(
                    _build_terminal_update(
                        request.job_id,
                        normalized_worker_id,
                        normalized_lease_token,
                        request.final_status,
                        operation_timestamp,
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
                    raise JobResultCommitError(
                        f"Job {request.job_id!r} result commitment failed due to "
                        "an internal lifecycle conflict"
                    )
                if update_result.rowcount != 1:
                    raise JobResultCommitError(
                        f"Job {request.job_id!r} result commitment affected an "
                        "unexpected number of rows"
                    )

                job_row = session.get(JobRow, request.job_id)
                if job_row is None:
                    raise JobNotFoundError(request.job_id)
                analysis_run = session.get(AnalysisRunRow, job_row.run_id)
                if analysis_run is None:
                    raise AnalysisRunNotFoundError(job_row.run_id)

                execution_id = str(self._execution_id_factory())
                execution_row = ToolExecutionRow(
                    id=execution_id,
                    run_id=job_row.run_id,
                    job_id=job_row.id,
                    attempt_number=job_row.attempt_count,
                    adapter_id=job_row.adapter_id,
                    tool_version=tool_execution.tool_version,
                    adapter_version=tool_execution.adapter_version,
                    outcome=tool_execution.outcome,
                    exit_code=tool_execution.exit_code,
                    duration_ms=tool_execution.duration_ms,
                    warning_json=deepcopy(tool_execution.warning_json),
                    error=tool_execution.error,
                )
                session.add(execution_row)
                analysis_run.report_json = deepcopy(canonical_report)
                recompute_analysis_run_status(
                    session,
                    job_row.run_id,
                    changed_at=operation_timestamp,
                )
                session.flush()

                job = job_record_from_row(job_row)
                result = JobResultCommitResult(
                    job=job,
                    run_id=job_row.run_id,
                    tool_execution_id=execution_id,
                    attempt_number=job_row.attempt_count,
                    report_json=deepcopy(canonical_report),
                )
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
            JobResultCommitError,
        ):
            raise
        except SQLAlchemyError:
            raise JobResultCommitError(
                f"Failed to commit result for job {request.job_id!r}"
            ) from None

        return result
