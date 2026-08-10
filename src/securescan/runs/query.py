from __future__ import annotations

from copy import deepcopy

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.domain.enums import JobFailureCategory, JobStatus, RunStatus
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    ToolExecutionRow,
)
from securescan.runs.models import (
    AnalysisRunRecord,
    PaginatedRunJobs,
    PaginatedToolExecutions,
    RunJobSummary,
    RunReportRecord,
    ToolExecutionSummary,
)

_ACTIVE_JOB_STATUSES = frozenset(
    {
        JobStatus.SUBMITTED,
        JobStatus.QUEUED,
        JobStatus.LEASED,
        JobStatus.RUNNING,
        JobStatus.RETRY_PENDING,
    }
)


class RunQueryError(RuntimeError):
    """Raised when a read-only analysis-run query is invalid."""


class RunNotFoundError(RunQueryError):
    """Raised when an analysis run does not exist."""

    def __init__(self) -> None:
        super().__init__("Analysis run was not found")


class RunReportNotReadyError(RunQueryError):
    """Raised when an analysis run has no stored canonical report."""

    def __init__(self) -> None:
        super().__init__("Analysis run report is not available")


class RunQueryPersistenceError(RunQueryError):
    """Raised when analysis-run read persistence is unavailable."""

    def __init__(self) -> None:
        super().__init__("Analysis run query persistence is unavailable")


class RunQueryService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
    ) -> None:
        self._session_factory = session_factory

    def get_run(
        self,
        run_id: str,
    ) -> AnalysisRunRecord:
        normalized_run_id = self._normalize_run_id(run_id)
        try:
            with self._session_factory() as session:
                run = session.get(AnalysisRunRow, normalized_run_id)
                if run is None:
                    raise RunNotFoundError
                persisted_statuses = list(
                    session.scalars(select(JobRow.status).where(JobRow.run_id == run.id))
                )
                statuses = [JobStatus(status) for status in persisted_statuses]
                record = AnalysisRunRecord(
                    id=run.id,
                    target_id=run.target_id,
                    status=RunStatus(run.status),
                    created_at=run.created_at,
                    updated_at=None,
                    finished_at=None,
                    total_jobs=len(statuses),
                    active_jobs=sum(status in _ACTIVE_JOB_STATUSES for status in statuses),
                    succeeded_jobs=statuses.count(JobStatus.SUCCEEDED),
                    partial_jobs=statuses.count(JobStatus.PARTIAL),
                    failed_jobs=statuses.count(JobStatus.FAILED),
                    cancelled_jobs=statuses.count(JobStatus.CANCELLED),
                    has_report=run.report_json is not None,
                )
        except RunQueryError:
            raise
        except SQLAlchemyError as exc:
            raise RunQueryPersistenceError from exc
        except (TypeError, ValueError) as exc:
            raise RunQueryPersistenceError from exc
        return record

    def list_jobs(
        self,
        run_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> PaginatedRunJobs:
        normalized_run_id = self._normalize_run_id(run_id)
        self._validate_pagination(limit, offset)
        try:
            with self._session_factory() as session:
                self._require_run(session, normalized_run_id)
                total = session.scalar(
                    select(func.count())
                    .select_from(JobRow)
                    .where(JobRow.run_id == normalized_run_id)
                )
                rows = list(
                    session.scalars(
                        select(JobRow)
                        .where(JobRow.run_id == normalized_run_id)
                        .order_by(JobRow.created_at.asc(), JobRow.id.asc())
                        .limit(limit)
                        .offset(offset)
                    )
                )
                items = tuple(
                    RunJobSummary(
                        job_id=row.id,
                        run_id=row.run_id,
                        adapter_id=row.adapter_id,
                        status=JobStatus(row.status),
                        priority=row.priority,
                        attempt_count=row.attempt_count,
                        max_attempts=row.max_attempts,
                        cancel_requested=row.cancel_requested,
                        created_at=row.created_at,
                        started_at=row.started_at,
                        finished_at=row.finished_at,
                        available_at=row.available_at,
                    )
                    for row in rows
                )
        except RunQueryError:
            raise
        except SQLAlchemyError as exc:
            raise RunQueryPersistenceError from exc
        except (TypeError, ValueError) as exc:
            raise RunQueryPersistenceError from exc
        return PaginatedRunJobs(
            items=items,
            total=int(total or 0),
            limit=limit,
            offset=offset,
        )

    def list_tool_executions(
        self,
        run_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> PaginatedToolExecutions:
        normalized_run_id = self._normalize_run_id(run_id)
        self._validate_pagination(limit, offset)
        try:
            with self._session_factory() as session:
                self._require_run(session, normalized_run_id)
                total = session.scalar(
                    select(func.count())
                    .select_from(ToolExecutionRow)
                    .where(ToolExecutionRow.run_id == normalized_run_id)
                )
                rows = list(
                    session.scalars(
                        select(ToolExecutionRow)
                        .where(ToolExecutionRow.run_id == normalized_run_id)
                        .order_by(
                            ToolExecutionRow.attempt_number.asc().nulls_last(),
                            ToolExecutionRow.id.asc(),
                        )
                        .limit(limit)
                        .offset(offset)
                    )
                )
                items = tuple(
                    ToolExecutionSummary(
                        execution_id=row.id,
                        run_id=row.run_id,
                        job_id=row.job_id,
                        attempt_number=row.attempt_number,
                        adapter_id=row.adapter_id,
                        adapter_version=row.adapter_version,
                        tool_version=row.tool_version,
                        outcome=row.outcome,
                        exit_code=row.exit_code,
                        duration_ms=row.duration_ms,
                        failure_category=(
                            JobFailureCategory(row.failure_category)
                            if row.failure_category is not None
                            else None
                        ),
                        retryable=row.retryable,
                        created_at=None,
                    )
                    for row in rows
                )
        except RunQueryError:
            raise
        except SQLAlchemyError as exc:
            raise RunQueryPersistenceError from exc
        except (TypeError, ValueError) as exc:
            raise RunQueryPersistenceError from exc
        return PaginatedToolExecutions(
            items=items,
            total=int(total or 0),
            limit=limit,
            offset=offset,
        )

    def get_report(
        self,
        run_id: str,
    ) -> RunReportRecord:
        normalized_run_id = self._normalize_run_id(run_id)
        try:
            with self._session_factory() as session:
                run = session.get(AnalysisRunRow, normalized_run_id)
                if run is None:
                    raise RunNotFoundError
                if run.report_json is None:
                    raise RunReportNotReadyError
                if not isinstance(run.report_json, dict):
                    raise RunQueryPersistenceError
                record = RunReportRecord(
                    run_id=run.id,
                    status=RunStatus(run.status),
                    report_json=deepcopy(run.report_json),
                )
        except RunQueryError:
            raise
        except SQLAlchemyError as exc:
            raise RunQueryPersistenceError from exc
        except (TypeError, ValueError) as exc:
            raise RunQueryPersistenceError from exc
        return record

    @staticmethod
    def _normalize_run_id(run_id: str) -> str:
        if not isinstance(run_id, str) or not run_id.strip():
            raise RunQueryError("Analysis run identity is invalid")
        return run_id.strip()

    @staticmethod
    def _validate_pagination(limit: int, offset: int) -> None:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 100
            or isinstance(offset, bool)
            or not isinstance(offset, int)
            or not 0 <= offset <= 1_000_000_000
        ):
            raise RunQueryError("Analysis run pagination is invalid")

    @staticmethod
    def _require_run(session: Session, run_id: str) -> None:
        if session.get(AnalysisRunRow, run_id) is None:
            raise RunNotFoundError
