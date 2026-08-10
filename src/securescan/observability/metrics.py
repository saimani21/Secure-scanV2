from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import case, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.domain.enums import JobStatus, RunStatus
from securescan.persistence.database import AnalysisRunRow, JobRow, ToolExecutionRow, utc_now

_TERMINAL_RUN_STATUSES = frozenset(
    {
        RunStatus.COMPLETED,
        RunStatus.PARTIAL,
        RunStatus.FAILED,
        RunStatus.CANCELLED,
    }
)
_ACTIVE_RUN_STATUSES = tuple(
    status.value for status in RunStatus if status not in _TERMINAL_RUN_STATUSES
)


class OperationalMetricsError(RuntimeError):
    """Raised when safe operational metrics cannot be produced."""


class OperationalMetricsPersistenceError(OperationalMetricsError):
    """Raised when operational metrics cannot be read from persistence."""

    def __init__(self) -> None:
        super().__init__("Operational metrics are temporarily unavailable.")


def _normalized_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise OperationalMetricsError("Operational metrics timestamp is invalid.")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class OperationalMetricsSnapshot:
    generated_at: datetime
    total_runs: int
    active_runs: int
    total_jobs: int
    queued_jobs: int
    leased_jobs: int
    running_jobs: int
    retry_pending_jobs: int
    succeeded_jobs: int
    partial_jobs: int
    failed_jobs: int
    cancelled_jobs: int
    cancellation_requested_jobs: int
    expired_active_leases: int
    total_tool_executions: int
    retryable_tool_failures: int
    permanent_tool_failures: int
    average_execution_duration_ms: float | None
    maximum_execution_duration_ms: int | None
    failures_by_category: dict[str, int]

    def __post_init__(self) -> None:
        object.__setattr__(self, "generated_at", _normalized_utc(self.generated_at))
        count_fields = (
            "total_runs",
            "active_runs",
            "total_jobs",
            "queued_jobs",
            "leased_jobs",
            "running_jobs",
            "retry_pending_jobs",
            "succeeded_jobs",
            "partial_jobs",
            "failed_jobs",
            "cancelled_jobs",
            "cancellation_requested_jobs",
            "expired_active_leases",
            "total_tool_executions",
            "retryable_tool_failures",
            "permanent_tool_failures",
        )
        if any(
            isinstance(getattr(self, name), bool)
            or not isinstance(getattr(self, name), int)
            or getattr(self, name) < 0
            for name in count_fields
        ):
            raise OperationalMetricsError("Operational metrics counts are invalid.")
        if self.average_execution_duration_ms is not None and (
            isinstance(self.average_execution_duration_ms, bool)
            or not isinstance(self.average_execution_duration_ms, (int, float))
            or self.average_execution_duration_ms < 0
        ):
            raise OperationalMetricsError("Operational metrics duration is invalid.")
        if self.maximum_execution_duration_ms is not None and (
            isinstance(self.maximum_execution_duration_ms, bool)
            or not isinstance(self.maximum_execution_duration_ms, int)
            or self.maximum_execution_duration_ms < 0
        ):
            raise OperationalMetricsError("Operational metrics duration is invalid.")
        if not isinstance(self.failures_by_category, dict):
            raise OperationalMetricsError("Operational metrics failure categories are invalid.")
        categories = dict(sorted(self.failures_by_category.items()))
        if any(
            not isinstance(key, str)
            or isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            for key, value in categories.items()
        ):
            raise OperationalMetricsError("Operational metrics failure categories are invalid.")
        object.__setattr__(self, "failures_by_category", categories)


def _count_when(condition):
    return func.coalesce(func.sum(case((condition, 1), else_=0)), 0)


class OperationalMetricsService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._session_factory = session_factory
        self._clock = clock

    def collect(self) -> OperationalMetricsSnapshot:
        generated_at = _normalized_utc(self._clock())
        try:
            with self._session_factory() as session:
                total_runs, active_runs = session.execute(
                    select(
                        func.count(),
                        _count_when(AnalysisRunRow.status.in_(_ACTIVE_RUN_STATUSES)),
                    ).select_from(AnalysisRunRow)
                ).one()

                # SUBMITTED is awaiting queue entry under the current queue contract.
                job_counts = session.execute(
                    select(
                        func.count(),
                        _count_when(
                            JobRow.status.in_(
                                (
                                    JobStatus.SUBMITTED.value,
                                    JobStatus.QUEUED.value,
                                )
                            )
                        ),
                        _count_when(JobRow.status == JobStatus.LEASED.value),
                        _count_when(JobRow.status == JobStatus.RUNNING.value),
                        _count_when(JobRow.status == JobStatus.RETRY_PENDING.value),
                        _count_when(JobRow.status == JobStatus.SUCCEEDED.value),
                        _count_when(JobRow.status == JobStatus.PARTIAL.value),
                        _count_when(JobRow.status == JobStatus.FAILED.value),
                        _count_when(JobRow.status == JobStatus.CANCELLED.value),
                        _count_when(JobRow.cancel_requested.is_(True)),
                        _count_when(
                            JobRow.status.in_(
                                (
                                    JobStatus.LEASED.value,
                                    JobStatus.RUNNING.value,
                                )
                            )
                            & JobRow.lease_expires_at.is_not(None)
                            & (JobRow.lease_expires_at < generated_at)
                        ),
                    ).select_from(JobRow)
                ).one()

                execution_counts = session.execute(
                    select(
                        func.count(),
                        _count_when(ToolExecutionRow.retryable.is_(True)),
                        _count_when(
                            ToolExecutionRow.failure_category.is_not(None)
                            & ToolExecutionRow.retryable.is_(False)
                        ),
                        func.avg(ToolExecutionRow.duration_ms),
                        func.max(ToolExecutionRow.duration_ms),
                    ).select_from(ToolExecutionRow)
                ).one()
                failures_by_category = dict(
                    session.execute(
                        select(
                            ToolExecutionRow.failure_category,
                            func.count(),
                        )
                        .where(ToolExecutionRow.failure_category.is_not(None))
                        .group_by(ToolExecutionRow.failure_category)
                        .order_by(ToolExecutionRow.failure_category.asc())
                    ).all()
                )
        except SQLAlchemyError as exc:
            raise OperationalMetricsPersistenceError from exc

        (
            total_jobs,
            queued_jobs,
            leased_jobs,
            running_jobs,
            retry_pending_jobs,
            succeeded_jobs,
            partial_jobs,
            failed_jobs,
            cancelled_jobs,
            cancellation_requested_jobs,
            expired_active_leases,
        ) = job_counts
        (
            total_tool_executions,
            retryable_tool_failures,
            permanent_tool_failures,
            average_execution_duration_ms,
            maximum_execution_duration_ms,
        ) = execution_counts

        return OperationalMetricsSnapshot(
            generated_at=generated_at,
            total_runs=total_runs,
            active_runs=active_runs,
            total_jobs=total_jobs,
            queued_jobs=queued_jobs,
            leased_jobs=leased_jobs,
            running_jobs=running_jobs,
            retry_pending_jobs=retry_pending_jobs,
            succeeded_jobs=succeeded_jobs,
            partial_jobs=partial_jobs,
            failed_jobs=failed_jobs,
            cancelled_jobs=cancelled_jobs,
            cancellation_requested_jobs=cancellation_requested_jobs,
            expired_active_leases=expired_active_leases,
            total_tool_executions=total_tool_executions,
            retryable_tool_failures=retryable_tool_failures,
            permanent_tool_failures=permanent_tool_failures,
            average_execution_duration_ms=(
                float(average_execution_duration_ms)
                if average_execution_duration_ms is not None
                else None
            ),
            maximum_execution_duration_ms=maximum_execution_duration_ms,
            failures_by_category=failures_by_category,
        )
