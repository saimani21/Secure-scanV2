from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from securescan.domain.enums import JobStatus, RunStatus
from securescan.persistence.database import AnalysisRunRow, JobRow

_QUEUED_JOB_STATUSES = frozenset(
    {
        JobStatus.SUBMITTED,
        JobStatus.QUEUED,
        JobStatus.RETRY_PENDING,
    }
)
_RUNNING_JOB_STATUSES = frozenset(
    {
        JobStatus.LEASED,
        JobStatus.RUNNING,
    }
)
_TERMINAL_JOB_STATUSES = frozenset(
    {
        JobStatus.SUCCEEDED,
        JobStatus.PARTIAL,
        JobStatus.FAILED,
        JobStatus.CANCELLED,
    }
)


class RunAggregationError(RuntimeError):
    """Raised when an analysis-run status cannot be aggregated safely."""


def aggregate_run_status(
    job_statuses: Sequence[JobStatus],
) -> RunStatus:
    if not job_statuses:
        raise RunAggregationError("Analysis run status requires at least one job")
    if any(not isinstance(status, JobStatus) for status in job_statuses):
        raise RunAggregationError("Analysis run contains an unsupported job status")

    statuses = set(job_statuses)
    if statuses & _RUNNING_JOB_STATUSES:
        return RunStatus.RUNNING
    if statuses & _QUEUED_JOB_STATUSES:
        return RunStatus.QUEUED
    if not statuses <= _TERMINAL_JOB_STATUSES:
        raise RunAggregationError("Analysis run contains an unsupported job status")
    if statuses == {JobStatus.SUCCEEDED}:
        return RunStatus.COMPLETED
    if statuses == {JobStatus.CANCELLED}:
        return RunStatus.CANCELLED
    if statuses == {JobStatus.FAILED}:
        return RunStatus.FAILED
    if JobStatus.PARTIAL in statuses:
        return RunStatus.PARTIAL
    if JobStatus.SUCCEEDED in statuses:
        return RunStatus.PARTIAL
    if statuses <= {JobStatus.FAILED, JobStatus.CANCELLED}:
        return RunStatus.FAILED
    raise RunAggregationError("Analysis run terminal status is inconsistent")


def recompute_analysis_run_status(
    session: Session,
    run_id: str,
    *,
    changed_at: datetime,
) -> RunStatus:
    if not isinstance(run_id, str) or not run_id.strip():
        raise RunAggregationError("Analysis run identity is invalid")
    if (
        not isinstance(changed_at, datetime)
        or changed_at.tzinfo is None
        or changed_at.utcoffset() is None
    ):
        raise RunAggregationError("Analysis run change time must be timezone-aware")

    # Make the caller's pending job mutation visible before the aggregate query.
    # This remains part of the caller-owned transaction and does not commit it.
    session.flush()
    run = session.scalar(
        select(AnalysisRunRow)
        .where(AnalysisRunRow.id == run_id.strip())
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if run is None:
        raise RunAggregationError("Analysis run was not found during aggregation")

    persisted_statuses = list(
        session.scalars(
            select(JobRow.status)
            .where(JobRow.run_id == run.id)
            .order_by(JobRow.created_at.asc(), JobRow.id.asc())
        )
    )
    try:
        job_statuses = [JobStatus(status) for status in persisted_statuses]
    except ValueError as exc:
        raise RunAggregationError(
            "Analysis run contains an unsupported persisted job status"
        ) from exc

    aggregated = aggregate_run_status(job_statuses)
    run.status = aggregated.value
    return aggregated
