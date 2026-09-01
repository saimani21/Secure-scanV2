from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from securescan.domain.enums import JobFailureCategory, JobStatus, RunStatus


def _normalize_utc_datetime(
    value: datetime | None,
) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class AnalysisRunRecord:
    id: str
    target_id: str
    target_content_digest: str
    status: RunStatus
    created_at: datetime
    updated_at: datetime | None
    finished_at: datetime | None
    total_jobs: int
    active_jobs: int
    succeeded_jobs: int
    partial_jobs: int
    failed_jobs: int
    cancelled_jobs: int
    has_report: bool

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "created_at",
            _normalize_utc_datetime(self.created_at),
        )
        object.__setattr__(
            self,
            "updated_at",
            _normalize_utc_datetime(self.updated_at),
        )
        object.__setattr__(
            self,
            "finished_at",
            _normalize_utc_datetime(self.finished_at),
        )


@dataclass(frozen=True, slots=True)
class RunJobSummary:
    job_id: str
    run_id: str
    adapter_id: str
    status: JobStatus
    priority: int
    attempt_count: int
    max_attempts: int
    cancel_requested: bool
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    available_at: datetime

    def __post_init__(self) -> None:
        for field_name in (
            "created_at",
            "started_at",
            "finished_at",
            "available_at",
        ):
            object.__setattr__(
                self,
                field_name,
                _normalize_utc_datetime(getattr(self, field_name)),
            )


@dataclass(frozen=True, slots=True)
class ToolExecutionSummary:
    execution_id: str
    run_id: str
    job_id: str | None
    attempt_number: int | None
    adapter_id: str
    adapter_version: str
    tool_version: str
    outcome: str
    exit_code: int | None
    duration_ms: int
    failure_category: JobFailureCategory | None
    retryable: bool | None
    created_at: datetime | None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "created_at",
            _normalize_utc_datetime(self.created_at),
        )


@dataclass(frozen=True, slots=True)
class PaginatedRunJobs:
    items: tuple[RunJobSummary, ...]
    total: int
    limit: int
    offset: int


@dataclass(frozen=True, slots=True)
class PaginatedToolExecutions:
    items: tuple[ToolExecutionSummary, ...]
    total: int
    limit: int
    offset: int


@dataclass(frozen=True, slots=True)
class RunReportRecord:
    run_id: str
    status: RunStatus
    report_json: dict[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "report_json", deepcopy(self.report_json))
