from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from securescan.domain.enums import JobFailureCategory, JobStatus, RunStatus


class AnalysisRunApiResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    target_id: str
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


class RunJobSummaryApiResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

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


class PaginatedRunJobsApiResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[RunJobSummaryApiResponse]
    total: int
    limit: int
    offset: int


class ToolExecutionSummaryApiResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

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


class PaginatedToolExecutionsApiResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ToolExecutionSummaryApiResponse]
    total: int
    limit: int
    offset: int


class RunReportApiResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    status: RunStatus
    report_json: dict[str, Any]
