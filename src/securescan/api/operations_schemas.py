from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from securescan.observability.readiness import ReadinessReason


class LivenessApiResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["alive"]


class ReadinessApiResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ready", "not_ready"]
    database_reachable: bool
    schema_at_head: bool
    reason: ReadinessReason
    checked_at: datetime


class OperationalMetricsApiResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_at: datetime
    total_runs: int = Field(ge=0)
    active_runs: int = Field(ge=0)
    total_jobs: int = Field(ge=0)
    queued_jobs: int = Field(ge=0)
    leased_jobs: int = Field(ge=0)
    running_jobs: int = Field(ge=0)
    retry_pending_jobs: int = Field(ge=0)
    succeeded_jobs: int = Field(ge=0)
    partial_jobs: int = Field(ge=0)
    failed_jobs: int = Field(ge=0)
    cancelled_jobs: int = Field(ge=0)
    cancellation_requested_jobs: int = Field(ge=0)
    expired_active_leases: int = Field(ge=0)
    total_tool_executions: int = Field(ge=0)
    retryable_tool_failures: int = Field(ge=0)
    permanent_tool_failures: int = Field(ge=0)
    average_execution_duration_ms: float | None = Field(default=None, ge=0)
    maximum_execution_duration_ms: int | None = Field(default=None, ge=0)
    failures_by_category: dict[str, int]
