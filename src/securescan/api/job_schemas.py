from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from securescan.domain.enums import JobStatus


class JobSubmissionApiRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: str = Field(min_length=1, max_length=36)
    adapter_id: str = Field(min_length=1, max_length=100)
    idempotency_key: str = Field(min_length=1, max_length=64)
    payload_json: dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(default=100, ge=0)
    max_attempts: int = Field(default=3, ge=1)


class JobSubmissionApiResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    job_id: str
    status: JobStatus
    idempotency_key: str
    created: bool


class JobStatusApiResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_id: str
    run_id: str
    adapter_id: str
    status: JobStatus
    priority: int
    attempt_count: int
    max_attempts: int
    available_at: datetime
    cancel_requested: bool
    idempotency_key: str
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class JobCancellationApiResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_id: str
    run_id: str
    status: JobStatus
    cancel_requested: bool
    cancel_requested_at: datetime | None
    finished_at: datetime | None
    immediate: bool
    already_requested: bool


class ApiErrorDetail(BaseModel):
    code: str
    message: str


class ApiErrorResponse(BaseModel):
    detail: ApiErrorDetail
