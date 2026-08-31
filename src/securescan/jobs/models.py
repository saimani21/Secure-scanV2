from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from securescan.domain.enums import JobStatus

RESERVED_INTERNAL_JOB_PAYLOAD_PREFIX = "__securescan_internal_"


@dataclass(frozen=True, slots=True)
class JobCreate:
    run_id: str
    adapter_id: str
    idempotency_key: str
    payload_json: dict[str, Any] = field(default_factory=dict)
    priority: int = 100
    max_attempts: int = 3
    available_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class JobRecord:
    id: str
    run_id: str
    adapter_id: str
    status: JobStatus
    priority: int
    attempt_count: int
    max_attempts: int
    available_at: datetime
    leased_by: str | None
    lease_expires_at: datetime | None
    heartbeat_at: datetime | None
    cancel_requested: bool
    idempotency_key: str
    payload_json: dict[str, Any]
    last_error: str | None
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    lease_token: str | None = None
    cancel_requested_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class JobSubmissionRequest:
    target_id: str
    adapter_id: str
    idempotency_key: str
    payload_json: dict[str, Any] = field(default_factory=dict)
    priority: int = 100
    max_attempts: int = 3


@dataclass(frozen=True, slots=True)
class JobSubmissionResult:
    run_id: str
    job_id: str
    status: JobStatus
    idempotency_key: str
    created: bool


@dataclass(frozen=True, slots=True)
class ServerOwnedJobSubmissionRequest:
    run_id: str
    job_id: str
    target_id: str
    adapter_id: str
    idempotency_key: str
    payload_json: dict[str, Any]
    expected_target_content_digest: str
    priority: int = 100
    max_attempts: int = 3
