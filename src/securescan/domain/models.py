from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from securescan.domain.enums import (
    ArtifactKind,
    ExecutionOutcome,
    ObservationType,
    RunStatus,
    TargetType,
)


def utc_now() -> datetime:
    return datetime.now(UTC)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TargetProfile(StrictModel):
    target_type: TargetType
    path: Path
    content_digest: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExecutionPlan(StrictModel):
    adapter_id: str
    command: list[str]
    cwd: Path | None = None
    environment: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=15, ge=1)
    max_output_bytes: int = Field(default=1_048_576, ge=1_024)


class CapturedProcess(StrictModel):
    command: list[str]
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    duration_ms: int
    timed_out: bool = False
    output_limit_exceeded: bool = False


class OutputValidation(StrictModel):
    valid: bool
    schema_version: str | None = None
    warnings: list[str] = Field(default_factory=list)
    error: str | None = None


class Observation(StrictModel):
    observation_id: UUID = Field(default_factory=uuid4)
    producer: str
    observation_type: ObservationType
    rule_id: str
    message: str
    native_severity: str | None = None
    path: str | None = None
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    symbol: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    fingerprint: str | None = None
    properties: dict[str, Any] = Field(default_factory=dict)


class ArtifactRecord(StrictModel):
    artifact_id: UUID = Field(default_factory=uuid4)
    kind: ArtifactKind
    sha256: str
    size_bytes: int
    media_type: str
    storage_path: str
    sanitized: bool
    created_at: datetime = Field(default_factory=utc_now)


class ToolExecutionRecord(StrictModel):
    execution_id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    adapter_id: str
    tool_version: str
    adapter_version: str
    status: RunStatus
    outcome: ExecutionOutcome
    exit_code: int | None = None
    started_at: datetime
    finished_at: datetime
    duration_ms: int
    warnings: list[str] = Field(default_factory=list)
    error: str | None = None
    artifacts: list[ArtifactRecord] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)


class AnalysisGap(StrictModel):
    code: str
    message: str
    adapter_id: str | None = None


class ScanReport(StrictModel):
    schema_version: str = "1.0.0"
    run_id: UUID
    target: TargetProfile
    status: RunStatus
    executions: list[ToolExecutionRecord]
    observations: list[Observation]
    analysis_gaps: list[AnalysisGap] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=utc_now)
