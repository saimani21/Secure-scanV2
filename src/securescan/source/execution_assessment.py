from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any
from uuid import UUID

from securescan.domain.enums import JobStatus, ObservationType
from securescan.source.enums import (
    AnalysisCapability,
    AssessmentStatus,
    CoverageStatus,
    SourceExecutionStatus,
)

_ASSESSMENT_STREAM_VERSION = b"securescan-source-execution-assessment-v0.3D\0"
_ASSESSMENT_SCHEMA_VERSION = "0.3D"
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_IDENTIFIER_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z", re.ASCII)
_GAP_CODE_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{1,127}\Z", re.ASCII)
_CWE_PATTERN = re.compile(r"CWE-[1-9][0-9]{0,5}\Z", re.ASCII)
_SEVERITIES = frozenset({"high", "medium", "low", "informational"})
_TERMINAL_JOB_STATUSES = frozenset(
    {JobStatus.SUCCEEDED, JobStatus.PARTIAL, JobStatus.FAILED, JobStatus.CANCELLED}
)


class SourceExecutionAssessmentError(RuntimeError):
    """Base class for Source execution assessment contract failures."""


class InvalidSourceExecutionAssessmentError(
    SourceExecutionAssessmentError,
    ValueError,
):
    def __init__(self) -> None:
        RuntimeError.__init__(self, "Source execution assessment is invalid")


def _valid_text(value: object, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and value == value.strip()
        and 1 <= len(value) <= maximum
        and not any(unicodedata.category(char).startswith("C") for char in value)
    )


def _valid_identifier(value: object) -> bool:
    return isinstance(value, str) and _IDENTIFIER_PATTERN.fullmatch(value) is not None


def _valid_uuid(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 36 or value != value.lower():
        return False
    try:
        return str(UUID(value)) == value
    except ValueError:
        return False


def _valid_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    if any(unicodedata.category(char).startswith("C") for char in value):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and path.as_posix() == value
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class SourceSecurityObservation:
    observation_id: str
    producer: str
    observation_type: ObservationType
    rule_id: str
    message: str
    native_severity: str
    relative_path: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    cwe_ids: tuple[str, ...]
    fingerprint: str

    def __post_init__(self) -> None:
        if (
            not _valid_uuid(self.observation_id)
            or not _valid_identifier(self.producer)
            or self.observation_type is not ObservationType.SOURCE_RULE_MATCH
            or not _valid_text(self.rule_id, 512)
            or not _valid_text(self.message, 256)
            or self.native_severity not in _SEVERITIES
            or not _valid_path(self.relative_path)
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 1
                for value in (
                    self.start_line,
                    self.start_column,
                    self.end_line,
                    self.end_column,
                )
            )
            or (self.end_line, self.end_column)
            < (self.start_line, self.start_column)
            or not isinstance(self.cwe_ids, tuple)
            or any(
                not isinstance(cwe, str) or _CWE_PATTERN.fullmatch(cwe) is None
                for cwe in self.cwe_ids
            )
            or self.cwe_ids != tuple(sorted(self.cwe_ids))
            or len(set(self.cwe_ids)) != len(self.cwe_ids)
            or not isinstance(self.fingerprint, str)
            or _SHA256_PATTERN.fullmatch(self.fingerprint) is None
            or self.observation_id != str(UUID(self.fingerprint[:32]))
        ):
            raise InvalidSourceExecutionAssessmentError

    def sort_key(self) -> tuple[object, ...]:
        return (
            self.relative_path,
            self.start_line,
            self.start_column,
            self.end_line,
            self.end_column,
            self.rule_id,
            self.fingerprint,
        )

    def canonical_data(self) -> dict[str, Any]:
        return {
            "cwe_ids": list(self.cwe_ids),
            "end_column": self.end_column,
            "end_line": self.end_line,
            "fingerprint": self.fingerprint,
            "message": self.message,
            "native_severity": self.native_severity,
            "observation_id": self.observation_id,
            "observation_type": self.observation_type.value,
            "producer": self.producer,
            "relative_path": self.relative_path,
            "rule_id": self.rule_id,
            "start_column": self.start_column,
            "start_line": self.start_line,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class SourceAnalysisGap:
    code: str
    capability: AnalysisCapability
    component_id: str | None
    stage: str
    relative_path: str | None
    message: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.code, str)
            or _GAP_CODE_PATTERN.fullmatch(self.code) is None
            or not isinstance(self.capability, AnalysisCapability)
            or (self.component_id is not None and not _valid_identifier(self.component_id))
            or not _valid_identifier(self.stage)
            or (self.relative_path is not None and not _valid_path(self.relative_path))
            or not _valid_text(self.message, 256)
        ):
            raise InvalidSourceExecutionAssessmentError

    def sort_key(self) -> tuple[str, str, str, str]:
        return (
            self.code,
            self.relative_path or "",
            self.stage,
            self.message,
        )

    def canonical_data(self) -> dict[str, Any]:
        return {
            "capability": self.capability.value,
            "code": self.code,
            "component_id": self.component_id,
            "message": self.message,
            "relative_path": self.relative_path,
            "stage": self.stage,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class SourceCapabilityExecutionAssessment:
    source_run_id: str
    job_id: str
    repository_digest: str
    profile_digest: str
    plan_digest: str
    source_analyzer_id: str
    capability: AnalysisCapability
    component_id: str | None
    binding_digest: str
    core_adapter_id: str
    execution_status: SourceExecutionStatus
    coverage_status: CoverageStatus
    assessment_status: AssessmentStatus
    declared_paths: tuple[str, ...]
    declared_file_count: int
    declared_total_bytes: int
    observations: tuple[SourceSecurityObservation, ...]
    gaps: tuple[SourceAnalysisGap, ...]
    attempt_count: int
    terminal_job_status: JobStatus
    final_tool_execution_id: str | None
    tool_version: str | None
    schema_version: str = _ASSESSMENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        digests = (
            self.repository_digest,
            self.profile_digest,
            self.plan_digest,
            self.binding_digest,
        )
        common_invalid = (
            self.schema_version != _ASSESSMENT_SCHEMA_VERSION
            or not _valid_uuid(self.source_run_id)
            or not _valid_uuid(self.job_id)
            or any(
                not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None
                for value in digests
            )
            or not _valid_identifier(self.source_analyzer_id)
            or not isinstance(self.capability, AnalysisCapability)
            or (self.component_id is not None and not _valid_identifier(self.component_id))
            or not _valid_identifier(self.core_adapter_id)
            or not isinstance(self.execution_status, SourceExecutionStatus)
            or not isinstance(self.coverage_status, CoverageStatus)
            or self.assessment_status is not AssessmentStatus.OBSERVATIONS_ONLY
            or not isinstance(self.declared_paths, tuple)
            or any(not _valid_path(path) for path in self.declared_paths)
            or self.declared_paths != tuple(sorted(self.declared_paths))
            or len(set(self.declared_paths)) != len(self.declared_paths)
            or isinstance(self.declared_file_count, bool)
            or not isinstance(self.declared_file_count, int)
            or self.declared_file_count != len(self.declared_paths)
            or self.declared_file_count < 1
            or isinstance(self.declared_total_bytes, bool)
            or not isinstance(self.declared_total_bytes, int)
            or self.declared_total_bytes < 0
            or not isinstance(self.observations, tuple)
            or any(not isinstance(item, SourceSecurityObservation) for item in self.observations)
            or self.observations
            != tuple(sorted(self.observations, key=lambda item: item.sort_key()))
            or len({item.fingerprint for item in self.observations}) != len(self.observations)
            or any(item.relative_path not in self.declared_paths for item in self.observations)
            or not isinstance(self.gaps, tuple)
            or any(not isinstance(item, SourceAnalysisGap) for item in self.gaps)
            or self.gaps != tuple(sorted(self.gaps, key=lambda item: item.sort_key()))
            or any(
                item.capability is not self.capability
                or item.component_id != self.component_id
                or (
                    item.relative_path is not None
                    and item.relative_path not in self.declared_paths
                )
                for item in self.gaps
            )
            or isinstance(self.attempt_count, bool)
            or not isinstance(self.attempt_count, int)
            or self.attempt_count < 0
            or self.terminal_job_status not in _TERMINAL_JOB_STATUSES
            or (
                self.final_tool_execution_id is not None
                and not _valid_uuid(self.final_tool_execution_id)
            )
            or (
                self.tool_version is not None
                and not _valid_text(self.tool_version, 64)
            )
        )
        complete_invalid = self.execution_status is SourceExecutionStatus.COMPLETE and (
            self.terminal_job_status is not JobStatus.SUCCEEDED
            or self.coverage_status is not CoverageStatus.FULL_FOR_DECLARED_SCOPE
            or bool(self.gaps)
            or self.attempt_count < 1
            or self.final_tool_execution_id is None
            or self.tool_version is None
        )
        partial_invalid = self.execution_status is SourceExecutionStatus.PARTIAL and (
            self.terminal_job_status is not JobStatus.PARTIAL
            or self.coverage_status is not CoverageStatus.PARTIAL
            or not self.gaps
            or self.attempt_count < 1
            or self.final_tool_execution_id is None
            or self.tool_version is None
        )
        failed_invalid = self.execution_status is SourceExecutionStatus.FAILED and (
            self.terminal_job_status not in {JobStatus.FAILED, JobStatus.CANCELLED}
            or self.coverage_status is not CoverageStatus.UNKNOWN
            or not self.gaps
            or (
                self.terminal_job_status is JobStatus.FAILED
                and (
                    self.attempt_count < 1
                    or self.final_tool_execution_id is None
                    or self.tool_version is None
                )
            )
            or (
                self.terminal_job_status is JobStatus.CANCELLED
                and (
                    (
                        self.attempt_count == 0
                        and (
                            self.final_tool_execution_id is not None
                            or self.tool_version is not None
                        )
                    )
                    or (
                        self.attempt_count > 0
                        and (
                            self.final_tool_execution_id is None
                            or self.tool_version is None
                        )
                    )
                )
            )
            or bool(self.observations)
        )
        if common_invalid or complete_invalid or partial_invalid or failed_invalid:
            raise InvalidSourceExecutionAssessmentError

    @property
    def observation_count(self) -> int:
        return len(self.observations)

    @property
    def gap_count(self) -> int:
        return len(self.gaps)

    def canonical_data(self) -> dict[str, Any]:
        return {
            "assessment_status": self.assessment_status.value,
            "attempt_count": self.attempt_count,
            "binding_digest": self.binding_digest,
            "capability": self.capability.value,
            "component_id": self.component_id,
            "core_adapter_id": self.core_adapter_id,
            "coverage_status": self.coverage_status.value,
            "declared_file_count": self.declared_file_count,
            "declared_paths": list(self.declared_paths),
            "declared_total_bytes": self.declared_total_bytes,
            "execution_status": self.execution_status.value,
            "final_tool_execution_id": self.final_tool_execution_id,
            "gap_count": self.gap_count,
            "gaps": [gap.canonical_data() for gap in self.gaps],
            "job_id": self.job_id,
            "observation_count": self.observation_count,
            "observations": [item.canonical_data() for item in self.observations],
            "plan_digest": self.plan_digest,
            "profile_digest": self.profile_digest,
            "repository_digest": self.repository_digest,
            "schema_version": self.schema_version,
            "source_analyzer_id": self.source_analyzer_id,
            "source_run_id": self.source_run_id,
            "terminal_job_status": self.terminal_job_status.value,
            "tool_version": self.tool_version,
        }

    def canonical_json(self) -> bytes:
        try:
            return json.dumps(
                self.canonical_data(),
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeEncodeError) as exc:
            raise InvalidSourceExecutionAssessmentError from exc

    def assessment_digest(self) -> str:
        digest = hashlib.sha256()
        digest.update(_ASSESSMENT_STREAM_VERSION)
        digest.update(self.canonical_json())
        return digest.hexdigest()


SOURCE_EXECUTION_ASSESSMENT_SCHEMA_VERSION = _ASSESSMENT_SCHEMA_VERSION
