from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Final
from uuid import UUID

from pydantic import ValidationError

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import (
    ArtifactKind,
    ExecutionOutcome,
    JobFailureCategory,
    JobStatus,
    ObservationType,
    RunStatus,
    TargetType,
)
from securescan.domain.models import AnalysisGap, Observation, ScanReport
from securescan.jobs.repository import JobRepository, JobRepositoryError
from securescan.runs.models import AnalysisRunRecord, ToolExecutionSummary
from securescan.runs.query import (
    RunQueryError,
    RunQueryService,
    RunReportNotReadyError,
)
from securescan.scanners.semgrep.source_execution import (
    SOURCE_EXECUTION_PAYLOAD_KEY,
    SourceSemgrepExecutionContextError,
    SourceSemgrepExecutionContextIntegrityResolver,
)
from securescan.source.enums import (
    AnalysisCapability,
    AssessmentStatus,
    CoverageStatus,
    SourceExecutionStatus,
)
from securescan.source.execution_assessment import (
    InvalidSourceExecutionAssessmentError,
    SourceAnalysisGap,
    SourceCapabilityExecutionAssessment,
    SourceSecurityObservation,
)
from securescan.source.execution_context import SourceExecutionContext
from securescan.workspaces.models import repository_content_digest

_ADAPTER_ID: Final = "semgrep-ce"
_ADAPTER_VERSION: Final = "1.0.0"
_ANALYZER_ID: Final = "python-semgrep-v1"
_TRUSTED_RULESET_IDENTITIES: Final = frozenset(
    {
        ("securescan-python-baseline-v1", "1"),
        ("securescan-python-baseline-v2", "2"),
    }
)
_SANITIZED_EVIDENCE_FIELDS: Final = frozenset(
    {"results", "ruleset", "scanner_id", "schema_version", "summary"}
)
_FINDING_MESSAGE: Final = "Semgrep security rule matched"
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_SUCCESS_OUTCOMES = frozenset(
    {
        ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
        ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS,
    }
)
_FAILED_OUTCOMES = frozenset(
    {
        ExecutionOutcome.TOOL_NOT_AVAILABLE,
        ExecutionOutcome.TOOL_VERSION_REJECTED,
        ExecutionOutcome.NETWORK_REQUIRED,
        ExecutionOutcome.AUTHORIZATION_REQUIRED,
        ExecutionOutcome.TIMEOUT,
        ExecutionOutcome.CANCELLED,
        ExecutionOutcome.RESOURCE_LIMIT_EXCEEDED,
        ExecutionOutcome.OUTPUT_LIMIT_EXCEEDED,
        ExecutionOutcome.INVALID_OUTPUT,
        ExecutionOutcome.PARSER_INCOMPATIBLE,
        ExecutionOutcome.SECURITY_POLICY_BLOCKED,
        ExecutionOutcome.INTERNAL_ERROR,
        ExecutionOutcome.UNSUPPORTED_TARGET,
        ExecutionOutcome.UNSUPPORTED_CONFIGURATION,
    }
)
_FAILURE_OUTCOMES: Final[dict[JobFailureCategory, frozenset[ExecutionOutcome]]] = {
    JobFailureCategory.NON_RETRYABLE_POLICY: frozenset(
        {
            ExecutionOutcome.AUTHORIZATION_REQUIRED,
            ExecutionOutcome.SECURITY_POLICY_BLOCKED,
            ExecutionOutcome.INTERNAL_ERROR,
        }
    ),
    JobFailureCategory.RETRYABLE_INFRASTRUCTURE: frozenset(
        {
            ExecutionOutcome.TOOL_NOT_AVAILABLE,
            ExecutionOutcome.NETWORK_REQUIRED,
            ExecutionOutcome.INVALID_OUTPUT,
            ExecutionOutcome.INTERNAL_ERROR,
        }
    ),
    JobFailureCategory.WORKER_CRASH: frozenset({ExecutionOutcome.INTERNAL_ERROR}),
    JobFailureCategory.NON_RETRYABLE_INPUT: frozenset(
        {
            ExecutionOutcome.UNSUPPORTED_TARGET,
            ExecutionOutcome.UNSUPPORTED_CONFIGURATION,
            ExecutionOutcome.INTERNAL_ERROR,
        }
    ),
    JobFailureCategory.NON_RETRYABLE_PARSER: frozenset(
        {
            ExecutionOutcome.INVALID_OUTPUT,
            ExecutionOutcome.PARSER_INCOMPATIBLE,
        }
    ),
    JobFailureCategory.TIMEOUT: frozenset({ExecutionOutcome.TIMEOUT}),
    JobFailureCategory.OUTPUT_LIMIT: frozenset(
        {
            ExecutionOutcome.OUTPUT_LIMIT_EXCEEDED,
            ExecutionOutcome.RESOURCE_LIMIT_EXCEEDED,
        }
    ),
    JobFailureCategory.CANCELLED: frozenset({ExecutionOutcome.CANCELLED}),
}
_REQUIRED_RETRYABILITY: Final[dict[JobFailureCategory, bool]] = {
    JobFailureCategory.RETRYABLE_INFRASTRUCTURE: True,
    JobFailureCategory.WORKER_CRASH: True,
    JobFailureCategory.NON_RETRYABLE_POLICY: False,
    JobFailureCategory.NON_RETRYABLE_INPUT: False,
    JobFailureCategory.NON_RETRYABLE_PARSER: False,
    JobFailureCategory.OUTPUT_LIMIT: False,
    JobFailureCategory.CANCELLED: False,
    JobFailureCategory.TIMEOUT: True,
}
_PARSER_GAPS: Final[dict[str, str]] = {
    "SEMGREP_FINDING_REJECTED": (
        "Semgrep returned a finding that could not be safely normalized"
    ),
    "SEMGREP_FINDING_LIMIT": (
        "Additional Semgrep findings were omitted by the configured limit"
    ),
    "SEMGREP_PARSE_ERROR": "Semgrep could not parse part of the repository",
    "SEMGREP_INVALID_TARGET": "Semgrep rejected a repository target",
    "SEMGREP_UNSUPPORTED_LANGUAGE": "Semgrep reported an unsupported language",
    "SEMGREP_TIMEOUT": "Semgrep timed out while analyzing a repository file",
    "SEMGREP_RULE_ERROR": "Semgrep reported a trusted rule diagnostic",
    "SEMGREP_INTERNAL_ERROR": "Semgrep reported an internal scanner diagnostic",
    "SEMGREP_UNKNOWN_DIAGNOSTIC": "Semgrep reported an unknown diagnostic",
    "SEMGREP_DIAGNOSTIC_LIMIT": (
        "Additional Semgrep diagnostics were omitted by the configured limit"
    ),
}
_FAILURE_GAPS: Final[dict[JobFailureCategory, tuple[str, str]]] = {
    JobFailureCategory.NON_RETRYABLE_POLICY: (
        "EXECUTION_AUTHORIZATION_FAILED",
        "The trusted Source execution authorization failed",
    ),
    JobFailureCategory.RETRYABLE_INFRASTRUCTURE: (
        "EXECUTION_INFRASTRUCTURE_FAILED",
        "The Source execution infrastructure did not complete the analysis",
    ),
    JobFailureCategory.WORKER_CRASH: (
        "EXECUTION_INFRASTRUCTURE_FAILED",
        "The Source execution infrastructure did not complete the analysis",
    ),
    JobFailureCategory.NON_RETRYABLE_INPUT: (
        "EXECUTION_TOOL_FAILED",
        "The Source analyzer did not complete the declared analysis",
    ),
    JobFailureCategory.NON_RETRYABLE_PARSER: (
        "EXECUTION_TOOL_FAILED",
        "The Source analyzer did not produce a valid complete result",
    ),
    JobFailureCategory.TIMEOUT: (
        "EXECUTION_TIMEOUT",
        "The Source analyzer did not complete before its time limit",
    ),
    JobFailureCategory.OUTPUT_LIMIT: (
        "EXECUTION_OUTPUT_LIMIT",
        "The Source analyzer result exceeded its trusted output limit",
    ),
    JobFailureCategory.CANCELLED: (
        "EXECUTION_CANCELLED",
        "The declared Source capability execution was cancelled",
    ),
}


class SourceSemgrepExecutionAssessmentError(RuntimeError):
    """Base class for fixed-message durable Source result failures."""


class SourceExecutionJobNotFoundError(SourceSemgrepExecutionAssessmentError):
    def __init__(self) -> None:
        super().__init__("Source execution job was not found")


class SourceExecutionNotSourceJobError(SourceSemgrepExecutionAssessmentError):
    def __init__(self) -> None:
        super().__init__("Job is not a Source Semgrep execution")


class SourceExecutionNotTerminalError(SourceSemgrepExecutionAssessmentError):
    def __init__(self) -> None:
        super().__init__("Source execution job is not terminal")


class SourceExecutionAssessmentIntegrityError(SourceSemgrepExecutionAssessmentError):
    def __init__(self) -> None:
        super().__init__("Durable Source execution evidence is inconsistent")


class SourceExecutionAssessmentPersistenceError(SourceSemgrepExecutionAssessmentError):
    def __init__(self) -> None:
        super().__init__("Durable Source execution evidence is unavailable")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_non_finite_constant(_value: str) -> None:
    raise ValueError


def _sanitized_ruleset_identity(payload: bytes) -> tuple[str, str]:
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_constant,
        )
        if (
            not isinstance(document, dict)
            or set(document) != _SANITIZED_EVIDENCE_FIELDS
            or document["schema_version"] != "securescan-semgrep-sanitized-v1"
            or document["scanner_id"] != _ADAPTER_ID
            or not isinstance(document["results"], list)
            or not isinstance(document["summary"], dict)
        ):
            raise ValueError
        ruleset = document["ruleset"]
        if not isinstance(ruleset, dict) or set(ruleset) != {"id", "version"}:
            raise ValueError
        identity = (ruleset["id"], ruleset["version"])
        if identity not in _TRUSTED_RULESET_IDENTITIES:
            raise ValueError
        return identity
    except (AttributeError, KeyError, TypeError, UnicodeDecodeError, ValueError) as exc:
        raise SourceExecutionAssessmentIntegrityError from exc


def _fingerprint(
    producer: str,
    rule_id: str,
    path: str,
    start_line: int,
    start_column: int,
    end_line: int,
    end_column: int,
) -> str:
    identity = "\x1f".join(
        (
            producer,
            rule_id,
            path,
            str(start_line),
            str(start_column),
            str(end_line),
            str(end_column),
        )
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _observation(
    value: Observation,
    context: SourceExecutionContext,
    tool_version: str,
) -> SourceSecurityObservation:
    try:
        properties = value.properties
        start_column = properties.get("start_column")
        end_column = properties.get("end_column")
        severity = properties.get("severity")
        expected_properties: dict[str, object] = {
            "end_column": end_column,
            "scanner_version": tool_version,
            "severity": value.native_severity,
            "start_column": start_column,
        }
        cwe_ids = tuple(value.cwe_ids)
        if cwe_ids:
            expected_properties["metadata"] = {"cwe": list(cwe_ids)}
        if (
            value.producer != _ADAPTER_ID
            or value.observation_type is not ObservationType.SOURCE_RULE_MATCH
            or value.message != _FINDING_MESSAGE
            or value.path is None
            or value.path not in {item.relative_path for item in context.selected_files}
            or value.start_line is None
            or value.end_line is None
            or not isinstance(start_column, int)
            or isinstance(start_column, bool)
            or not isinstance(end_column, int)
            or isinstance(end_column, bool)
            or severity != value.native_severity
            or value.symbol is not None
            or properties != expected_properties
            or value.fingerprint is None
        ):
            raise ValueError
        expected_fingerprint = _fingerprint(
            value.producer,
            value.rule_id,
            value.path,
            value.start_line,
            start_column,
            value.end_line,
            end_column,
        )
        if (
            value.fingerprint != expected_fingerprint
            or value.observation_id != UUID(expected_fingerprint[:32])
        ):
            raise ValueError
        return SourceSecurityObservation(
            observation_id=str(value.observation_id),
            producer=value.producer,
            observation_type=value.observation_type,
            rule_id=value.rule_id,
            message=value.message,
            native_severity=value.native_severity,
            relative_path=value.path,
            start_line=value.start_line,
            start_column=start_column,
            end_line=value.end_line,
            end_column=end_column,
            cwe_ids=cwe_ids,
            fingerprint=value.fingerprint,
        )
    except (InvalidSourceExecutionAssessmentError, TypeError, ValueError) as exc:
        raise SourceExecutionAssessmentIntegrityError from exc


def _parser_gap(value: AnalysisGap, context: SourceExecutionContext) -> SourceAnalysisGap:
    try:
        if (
            value.adapter_id != _ADAPTER_ID
            or _PARSER_GAPS.get(value.code) != value.message
        ):
            raise ValueError
        return SourceAnalysisGap(
            code=value.code,
            capability=context.capability,
            component_id=context.component_id,
            stage="parsing",
            relative_path=None,
            message=value.message,
        )
    except (InvalidSourceExecutionAssessmentError, TypeError, ValueError) as exc:
        raise SourceExecutionAssessmentIntegrityError from exc


def _failure_gap(
    category: JobFailureCategory,
    context: SourceExecutionContext,
) -> SourceAnalysisGap:
    try:
        code, message = _FAILURE_GAPS[category]
        return SourceAnalysisGap(
            code=code,
            capability=context.capability,
            component_id=context.component_id,
            stage="execution",
            relative_path=None,
            message=message,
        )
    except (InvalidSourceExecutionAssessmentError, KeyError) as exc:
        raise SourceExecutionAssessmentIntegrityError from exc


def _cancelled_gap(context: SourceExecutionContext) -> SourceAnalysisGap:
    return _failure_gap(JobFailureCategory.CANCELLED, context)


class SourceSemgrepExecutionAssessmentService:
    def __init__(
        self,
        job_repository: JobRepository,
        context_resolver: SourceSemgrepExecutionContextIntegrityResolver,
        run_query_service: RunQueryService,
        artifact_store: ContentAddressedArtifactStore,
    ) -> None:
        if (
            not isinstance(job_repository, JobRepository)
            or not isinstance(
                context_resolver,
                SourceSemgrepExecutionContextIntegrityResolver,
            )
            or not isinstance(run_query_service, RunQueryService)
            or not isinstance(artifact_store, ContentAddressedArtifactStore)
        ):
            raise SourceExecutionAssessmentIntegrityError
        self._job_repository = job_repository
        self._context_resolver = context_resolver
        self._run_query_service = run_query_service
        self._artifact_store = artifact_store

    def assess_job(self, job_id: str) -> SourceCapabilityExecutionAssessment:
        try:
            job = self._job_repository.get_job(job_id)
        except JobRepositoryError as exc:
            raise SourceExecutionAssessmentPersistenceError from exc
        if job is None:
            raise SourceExecutionJobNotFoundError
        if (
            not isinstance(job.payload_json, dict)
            or SOURCE_EXECUTION_PAYLOAD_KEY not in job.payload_json
        ):
            raise SourceExecutionNotSourceJobError
        if job.status not in {
            JobStatus.SUCCEEDED,
            JobStatus.PARTIAL,
            JobStatus.FAILED,
            JobStatus.CANCELLED,
        }:
            raise SourceExecutionNotTerminalError
        try:
            context = self._context_resolver.resolve(job)
        except SourceSemgrepExecutionContextError as exc:
            raise SourceExecutionAssessmentIntegrityError from exc
        except Exception as exc:
            raise SourceExecutionAssessmentIntegrityError from exc
        if (
            context.capability is not AnalysisCapability.PYTHON_SAST
            or context.source_analyzer_id != _ANALYZER_ID
            or context.core_adapter_id != _ADAPTER_ID
            or job.adapter_id != _ADAPTER_ID
        ):
            raise SourceExecutionAssessmentIntegrityError

        try:
            run = self._run_query_service.get_run(job.run_id)
            tool_execution = (
                self._run_query_service.find_job_tool_execution(
                    job.id,
                    job.attempt_count,
                )
                if job.attempt_count > 0
                else None
            )
        except RunQueryError as exc:
            raise SourceExecutionAssessmentPersistenceError from exc
        self._validate_run(run, job.status, context)

        if job.status in {JobStatus.SUCCEEDED, JobStatus.PARTIAL}:
            return self._assess_reported(job, context, run, tool_execution)
        return self._assess_failed(job, context, run, tool_execution)

    @staticmethod
    def _validate_run(
        run: AnalysisRunRecord,
        job_status: JobStatus,
        context: SourceExecutionContext,
    ) -> None:
        expected_status = {
            JobStatus.SUCCEEDED: RunStatus.COMPLETED,
            JobStatus.PARTIAL: RunStatus.PARTIAL,
            JobStatus.FAILED: RunStatus.FAILED,
            JobStatus.CANCELLED: RunStatus.CANCELLED,
        }[job_status]
        expected_counts = {
            JobStatus.SUCCEEDED: (1, 0, 0, 0),
            JobStatus.PARTIAL: (0, 1, 0, 0),
            JobStatus.FAILED: (0, 0, 1, 0),
            JobStatus.CANCELLED: (0, 0, 0, 1),
        }[job_status]
        actual_counts = (
            run.succeeded_jobs,
            run.partial_jobs,
            run.failed_jobs,
            run.cancelled_jobs,
        )
        if (
            run.status is not expected_status
            or run.id != context.source_run_id
            or run.target_content_digest != context.repository_digest
            or run.total_jobs != 1
            or run.active_jobs != 0
            or actual_counts != expected_counts
        ):
            raise SourceExecutionAssessmentIntegrityError

    def _assess_reported(
        self,
        job,
        context: SourceExecutionContext,
        run: AnalysisRunRecord,
        tool_execution: ToolExecutionSummary | None,
    ) -> SourceCapabilityExecutionAssessment:
        if not run.has_report or tool_execution is None:
            raise SourceExecutionAssessmentIntegrityError
        self._validate_tool_identity(job, tool_execution)
        try:
            record = self._run_query_service.get_report(job.run_id)
        except RunReportNotReadyError as exc:
            raise SourceExecutionAssessmentIntegrityError from exc
        except RunQueryError as exc:
            raise SourceExecutionAssessmentPersistenceError from exc
        try:
            report = ScanReport.model_validate(record.report_json)
            if report.model_dump(mode="json") != record.report_json:
                raise ValueError
        except (TypeError, ValidationError, ValueError) as exc:
            raise SourceExecutionAssessmentIntegrityError from exc

        is_partial = job.status is JobStatus.PARTIAL
        expected_run_status = RunStatus.PARTIAL if is_partial else RunStatus.COMPLETED
        expected_outcome = (
            ExecutionOutcome.PARTIAL_ANALYSIS
            if is_partial
            else (
                ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS
                if report.observations
                else ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS
            )
        )
        selected_entries = tuple(item.entry for item in context.selected_files)
        expected_target_digest = repository_content_digest(selected_entries)
        if (
            record.run_id != job.run_id
            or record.status is not expected_run_status
            or str(report.run_id) != job.run_id
            or report.schema_version != "1.0.0"
            or report.status is not expected_run_status
            or report.target.target_type is not TargetType.SOURCE_REPOSITORY
            or report.target.path != Path(".")
            or report.target.content_digest != expected_target_digest
            or set(report.target.metadata)
            != {"file_count", "ruleset_id", "ruleset_version"}
            or report.target.metadata["file_count"] != len(context.selected_files)
            or (
                report.target.metadata["ruleset_id"],
                report.target.metadata["ruleset_version"],
            )
            not in _TRUSTED_RULESET_IDENTITIES
            or len(report.executions) != 1
        ):
            raise SourceExecutionAssessmentIntegrityError
        report_ruleset_identity = (
            report.target.metadata["ruleset_id"],
            report.target.metadata["ruleset_version"],
        )
        execution = report.executions[0]
        try:
            row_outcome = ExecutionOutcome(tool_execution.outcome)
        except ValueError as exc:
            raise SourceExecutionAssessmentIntegrityError from exc
        if (
            execution.run_id != report.run_id
            or execution.adapter_id != _ADAPTER_ID
            or execution.adapter_version != _ADAPTER_VERSION
            or execution.adapter_version != tool_execution.adapter_version
            or execution.tool_version != tool_execution.tool_version
            or execution.status is not expected_run_status
            or execution.outcome is not expected_outcome
            or row_outcome is not expected_outcome
            or execution.exit_code != tool_execution.exit_code
            or execution.duration_ms != tool_execution.duration_ms
            or execution.error is not None
            or tool_execution.failure_category is not None
            or tool_execution.retryable is not None
            or execution.observations != report.observations
            or len(execution.artifacts) != 1
        ):
            raise SourceExecutionAssessmentIntegrityError
        artifact = execution.artifacts[0]
        if (
            artifact.kind is not ArtifactKind.SANITIZED_NATIVE_REPORT
            or artifact.media_type != "application/json"
            or artifact.sanitized is not True
            or artifact.size_bytes < 1
            or _SHA256_PATTERN.fullmatch(artifact.sha256) is None
            or artifact.storage_path
            != f"sha256/{artifact.sha256[:2]}/{artifact.sha256}"
        ):
            raise SourceExecutionAssessmentIntegrityError
        try:
            sanitized_evidence = self._artifact_store.read_by_sha256(
                artifact.sha256,
                expected_size_bytes=artifact.size_bytes,
            )
        except Exception as exc:
            raise SourceExecutionAssessmentIntegrityError from exc
        if _sanitized_ruleset_identity(sanitized_evidence) != report_ruleset_identity:
            raise SourceExecutionAssessmentIntegrityError

        observations = tuple(
            sorted(
                (
                    _observation(value, context, tool_execution.tool_version)
                    for value in report.observations
                ),
                key=lambda item: item.sort_key(),
            )
        )
        if len({item.fingerprint for item in observations}) != len(observations):
            raise SourceExecutionAssessmentIntegrityError
        gaps = tuple(
            sorted(
                (_parser_gap(value, context) for value in report.analysis_gaps),
                key=lambda item: item.sort_key(),
            )
        )
        if execution.warnings != [value.message for value in report.analysis_gaps]:
            raise SourceExecutionAssessmentIntegrityError
        if is_partial != bool(gaps):
            raise SourceExecutionAssessmentIntegrityError
        if not is_partial and row_outcome not in _SUCCESS_OUTCOMES:
            raise SourceExecutionAssessmentIntegrityError
        return self._assessment(
            job=job,
            context=context,
            execution_status=(
                SourceExecutionStatus.PARTIAL
                if is_partial
                else SourceExecutionStatus.COMPLETE
            ),
            coverage_status=(
                CoverageStatus.PARTIAL
                if is_partial
                else CoverageStatus.FULL_FOR_DECLARED_SCOPE
            ),
            observations=observations,
            gaps=gaps,
            final_tool_execution_id=tool_execution.execution_id,
            tool_version=tool_execution.tool_version,
        )

    def _assess_failed(
        self,
        job,
        context: SourceExecutionContext,
        run: AnalysisRunRecord,
        tool_execution: ToolExecutionSummary | None,
    ) -> SourceCapabilityExecutionAssessment:
        if run.has_report:
            raise SourceExecutionAssessmentIntegrityError
        if job.status is JobStatus.FAILED:
            if tool_execution is None:
                raise SourceExecutionAssessmentIntegrityError
            self._validate_tool_identity(job, tool_execution)
            try:
                outcome = ExecutionOutcome(tool_execution.outcome)
            except ValueError as exc:
                raise SourceExecutionAssessmentIntegrityError from exc
            if (
                outcome not in _FAILED_OUTCOMES
                or tool_execution.failure_category is None
                or not isinstance(tool_execution.retryable, bool)
                or outcome
                not in _FAILURE_OUTCOMES.get(
                    tool_execution.failure_category,
                    frozenset(),
                )
                or (
                    tool_execution.failure_category in _REQUIRED_RETRYABILITY
                    and tool_execution.retryable
                    is not _REQUIRED_RETRYABILITY[tool_execution.failure_category]
                )
            ):
                raise SourceExecutionAssessmentIntegrityError
            gaps = (_failure_gap(tool_execution.failure_category, context),)
            execution_id = tool_execution.execution_id
        else:
            if job.attempt_count == 0:
                if tool_execution is not None:
                    raise SourceExecutionAssessmentIntegrityError
            else:
                if tool_execution is None:
                    raise SourceExecutionAssessmentIntegrityError
                self._validate_tool_identity(job, tool_execution)
                try:
                    outcome = ExecutionOutcome(tool_execution.outcome)
                except ValueError as exc:
                    raise SourceExecutionAssessmentIntegrityError from exc
                if outcome not in _FAILED_OUTCOMES:
                    raise SourceExecutionAssessmentIntegrityError
            gaps = (_cancelled_gap(context),)
            execution_id = (
                tool_execution.execution_id if tool_execution is not None else None
            )
        return self._assessment(
            job=job,
            context=context,
            execution_status=SourceExecutionStatus.FAILED,
            coverage_status=CoverageStatus.UNKNOWN,
            observations=(),
            gaps=gaps,
            final_tool_execution_id=execution_id,
            tool_version=(
                tool_execution.tool_version if tool_execution is not None else None
            ),
        )

    @staticmethod
    def _validate_tool_identity(job, tool_execution: ToolExecutionSummary) -> None:
        if (
            tool_execution.job_id != job.id
            or tool_execution.run_id != job.run_id
            or tool_execution.attempt_number != job.attempt_count
            or tool_execution.adapter_id != _ADAPTER_ID
            or tool_execution.adapter_version != _ADAPTER_VERSION
        ):
            raise SourceExecutionAssessmentIntegrityError

    @staticmethod
    def _assessment(
        *,
        job,
        context: SourceExecutionContext,
        execution_status: SourceExecutionStatus,
        coverage_status: CoverageStatus,
        observations: tuple[SourceSecurityObservation, ...],
        gaps: tuple[SourceAnalysisGap, ...],
        final_tool_execution_id: str | None,
        tool_version: str | None,
    ) -> SourceCapabilityExecutionAssessment:
        try:
            return SourceCapabilityExecutionAssessment(
                source_run_id=context.source_run_id,
                job_id=context.job_id,
                repository_digest=context.repository_digest,
                profile_digest=context.profile_digest,
                plan_digest=context.plan_digest,
                source_analyzer_id=context.source_analyzer_id,
                capability=context.capability,
                component_id=context.component_id,
                binding_digest=context.binding_digest,
                core_adapter_id=context.core_adapter_id,
                execution_status=execution_status,
                coverage_status=coverage_status,
                assessment_status=AssessmentStatus.OBSERVATIONS_ONLY,
                declared_paths=tuple(
                    item.relative_path for item in context.selected_files
                ),
                declared_file_count=len(context.selected_files),
                declared_total_bytes=sum(
                    item.entry.size_bytes for item in context.selected_files
                ),
                observations=observations,
                gaps=gaps,
                attempt_count=job.attempt_count,
                terminal_job_status=job.status,
                final_tool_execution_id=final_tool_execution_id,
                tool_version=tool_version,
            )
        except InvalidSourceExecutionAssessmentError as exc:
            raise SourceExecutionAssessmentIntegrityError from exc
