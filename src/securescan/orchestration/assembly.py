from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any
from uuid import UUID, uuid5

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import ArtifactKind, RunStatus
from securescan.evidence import (
    CHECKOV_NATIVE_IDENTITY_SCHEMA,
    CHECKOV_SUPPRESSION_IDENTITY_SCHEMA,
    SECURESCAN_EVIDENCE_SCHEMA_VERSION,
    SEMGREP_NATIVE_IDENTITY_SCHEMA,
    CheckovEvidencePayload,
    CheckovSuppressionPayload,
    ComponentKind,
    ConfigurationResourceSubject,
    CoverageState,
    EvidenceAuthority,
    EvidenceKind,
    FindingCategory,
    GapScopeKind,
    LocalScannerProvenance,
    RepositoryComponentPayload,
    RepositoryPathLocation,
    RepositoryScopeLocation,
    SecureScanComponent,
    SecureScanCoverageOutcome,
    SecureScanEvidence,
    SecureScanEvidenceFragment,
    SecureScanEvidenceReport,
    SecureScanFinding,
    SecureScanGap,
    SecureScanGapScope,
    SecureScanLocation,
    SecureScanReportScope,
    SecureScanSuppression,
    SemgrepEvidencePayload,
    SemgrepProvenance,
    SemgrepSanitizedArtifactReference,
    SeverityProjection,
    SeverityScheme,
    SourceCodeSubject,
    SourceSpanLocation,
    adapt_gitleaks_result,
    adapt_osv_analysis,
    adapt_syft_result,
    build_component_ref,
    build_evidence_id,
    build_finding_id,
    build_report,
    coverage_id,
    gap_id,
    suppression_id,
)
from securescan.evidence.adapters import (
    CHECKOV_GAP_IDENTITY_SCHEMA,
    OSV_GAP_IDENTITY_SCHEMA,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    SourceOrchestrationAttemptRow,
    SourceOrchestrationDependencyEvaluationRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationRow,
    SourceOrchestrationScannerJobRow,
    utc_now,
)
from securescan.scanners.gitleaks import (
    GitleaksDetectionKind,
    GitleaksParseResult,
    NormalizedGitleaksFinding,
)
from securescan.scanners.semgrep.source_execution import (
    SourceProjectionExecutionReference,
)
from securescan.scanners.syft import PackageObservation, SyftParseResult
from securescan.source import AnalysisCapability, SourceExecutionContext

from .dependency_evaluation import SourceDependencyEvaluation
from .execution_models import (
    SAFE_NATIVE_RESULT_MEDIA_TYPE,
    SAFE_NATIVE_RESULT_SCHEMA_VERSION,
    SafeSourceNativeResult,
)
from .models import (
    OrchestrationContainmentState,
    OrchestrationLifecycleState,
    OrchestrationNodeDisposition,
    OrchestrationNodeLifecycleState,
    OrchestrationTerminalOutcome,
    SourceAuthority,
    SourcePlanningSnapshot,
)
from .osv_execution import (
    OSV_NATIVE_RESULT_MEDIA_TYPE,
    OSV_NATIVE_RESULT_SCHEMA_VERSION,
    SafeSourceOsvResult,
)

SOURCE_FINAL_RESULT_MEDIA_TYPE = "application/vnd.securescan.source-result+json"
SOURCE_FINAL_RESULT_SCHEMA_VERSION = SECURESCAN_EVIDENCE_SCHEMA_VERSION
ENGINE_GAP_IDENTITY_SCHEMA = "securescan-source-engine-gap-s6d-v1"
SOURCE_ASSEMBLY_MAX_ATTEMPTS = 3
_SOURCE_ASSEMBLY_FAILURE_CODES = frozenset(
    {
        "ASSEMBLY_ARTIFACT_IO_FAILED",
        "ASSEMBLY_DATABASE_FAILED",
        "ASSEMBLY_FAILURE_RECORD_FAILED",
        "ASSEMBLY_UNEXPECTED_FAILURE",
        "ASSEMBLY_VALIDATION_FAILED",
    }
)
_SOURCE_ASSEMBLY_FAILURE_PHASES = frozenset({"ASSEMBLY", "PUBLICATION"})

_SEMGREP_RULESET_ID = "securescan-python-baseline-v2"
_SEMGREP_RULESET_VERSION = "2"
_SEMGREP_RULESET_SHA256 = (
    "e10fb04e6b5abb35e0b83bdd718c2e973a8026e3630e420dc398db95e59d01a5"
)
_SEMGREP_MESSAGE = "Semgrep rule match"
_SEMGREP_ARTIFACT_NAMESPACE = UUID("ed9b5c66-e03c-53c8-8b17-611dffaf5743")


class SourceResultAssemblyError(RuntimeError):
    def __init__(
        self,
        reason_code: str = "ASSEMBLY_VALIDATION_FAILED",
        *,
        retryable: bool = False,
        phase: str = "ASSEMBLY",
    ) -> None:
        super().__init__("Source result assembly failed")
        if (
            reason_code not in _SOURCE_ASSEMBLY_FAILURE_CODES
            or type(retryable) is not bool
            or phase not in _SOURCE_ASSEMBLY_FAILURE_PHASES
        ):
            raise ValueError("Source result assembly failure metadata is invalid")
        self.reason_code = reason_code
        self.retryable = retryable
        self.phase = phase


@dataclass(frozen=True, slots=True)
class SourceAssemblyRecord:
    run_id: str
    artifact_sha256: str
    artifact_size_bytes: int
    lifecycle_state: OrchestrationLifecycleState
    terminal_outcome: OrchestrationTerminalOutcome | None
    assembled: bool
    published: bool


@dataclass(frozen=True, slots=True)
class SourceAssemblyFailureRecord:
    run_id: str
    attempt_count: int
    reason_code: str
    retryable: bool
    terminalized: bool


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _native_dict(value: Mapping[str, Any]) -> dict[str, Any]:
    def thaw(item: object) -> object:
        if isinstance(item, Mapping):
            return {key: thaw(child) for key, child in item.items()}
        if isinstance(item, tuple):
            return [thaw(child) for child in item]
        return item

    try:
        data = json.loads(
            json.dumps(
                thaw(value),
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
    except (TypeError, ValueError, UnicodeError):
        raise SourceResultAssemblyError from None
    if not isinstance(data, dict):
        raise SourceResultAssemblyError
    return data


def _identity(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)[:-1]).hexdigest()


def _locations(paths: tuple[str, ...]) -> tuple[RepositoryPathLocation, ...]:
    return tuple(RepositoryPathLocation(path) for path in sorted(set(paths)))


def _scope_locations(paths: tuple[str, ...]) -> tuple[SecureScanLocation, ...]:
    return _locations(paths) if paths else (RepositoryScopeLocation(),)


def _component_ref(snapshot: SourcePlanningSnapshot, component_id: str | None) -> str | None:
    if component_id is None:
        return None
    if not any(item.component_id == component_id for item in snapshot.profile.components):
        raise SourceResultAssemblyError
    return build_component_ref(ComponentKind.REPOSITORY, component_id)


def _repository_fragment(snapshot: SourcePlanningSnapshot) -> SecureScanEvidenceFragment:
    components = []
    for component in snapshot.profile.components:
        root = "" if component.root_path == "." else component.root_path
        components.append(
            SecureScanComponent(
                component_ref=build_component_ref(
                    ComponentKind.REPOSITORY, component.component_id
                ),
                component_kind=ComponentKind.REPOSITORY,
                native_component_identity=component.component_id,
                payload=RepositoryComponentPayload(
                    component.component_id,
                    component.display_name,
                    root,
                    component.manifest_paths,
                    component.lockfile_paths,
                ),
            )
        )
    return SecureScanEvidenceFragment(
        components=tuple(sorted(components, key=lambda item: item.component_ref))
    )


def _projection(result: SafeSourceNativeResult) -> SourceProjectionExecutionReference:
    try:
        return SourceProjectionExecutionReference(
            result.projection_id,
            result.context_digest,
            result.projection_digest,
        )
    except Exception:
        raise SourceResultAssemblyError from None


def _gitleaks_result(result: SafeSourceNativeResult) -> GitleaksParseResult:
    data = _native_dict(result.native_data)
    try:
        findings = tuple(
            NormalizedGitleaksFinding(
                scanner_id=item["scanner_id"],
                scanner_version=item["scanner_version"],
                rule_id=item["rule_id"],
                file_path=item["file_path"],
                detection_kind=GitleaksDetectionKind(item["detection_kind"]),
                start_line=item["start_line"],
                end_line=item["end_line"],
                start_column=item["start_column"],
                end_column=item["end_column"],
                projection_id=item["projection_id"],
                context_digest=item["context_digest"],
                projection_digest=item["projection_digest"],
            )
            for item in data["findings"]
        )
        parsed = GitleaksParseResult(
            scanner_id=data["scanner_id"],
            scanner_version=data["scanner_version"],
            binding_digest=data["binding_digest"],
            projection_id=data["projection_id"],
            context_digest=data["context_digest"],
            projection_digest=data["projection_digest"],
            findings=findings,
            finding_count=data["finding_count"],
            schema_version=data["schema_version"],
        )
    except (KeyError, TypeError, ValueError):
        raise SourceResultAssemblyError from None
    if _native_dict(MappingProxyType(parsed.canonical_data())) != data:
        raise SourceResultAssemblyError
    return parsed


def _syft_result(result: SafeSourceNativeResult) -> SyftParseResult:
    data = _native_dict(result.native_data)
    try:
        observations = tuple(
            PackageObservation(**{**item, "locations": tuple(item["locations"])})
            for item in data["observations"]
        )
        parsed = SyftParseResult(
            scanner_id=data["scanner_id"],
            scanner_version=data["scanner_version"],
            binding_digest=data["binding_digest"],
            projection_id=data["projection_id"],
            snapshot_digest=data["snapshot_digest"],
            syft_schema_version=data["syft_schema_version"],
            requested_cataloger_strategy=tuple(data["requested_cataloger_strategy"]),
            used_catalogers=tuple(data["used_catalogers"]),
            observations=observations,
            package_count=data["package_count"],
            schema_version=data["schema_version"],
        )
    except (KeyError, TypeError, ValueError):
        raise SourceResultAssemblyError from None
    if _native_dict(MappingProxyType(parsed.canonical_data())) != data:
        raise SourceResultAssemblyError
    return parsed


def _scanner_provenance(result: SafeSourceNativeResult) -> LocalScannerProvenance:
    return LocalScannerProvenance(
        scanner_id=result.scanner_id,
        scanner_version=result.scanner_version,
        binding_digest=result.binding_digest,
        projection_id=result.projection_id,
        context_digest=result.context_digest,
        projection_digest=result.projection_digest,
    )


def _checkov_fragment(
    result: SafeSourceNativeResult,
    context: SourceExecutionContext,
    report_scope: SecureScanReportScope,
) -> SecureScanEvidenceFragment:
    data = _native_dict(result.native_data)
    if data.get("observation_count") != len(data.get("findings", ())):
        raise SourceResultAssemblyError
    provenance = _scanner_provenance(result)
    evidence: list[SecureScanEvidence] = []
    findings: list[SecureScanFinding] = []
    for item in data.get("findings", ()):
        try:
            identity = item["finding_id"]
            location: tuple[SecureScanLocation, ...] = (
                (RepositoryPathLocation(item["normalized_path"]),)
                if item["line_start"] is None
                else (
                    SourceSpanLocation(
                        item["normalized_path"], item["line_start"], item["line_end"]
                    ),
                )
            )
            evidence_id = build_evidence_id(
                EvidenceAuthority.CHECKOV, CHECKOV_NATIVE_IDENTITY_SCHEMA, identity
            )
            evidence.append(
                SecureScanEvidence(
                    evidence_id=evidence_id,
                    authority=EvidenceAuthority.CHECKOV,
                    evidence_kind=EvidenceKind.CHECKOV_POLICY_OBSERVATION,
                    native_identity_schema=CHECKOV_NATIVE_IDENTITY_SCHEMA,
                    native_identity=identity,
                    payload=CheckovEvidencePayload(
                        identity,
                        item["framework"],
                        item["check_id"],
                        item["check_name"],
                        item["resource"],
                        "FAILED",
                    ),
                    provenance=provenance,
                    locations=location,
                )
            )
            findings.append(
                SecureScanFinding(
                    finding_id=build_finding_id(
                        EvidenceAuthority.CHECKOV,
                        CHECKOV_NATIVE_IDENTITY_SCHEMA,
                        identity,
                    ),
                    category=FindingCategory.CONFIGURATION_SECURITY,
                    authority=EvidenceAuthority.CHECKOV,
                    native_identity_schema=CHECKOV_NATIVE_IDENTITY_SCHEMA,
                    native_finding_identity=identity,
                    subject=ConfigurationResourceSubject(
                        item["framework"], item["resource"]
                    ),
                    locations=location,
                    primary_evidence_refs=(evidence_id,),
                    severity=(
                        None
                        if item["severity"] is None
                        else SeverityProjection(
                            item["severity"],
                            SeverityScheme.CHECKOV,
                            EvidenceAuthority.CHECKOV,
                        )
                    ),
                )
            )
        except (KeyError, TypeError, ValueError):
            raise SourceResultAssemblyError from None
    suppressions: list[SecureScanSuppression] = []
    for item in data.get("suppressions", ()):
        native = _identity(
            [item["framework"], item["check_id"], item["normalized_path"], item["resource"]]
        )
        suppressions.append(
            SecureScanSuppression(
                suppression_id=suppression_id(
                    EvidenceAuthority.CHECKOV,
                    CHECKOV_SUPPRESSION_IDENTITY_SCHEMA,
                    native,
                ),
                authority=EvidenceAuthority.CHECKOV,
                native_identity_schema=CHECKOV_SUPPRESSION_IDENTITY_SCHEMA,
                native_identity=native,
                subject=ConfigurationResourceSubject(item["framework"], item["resource"]),
                locations=(RepositoryPathLocation(item["normalized_path"]),),
                payload=CheckovSuppressionPayload(
                    item["framework"], item["check_id"], item["resource"], item["reason"]
                ),
                provenance=provenance,
            )
        )
    gaps: list[SecureScanGap] = []
    for item in data.get("gaps", ()):
        native = _identity(item)
        gaps.append(
            SecureScanGap(
                gap_id=gap_id(
                    EvidenceAuthority.CHECKOV, CHECKOV_GAP_IDENTITY_SCHEMA, native
                ),
                authority=EvidenceAuthority.CHECKOV,
                native_identity_schema=CHECKOV_GAP_IDENTITY_SCHEMA,
                native_identity=native,
                code=item["code"],
                scope=SecureScanGapScope(
                    GapScopeKind.PATH,
                    item["normalized_path"],
                    _context_component_ref(context),
                    framework=item["framework"],
                ),
                message="Checkov could not parse part of the selected framework scope",
            )
        )
    selected_scope = _locations(tuple(item.relative_path for item in context.selected_files))
    outcomes = []
    states = {
        "completed": CoverageState.COMPLETE,
        "completed_with_findings": CoverageState.COMPLETE_WITH_FINDINGS,
        "completed_with_suppressions": CoverageState.COMPLETE_WITH_SUPPRESSIONS,
        "not_applicable": CoverageState.NOT_APPLICABLE,
        "incomplete_parse_gap": CoverageState.PARTIAL,
    }
    for item in data.get("framework_outcomes", ()):
        try:
            state = states[item["state"]]
            outcomes.append(
                SecureScanCoverageOutcome(
                    coverage_id=coverage_id(
                        EvidenceAuthority.CHECKOV,
                        "configuration_security",
                        item["framework"],
                        _context_component_ref(context),
                        selected_scope,
                    ),
                    authority=EvidenceAuthority.CHECKOV,
                    capability="configuration_security",
                    framework=item["framework"],
                    component_ref=_context_component_ref(context),
                    state=state,
                    selected_scope=selected_scope,
                    finding_count=item["failed_count"],
                    suppression_count=item["suppressed_count"],
                    gap_count=item["parsing_gap_count"],
                    reason_code=(
                        "CHECKOV_PARSE_GAP" if item["parsing_gap_count"] else None
                    ),
                )
            )
        except (KeyError, TypeError, ValueError):
            raise SourceResultAssemblyError from None
    return SecureScanEvidenceFragment(
        scope=report_scope,
        evidence=tuple(sorted(evidence, key=lambda item: item.evidence_id)),
        findings=tuple(sorted(findings, key=lambda item: item.finding_id)),
        suppressions=tuple(sorted(suppressions, key=lambda item: item.suppression_id)),
        gaps=tuple(sorted(gaps, key=lambda item: item.gap_id)),
        coverage_outcomes=tuple(sorted(outcomes, key=lambda item: item.coverage_id)),
    )


def _context_component_ref(context: SourceExecutionContext) -> str | None:
    if context.component_id is None:
        return None
    return build_component_ref(ComponentKind.REPOSITORY, context.component_id)


def _semgrep_fragment(
    result: SafeSourceNativeResult,
    context: SourceExecutionContext,
    report_scope: SecureScanReportScope,
    tool_execution_id: str,
    artifact_store: ContentAddressedArtifactStore,
) -> SecureScanEvidenceFragment:
    data = _native_dict(result.native_data)
    if (
        set(data) != {"results", "ruleset", "scanner_id", "schema_version", "summary"}
        or data["ruleset"]
        != {"id": _SEMGREP_RULESET_ID, "version": _SEMGREP_RULESET_VERSION}
        or data["scanner_id"] != EvidenceAuthority.SEMGREP.value
        or data["summary"].get("accepted_findings") != len(data["results"])
    ):
        raise SourceResultAssemblyError
    sanitized = json.dumps(
        data,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    artifact_sha = hashlib.sha256(sanitized).hexdigest()
    artifact = artifact_store.put(
        sanitized,
        kind=ArtifactKind.SANITIZED_NATIVE_REPORT,
        media_type="application/json",
        sanitized=True,
    )
    if (
        artifact.sha256 != artifact_sha
        or artifact.size_bytes != len(sanitized)
        or artifact.storage_path != f"sha256/{artifact_sha[:2]}/{artifact_sha}"
        or artifact_store.read_by_sha256(
            artifact_sha, expected_size_bytes=len(sanitized)
        )
        != sanitized
    ):
        raise SourceResultAssemblyError
    artifact_reference = SemgrepSanitizedArtifactReference(
        artifact_id=str(uuid5(_SEMGREP_ARTIFACT_NAMESPACE, artifact_sha)),
        tool_execution_id=tool_execution_id,
        sha256=artifact_sha,
        size_bytes=len(sanitized),
        media_type="application/json",
        sanitized=True,
        artifact_kind=ArtifactKind.SANITIZED_NATIVE_REPORT.value,
    )
    evidence = []
    findings = []
    selected = {item.relative_path for item in context.selected_files}
    for item in data["results"]:
        try:
            if set(item) != {
                "end",
                "fingerprint",
                "metadata",
                "path",
                "rule_id",
                "severity",
                "start",
            } or item["path"] not in selected:
                raise ValueError
            location = SourceSpanLocation(
                item["path"],
                item["start"]["line"],
                item["end"]["line"],
                item["start"]["column"],
                item["end"]["column"],
            )
            fingerprint = item["fingerprint"]
            cwe_ids = tuple(item["metadata"]["cwe"])
            evidence_id = build_evidence_id(
                EvidenceAuthority.SEMGREP,
                SEMGREP_NATIVE_IDENTITY_SCHEMA,
                fingerprint,
            )
            evidence.append(
                SecureScanEvidence(
                    evidence_id=evidence_id,
                    authority=EvidenceAuthority.SEMGREP,
                    evidence_kind=EvidenceKind.SEMGREP_RULE_MATCH,
                    native_identity_schema=SEMGREP_NATIVE_IDENTITY_SCHEMA,
                    native_identity=fingerprint,
                    payload=SemgrepEvidencePayload(
                        fingerprint, item["rule_id"], _SEMGREP_MESSAGE, cwe_ids
                    ),
                    provenance=SemgrepProvenance(
                        scanner_id=result.scanner_id,
                        scanner_version=result.scanner_version,
                        source_analyzer_id=result.analyzer_id,
                        binding_digest=result.binding_digest,
                        ruleset_id=_SEMGREP_RULESET_ID,
                        ruleset_version=_SEMGREP_RULESET_VERSION,
                        ruleset_digest=_SEMGREP_RULESET_SHA256,
                        projection_id=result.projection_id,
                        context_digest=result.context_digest,
                        projection_digest=result.projection_digest,
                        sanitized_artifact=artifact_reference,
                    ),
                    locations=(location,),
                )
            )
            findings.append(
                SecureScanFinding(
                    finding_id=build_finding_id(
                        EvidenceAuthority.SEMGREP,
                        SEMGREP_NATIVE_IDENTITY_SCHEMA,
                        fingerprint,
                    ),
                    category=FindingCategory.CODE_SECURITY,
                    authority=EvidenceAuthority.SEMGREP,
                    native_identity_schema=SEMGREP_NATIVE_IDENTITY_SCHEMA,
                    native_finding_identity=fingerprint,
                    subject=SourceCodeSubject(item["rule_id"]),
                    locations=(location,),
                    primary_evidence_refs=(evidence_id,),
                    severity=SeverityProjection(
                        item["severity"].upper(),
                        SeverityScheme.SEMGREP_NORMALIZED,
                        EvidenceAuthority.SEMGREP,
                    ),
                )
            )
        except (KeyError, TypeError, ValueError):
            raise SourceResultAssemblyError from None
    selected_scope = _locations(tuple(item.relative_path for item in context.selected_files))
    component_ref = _context_component_ref(context)
    return SecureScanEvidenceFragment(
        scope=report_scope,
        evidence=tuple(sorted(evidence, key=lambda item: item.evidence_id)),
        findings=tuple(sorted(findings, key=lambda item: item.finding_id)),
        coverage_outcomes=(
            SecureScanCoverageOutcome(
                coverage_id=coverage_id(
                    EvidenceAuthority.SEMGREP,
                    context.capability.value,
                    component_ref=component_ref,
                    selected_scope=selected_scope,
                ),
                authority=EvidenceAuthority.SEMGREP,
                capability=context.capability.value,
                state=(
                    CoverageState.COMPLETE_WITH_FINDINGS
                    if findings
                    else CoverageState.COMPLETE
                ),
                framework=None,
                component_ref=component_ref,
                selected_scope=selected_scope,
                finding_count=len(findings),
                suppression_count=0,
                gap_count=0,
            ),
        ),
    )


class SourceResultAssemblyService:
    """Project accepted durable engine evidence into one frozen S4 report."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        artifact_store: ContentAddressedArtifactStore,
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        if not isinstance(artifact_store, ContentAddressedArtifactStore):
            raise SourceResultAssemblyError
        self._sessions = session_factory
        self._artifacts = artifact_store
        self._clock = clock

    def assemble(self, run_id: str) -> SourceAssemblyRecord:
        report = self._build_report(run_id)
        payload = report.canonical_json()
        try:
            artifact = self._artifacts.put(
                payload,
                kind=ArtifactKind.SOURCE_FINAL_RESULT,
                media_type=SOURCE_FINAL_RESULT_MEDIA_TYPE,
                sanitized=True,
            )
            if self._artifacts.read_by_sha256(
                artifact.sha256, expected_size_bytes=artifact.size_bytes
            ) != payload:
                raise SourceResultAssemblyError
        except SourceResultAssemblyError:
            raise
        except OSError:
            raise SourceResultAssemblyError(
                "ASSEMBLY_ARTIFACT_IO_FAILED", retryable=True
            ) from None
        now = self._now()
        try:
            with self._sessions.begin() as session:
                parent = self._locked_parent(session, run_id)
                if parent.cancel_requested:
                    raise SourceResultAssemblyError
                if parent.assembly_artifact_sha256 is not None:
                    self._validate_assembly_reference(parent, artifact.sha256, len(payload))
                    parent.assembly_failure_code = None
                    parent.assembly_failure_at = None
                    return self._record(parent, assembled=False)
                if parent.lifecycle_state != OrchestrationLifecycleState.ASSEMBLY_READY.value:
                    raise SourceResultAssemblyError
                parent.assembly_artifact_sha256 = artifact.sha256
                parent.assembly_artifact_size_bytes = artifact.size_bytes
                parent.assembly_artifact_media_type = SOURCE_FINAL_RESULT_MEDIA_TYPE
                parent.assembly_schema_version = SOURCE_FINAL_RESULT_SCHEMA_VERSION
                parent.assembly_artifact_storage_path = artifact.storage_path
                parent.assembled_at = now
                parent.assembly_failure_code = None
                parent.assembly_failure_at = None
                parent.lifecycle_state = OrchestrationLifecycleState.COMMITTING.value
                parent.state_version += 1
                parent.updated_at = now
                return self._record(parent, assembled=True)
        except SourceResultAssemblyError:
            raise
        except SQLAlchemyError:
            raise SourceResultAssemblyError(
                "ASSEMBLY_DATABASE_FAILED", retryable=True
            ) from None

    def publish(self, run_id: str) -> SourceAssemblyRecord:
        now = self._now()
        try:
            with self._sessions.begin() as session:
                parent = self._locked_parent(session, run_id)
                run = session.get(AnalysisRunRow, run_id)
                if run is None or parent.cancel_requested:
                    raise SourceResultAssemblyError
                if parent.lifecycle_state == OrchestrationLifecycleState.TERMINAL.value:
                    if run.report_json is None or parent.published_at is None:
                        raise SourceResultAssemblyError
                    self._load_assembly_document(parent, run.report_json)
                    return self._record(parent, assembled=False)
                if parent.lifecycle_state != OrchestrationLifecycleState.COMMITTING.value:
                    raise SourceResultAssemblyError
                document = self._load_assembly_document(parent, None)
                if run.report_json is not None:
                    raise SourceResultAssemblyError
                outcome = self._terminal_outcome(session, run_id)
                run.report_json = document
                run.status = {
                    OrchestrationTerminalOutcome.COMPLETED: RunStatus.COMPLETED,
                    OrchestrationTerminalOutcome.PARTIAL: RunStatus.PARTIAL,
                    OrchestrationTerminalOutcome.FAILED: RunStatus.FAILED,
                }[outcome].value
                parent.lifecycle_state = OrchestrationLifecycleState.TERMINAL.value
                parent.terminal_outcome = outcome.value
                parent.published_at = now
                parent.assembly_failure_code = None
                parent.assembly_failure_at = None
                parent.state_version += 1
                parent.updated_at = now
                return self._record(parent, assembled=False)
        except SourceResultAssemblyError:
            raise
        except KeyError:
            raise SourceResultAssemblyError from None
        except SQLAlchemyError:
            raise SourceResultAssemblyError(
                "ASSEMBLY_DATABASE_FAILED", retryable=True, phase="PUBLICATION"
            ) from None

    def assemble_and_publish(self, run_id: str) -> SourceAssemblyRecord:
        self.assemble(run_id)
        return self.publish(run_id)

    def record_failure(
        self, run_id: str, failure: SourceResultAssemblyError
    ) -> SourceAssemblyFailureRecord:
        if not isinstance(failure, SourceResultAssemblyError):
            raise SourceResultAssemblyError
        now = self._now()
        try:
            with self._sessions.begin() as session:
                parent = self._locked_parent(session, run_id)
                run = session.get(AnalysisRunRow, run_id)
                if run is None:
                    raise SourceResultAssemblyError
                if (
                    parent.lifecycle_state == OrchestrationLifecycleState.TERMINAL.value
                    and parent.terminal_outcome
                    == OrchestrationTerminalOutcome.FAILED.value
                    and parent.assembly_failure_code is not None
                ):
                    return SourceAssemblyFailureRecord(
                        run_id,
                        parent.assembly_attempt_count,
                        parent.assembly_failure_code,
                        failure.retryable,
                        True,
                    )
                if parent.lifecycle_state not in {
                    OrchestrationLifecycleState.ASSEMBLY_READY.value,
                    OrchestrationLifecycleState.COMMITTING.value,
                }:
                    raise SourceResultAssemblyError
                parent.assembly_attempt_count += 1
                parent.assembly_failure_code = failure.reason_code
                parent.assembly_failure_at = now
                terminalized = bool(
                    not failure.retryable
                    or parent.assembly_attempt_count >= SOURCE_ASSEMBLY_MAX_ATTEMPTS
                )
                if terminalized:
                    parent.lifecycle_state = OrchestrationLifecycleState.TERMINAL.value
                    parent.terminal_outcome = OrchestrationTerminalOutcome.FAILED.value
                    run.status = RunStatus.FAILED.value
                parent.state_version += 1
                parent.updated_at = now
                return SourceAssemblyFailureRecord(
                    run_id,
                    parent.assembly_attempt_count,
                    failure.reason_code,
                    failure.retryable,
                    terminalized,
                )
        except SourceResultAssemblyError:
            raise
        except SQLAlchemyError:
            raise SourceResultAssemblyError(
                "ASSEMBLY_FAILURE_RECORD_FAILED", retryable=True
            ) from None

    def load(self, run_id: str) -> SourceAssemblyRecord:
        try:
            with self._sessions() as session:
                parent = session.get(SourceOrchestrationRow, run_id)
                if parent is None or parent.assembly_artifact_sha256 is None:
                    raise SourceResultAssemblyError
                run = session.get(AnalysisRunRow, run_id)
                if run is None:
                    raise SourceResultAssemblyError
                self._load_assembly_document(parent, run.report_json)
                return self._record(parent, assembled=False)
        except SourceResultAssemblyError:
            raise
        except SQLAlchemyError:
            raise SourceResultAssemblyError from None

    def _build_report(self, run_id: str) -> SecureScanEvidenceReport:
        try:
            with self._sessions() as session:
                parent = session.get(SourceOrchestrationRow, run_id)
                if (
                    parent is None
                    or parent.cancel_requested
                    or parent.lifecycle_state
                    not in {
                        OrchestrationLifecycleState.ASSEMBLY_READY.value,
                        OrchestrationLifecycleState.COMMITTING.value,
                        OrchestrationLifecycleState.TERMINAL.value,
                    }
                ):
                    raise SourceResultAssemblyError
                snapshot = self._load_snapshot(parent)
                nodes = tuple(
                    session.scalars(
                        select(SourceOrchestrationNodeRow)
                        .where(SourceOrchestrationNodeRow.run_id == run_id)
                        .order_by(SourceOrchestrationNodeRow.node_id)
                    )
                )
                expected_nodes = {
                    item.node_id: item.canonical_data() for item in snapshot.nodes
                }
                durable_nodes = {
                    item.node_id: {
                        "analyzer_id": item.analyzer_id,
                        "authority": item.authority,
                        "capability": item.capability,
                        "component_id": item.component_id,
                        "contract_digest": item.contract_digest,
                        "initial_state": expected_nodes.get(item.node_id, {}).get(
                            "initial_state"
                        ),
                        "node_id": item.node_id,
                        "plan_entry_keys": item.plan_entry_keys_json,
                        "scope_digest": item.scope_digest,
                        "selected_paths": item.selected_paths_json,
                    }
                    for item in nodes
                }
                if expected_nodes != durable_nodes or any(
                    node.lifecycle_state != OrchestrationNodeLifecycleState.TERMINAL.value
                    or node.containment_state
                    not in {
                        OrchestrationContainmentState.CLEAN.value,
                        OrchestrationContainmentState.NOT_STARTED.value,
                    }
                    for node in nodes
                ):
                    raise SourceResultAssemblyError
                scope = SecureScanReportScope(
                    run_id,
                    parent.repository_digest,
                    parent.profile_digest,
                    parent.plan_digest,
                )
                fragments: list[SecureScanEvidenceFragment] = [
                    _repository_fragment(snapshot)
                ]
                for node in nodes:
                    fragments.append(
                        self._node_fragment(session, snapshot, scope, node)
                    )
                report = build_report(scope, *fragments)
                report.canonical_json()
                return report
        except SourceResultAssemblyError:
            raise
        except OSError:
            raise SourceResultAssemblyError(
                "ASSEMBLY_ARTIFACT_IO_FAILED", retryable=True
            ) from None
        except Exception:
            raise SourceResultAssemblyError from None

    def _node_fragment(
        self,
        session: Session,
        snapshot: SourcePlanningSnapshot,
        scope: SecureScanReportScope,
        node: SourceOrchestrationNodeRow,
    ) -> SecureScanEvidenceFragment:
        disposition = OrchestrationNodeDisposition(node.terminal_disposition)
        mapping = session.scalar(
            select(SourceOrchestrationScannerJobRow).where(
                SourceOrchestrationScannerJobRow.run_id == node.run_id,
                SourceOrchestrationScannerJobRow.node_id == node.node_id,
            )
        )
        if mapping is None or mapping.selected_attempt_number is None:
            return self._terminal_fragment(snapshot, scope, node, disposition)
        attempt = session.get(
            SourceOrchestrationAttemptRow,
            (mapping.job_id, mapping.selected_attempt_number),
        )
        if (
            attempt is None
            or attempt.acceptance_state != "ACCEPTED"
            or attempt.containment_state != OrchestrationContainmentState.CLEAN.value
            or attempt.native_result_sha256 is None
            or attempt.native_result_size_bytes is None
            or attempt.tool_execution_id is None
        ):
            raise SourceResultAssemblyError
        payload = self._artifacts.read_by_sha256(
            attempt.native_result_sha256,
            expected_size_bytes=attempt.native_result_size_bytes,
        )
        authority = SourceAuthority(node.authority)
        if authority is SourceAuthority.OSV:
            if (
                attempt.native_result_media_type != OSV_NATIVE_RESULT_MEDIA_TYPE
                or attempt.native_result_schema_version != OSV_NATIVE_RESULT_SCHEMA_VERSION
            ):
                raise SourceResultAssemblyError
            result = SafeSourceOsvResult.from_json(payload)
            fragment = self._osv_fragment(session, scope, node, result)
        else:
            if (
                attempt.native_result_media_type != SAFE_NATIVE_RESULT_MEDIA_TYPE
                or attempt.native_result_schema_version != SAFE_NATIVE_RESULT_SCHEMA_VERSION
            ):
                raise SourceResultAssemblyError
            result = SafeSourceNativeResult.from_json(payload)
            context = self._load_context(mapping)
            self._validate_local_result(node, mapping, attempt, result, context)
            if authority is SourceAuthority.GITLEAKS:
                fragment = adapt_gitleaks_result(
                    _gitleaks_result(result), context=context, projection=_projection(result)
                )
            elif authority is SourceAuthority.SYFT:
                fragment = adapt_syft_result(
                    _syft_result(result), context=context, projection=_projection(result)
                )
            elif authority is SourceAuthority.CHECKOV:
                fragment = _checkov_fragment(result, context, scope)
            elif authority is SourceAuthority.SEMGREP:
                fragment = _semgrep_fragment(
                    result,
                    context,
                    scope,
                    attempt.tool_execution_id,
                    self._artifacts,
                )
            else:
                raise SourceResultAssemblyError
        return self._limit_fragment(fragment, snapshot, node, disposition)

    def _osv_fragment(
        self,
        session: Session,
        scope: SecureScanReportScope,
        node: SourceOrchestrationNodeRow,
        result: SafeSourceOsvResult,
    ) -> SecureScanEvidenceFragment:
        row = session.get(
            SourceOrchestrationDependencyEvaluationRow, (node.run_id, node.node_id)
        )
        if row is None:
            raise SourceResultAssemblyError
        payload = self._artifacts.read_by_sha256(
            row.evaluation_artifact_sha256,
            expected_size_bytes=row.evaluation_artifact_size_bytes,
        )
        evaluation = SourceDependencyEvaluation.from_json(payload)
        if (
            result.run_id != node.run_id
            or result.node_id != node.node_id
            or result.scope_digest != node.scope_digest
            or result.dependency_evaluation_sha256 != evaluation.sha256()
            or result.coverage_limited != evaluation.coverage_limited
        ):
            raise SourceResultAssemblyError
        base = adapt_osv_analysis(result.analysis, scope=scope)
        extra_gaps: list[SecureScanGap] = []
        for native_gap in (*evaluation.mixed_scope_gaps, *evaluation.coordinate_gaps):
            native = _identity(
                {
                    "locations": native_gap.locations,
                    "package_key": native_gap.package_key,
                    "package_observation_ids": native_gap.package_observation_ids,
                    "reason_code": native_gap.reason_code,
                }
            )
            component_ref = build_component_ref(
                ComponentKind.PACKAGE, native_gap.package_key
            )
            extra_gaps.append(
                SecureScanGap(
                    gap_id=gap_id(
                        EvidenceAuthority.OSV, OSV_GAP_IDENTITY_SCHEMA, native
                    ),
                    authority=EvidenceAuthority.OSV,
                    native_identity_schema=OSV_GAP_IDENTITY_SCHEMA,
                    native_identity=native,
                    code=native_gap.reason_code,
                    scope=SecureScanGapScope(
                        GapScopeKind.PACKAGE, native_gap.package_key, component_ref
                    ),
                )
            )
        if not evaluation.syft_prerequisite.prerequisite_complete:
            extra_gaps.append(
                self._engine_gap(
                    EvidenceAuthority.OSV,
                    node.capability,
                    "PARTIAL_SYFT_PREREQUISITE",
                    None,
                    None,
                )
            )
        if not extra_gaps:
            return base
        paths = tuple(
            sorted(
                {
                    path
                    for candidate in result.analysis.candidates
                    for path in candidate.locations
                }
                | {
                    path
                    for gap in (*evaluation.mixed_scope_gaps, *evaluation.coordinate_gaps)
                    for path in gap.locations
                }
            )
        )
        selected_scope = _scope_locations(paths)
        outcome = SecureScanCoverageOutcome(
            coverage_id=coverage_id(
                EvidenceAuthority.OSV,
                AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING.value,
                selected_scope=selected_scope,
            ),
            authority=EvidenceAuthority.OSV,
            capability=AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING.value,
            state=CoverageState.PARTIAL,
            framework=None,
            component_ref=None,
            selected_scope=selected_scope,
            finding_count=len(base.findings),
            suppression_count=0,
            gap_count=len(extra_gaps),
            reason_code="PACKAGE_GAPS_PRESENT",
        )
        return replace(
            base,
            gaps=tuple(sorted(extra_gaps, key=lambda item: item.gap_id)),
            coverage_outcomes=(outcome,),
        )

    def _limit_fragment(
        self,
        fragment: SecureScanEvidenceFragment,
        snapshot: SourcePlanningSnapshot,
        node: SourceOrchestrationNodeRow,
        disposition: OrchestrationNodeDisposition,
    ) -> SecureScanEvidenceFragment:
        if disposition is OrchestrationNodeDisposition.COMPLETE:
            return fragment
        if disposition is not OrchestrationNodeDisposition.PARTIAL:
            raise SourceResultAssemblyError
        reason = node.terminal_reason_code or "PARTIAL_EXECUTION"
        gaps = list(fragment.gaps)
        outcomes = []
        for outcome in fragment.coverage_outcomes:
            gap = self._engine_gap(
                outcome.authority,
                outcome.capability,
                reason,
                outcome.component_ref,
                outcome.framework,
            )
            if not any(item.gap_id == gap.gap_id for item in gaps):
                gaps.append(gap)
            outcomes.append(
                replace(
                    outcome,
                    state=CoverageState.PARTIAL,
                    gap_count=sum(
                        self._gap_matches_outcome(item, outcome)
                        for item in gaps
                    ),
                    reason_code=reason,
                )
            )
        return replace(
            fragment,
            gaps=tuple(sorted(gaps, key=lambda item: item.gap_id)),
            coverage_outcomes=tuple(sorted(outcomes, key=lambda item: item.coverage_id)),
        )

    def _terminal_fragment(
        self,
        snapshot: SourcePlanningSnapshot,
        scope: SecureScanReportScope,
        node: SourceOrchestrationNodeRow,
        disposition: OrchestrationNodeDisposition,
    ) -> SecureScanEvidenceFragment:
        authority = EvidenceAuthority(node.authority)
        selected_scope = _scope_locations(tuple(node.selected_paths_json))
        component_ref = _component_ref(snapshot, node.component_id)
        state = {
            OrchestrationNodeDisposition.NOT_APPLICABLE: CoverageState.NOT_APPLICABLE,
            OrchestrationNodeDisposition.FAILED: CoverageState.FAILED,
            OrchestrationNodeDisposition.BLOCKED_BY_DEPENDENCY: CoverageState.FAILED,
            OrchestrationNodeDisposition.CANCELLED: CoverageState.FAILED,
        }.get(disposition)
        if state is None:
            raise SourceResultAssemblyError
        reason = node.terminal_reason_code or disposition.value
        gaps = ()
        if state is CoverageState.FAILED:
            gaps = (
                self._engine_gap(
                    authority, node.capability, reason, component_ref, None
                ),
            )
        return SecureScanEvidenceFragment(
            scope=scope,
            gaps=gaps,
            coverage_outcomes=(
                SecureScanCoverageOutcome(
                    coverage_id=coverage_id(
                        authority,
                        node.capability,
                        component_ref=component_ref,
                        selected_scope=selected_scope,
                    ),
                    authority=authority,
                    capability=node.capability,
                    state=state,
                    framework=None,
                    component_ref=component_ref,
                    selected_scope=selected_scope,
                    finding_count=0,
                    suppression_count=0,
                    gap_count=len(gaps),
                    reason_code=reason,
                ),
            ),
        )

    @staticmethod
    def _engine_gap(
        authority: EvidenceAuthority,
        capability: str,
        reason: str,
        component_ref: str | None,
        framework: str | None,
    ) -> SecureScanGap:
        material = {
            "authority": authority.value,
            "capability": capability,
            "component_ref": component_ref,
            "framework": framework,
            "reason": reason,
        }
        native = _identity(material)
        scope = (
            SecureScanGapScope(GapScopeKind.FRAMEWORK, framework, component_ref)
            if framework is not None
            else SecureScanGapScope(GapScopeKind.CAPABILITY, capability, component_ref)
        )
        return SecureScanGap(
            gap_id=gap_id(authority, ENGINE_GAP_IDENTITY_SCHEMA, native),
            authority=authority,
            native_identity_schema=ENGINE_GAP_IDENTITY_SCHEMA,
            native_identity=native,
            code=reason,
            scope=scope,
            message="The selected authority did not complete its declared scope",
        )

    @staticmethod
    def _gap_matches_outcome(
        gap: SecureScanGap, outcome: SecureScanCoverageOutcome
    ) -> int:
        if gap.authority is not outcome.authority:
            return 0
        if gap.scope.kind is GapScopeKind.FRAMEWORK:
            return int(gap.scope.value == outcome.framework)
        return int(
            gap.scope.kind is not GapScopeKind.CAPABILITY
            or gap.scope.value == outcome.capability
        )

    def _load_context(
        self, mapping: SourceOrchestrationScannerJobRow
    ) -> SourceExecutionContext:
        if (
            mapping.context_artifact_sha256 is None
            or mapping.context_artifact_size_bytes is None
        ):
            raise SourceResultAssemblyError
        payload = self._artifacts.read_by_sha256(
            mapping.context_artifact_sha256,
            expected_size_bytes=mapping.context_artifact_size_bytes,
        )
        context = SourceExecutionContext.from_json(payload)
        if context.context_digest() != mapping.context_digest:
            raise SourceResultAssemblyError
        return context

    @staticmethod
    def _validate_local_result(
        node: SourceOrchestrationNodeRow,
        mapping: SourceOrchestrationScannerJobRow,
        attempt: SourceOrchestrationAttemptRow,
        result: SafeSourceNativeResult,
        context: SourceExecutionContext,
    ) -> None:
        if (
            context.source_run_id != node.run_id
            or context.job_id != mapping.job_id
            or result.node_id != node.node_id
            or result.job_id != mapping.job_id
            or result.attempt_number != attempt.attempt_number
            or result.authority != node.authority
            or result.analyzer_id != node.analyzer_id
            or result.binding_digest != node.contract_digest
            or result.repository_digest != context.repository_digest
            or result.profile_digest != context.profile_digest
            or result.plan_digest != context.plan_digest
        ):
            raise SourceResultAssemblyError

    def _load_snapshot(self, parent: SourceOrchestrationRow) -> SourcePlanningSnapshot:
        payload = self._artifacts.read_by_sha256(
            parent.planning_snapshot_sha256,
            expected_size_bytes=parent.snapshot_size_bytes,
        )
        snapshot = SourcePlanningSnapshot.from_json(payload)
        if snapshot.snapshot_digest() != parent.planning_snapshot_sha256:
            raise SourceResultAssemblyError
        return snapshot

    def _load_assembly_document(
        self, parent: SourceOrchestrationRow, existing: dict[str, Any] | None
    ) -> dict[str, Any]:
        if (
            parent.assembly_artifact_sha256 is None
            or parent.assembly_artifact_size_bytes is None
            or parent.assembly_artifact_media_type != SOURCE_FINAL_RESULT_MEDIA_TYPE
            or parent.assembly_schema_version != SOURCE_FINAL_RESULT_SCHEMA_VERSION
            or parent.assembly_artifact_storage_path
            != f"sha256/{parent.assembly_artifact_sha256[:2]}/{parent.assembly_artifact_sha256}"
        ):
            raise SourceResultAssemblyError
        payload = self._artifacts.read_by_sha256(
            parent.assembly_artifact_sha256,
            expected_size_bytes=parent.assembly_artifact_size_bytes,
        )
        try:
            document = json.loads(payload.decode("utf-8"))
        except (TypeError, ValueError, UnicodeError):
            raise SourceResultAssemblyError from None
        if (
            not isinstance(document, dict)
            or _canonical_json(document) != payload
            or document.get("schema_version") != SOURCE_FINAL_RESULT_SCHEMA_VERSION
            or (existing is not None and existing != document)
        ):
            raise SourceResultAssemblyError
        return document

    @staticmethod
    def _terminal_outcome(
        session: Session, run_id: str
    ) -> OrchestrationTerminalOutcome:
        dispositions = tuple(
            OrchestrationNodeDisposition(value)
            for value in session.scalars(
                select(SourceOrchestrationNodeRow.terminal_disposition).where(
                    SourceOrchestrationNodeRow.run_id == run_id
                )
            )
        )
        incomplete = {
            OrchestrationNodeDisposition.PARTIAL,
            OrchestrationNodeDisposition.FAILED,
            OrchestrationNodeDisposition.BLOCKED_BY_DEPENDENCY,
            OrchestrationNodeDisposition.CANCELLED,
        }
        if (
            dispositions
            and all(value in incomplete for value in dispositions)
            and all(
                value
                in {
                    OrchestrationNodeDisposition.FAILED,
                    OrchestrationNodeDisposition.BLOCKED_BY_DEPENDENCY,
                    OrchestrationNodeDisposition.CANCELLED,
                }
                for value in dispositions
            )
        ):
            return OrchestrationTerminalOutcome.FAILED
        if any(value in incomplete for value in dispositions):
            return OrchestrationTerminalOutcome.PARTIAL
        return OrchestrationTerminalOutcome.COMPLETED

    @staticmethod
    def _locked_parent(session: Session, run_id: str) -> SourceOrchestrationRow:
        parent = session.scalar(
            select(SourceOrchestrationRow)
            .where(SourceOrchestrationRow.run_id == run_id)
            .with_for_update()
        )
        if parent is None:
            raise SourceResultAssemblyError
        return parent

    @staticmethod
    def _validate_assembly_reference(
        parent: SourceOrchestrationRow, sha256: str, size_bytes: int
    ) -> None:
        if (
            parent.assembly_artifact_sha256 != sha256
            or parent.assembly_artifact_size_bytes != size_bytes
            or parent.assembly_artifact_media_type != SOURCE_FINAL_RESULT_MEDIA_TYPE
            or parent.assembly_schema_version != SOURCE_FINAL_RESULT_SCHEMA_VERSION
            or parent.assembly_artifact_storage_path != f"sha256/{sha256[:2]}/{sha256}"
            or parent.assembled_at is None
        ):
            raise SourceResultAssemblyError

    def _record(
        self, parent: SourceOrchestrationRow, *, assembled: bool
    ) -> SourceAssemblyRecord:
        if (
            parent.assembly_artifact_sha256 is None
            or parent.assembly_artifact_size_bytes is None
        ):
            raise SourceResultAssemblyError
        outcome = (
            None
            if parent.terminal_outcome is None
            else OrchestrationTerminalOutcome(parent.terminal_outcome)
        )
        return SourceAssemblyRecord(
            parent.run_id,
            parent.assembly_artifact_sha256,
            parent.assembly_artifact_size_bytes,
            OrchestrationLifecycleState(parent.lifecycle_state),
            outcome,
            assembled,
            parent.published_at is not None,
        )

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise SourceResultAssemblyError
        return value.astimezone(UTC)
