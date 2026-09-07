from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import Any

from securescan.advisories.osv import (
    OSV_SCHEMA_VERSION,
    DependencyVulnerabilityFinding,
    OsvAdvisoryObservation,
    OsvDependencyAnalysis,
)
from securescan.domain.enums import ArtifactKind
from securescan.domain.models import ToolExecutionRecord
from securescan.scanners.checkov import (
    CHECKOV_SOURCE_ANALYZER_ID,
    CheckovFrameworkState,
    CheckovParseResult,
)
from securescan.scanners.gitleaks import (
    GITLEAKS_IDENTITY_SCHEMA_VERSION,
    GITLEAKS_SOURCE_ANALYZER_ID,
    GitleaksDetectionKind,
    GitleaksFindingIdentity,
    GitleaksParseResult,
    build_gitleaks_finding_identities,
)
from securescan.scanners.semgrep import TrustedSemgrepSourceBinding
from securescan.scanners.semgrep.source_execution import SourceProjectionExecutionReference
from securescan.scanners.syft import (
    SYFT_SOURCE_ANALYZER_ID,
    PackageObservation,
    SyftParseResult,
)
from securescan.source import (
    AnalysisCapability,
    RepositoryComponent,
    SourceCapabilityExecutionAssessment,
    SourceExecutionContext,
    SourceExecutionStatus,
)

from .models import (
    SYFT_EVIDENCE_IDENTITY_SCHEMA,
    CheckovEvidencePayload,
    CheckovSuppressionPayload,
    ComponentKind,
    ConfigurationResourceSubject,
    CoverageState,
    EvidenceAuthority,
    EvidenceKind,
    FindingCategory,
    GapScopeKind,
    GitleaksEvidencePayload,
    LocalScannerProvenance,
    OsvAdvisoryGroupEvidencePayload,
    OsvAdvisoryRevisionEvidencePayload,
    OsvCvssProjection,
    OsvProvenance,
    PackageComponentPayload,
    PackageSubject,
    RepositoryComponentPayload,
    RepositoryPathLocation,
    RepositoryScopeLocation,
    SecretExposureSubject,
    SecureScanComponent,
    SecureScanCoverageOutcome,
    SecureScanEvidence,
    SecureScanEvidenceFragment,
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
    SyftPackageEvidencePayload,
    UnifiedEvidenceError,
    build_component_ref,
    build_evidence_id,
    build_finding_id,
    coverage_id,
    gap_id,
    suppression_id,
)

SEMGREP_NATIVE_IDENTITY_SCHEMA = "semgrep-structural-fingerprint-v1"
SYFT_PACKAGE_IDENTITY_SCHEMA = "securescan-syft-package-key-s1"
OSV_FINDING_IDENTITY_SCHEMA = "securescan-dependency-vulnerability-finding-s2"
OSV_GROUP_EVIDENCE_IDENTITY_SCHEMA = "securescan-osv-advisory-group-s2"
OSV_REVISION_EVIDENCE_IDENTITY_SCHEMA = "securescan-osv-advisory-revision-s2"
CHECKOV_NATIVE_IDENTITY_SCHEMA = "securescan-configuration-security-finding-s3"
CHECKOV_SUPPRESSION_IDENTITY_SCHEMA = "securescan-checkov-suppression-s3"
SEMGREP_GAP_IDENTITY_SCHEMA = "securescan-source-analysis-gap-v1"
OSV_GAP_IDENTITY_SCHEMA = "securescan-osv-package-gap-s2"
CHECKOV_GAP_IDENTITY_SCHEMA = "securescan-checkov-parse-gap-s3"


def _validated(value: Any, expected: type[Any]) -> Any:
    if not isinstance(value, expected):
        raise UnifiedEvidenceError
    try:
        copied = replace(value)
    except Exception:
        raise UnifiedEvidenceError from None
    if copied != value:
        raise UnifiedEvidenceError
    return copied


def _validated_model(value: Any, expected: type[Any]) -> Any:
    if not isinstance(value, expected):
        raise UnifiedEvidenceError
    try:
        copied = expected.model_validate(value.model_dump(mode="python"))
    except Exception:
        raise UnifiedEvidenceError from None
    if copied != value:
        raise UnifiedEvidenceError
    return copied


def _identity(value: object) -> str:
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _locations(paths: tuple[str, ...]) -> tuple[RepositoryPathLocation, ...]:
    return tuple(
        sorted(
            (RepositoryPathLocation(path) for path in set(paths)),
            key=lambda item: json.dumps(item.canonical_data(), sort_keys=True),
        )
    )


def _scanner_provenance(
    *,
    scanner_id: str,
    scanner_version: str,
    binding_digest: str,
    projection_id: str,
    context_digest: str,
    projection_digest: str,
) -> LocalScannerProvenance:
    return LocalScannerProvenance(
        scanner_id=scanner_id,
        scanner_version=scanner_version,
        binding_digest=binding_digest,
        projection_id=projection_id,
        context_digest=context_digest,
        projection_digest=projection_digest,
    )


def _scope(context: SourceExecutionContext) -> SecureScanReportScope:
    return SecureScanReportScope(
        source_run_id=context.source_run_id,
        repository_digest=context.repository_digest,
        profile_digest=context.profile_digest,
        plan_digest=context.plan_digest,
    )


def _repository_component_ref(context: SourceExecutionContext) -> str | None:
    return (
        None
        if context.component_id is None
        else build_component_ref(ComponentKind.REPOSITORY, context.component_id)
    )


def _validate_context_projection(
    context: SourceExecutionContext,
    projection: SourceProjectionExecutionReference,
    *,
    source_analyzer_id: str,
    capability: AnalysisCapability,
    binding_digest: str,
    projection_id: str,
    projection_digest: str,
) -> None:
    if (
        context.source_analyzer_id != source_analyzer_id
        or context.capability is not capability
        or context.binding_digest != binding_digest
        or projection.context_digest != context.context_digest()
        or projection.projection_id != projection_id
        or projection.projection_digest != projection_digest
    ):
        raise UnifiedEvidenceError


def adapt_repository_components(
    components: tuple[RepositoryComponent, ...],
) -> SecureScanEvidenceFragment:
    values = []
    for component in components:
        item = _validated(component, RepositoryComponent)
        values.append(
            SecureScanComponent(
                component_ref=build_component_ref(ComponentKind.REPOSITORY, item.component_id),
                component_kind=ComponentKind.REPOSITORY,
                native_component_identity=item.component_id,
                payload=RepositoryComponentPayload(
                    component_id=item.component_id,
                    display_name=item.display_name,
                    root_path=item.root_path,
                    manifest_paths=item.manifest_paths,
                    lockfile_paths=item.lockfile_paths,
                ),
            )
        )
    return SecureScanEvidenceFragment(
        components=tuple(sorted(values, key=lambda item: item.component_ref))
    )


def adapt_semgrep_assessment(
    assessment: SourceCapabilityExecutionAssessment,
    *,
    context: SourceExecutionContext,
    projection: SourceProjectionExecutionReference,
    binding: TrustedSemgrepSourceBinding,
    tool_execution: ToolExecutionRecord,
    sanitized_artifact_bytes: bytes,
) -> SecureScanEvidenceFragment:
    assessment = _validated(assessment, SourceCapabilityExecutionAssessment)
    context = _validated(context, SourceExecutionContext)
    projection = _validated(projection, SourceProjectionExecutionReference)
    tool_execution = _validated_model(tool_execution, ToolExecutionRecord)
    if not isinstance(sanitized_artifact_bytes, bytes):
        raise UnifiedEvidenceError
    if not isinstance(binding, TrustedSemgrepSourceBinding):
        raise UnifiedEvidenceError
    try:
        binding.canonical_data()
    except Exception:
        raise UnifiedEvidenceError from None
    if (
        assessment.source_run_id != context.source_run_id
        or assessment.job_id != context.job_id
        or assessment.repository_digest != context.repository_digest
        or assessment.profile_digest != context.profile_digest
        or assessment.plan_digest != context.plan_digest
        or assessment.binding_digest != context.binding_digest
        or assessment.source_analyzer_id != context.source_analyzer_id
        or assessment.core_adapter_id != context.core_adapter_id
        or assessment.capability is not context.capability
        or assessment.component_id != context.component_id
        or assessment.declared_paths != tuple(item.relative_path for item in context.selected_files)
        or projection.context_digest != context.context_digest()
        or assessment.binding_digest != binding.binding_digest()
        or assessment.source_analyzer_id != binding.source_analyzer_id
        or assessment.core_adapter_id != binding.core_adapter_id
        or assessment.capability is not binding.capability
        or (
            assessment.tool_version is not None
            and assessment.tool_version != binding.declared_tool_version
        )
        or assessment.final_tool_execution_id is None
        or str(tool_execution.execution_id) != assessment.final_tool_execution_id
        or str(tool_execution.run_id) != assessment.source_run_id
        or tool_execution.adapter_id != binding.core_adapter_id
        or tool_execution.tool_version != assessment.tool_version
        or len(tool_execution.artifacts) != 1
    ):
        raise UnifiedEvidenceError
    artifact = tool_execution.artifacts[0]
    if (
        artifact.kind is not ArtifactKind.SANITIZED_NATIVE_REPORT
        or artifact.media_type != "application/json"
        or artifact.sanitized is not True
        or type(artifact.size_bytes) is not int
        or artifact.size_bytes < 1
        or artifact.size_bytes != len(sanitized_artifact_bytes)
        or artifact.sha256 != hashlib.sha256(sanitized_artifact_bytes).hexdigest()
        or artifact.storage_path != f"sha256/{artifact.sha256[:2]}/{artifact.sha256}"
    ):
        raise UnifiedEvidenceError
    artifact_reference = SemgrepSanitizedArtifactReference(
        artifact_id=str(artifact.artifact_id),
        tool_execution_id=str(tool_execution.execution_id),
        sha256=artifact.sha256,
        size_bytes=artifact.size_bytes,
        media_type=artifact.media_type,
        sanitized=artifact.sanitized,
        artifact_kind=artifact.kind.value,
    )
    evidence = []
    findings = []
    tool_version = assessment.tool_version
    if assessment.observations and tool_version is None:
        raise UnifiedEvidenceError
    for observation in assessment.observations:
        location = SourceSpanLocation(
            path=observation.relative_path,
            start_line=observation.start_line,
            end_line=observation.end_line,
            start_column=observation.start_column,
            end_column=observation.end_column,
        )
        evidence_id = build_evidence_id(
            EvidenceAuthority.SEMGREP,
            SEMGREP_NATIVE_IDENTITY_SCHEMA,
            observation.fingerprint,
        )
        evidence.append(
            SecureScanEvidence(
                evidence_id=evidence_id,
                authority=EvidenceAuthority.SEMGREP,
                evidence_kind=EvidenceKind.SEMGREP_RULE_MATCH,
                native_identity_schema=SEMGREP_NATIVE_IDENTITY_SCHEMA,
                native_identity=observation.fingerprint,
                payload=SemgrepEvidencePayload(
                    fingerprint=observation.fingerprint,
                    rule_id=observation.rule_id,
                    message=observation.message,
                    cwe_ids=observation.cwe_ids,
                ),
                provenance=SemgrepProvenance(
                    scanner_id=observation.producer,
                    scanner_version=tool_version or "unavailable",
                    source_analyzer_id=assessment.source_analyzer_id,
                    binding_digest=assessment.binding_digest,
                    ruleset_id=binding.ruleset_id,
                    ruleset_version=binding.ruleset_version,
                    ruleset_digest=binding.ruleset_sha256,
                    projection_id=projection.projection_id,
                    context_digest=projection.context_digest,
                    projection_digest=projection.projection_digest,
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
                    observation.fingerprint,
                ),
                category=FindingCategory.CODE_SECURITY,
                authority=EvidenceAuthority.SEMGREP,
                native_identity_schema=SEMGREP_NATIVE_IDENTITY_SCHEMA,
                native_finding_identity=observation.fingerprint,
                subject=SourceCodeSubject(observation.rule_id),
                locations=(location,),
                primary_evidence_refs=(evidence_id,),
                severity=SeverityProjection(
                    value=observation.native_severity.upper(),
                    scheme=SeverityScheme.SEMGREP_NORMALIZED,
                    authority=EvidenceAuthority.SEMGREP,
                ),
            )
        )
    gaps = []
    for gap in assessment.gaps:
        native_gap_identity = _identity(gap.canonical_data())
        scope = (
            SecureScanGapScope(
                GapScopeKind.PATH,
                gap.relative_path,
                _repository_component_ref(context),
            )
            if gap.relative_path is not None
            else SecureScanGapScope(
                GapScopeKind.CAPABILITY,
                gap.capability.value,
                _repository_component_ref(context),
            )
        )
        gaps.append(
            SecureScanGap(
                gap_id=gap_id(
                    EvidenceAuthority.SEMGREP,
                    SEMGREP_GAP_IDENTITY_SCHEMA,
                    native_gap_identity,
                ),
                authority=EvidenceAuthority.SEMGREP,
                native_identity_schema=SEMGREP_GAP_IDENTITY_SCHEMA,
                native_identity=native_gap_identity,
                code=gap.code,
                scope=scope,
                message=gap.message,
            )
        )
    state = {
        SourceExecutionStatus.COMPLETE: (
            CoverageState.COMPLETE_WITH_FINDINGS if findings else CoverageState.COMPLETE
        ),
        SourceExecutionStatus.PARTIAL: CoverageState.PARTIAL,
        SourceExecutionStatus.FAILED: CoverageState.FAILED,
    }[assessment.execution_status]
    selected_scope = _locations(assessment.declared_paths)
    component_ref = _repository_component_ref(context)
    outcome = SecureScanCoverageOutcome(
        coverage_id=coverage_id(
            EvidenceAuthority.SEMGREP,
            assessment.capability.value,
            component_ref=component_ref,
            selected_scope=selected_scope,
        ),
        authority=EvidenceAuthority.SEMGREP,
        capability=assessment.capability.value,
        state=state,
        framework=None,
        component_ref=component_ref,
        selected_scope=selected_scope,
        finding_count=len(findings),
        suppression_count=0,
        gap_count=len(gaps),
        reason_code="ANALYSIS_GAPS_PRESENT" if gaps else None,
    )
    return SecureScanEvidenceFragment(
        scope=_scope(context),
        evidence=tuple(sorted(evidence, key=lambda item: item.evidence_id)),
        findings=tuple(sorted(findings, key=lambda item: item.finding_id)),
        gaps=tuple(sorted(gaps, key=lambda item: item.gap_id)),
        coverage_outcomes=(outcome,),
    )


def adapt_gitleaks_result(
    result: GitleaksParseResult,
    *,
    context: SourceExecutionContext,
    projection: SourceProjectionExecutionReference,
) -> SecureScanEvidenceFragment:
    result = _validated(result, GitleaksParseResult)
    context = _validated(context, SourceExecutionContext)
    projection = _validated(projection, SourceProjectionExecutionReference)
    _validate_context_projection(
        context,
        projection,
        source_analyzer_id=GITLEAKS_SOURCE_ANALYZER_ID,
        capability=AnalysisCapability.SECRET_DETECTION,
        binding_digest=result.binding_digest,
        projection_id=result.projection_id,
        projection_digest=result.projection_digest,
    )
    if result.context_digest != context.context_digest():
        raise UnifiedEvidenceError
    identities = build_gitleaks_finding_identities(result.findings)
    evidence_by_identity: dict[str, SecureScanEvidence] = {}
    findings_by_identity: dict[str, SecureScanFinding] = {}
    occurrence_counts: dict[str, int] = {}
    for observation, raw_identity in zip(result.findings, identities, strict=True):
        identity = _validated(raw_identity, GitleaksFindingIdentity)
        if (
            identity.rule_id != observation.rule_id
            or identity.file_path != observation.file_path
            or identity.detection_kind is not observation.detection_kind
            or identity.start_line != observation.start_line
            or identity.end_line != observation.end_line
            or identity.start_column != observation.start_column
            or identity.end_column != observation.end_column
            or identity.scanner_id != observation.scanner_id
            or identity.scanner_version != observation.scanner_version
        ):
            raise UnifiedEvidenceError
        locations: tuple[SecureScanLocation, ...] = (
            (RepositoryPathLocation(observation.file_path),)
            if observation.detection_kind is GitleaksDetectionKind.PATH
            else (
                SourceSpanLocation(
                    observation.file_path,
                    observation.start_line or 0,
                    observation.end_line or 0,
                    observation.start_column,
                    observation.end_column,
                ),
            )
        )
        evidence_id = build_evidence_id(
            EvidenceAuthority.GITLEAKS,
            GITLEAKS_IDENTITY_SCHEMA_VERSION,
            identity.finding_instance_id,
        )
        mapped_evidence = SecureScanEvidence(
            evidence_id=evidence_id,
            authority=EvidenceAuthority.GITLEAKS,
            evidence_kind=EvidenceKind.GITLEAKS_SECRET_OBSERVATION,
            native_identity_schema=GITLEAKS_IDENTITY_SCHEMA_VERSION,
            native_identity=identity.finding_instance_id,
            payload=GitleaksEvidencePayload(
                finding_instance_id=identity.finding_instance_id,
                rule_id=observation.rule_id,
                detection_kind=observation.detection_kind.value,
                native_occurrence_count=1,
            ),
            provenance=_scanner_provenance(
                scanner_id=result.scanner_id,
                scanner_version=result.scanner_version,
                binding_digest=result.binding_digest,
                projection_id=result.projection_id,
                context_digest=result.context_digest,
                projection_digest=result.projection_digest,
            ),
            locations=locations,
        )
        mapped_finding = SecureScanFinding(
            finding_id=build_finding_id(
                EvidenceAuthority.GITLEAKS,
                GITLEAKS_IDENTITY_SCHEMA_VERSION,
                identity.finding_instance_id,
            ),
            category=FindingCategory.SECRET_EXPOSURE,
            authority=EvidenceAuthority.GITLEAKS,
            native_identity_schema=GITLEAKS_IDENTITY_SCHEMA_VERSION,
            native_finding_identity=identity.finding_instance_id,
            subject=SecretExposureSubject(observation.rule_id, observation.detection_kind.value),
            locations=locations,
            primary_evidence_refs=(evidence_id,),
        )
        previous_evidence = evidence_by_identity.get(identity.finding_instance_id)
        previous_finding = findings_by_identity.get(identity.finding_instance_id)
        if previous_evidence is not None and (
            previous_evidence != mapped_evidence or previous_finding != mapped_finding
        ):
            raise UnifiedEvidenceError
        evidence_by_identity[identity.finding_instance_id] = mapped_evidence
        findings_by_identity[identity.finding_instance_id] = mapped_finding
        occurrence_counts[identity.finding_instance_id] = (
            occurrence_counts.get(identity.finding_instance_id, 0) + 1
        )
    evidence = tuple(
        sorted(
            (
                replace(
                    item,
                    payload=replace(
                        item.payload,
                        native_occurrence_count=occurrence_counts[native_identity],
                    ),
                )
                for native_identity, item in evidence_by_identity.items()
            ),
            key=lambda item: item.evidence_id,
        )
    )
    findings = tuple(sorted(findings_by_identity.values(), key=lambda item: item.finding_id))
    selected_scope = _locations(tuple(item.relative_path for item in context.selected_files))
    component_ref = _repository_component_ref(context)
    outcome = SecureScanCoverageOutcome(
        coverage_id=coverage_id(
            EvidenceAuthority.GITLEAKS,
            "secret_detection",
            component_ref=component_ref,
            selected_scope=selected_scope,
        ),
        authority=EvidenceAuthority.GITLEAKS,
        capability="secret_detection",
        state=(CoverageState.COMPLETE_WITH_FINDINGS if findings else CoverageState.COMPLETE),
        framework=None,
        component_ref=component_ref,
        selected_scope=selected_scope,
        finding_count=result.finding_count,
        suppression_count=0,
        gap_count=0,
    )
    return SecureScanEvidenceFragment(
        scope=_scope(context),
        evidence=evidence,
        findings=findings,
        coverage_outcomes=(outcome,),
    )


def _package_component(observation: PackageObservation) -> SecureScanComponent:
    return SecureScanComponent(
        component_ref=build_component_ref(ComponentKind.PACKAGE, observation.package_key),
        component_kind=ComponentKind.PACKAGE,
        native_component_identity=observation.package_key,
        payload=PackageComponentPayload(
            package_key=observation.package_key,
            package_name=observation.package_name,
            package_version=observation.package_version,
            package_type=observation.package_type,
            purl=observation.purl,
        ),
    )


def adapt_syft_result(
    result: SyftParseResult,
    *,
    context: SourceExecutionContext,
    projection: SourceProjectionExecutionReference,
) -> SecureScanEvidenceFragment:
    result = _validated(result, SyftParseResult)
    context = _validated(context, SourceExecutionContext)
    projection = _validated(projection, SourceProjectionExecutionReference)
    _validate_context_projection(
        context,
        projection,
        source_analyzer_id=SYFT_SOURCE_ANALYZER_ID,
        capability=AnalysisCapability.PACKAGE_INVENTORY,
        binding_digest=result.binding_digest,
        projection_id=result.projection_id,
        projection_digest=result.snapshot_digest,
    )
    components: dict[str, SecureScanComponent] = {}
    evidence = []
    for raw in result.observations:
        observation = _validated(raw, PackageObservation)
        component = _package_component(observation)
        previous = components.get(component.component_ref)
        if previous is not None and previous != component:
            raise UnifiedEvidenceError
        components[component.component_ref] = component
        evidence_id = build_evidence_id(
            EvidenceAuthority.SYFT,
            SYFT_EVIDENCE_IDENTITY_SCHEMA,
            observation.package_observation_id,
        )
        evidence.append(
            SecureScanEvidence(
                evidence_id=evidence_id,
                authority=EvidenceAuthority.SYFT,
                evidence_kind=EvidenceKind.SYFT_PACKAGE_OBSERVATION,
                native_identity_schema=SYFT_EVIDENCE_IDENTITY_SCHEMA,
                native_identity=observation.package_observation_id,
                payload=SyftPackageEvidencePayload(
                    package_observation_id=observation.package_observation_id,
                    package_key=observation.package_key,
                    found_by=observation.found_by,
                    language=observation.language,
                ),
                provenance=_scanner_provenance(
                    scanner_id=result.scanner_id,
                    scanner_version=result.scanner_version,
                    binding_digest=result.binding_digest,
                    projection_id=result.projection_id,
                    context_digest=context.context_digest(),
                    projection_digest=result.snapshot_digest,
                ),
                component_refs=(component.component_ref,),
                locations=_locations(observation.locations),
            )
        )
    selected_scope = _locations(tuple(item.relative_path for item in context.selected_files))
    component_ref = _repository_component_ref(context)
    outcome = SecureScanCoverageOutcome(
        coverage_id=coverage_id(
            EvidenceAuthority.SYFT,
            "package_inventory",
            component_ref=component_ref,
            selected_scope=selected_scope,
        ),
        authority=EvidenceAuthority.SYFT,
        capability="package_inventory",
        state=CoverageState.COMPLETE,
        framework=None,
        component_ref=component_ref,
        selected_scope=selected_scope,
        finding_count=0,
        suppression_count=0,
        gap_count=0,
    )
    return SecureScanEvidenceFragment(
        scope=_scope(context),
        components=tuple(sorted(components.values(), key=lambda item: item.component_ref)),
        evidence=tuple(sorted(evidence, key=lambda item: item.evidence_id)),
        coverage_outcomes=(outcome,),
    )


def _osv_provenance(finding: DependencyVulnerabilityFinding) -> OsvProvenance:
    return OsvProvenance(
        source_service=finding.source_service,
        api_version=finding.api_version,
        schema_version=OSV_SCHEMA_VERSION,
        projection_id=finding.projection_id,
        snapshot_digest=finding.snapshot_digest,
        syft_binding_digest=finding.syft_binding_digest,
    )


def adapt_osv_analysis(
    analysis: OsvDependencyAnalysis, *, scope: SecureScanReportScope
) -> SecureScanEvidenceFragment:
    analysis = _validated(analysis, OsvDependencyAnalysis)
    if not isinstance(scope, SecureScanReportScope):
        raise UnifiedEvidenceError
    report_scope = scope
    evidence: dict[str, SecureScanEvidence] = {}
    findings = []
    for raw_finding in analysis.findings:
        finding = _validated(raw_finding, DependencyVulnerabilityFinding)
        component_ref = build_component_ref(ComponentKind.PACKAGE, finding.package_key)
        group_evidence_id = build_evidence_id(
            EvidenceAuthority.OSV,
            OSV_GROUP_EVIDENCE_IDENTITY_SCHEMA,
            finding.advisory_group_key,
        )
        group_evidence = SecureScanEvidence(
            evidence_id=group_evidence_id,
            authority=EvidenceAuthority.OSV,
            evidence_kind=EvidenceKind.OSV_ADVISORY_GROUP,
            native_identity_schema=OSV_GROUP_EVIDENCE_IDENTITY_SCHEMA,
            native_identity=finding.advisory_group_key,
            payload=OsvAdvisoryGroupEvidencePayload(
                finding_id=finding.finding_id,
                advisory_group_key=finding.advisory_group_key,
                package_observation_ids=finding.package_observation_ids,
                canonical_advisory_id=finding.canonical_advisory_id,
                osv_record_ids=finding.osv_record_ids,
                aliases=finding.aliases,
                cve_aliases=finding.cve_aliases,
                ghsa_aliases=finding.ghsa_aliases,
                fixed_versions=finding.fixed_versions,
                cvss=tuple(
                    sorted(
                        (
                            OsvCvssProjection(
                                item.cvss_type,
                                item.vector,
                                item.source,
                                item.base_score,
                                item.scope.value,
                            )
                            for item in finding.cvss
                        ),
                        key=lambda item: json.dumps(item.canonical_data(), sort_keys=True),
                    )
                ),
                affected_match=finding.affected_match,
            ),
            provenance=_osv_provenance(finding),
            component_refs=(component_ref,),
            locations=_locations(finding.locations),
        )
        evidence[group_evidence_id] = group_evidence
        revision_ids = []
        advisory_observations: dict[tuple[str, str], OsvAdvisoryObservation] = {}
        for match in analysis.candidate_matches:
            if match.candidate.package_key == finding.package_key:
                for advisory in match.advisories:
                    advisory_observations[(advisory.osv_record_id, advisory.modified)] = advisory
        for record_id, modified in finding.modified:
            advisory = advisory_observations.get((record_id, modified))
            if advisory is None:
                raise UnifiedEvidenceError
            native_revision = f"{record_id}@{modified}"
            evidence_id = build_evidence_id(
                EvidenceAuthority.OSV,
                OSV_REVISION_EVIDENCE_IDENTITY_SCHEMA,
                native_revision,
            )
            revision = SecureScanEvidence(
                evidence_id=evidence_id,
                authority=EvidenceAuthority.OSV,
                evidence_kind=EvidenceKind.OSV_ADVISORY_REVISION,
                native_identity_schema=OSV_REVISION_EVIDENCE_IDENTITY_SCHEMA,
                native_identity=native_revision,
                payload=OsvAdvisoryRevisionEvidencePayload(
                    osv_record_id=advisory.osv_record_id,
                    modified=advisory.modified,
                    published=advisory.published,
                    aliases=advisory.aliases,
                ),
                provenance=_osv_provenance(finding),
                component_refs=(component_ref,),
                locations=_locations(finding.locations),
            )
            previous = evidence.get(evidence_id)
            if previous is not None:
                if (
                    previous.payload != revision.payload
                    or previous.provenance != revision.provenance
                ):
                    raise UnifiedEvidenceError
                revision = replace(
                    previous,
                    component_refs=tuple(
                        sorted(set(previous.component_refs + revision.component_refs))
                    ),
                    locations=tuple(
                        sorted(
                            set(previous.locations + revision.locations),
                            key=lambda item: json.dumps(item.canonical_data(), sort_keys=True),
                        )
                    ),
                )
            evidence[evidence_id] = revision
            revision_ids.append(evidence_id)
        primary_refs = tuple(sorted((group_evidence_id, *revision_ids)))
        supporting_refs = tuple(
            sorted(
                build_evidence_id(
                    EvidenceAuthority.SYFT,
                    SYFT_EVIDENCE_IDENTITY_SCHEMA,
                    item,
                )
                for item in finding.package_observation_ids
            )
        )
        findings.append(
            SecureScanFinding(
                finding_id=build_finding_id(
                    EvidenceAuthority.OSV,
                    OSV_FINDING_IDENTITY_SCHEMA,
                    finding.finding_id,
                ),
                category=FindingCategory.DEPENDENCY_VULNERABILITY,
                authority=EvidenceAuthority.OSV,
                native_identity_schema=OSV_FINDING_IDENTITY_SCHEMA,
                native_finding_identity=finding.finding_id,
                subject=PackageSubject(component_ref),
                locations=_locations(finding.locations),
                primary_evidence_refs=primary_refs,
                supporting_evidence_refs=supporting_refs,
            )
        )
    gaps = []
    for native_gap in analysis.gaps:
        component_ref = build_component_ref(ComponentKind.PACKAGE, native_gap.package_key)
        native_gap_identity = _identity(
            {
                "locations": native_gap.locations,
                "package_key": native_gap.package_key,
                "package_observation_ids": native_gap.package_observation_ids,
                "reason_code": native_gap.reason_code.value,
            }
        )
        gap_scope = SecureScanGapScope(GapScopeKind.PACKAGE, native_gap.package_key, component_ref)
        gaps.append(
            SecureScanGap(
                gap_id=gap_id(
                    EvidenceAuthority.OSV,
                    OSV_GAP_IDENTITY_SCHEMA,
                    native_gap_identity,
                ),
                authority=EvidenceAuthority.OSV,
                native_identity_schema=OSV_GAP_IDENTITY_SCHEMA,
                native_identity=native_gap_identity,
                code=native_gap.reason_code.value,
                scope=gap_scope,
            )
        )
    paths = tuple(
        sorted(
            {path for candidate in analysis.candidates for path in candidate.locations}
            | {path for gap in analysis.gaps for path in gap.locations}
        )
    )
    selected_scope = _locations(paths) if paths else (RepositoryScopeLocation(),)
    outcome = SecureScanCoverageOutcome(
        coverage_id=coverage_id(
            EvidenceAuthority.OSV,
            "dependency_advisory_matching",
            selected_scope=selected_scope,
        ),
        authority=EvidenceAuthority.OSV,
        capability="dependency_advisory_matching",
        state=(
            CoverageState.PARTIAL
            if gaps
            else CoverageState.COMPLETE_WITH_FINDINGS
            if findings
            else CoverageState.COMPLETE
        ),
        framework=None,
        component_ref=None,
        selected_scope=selected_scope,
        finding_count=len(findings),
        suppression_count=0,
        gap_count=len(gaps),
        reason_code="PACKAGE_GAPS_PRESENT" if gaps else None,
    )
    return SecureScanEvidenceFragment(
        scope=report_scope,
        evidence=tuple(sorted(evidence.values(), key=lambda item: item.evidence_id)),
        findings=tuple(sorted(findings, key=lambda item: item.finding_id)),
        gaps=tuple(sorted(gaps, key=lambda item: item.gap_id)),
        coverage_outcomes=(outcome,),
    )


def adapt_checkov_result(
    result: CheckovParseResult,
    *,
    context: SourceExecutionContext,
    projection: SourceProjectionExecutionReference,
) -> SecureScanEvidenceFragment:
    result = _validated(result, CheckovParseResult)
    context = _validated(context, SourceExecutionContext)
    projection = _validated(projection, SourceProjectionExecutionReference)
    _validate_context_projection(
        context,
        projection,
        source_analyzer_id=CHECKOV_SOURCE_ANALYZER_ID,
        capability=AnalysisCapability.CONFIGURATION_SECURITY,
        binding_digest=result.binding_digest,
        projection_id=result.projection_id,
        projection_digest=result.snapshot_digest,
    )
    provenance = _scanner_provenance(
        scanner_id=result.scanner_id,
        scanner_version=result.scanner_version,
        binding_digest=result.binding_digest,
        projection_id=result.projection_id,
        context_digest=context.context_digest(),
        projection_digest=result.snapshot_digest,
    )
    evidence = []
    findings = []
    for observation, finding in zip(result.observations, result.findings, strict=True):
        if finding.finding_id != observation.observation_id:
            raise UnifiedEvidenceError
        locations: tuple[SecureScanLocation, ...] = (
            (RepositoryPathLocation(finding.normalized_path),)
            if finding.line_start is None
            else (
                SourceSpanLocation(
                    finding.normalized_path,
                    finding.line_start,
                    finding.line_end or 0,
                ),
            )
        )
        evidence_id = build_evidence_id(
            EvidenceAuthority.CHECKOV,
            CHECKOV_NATIVE_IDENTITY_SCHEMA,
            observation.observation_id,
        )
        evidence.append(
            SecureScanEvidence(
                evidence_id=evidence_id,
                authority=EvidenceAuthority.CHECKOV,
                evidence_kind=EvidenceKind.CHECKOV_POLICY_OBSERVATION,
                native_identity_schema=CHECKOV_NATIVE_IDENTITY_SCHEMA,
                native_identity=observation.observation_id,
                payload=CheckovEvidencePayload(
                    observation_id=observation.observation_id,
                    framework=observation.framework,
                    check_id=observation.check_id,
                    check_name=observation.check_name,
                    resource=observation.resource,
                    result=observation.result,
                ),
                provenance=provenance,
                locations=locations,
            )
        )
        findings.append(
            SecureScanFinding(
                finding_id=build_finding_id(
                    EvidenceAuthority.CHECKOV,
                    CHECKOV_NATIVE_IDENTITY_SCHEMA,
                    finding.finding_id,
                ),
                category=FindingCategory.CONFIGURATION_SECURITY,
                authority=EvidenceAuthority.CHECKOV,
                native_identity_schema=CHECKOV_NATIVE_IDENTITY_SCHEMA,
                native_finding_identity=finding.finding_id,
                subject=ConfigurationResourceSubject(finding.framework, finding.resource),
                locations=locations,
                primary_evidence_refs=(evidence_id,),
                severity=(
                    None
                    if finding.severity is None
                    else SeverityProjection(
                        finding.severity,
                        SeverityScheme.CHECKOV,
                        EvidenceAuthority.CHECKOV,
                    )
                ),
            )
        )
    suppressions = []
    for item in result.suppressions:
        native_identity = _identity(
            [item.framework, item.check_id, item.normalized_path, item.resource]
        )
        suppressions.append(
            SecureScanSuppression(
                suppression_id=suppression_id(
                    EvidenceAuthority.CHECKOV,
                    CHECKOV_SUPPRESSION_IDENTITY_SCHEMA,
                    native_identity,
                ),
                authority=EvidenceAuthority.CHECKOV,
                native_identity_schema=CHECKOV_SUPPRESSION_IDENTITY_SCHEMA,
                native_identity=native_identity,
                subject=ConfigurationResourceSubject(item.framework, item.resource),
                locations=(RepositoryPathLocation(item.normalized_path),),
                payload=CheckovSuppressionPayload(
                    item.framework,
                    item.check_id,
                    item.resource,
                    item.reason,
                ),
                provenance=provenance,
            )
        )
    gaps = []
    for item in result.gaps:
        native_gap_identity = _identity(item.canonical_data())
        scope = SecureScanGapScope(
            GapScopeKind.PATH,
            item.normalized_path,
            _repository_component_ref(context),
            framework=item.framework,
        )
        gaps.append(
            SecureScanGap(
                gap_id=gap_id(
                    EvidenceAuthority.CHECKOV,
                    CHECKOV_GAP_IDENTITY_SCHEMA,
                    native_gap_identity,
                ),
                authority=EvidenceAuthority.CHECKOV,
                native_identity_schema=CHECKOV_GAP_IDENTITY_SCHEMA,
                native_identity=native_gap_identity,
                code=item.code,
                scope=scope,
                message="Checkov could not parse part of the selected framework scope",
            )
        )
    outcomes = []
    state_map = {
        CheckovFrameworkState.COMPLETED: CoverageState.COMPLETE,
        CheckovFrameworkState.COMPLETED_WITH_FINDINGS: (CoverageState.COMPLETE_WITH_FINDINGS),
        CheckovFrameworkState.COMPLETED_WITH_SUPPRESSIONS: (
            CoverageState.COMPLETE_WITH_SUPPRESSIONS
        ),
        CheckovFrameworkState.NOT_APPLICABLE: CoverageState.NOT_APPLICABLE,
        CheckovFrameworkState.INCOMPLETE_PARSE_GAP: CoverageState.PARTIAL,
    }
    for item in result.framework_outcomes:
        selected_scope = _locations(
            tuple(selected.relative_path for selected in context.selected_files)
        )
        component_ref = _repository_component_ref(context)
        outcomes.append(
            SecureScanCoverageOutcome(
                coverage_id=coverage_id(
                    EvidenceAuthority.CHECKOV,
                    "configuration_security",
                    item.framework,
                    component_ref,
                    selected_scope,
                ),
                authority=EvidenceAuthority.CHECKOV,
                capability="configuration_security",
                framework=item.framework,
                component_ref=component_ref,
                state=state_map[item.state],
                selected_scope=selected_scope,
                finding_count=item.failed_count,
                suppression_count=item.suppressed_count,
                gap_count=item.parsing_gap_count,
                reason_code=("CHECKOV_PARSE_GAP" if item.parsing_gap_count else None),
            )
        )
    return SecureScanEvidenceFragment(
        scope=_scope(context),
        evidence=tuple(sorted(evidence, key=lambda item: item.evidence_id)),
        findings=tuple(sorted(findings, key=lambda item: item.finding_id)),
        suppressions=tuple(sorted(suppressions, key=lambda item: item.suppression_id)),
        gaps=tuple(sorted(gaps, key=lambda item: item.gap_id)),
        coverage_outcomes=tuple(sorted(outcomes, key=lambda item: item.coverage_id)),
    )
