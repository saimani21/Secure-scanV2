from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from securescan.adapters.sandbox_policy import (
    SandboxExecutionBackend,
    SandboxExecutionPolicy,
)
from securescan.adapters.trusted_registry import TrustedAdapterDefinition
from securescan.advisories.osv import (
    OsvAdvisoryObservation,
    OsvAdvisoryReference,
    OsvCandidateMatch,
    OsvDependencyAnalysis,
    build_osv_query_candidates,
    group_advisories,
)
from securescan.domain.enums import (
    ArtifactKind,
    ExecutionOutcome,
    JobStatus,
    ObservationType,
    RunStatus,
)
from securescan.domain.models import ArtifactRecord, ToolExecutionRecord
from securescan.scanners.checkov import (
    CHECKOV_SOURCE_ANALYZER_ID,
    parse_checkov_json,
)
from securescan.scanners.gitleaks import (
    GITLEAKS_SCANNER_ID,
    GITLEAKS_SOURCE_ANALYZER_ID,
    GITLEAKS_VERSION,
    GitleaksDetectionKind,
    GitleaksParseResult,
    NormalizedGitleaksFinding,
)
from securescan.scanners.semgrep import (
    DECLARED_SEMGREP_TOOL_VERSION,
    PRODUCTION_SEMGREP_IMAGE_REFERENCE,
    TrustedSemgrepSourceBinding,
    create_production_semgrep_source_binding,
    load_source_ruleset,
)
from securescan.scanners.semgrep.source_execution import SourceProjectionExecutionReference
from securescan.scanners.syft import (
    SYFT_JSON_SCHEMA_VERSION,
    SYFT_SOURCE_ANALYZER_ID,
    SYFT_VERSION,
    PackageObservation,
    SyftParseResult,
)
from securescan.source import (
    AnalysisCapability,
    AssessmentStatus,
    CoverageStatus,
    SourceCapabilityExecutionAssessment,
    SourceExecutionContext,
    SourceExecutionSelectedFile,
    SourceExecutionStatus,
    SourceSecurityObservation,
)
from securescan.workspaces.models import RepositoryManifestEntry

RUN_ID = "00000000-0000-4000-8000-00000000a401"
SECOND_RUN_ID = "00000000-0000-4000-8000-00000000a402"
JOB_ID = "00000000-0000-4000-8000-00000000a403"
TOOL_EXECUTION_ID = "00000000-0000-4000-8000-00000000a404"
REPOSITORY_DIGEST = "a" * 64
PROFILE_DIGEST = "b" * 64
PLAN_DIGEST = "c" * 64
PROJECTION_DIGEST = "d" * 64
PROJECTION_ID = "securescan-source-projection-" + "4" * 32
SEMGREP_ARTIFACT_BYTES = b'{"schema_version":"controlled-sanitized-semgrep-v1"}\n'
SEMGREP_ARTIFACT_ID = "00000000-0000-4000-8000-00000000a405"


def semgrep_binding(*, production: bool = False) -> TrustedSemgrepSourceBinding:
    definition = TrustedAdapterDefinition(
        adapter_id="semgrep-ce",
        display_name="Semgrep Community Edition",
        tool_name="semgrep",
        tool_version=DECLARED_SEMGREP_TOOL_VERSION,
        backend=SandboxExecutionBackend.DOCKER_SANDBOX,
        policy=SandboxExecutionPolicy(allowed_environment_names=("HOME",)),
        factory=lambda: object(),
        image_reference=(
            PRODUCTION_SEMGREP_IMAGE_REFERENCE
            if production
            else "registry.example/securescan/semgrep@sha256:" + "4" * 64
        ),
        command_prefix=("semgrep",),
    )
    factory = (
        create_production_semgrep_source_binding if production else TrustedSemgrepSourceBinding
    )
    return factory(definition=definition, ruleset=load_source_ruleset())


def source_context(
    *,
    capability: AnalysisCapability,
    source_analyzer_id: str,
    binding_digest: str,
    paths: tuple[str, ...],
    source_run_id: str = RUN_ID,
    component_id: str | None = None,
) -> SourceExecutionContext:
    selected = tuple(
        SourceExecutionSelectedFile(
            RepositoryManifestEntry(
                relative_path=path,
                size_bytes=1,
                sha256=hashlib.sha256(path.encode()).hexdigest(),
            ),
            component_id,
        )
        for path in sorted(paths)
    )
    return SourceExecutionContext(
        source_run_id=source_run_id,
        job_id=JOB_ID,
        repository_digest=REPOSITORY_DIGEST,
        profile_digest=PROFILE_DIGEST,
        plan_digest=PLAN_DIGEST,
        source_analyzer_id=source_analyzer_id,
        capability=capability,
        component_id=component_id,
        selected_files=selected,
        binding_digest=binding_digest,
        core_adapter_id=(
            "semgrep-ce"
            if source_analyzer_id == "semgrep-source-v1"
            else source_analyzer_id.split("-source-v1")[0]
        ),
    )


def projection(context: SourceExecutionContext) -> SourceProjectionExecutionReference:
    return SourceProjectionExecutionReference(
        projection_id=PROJECTION_ID,
        context_digest=context.context_digest(),
        projection_digest=PROJECTION_DIGEST,
    )


def semgrep_native(
    *,
    source_run_id: str = RUN_ID,
    line: int = 7,
    rule_id: str = "securescan.python.dangerous-eval",
    message: str = "Semgrep matched a trusted SecureScan rule",
    severity: str = "high",
    path: str = "src/app.py",
    component_id: str | None = None,
    binding: TrustedSemgrepSourceBinding | None = None,
) -> tuple[
    SourceCapabilityExecutionAssessment,
    SourceExecutionContext,
    SourceProjectionExecutionReference,
    TrustedSemgrepSourceBinding,
]:
    binding = binding or semgrep_binding()
    context = source_context(
        capability=AnalysisCapability.SOURCE_SAST,
        source_analyzer_id=binding.source_analyzer_id,
        binding_digest=binding.binding_digest(),
        paths=(path,),
        source_run_id=source_run_id,
        component_id=component_id,
    )
    fingerprint = hashlib.sha256(
        "\x1f".join(
            (
                "semgrep-ce",
                rule_id,
                path,
                str(line),
                "1",
                str(line),
                "12",
            )
        ).encode()
    ).hexdigest()
    observation = SourceSecurityObservation(
        observation_id=str(UUID(fingerprint[:32])),
        producer="semgrep-ce",
        observation_type=ObservationType.SOURCE_RULE_MATCH,
        rule_id=rule_id,
        message=message,
        native_severity=severity,
        relative_path=path,
        start_line=line,
        start_column=1,
        end_line=line,
        end_column=12,
        cwe_ids=("CWE-95",),
        fingerprint=fingerprint,
    )
    assessment = SourceCapabilityExecutionAssessment(
        source_run_id=context.source_run_id,
        job_id=context.job_id,
        repository_digest=context.repository_digest,
        profile_digest=context.profile_digest,
        plan_digest=context.plan_digest,
        source_analyzer_id=context.source_analyzer_id,
        capability=context.capability,
        component_id=component_id,
        binding_digest=context.binding_digest,
        core_adapter_id=context.core_adapter_id,
        execution_status=SourceExecutionStatus.COMPLETE,
        coverage_status=CoverageStatus.FULL_FOR_DECLARED_SCOPE,
        assessment_status=AssessmentStatus.OBSERVATIONS_ONLY,
        declared_paths=(path,),
        declared_file_count=1,
        declared_total_bytes=1,
        observations=(observation,),
        gaps=(),
        attempt_count=1,
        terminal_job_status=JobStatus.SUCCEEDED,
        final_tool_execution_id=TOOL_EXECUTION_ID,
        tool_version=DECLARED_SEMGREP_TOOL_VERSION,
    )
    return assessment, context, projection(context), binding


def semgrep_tool_execution(
    assessment: SourceCapabilityExecutionAssessment,
    *,
    artifact_bytes: bytes = SEMGREP_ARTIFACT_BYTES,
) -> ToolExecutionRecord:
    digest = hashlib.sha256(artifact_bytes).hexdigest()
    timestamp = datetime(2026, 1, 1, tzinfo=UTC)
    return ToolExecutionRecord(
        execution_id=UUID(assessment.final_tool_execution_id or ""),
        run_id=UUID(assessment.source_run_id),
        adapter_id="semgrep-ce",
        tool_version=assessment.tool_version or "",
        adapter_version="1.0.0",
        status=RunStatus.COMPLETED,
        outcome=ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS,
        exit_code=0,
        started_at=timestamp,
        finished_at=timestamp,
        duration_ms=0,
        artifacts=[
            ArtifactRecord(
                artifact_id=UUID(SEMGREP_ARTIFACT_ID),
                kind=ArtifactKind.SANITIZED_NATIVE_REPORT,
                sha256=digest,
                size_bytes=len(artifact_bytes),
                media_type="application/json",
                storage_path=f"sha256/{digest[:2]}/{digest}",
                sanitized=True,
                created_at=timestamp,
            )
        ],
    )


def gitleaks_native(
    *, source_run_id: str = RUN_ID, line: int = 3
) -> tuple[GitleaksParseResult, SourceExecutionContext, SourceProjectionExecutionReference]:
    binding_digest = "e" * 64
    context = source_context(
        capability=AnalysisCapability.SECRET_DETECTION,
        source_analyzer_id=GITLEAKS_SOURCE_ANALYZER_ID,
        binding_digest=binding_digest,
        paths=("config/credential.txt",),
        source_run_id=source_run_id,
    )
    finding = NormalizedGitleaksFinding(
        scanner_id=GITLEAKS_SCANNER_ID,
        scanner_version=GITLEAKS_VERSION,
        rule_id="github-pat",
        file_path="config/credential.txt",
        detection_kind=GitleaksDetectionKind.CONTENT,
        start_line=line,
        end_line=line,
        start_column=1,
        end_column=40,
        projection_id=PROJECTION_ID,
        context_digest=context.context_digest(),
        projection_digest=PROJECTION_DIGEST,
    )
    result = GitleaksParseResult(
        scanner_id=GITLEAKS_SCANNER_ID,
        scanner_version=GITLEAKS_VERSION,
        binding_digest=binding_digest,
        projection_id=PROJECTION_ID,
        context_digest=context.context_digest(),
        projection_digest=PROJECTION_DIGEST,
        findings=(finding,),
        finding_count=1,
    )
    return result, context, projection(context)


def syft_native(
    *,
    source_run_id: str = RUN_ID,
    version: str | None = "2.31.0",
    locations: tuple[str, ...] = ("requirements.txt",),
) -> tuple[SyftParseResult, SourceExecutionContext, SourceProjectionExecutionReference]:
    binding_digest = "f" * 64
    context = source_context(
        capability=AnalysisCapability.PACKAGE_INVENTORY,
        source_analyzer_id=SYFT_SOURCE_ANALYZER_ID,
        binding_digest=binding_digest,
        paths=locations,
        source_run_id=source_run_id,
    )
    observation = PackageObservation.create(
        package_name="requests",
        package_version=version,
        package_type="python",
        language="python",
        purl=None if version is None else f"pkg:pypi/requests@{version}",
        found_by="python-package-cataloger",
        locations=locations,
        projection_id=PROJECTION_ID,
        snapshot_digest=PROJECTION_DIGEST,
        binding_digest=binding_digest,
    )
    result = SyftParseResult(
        scanner_id="syft",
        scanner_version=SYFT_VERSION,
        binding_digest=binding_digest,
        projection_id=PROJECTION_ID,
        snapshot_digest=PROJECTION_DIGEST,
        syft_schema_version=SYFT_JSON_SCHEMA_VERSION,
        requested_cataloger_strategy=("directory", "file"),
        used_catalogers=("python-package-cataloger",),
        observations=(observation,),
        package_count=1,
    )
    return result, context, projection(context)


def osv_native(
    syft_result: SyftParseResult,
    *,
    alias: str = "CVE-2025-12345",
) -> OsvDependencyAnalysis:
    candidates, gaps = build_osv_query_candidates(syft_result.observations)
    assert not gaps
    candidate = candidates[0]
    advisory = OsvAdvisoryObservation(
        osv_record_id="GHSA-9wx4-h78v-vm56",
        modified="2026-01-02T03:04:05Z",
        published="2025-01-02T03:04:05Z",
        aliases=(alias,),
        cve_aliases=(alias,) if alias.startswith("CVE-") else (),
        ghsa_aliases=("GHSA-9wx4-h78v-vm56",),
        summary="Controlled advisory revision",
        applicable_package_key=candidate.package_key,
        fixed_versions=("2.32.0",),
        cvss=(),
    )
    reference = OsvAdvisoryReference(advisory.osv_record_id, advisory.modified)
    match = OsvCandidateMatch(candidate, (reference,), (advisory,))
    findings = group_advisories(candidate, (advisory,))
    return OsvDependencyAnalysis(
        candidates=(candidate,),
        gaps=(),
        candidate_matches=(match,),
        findings=findings,
        completed_candidate_ids=(candidate.candidate_id,),
        zero_advisory_candidate_ids=(),
    )


def checkov_native(
    *,
    source_run_id: str = RUN_ID,
    line_start: int = 1,
    check_name: str = "Controlled logging check",
    severity: str | None = "HIGH",
) -> tuple[object, SourceExecutionContext, SourceProjectionExecutionReference]:
    binding_digest = "9" * 64
    paths = ("main.tf", "malformed.tf", "suppressed.tf")
    context = source_context(
        capability=AnalysisCapability.CONFIGURATION_SECURITY,
        source_analyzer_id=CHECKOV_SOURCE_ANALYZER_ID,
        binding_digest=binding_digest,
        paths=paths,
        source_run_id=source_run_id,
    )
    root = Path("/tmp") / PROJECTION_ID / "source"
    raw = {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_18",
                    "check_name": check_name,
                    "resource": "aws_s3_bucket.controlled",
                    "file_path": "/main.tf",
                    "file_line_range": [line_start, line_start + 2],
                    "check_result": {
                        "result": "FAILED",
                        "evaluations": {"RAW_SECRET": "must-not-persist"},
                    },
                    "severity": severity,
                    "code_block": [[line_start, "RAW_SECRET"]],
                    "connected_node": {"RAW_SECRET": "must-not-persist"},
                    "evaluations": {"RAW_SECRET": "must-not-persist"},
                }
            ],
            "passed_checks": [],
            "skipped_checks": [
                {
                    "check_id": "CKV_AWS_18",
                    "check_name": "Controlled logging check",
                    "resource": "aws_s3_bucket.accepted",
                    "file_path": "/suppressed.tf",
                    "file_line_range": [1, 2],
                    "check_result": {
                        "result": "SKIPPED",
                        "suppress_comment": "controlled accepted risk",
                    },
                    "severity": None,
                }
            ],
            "parsing_errors": [str(root / "malformed.tf")],
        },
        "summary": {
            "passed": 0,
            "failed": 1,
            "skipped": 1,
            "parsing_errors": 1,
            "resource_count": 2,
            "checkov_version": "3.3.16",
        },
        "url": "Controlled offline fixture",
    }
    result = parse_checkov_json(
        json.dumps(raw).encode(),
        projection_root=root,
        authorized_paths=frozenset(paths),
        projection_id=PROJECTION_ID,
        snapshot_digest=PROJECTION_DIGEST,
        binding_digest=binding_digest,
    )
    return result, context, projection(context)
