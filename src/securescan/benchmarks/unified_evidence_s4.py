from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from securescan.adapters.sandbox_policy import (
    SandboxExecutionBackend,
    SandboxExecutionPolicy,
)
from securescan.adapters.trusted_registry import TrustedAdapterDefinition
from securescan.advisories.osv import (
    OsvAdvisoryReference,
    OsvCandidateMatch,
    OsvDependencyAnalysis,
    build_osv_query_candidates,
    group_advisories,
    parse_advisory_response,
)
from securescan.advisories.osv import (
    canonical_json as osv_canonical_json,
)
from securescan.benchmarks.osv_s2 import build_controlled_candidates
from securescan.domain.enums import (
    ArtifactKind,
    ExecutionOutcome,
    JobStatus,
    ObservationType,
    RunStatus,
)
from securescan.domain.models import ArtifactRecord, ToolExecutionRecord
from securescan.evidence import (
    SecureScanReportScope,
    adapt_checkov_result,
    adapt_gitleaks_result,
    adapt_osv_analysis,
    adapt_semgrep_assessment,
    adapt_syft_result,
    build_report,
)
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
    TrustedSemgrepSourceBinding,
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

CONTROLLED_SCHEMA_VERSION = "securescan-unified-evidence-controlled-s4-v1"
CONTROLLED_REPORT_PATH = Path("benchmarks/unified_evidence/controlled-s4-report.json")
CONTROLLED_REPORT_SHA256 = "3eeae75911f2794740763fc448ce8089e6a9ddc1e80b734b5308bf7c31a621df"
_RUN_ID = "00000000-0000-4000-8000-00000000a401"
_JOB_ID = "00000000-0000-4000-8000-00000000a403"
_EXECUTION_ID = "00000000-0000-4000-8000-00000000a404"
_ARTIFACT_ID = "00000000-0000-4000-8000-00000000a405"
_SEMGREP_ARTIFACT_BYTES = b'{"schema_version":"controlled-sanitized-semgrep-v1"}\n'
_REPOSITORY_DIGEST = "a" * 64
_PROFILE_DIGEST = "b" * 64
_PLAN_DIGEST = "c" * 64
_PROJECTION_DIGEST = "d" * 64
_PROJECTION_ID = "securescan-source-projection-" + "4" * 32
_FROZEN_INPUTS = (
    (
        "semgrep-ce",
        Path("benchmarks/python_sast/initial-v0.3e-baseline.json"),
        "6784c114aab842ebabd181bd8a749949bd04b1f534f40115599eec7e8173b814",
    ),
    (
        "gitleaks",
        Path("benchmarks/gitleaks/realworld/realworld-result-v1.json"),
        "33062f73834e348492349ce00b509f478ed5509b4b1b40183eba034be3a74313",
    ),
    (
        "syft",
        Path("benchmarks/syft/controlled-s1-evidence.json"),
        "ec1dad7520c99cae66cdfb0de0100fc895576356ad917da30dcceba805ed2bc4",
    ),
    (
        "osv.dev",
        Path("benchmarks/osv/controlled-evaluation-v1.json"),
        "d86b97fd1cb732afe5bcb7947e47353553eb0e877217832ce4b2cecec1d70ef2",
    ),
    (
        "checkov",
        Path("benchmarks/checkov/controlled-evaluation-v1.json"),
        "5f30ca5511c1aa12c408d5d323d9922f8a69abfbe7babf5fcaac170bbf8dc4ad",
    ),
)


class UnifiedEvidenceBenchmarkError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Controlled S4 unified evidence replay failed")


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        + b"\n"
    )


def _scope() -> SecureScanReportScope:
    return SecureScanReportScope(
        _RUN_ID,
        _REPOSITORY_DIGEST,
        _PROFILE_DIGEST,
        _PLAN_DIGEST,
    )


def _context(
    capability: AnalysisCapability,
    analyzer_id: str,
    binding_digest: str,
    paths: tuple[str, ...],
) -> SourceExecutionContext:
    selected = tuple(
        SourceExecutionSelectedFile(
            RepositoryManifestEntry(
                path,
                1,
                hashlib.sha256(path.encode()).hexdigest(),
            ),
            None,
        )
        for path in sorted(paths)
    )
    adapter_id = (
        "semgrep-ce" if analyzer_id == "semgrep-source-v1" else analyzer_id.split("-source-v1")[0]
    )
    return SourceExecutionContext(
        source_run_id=_RUN_ID,
        job_id=_JOB_ID,
        repository_digest=_REPOSITORY_DIGEST,
        profile_digest=_PROFILE_DIGEST,
        plan_digest=_PLAN_DIGEST,
        source_analyzer_id=analyzer_id,
        capability=capability,
        component_id=None,
        selected_files=selected,
        binding_digest=binding_digest,
        core_adapter_id=adapter_id,
    )


def _projection(
    context: SourceExecutionContext,
    *,
    projection_id: str = _PROJECTION_ID,
    projection_digest: str = _PROJECTION_DIGEST,
) -> SourceProjectionExecutionReference:
    return SourceProjectionExecutionReference(
        projection_id,
        context.context_digest(),
        projection_digest,
    )


def _semgrep_fragment():
    definition = TrustedAdapterDefinition(
        adapter_id="semgrep-ce",
        display_name="Semgrep Community Edition",
        tool_name="semgrep",
        tool_version=DECLARED_SEMGREP_TOOL_VERSION,
        backend=SandboxExecutionBackend.DOCKER_SANDBOX,
        policy=SandboxExecutionPolicy(allowed_environment_names=("HOME",)),
        factory=lambda: object(),
        image_reference="registry.example/securescan/semgrep@sha256:" + "4" * 64,
        command_prefix=("semgrep",),
    )
    binding = TrustedSemgrepSourceBinding(
        definition=definition,
        ruleset=load_source_ruleset(),
    )
    context = _context(
        AnalysisCapability.SOURCE_SAST,
        binding.source_analyzer_id,
        binding.binding_digest(),
        ("src/app.py",),
    )
    fingerprint = hashlib.sha256(
        "\x1f".join(
            (
                "semgrep-ce",
                "securescan.python.dangerous-eval",
                "src/app.py",
                "7",
                "1",
                "7",
                "12",
            )
        ).encode()
    ).hexdigest()
    observation = SourceSecurityObservation(
        observation_id=str(UUID(fingerprint[:32])),
        producer="semgrep-ce",
        observation_type=ObservationType.SOURCE_RULE_MATCH,
        rule_id="securescan.python.dangerous-eval",
        message="Semgrep matched a trusted SecureScan rule",
        native_severity="high",
        relative_path="src/app.py",
        start_line=7,
        start_column=1,
        end_line=7,
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
        component_id=None,
        binding_digest=context.binding_digest,
        core_adapter_id=context.core_adapter_id,
        execution_status=SourceExecutionStatus.COMPLETE,
        coverage_status=CoverageStatus.FULL_FOR_DECLARED_SCOPE,
        assessment_status=AssessmentStatus.OBSERVATIONS_ONLY,
        declared_paths=("src/app.py",),
        declared_file_count=1,
        declared_total_bytes=1,
        observations=(observation,),
        gaps=(),
        attempt_count=1,
        terminal_job_status=JobStatus.SUCCEEDED,
        final_tool_execution_id=_EXECUTION_ID,
        tool_version=DECLARED_SEMGREP_TOOL_VERSION,
    )
    artifact_digest = hashlib.sha256(_SEMGREP_ARTIFACT_BYTES).hexdigest()
    timestamp = datetime(2026, 1, 1, tzinfo=UTC)
    tool_execution = ToolExecutionRecord(
        execution_id=UUID(_EXECUTION_ID),
        run_id=UUID(_RUN_ID),
        adapter_id="semgrep-ce",
        tool_version=DECLARED_SEMGREP_TOOL_VERSION,
        adapter_version="1.0.0",
        status=RunStatus.COMPLETED,
        outcome=ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS,
        exit_code=0,
        started_at=timestamp,
        finished_at=timestamp,
        duration_ms=0,
        artifacts=[
            ArtifactRecord(
                artifact_id=UUID(_ARTIFACT_ID),
                kind=ArtifactKind.SANITIZED_NATIVE_REPORT,
                sha256=artifact_digest,
                size_bytes=len(_SEMGREP_ARTIFACT_BYTES),
                media_type="application/json",
                storage_path=(f"sha256/{artifact_digest[:2]}/{artifact_digest}"),
                sanitized=True,
                created_at=timestamp,
            )
        ],
    )
    return adapt_semgrep_assessment(
        assessment,
        context=context,
        projection=_projection(context),
        binding=binding,
        tool_execution=tool_execution,
        sanitized_artifact_bytes=_SEMGREP_ARTIFACT_BYTES,
    )


def _gitleaks_fragment():
    binding_digest = "e" * 64
    context = _context(
        AnalysisCapability.SECRET_DETECTION,
        GITLEAKS_SOURCE_ANALYZER_ID,
        binding_digest,
        ("docs/config.rst",),
    )
    finding = NormalizedGitleaksFinding(
        GITLEAKS_SCANNER_ID,
        GITLEAKS_VERSION,
        "generic-api-key",
        "docs/config.rst",
        GitleaksDetectionKind.CONTENT,
        41,
        41,
        10,
        86,
        _PROJECTION_ID,
        context.context_digest(),
        _PROJECTION_DIGEST,
    )
    result = GitleaksParseResult(
        GITLEAKS_SCANNER_ID,
        GITLEAKS_VERSION,
        binding_digest,
        _PROJECTION_ID,
        context.context_digest(),
        _PROJECTION_DIGEST,
        (finding,),
        1,
    )
    fragment = adapt_gitleaks_result(
        result,
        context=context,
        projection=_projection(context),
    )
    if (
        fragment.findings[0].native_finding_identity
        != "f347c22cbab714e0bf0a7e51cc9c62c90e5c0d1f4c477c43314c627df9e82409"
    ):
        raise UnifiedEvidenceBenchmarkError
    return fragment


def _syft_and_osv_fragments(repository_root: Path):
    candidate = next(
        item for item in build_controlled_candidates() if item.purl == "pkg:pypi/pyyaml@5.3.1"
    )
    package = PackageObservation.create(
        package_name=candidate.package_name,
        package_version=candidate.package_version,
        package_type=candidate.package_type,
        language="python",
        purl=candidate.purl,
        found_by="securescan-s2-controlled-plan",
        locations=candidate.locations,
        projection_id=candidate.projection_id,
        snapshot_digest=candidate.snapshot_digest,
        binding_digest=candidate.syft_binding_digest,
    )
    if (
        package.package_key != candidate.package_key
        or package.package_observation_id != candidate.package_observation_ids[0]
    ):
        raise UnifiedEvidenceBenchmarkError
    context = _context(
        AnalysisCapability.PACKAGE_INVENTORY,
        SYFT_SOURCE_ANALYZER_ID,
        candidate.syft_binding_digest,
        candidate.locations,
    )
    result = SyftParseResult(
        "syft",
        SYFT_VERSION,
        candidate.syft_binding_digest,
        candidate.projection_id,
        candidate.snapshot_digest,
        SYFT_JSON_SCHEMA_VERSION,
        ("directory", "file"),
        ("securescan-s2-controlled-plan",),
        (package,),
        1,
    )
    syft = adapt_syft_result(
        result,
        context=context,
        projection=_projection(
            context,
            projection_id=candidate.projection_id,
            projection_digest=candidate.snapshot_digest,
        ),
    )
    built_candidates, gaps = build_osv_query_candidates((package,))
    if gaps or built_candidates != (candidate,):
        raise UnifiedEvidenceBenchmarkError
    snapshot = json.loads(
        (repository_root / "benchmarks/osv/controlled-service-snapshot-v1.json").read_bytes()
    )
    exchange = next(
        item
        for item in snapshot["exchanges"]
        if item["method"] == "GET" and item["response"]["id"] == "GHSA-8q59-q68h-6hv4"
    )
    reference = OsvAdvisoryReference(exchange["response"]["id"], exchange["response"]["modified"])
    advisory = parse_advisory_response(
        osv_canonical_json(exchange["response"]),
        expected=reference,
        candidate=candidate,
    )
    match = OsvCandidateMatch(candidate, (reference,), (advisory,))
    findings = group_advisories(candidate, (advisory,))
    analysis = OsvDependencyAnalysis(
        candidates=(candidate,),
        gaps=(),
        candidate_matches=(match,),
        findings=findings,
        completed_candidate_ids=(candidate.candidate_id,),
        zero_advisory_candidate_ids=(),
    )
    return syft, adapt_osv_analysis(analysis, scope=_scope())


def _checkov_fragment():
    binding_digest = "9" * 64
    paths = ("main.tf", "malformed.tf", "suppressed.tf")
    context = _context(
        AnalysisCapability.CONFIGURATION_SECURITY,
        CHECKOV_SOURCE_ANALYZER_ID,
        binding_digest,
        paths,
    )
    root = Path("/tmp") / _PROJECTION_ID / "source"

    def record(result: str, path: str, resource: str) -> dict[str, object]:
        check_result: dict[str, object] = {"result": result}
        if result == "SKIPPED":
            check_result["suppress_comment"] = "controlled accepted risk"
        return {
            "check_id": "CKV_AWS_18",
            "check_name": "Controlled logging check",
            "resource": resource,
            "file_path": f"/{path}",
            "file_line_range": [1, 3],
            "check_result": check_result,
            "severity": "HIGH" if result == "FAILED" else None,
        }

    document = {
        "check_type": "terraform",
        "results": {
            "failed_checks": [record("FAILED", "main.tf", "aws_s3_bucket.controlled")],
            "passed_checks": [],
            "skipped_checks": [record("SKIPPED", "suppressed.tf", "aws_s3_bucket.accepted")],
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
        json.dumps(document).encode(),
        projection_root=root,
        authorized_paths=frozenset(paths),
        projection_id=_PROJECTION_ID,
        snapshot_digest=_PROJECTION_DIGEST,
        binding_digest=binding_digest,
    )
    return adapt_checkov_result(
        result,
        context=context,
        projection=_projection(context),
    )


def _frozen_inputs(repository_root: Path) -> list[dict[str, str]]:
    values = []
    for authority, relative_path, expected_digest in _FROZEN_INPUTS:
        path = repository_root / relative_path
        try:
            payload = path.read_bytes()
        except OSError:
            raise UnifiedEvidenceBenchmarkError from None
        if hashlib.sha256(payload).hexdigest() != expected_digest:
            raise UnifiedEvidenceBenchmarkError
        values.append(
            {
                "authority": authority,
                "path": relative_path.as_posix(),
                "sha256": expected_digest,
            }
        )
    return values


def build_controlled_unified_report(repository_root: Path):
    if not isinstance(repository_root, Path) or not repository_root.is_absolute():
        raise UnifiedEvidenceBenchmarkError
    _frozen_inputs(repository_root)
    syft, osv = _syft_and_osv_fragments(repository_root)
    return build_report(
        _scope(),
        _semgrep_fragment(),
        _gitleaks_fragment(),
        syft,
        osv,
        _checkov_fragment(),
    )


def build_controlled_artifact(repository_root: Path) -> bytes:
    report = build_controlled_unified_report(repository_root)
    report_payload = report.canonical_json()
    return _canonical_json(
        {
            "frozen_evidence_anchors": _frozen_inputs(repository_root),
            "report": report.canonical_data(),
            "report_sha256": hashlib.sha256(report_payload).hexdigest(),
            "schema_version": CONTROLLED_SCHEMA_VERSION,
        }
    )


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1 or arguments[0] not in {"check", "report", "record"}:
        raise UnifiedEvidenceBenchmarkError
    root = Path(__file__).resolve().parents[3]
    payload = build_controlled_artifact(root)
    path = root / CONTROLLED_REPORT_PATH
    if arguments[0] == "record":
        if os.path.lexists(path):
            raise UnifiedEvidenceBenchmarkError
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    elif arguments[0] == "check":
        try:
            recorded = path.read_bytes()
        except OSError:
            raise UnifiedEvidenceBenchmarkError from None
        if recorded != payload or hashlib.sha256(recorded).hexdigest() != CONTROLLED_REPORT_SHA256:
            raise UnifiedEvidenceBenchmarkError
    else:
        sys.stdout.buffer.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
