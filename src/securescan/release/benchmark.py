from __future__ import annotations

import hashlib
import json
import stat
import tempfile
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import uuid4

from securescan import __version__
from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import ArtifactKind, JobStatus
from securescan.execution.docker_sandbox import DockerSandboxExecutor
from securescan.jobs.models import JobRecord
from securescan.release.models import (
    BenchmarkCaseResult,
    BenchmarkExpectation,
    BenchmarkMetrics,
    BenchmarkObservation,
    CoreReleaseEvaluation,
)
from securescan.release.report import release_evidence_digest
from securescan.scanners.semgrep.factory import create_semgrep_trusted_definition
from securescan.scanners.semgrep.ruleset import load_baseline_ruleset
from securescan.scanners.semgrep.source_binding import DECLARED_SEMGREP_TOOL_VERSION
from securescan.worker.models import WorkerSuccessfulExecution
from securescan.workspaces.intake import RepositoryWorkspaceManager

CORE_RELEASE_VERSION = __version__
CORE_BENCHMARK_ID = "securescan-core-v0.1-three-rule-python"
BENCHMARK_SCHEMA_VERSION = "1.0.0"
CURATED_LIMITATIONS = (
    "The benchmark covers local repository directories only.",
    "The bundled corpus exercises exactly three Python demonstration rules.",
    "The result does not establish broad SAST, multi-language, or production accuracy.",
    "Semgrep CE execution depends on a trusted local digest-pinned container image.",
)
_GROUND_TRUTH_KEYS = {
    "schema_version",
    "benchmark_id",
    "expected_findings",
    "expected_finding_count",
    "expected_clean_finding_count",
}


@dataclass(frozen=True, slots=True)
class GroundTruth:
    schema_version: str
    benchmark_id: str
    expected_findings: tuple[BenchmarkExpectation, ...]
    expected_finding_count: int
    expected_clean_finding_count: int

    def __post_init__(self) -> None:
        expected = tuple(sorted(self.expected_findings))
        if (
            self.schema_version != BENCHMARK_SCHEMA_VERSION
            or self.benchmark_id != CORE_BENCHMARK_ID
            or self.expected_finding_count != len(expected)
            or self.expected_finding_count != 3
            or self.expected_clean_finding_count != 0
            or isinstance(self.expected_finding_count, bool)
            or isinstance(self.expected_clean_finding_count, bool)
        ):
            raise ValueError("Benchmark ground truth is invalid")
        object.__setattr__(self, "expected_findings", expected)

    def canonical_data(self) -> dict[str, Any]:
        return {
            "benchmark_id": self.benchmark_id,
            "expected_clean_finding_count": self.expected_clean_finding_count,
            "expected_finding_count": self.expected_finding_count,
            "expected_findings": [
                {
                    "relative_path": finding.relative_path,
                    "rule_id": finding.rule_id,
                    "start_line": finding.start_line,
                }
                for finding in self.expected_findings
            ],
            "schema_version": self.schema_version,
        }


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def load_ground_truth(path: Path) -> GroundTruth:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or set(raw) != _GROUND_TRUTH_KEYS:
            raise ValueError
        raw_findings = raw["expected_findings"]
        if not isinstance(raw_findings, list):
            raise ValueError
        findings = tuple(
            BenchmarkExpectation(
                rule_id=item["rule_id"],
                relative_path=item["relative_path"],
                start_line=item["start_line"],
            )
            for item in raw_findings
            if isinstance(item, dict)
            and set(item) == {"rule_id", "relative_path", "start_line"}
        )
        if len(findings) != len(raw_findings):
            raise ValueError
        ground_truth = GroundTruth(
            schema_version=raw["schema_version"],
            benchmark_id=raw["benchmark_id"],
            expected_findings=findings,
            expected_finding_count=raw["expected_finding_count"],
            expected_clean_finding_count=raw["expected_clean_finding_count"],
        )
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("Benchmark ground truth is invalid") from exc
    if _canonical_json_bytes(raw) != _canonical_json_bytes(ground_truth.canonical_data()):
        raise ValueError("Benchmark ground truth is not canonical")
    return ground_truth


def _corpus_files(corpus_root: Path) -> tuple[tuple[str, str], ...]:
    try:
        root = corpus_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("Benchmark corpus is invalid") from exc
    if not root.is_dir() or corpus_root.is_symlink():
        raise ValueError("Benchmark corpus is invalid")
    files: list[tuple[str, str]] = []
    try:
        for candidate in sorted(root.rglob("*")):
            metadata = candidate.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError("Benchmark corpus is invalid")
            relative_path = candidate.relative_to(root).as_posix()
            if PurePosixPath(relative_path).as_posix() != relative_path:
                raise ValueError("Benchmark corpus is invalid")
            files.append((relative_path, hashlib.sha256(candidate.read_bytes()).hexdigest()))
    except OSError as exc:
        raise ValueError("Benchmark corpus is invalid") from exc
    return tuple(files)


def calculate_corpus_digest(
    corpus_root: Path,
    ground_truth: GroundTruth,
    expected_findings: tuple[BenchmarkExpectation, ...],
) -> str:
    if not isinstance(ground_truth, GroundTruth):
        raise ValueError("Benchmark ground truth is invalid")
    canonical = {
        "benchmark_id": ground_truth.benchmark_id,
        "expected_findings": [
            {
                "relative_path": finding.relative_path,
                "rule_id": finding.rule_id,
                "start_line": finding.start_line,
            }
            for finding in sorted(expected_findings)
        ],
        "files": [
            {"relative_path": relative_path, "sha256": digest}
            for relative_path, digest in _corpus_files(corpus_root)
        ],
        "schema_version": ground_truth.schema_version,
    }
    return hashlib.sha256(_canonical_json_bytes(canonical)).hexdigest()


def _identity(
    finding: BenchmarkExpectation | BenchmarkObservation,
) -> tuple[str, str, int]:
    return finding.rule_id, finding.relative_path, finding.start_line


def calculate_metrics(
    expected: tuple[BenchmarkExpectation, ...],
    observed: tuple[BenchmarkObservation, ...],
) -> BenchmarkMetrics:
    expected_counts = Counter(_identity(finding) for finding in expected)
    observed_counts = Counter(_identity(finding) for finding in observed)
    true_positives = sum((expected_counts & observed_counts).values())
    false_positives = sum((observed_counts - expected_counts).values())
    false_negatives = sum((expected_counts - observed_counts).values())
    precision = (
        true_positives / (true_positives + false_positives)
        if true_positives + false_positives
        else 1.0
    )
    recall = (
        true_positives / (true_positives + false_negatives)
        if true_positives + false_negatives
        else 1.0
    )
    f1_score = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    return BenchmarkMetrics(
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision=precision,
        recall=recall,
        f1_score=f1_score,
    )


def evaluate_benchmark_case(
    *,
    case_id: str,
    corpus_digest: str,
    expected_findings: tuple[BenchmarkExpectation, ...],
    observed_findings: tuple[BenchmarkObservation, ...],
    analysis_gap_count: int,
    raw_artifact_count: int,
    deterministic: bool = True,
) -> BenchmarkCaseResult:
    return BenchmarkCaseResult(
        case_id=case_id,
        corpus_digest=corpus_digest,
        expected_findings=expected_findings,
        observed_findings=observed_findings,
        metrics=calculate_metrics(expected_findings, observed_findings),
        analysis_gap_count=analysis_gap_count,
        raw_artifact_count=raw_artifact_count,
        deterministic=deterministic,
    )


def observations_from_report(report_json: dict[str, Any]) -> tuple[BenchmarkObservation, ...]:
    try:
        observations = tuple(
            BenchmarkObservation(
                fingerprint=finding["fingerprint"],
                rule_id=finding["rule_id"],
                relative_path=finding["path"],
                start_line=finding["start_line"],
                severity=finding["native_severity"] or "unknown",
            )
            for finding in report_json["observations"]
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Benchmark scanner report is invalid") from exc
    return tuple(sorted(observations))


def curated_acceptance_passes(
    vulnerable: BenchmarkCaseResult,
    clean: BenchmarkCaseResult,
) -> bool:
    vulnerable_metrics = vulnerable.metrics
    return (
        len(vulnerable.expected_findings) == 3
        and len(vulnerable.observed_findings) == 3
        and vulnerable_metrics.true_positives == 3
        and vulnerable_metrics.false_positives == 0
        and vulnerable_metrics.false_negatives == 0
        and vulnerable_metrics.precision == 1.0
        and vulnerable_metrics.recall == 1.0
        and vulnerable_metrics.f1_score == 1.0
        and vulnerable.analysis_gap_count == 0
        and vulnerable.raw_artifact_count == 1
        and not clean.observed_findings
        and clean.metrics.false_positives == 0
        and clean.analysis_gap_count == 0
        and clean.raw_artifact_count == 1
    )


def benchmark_results_repeatable(
    first: BenchmarkCaseResult,
    repeated: BenchmarkCaseResult,
    *,
    first_repository_digest: str,
    repeated_repository_digest: str,
) -> bool:
    return (
        first_repository_digest == repeated_repository_digest
        and first.observed_findings == repeated.observed_findings
        and first.metrics == repeated.metrics
        and first.analysis_gap_count == repeated.analysis_gap_count
        and first.raw_artifact_count == repeated.raw_artifact_count
    )


class CoreV01ReleaseEvaluator:
    def __init__(
        self,
        *,
        corpus_root: Path,
        semgrep_image: str,
        workspace_base: Path,
        tool_version: str = DECLARED_SEMGREP_TOOL_VERSION,
    ) -> None:
        self._corpus_root = corpus_root
        self._semgrep_image = semgrep_image
        self._workspace_base = workspace_base
        self._tool_version = tool_version

    @staticmethod
    def _job() -> JobRecord:
        now = datetime.now(UTC)
        identity = str(uuid4())
        return JobRecord(
            id=identity,
            run_id=str(uuid4()),
            adapter_id="semgrep-ce",
            status=JobStatus.RUNNING,
            priority=100,
            attempt_count=1,
            max_attempts=1,
            available_at=now,
            leased_by="release-evaluator",
            lease_expires_at=now + timedelta(minutes=5),
            heartbeat_at=now,
            cancel_requested=False,
            idempotency_key=identity.replace("-", "").ljust(64, "0"),
            payload_json={},
            last_error=None,
            created_at=now,
            updated_at=now,
            started_at=now,
            finished_at=None,
            lease_token=str(uuid4()),
        )

    def _scan(
        self,
        source: Path,
        workspace_manager: RepositoryWorkspaceManager,
        artifact_store: ContentAddressedArtifactStore,
    ) -> tuple[tuple[BenchmarkObservation, ...], int, int, str]:
        ruleset = load_baseline_ruleset()
        definition = create_semgrep_trusted_definition(
            image_reference=self._semgrep_image,
            tool_version=self._tool_version,
            docker_executor=DockerSandboxExecutor(),
            workspace_manager=workspace_manager,
            ruleset=ruleset,
            artifact_store=artifact_store,
            source_resolver=lambda _run_id: source,
        )
        outcome = definition.factory().execute(self._job())
        if not isinstance(outcome, WorkerSuccessfulExecution):
            raise RuntimeError("Release benchmark scanner did not complete")
        report = outcome.report_json
        artifacts = report["executions"][0]["artifacts"]
        raw_artifact_count = sum(
            artifact["kind"] == ArtifactKind.SANITIZED_NATIVE_REPORT.value
            for artifact in artifacts
        )
        return (
            observations_from_report(report),
            len(report["analysis_gaps"]),
            raw_artifact_count,
            report["target"]["content_digest"],
        )

    def evaluate(self) -> CoreReleaseEvaluation:
        ground_truth = load_ground_truth(self._corpus_root / "ground_truth.json")
        vulnerable_source = self._corpus_root / "vulnerable"
        clean_source = self._corpus_root / "clean"
        vulnerable_digest = calculate_corpus_digest(
            vulnerable_source,
            ground_truth,
            ground_truth.expected_findings,
        )
        clean_digest = calculate_corpus_digest(clean_source, ground_truth, ())
        self._workspace_base.mkdir(mode=0o700, parents=True, exist_ok=True)
        workspaces = RepositoryWorkspaceManager(self._workspace_base / "workspaces")

        with tempfile.TemporaryDirectory(
            prefix=".release-artifacts-",
            dir=self._workspace_base,
        ) as artifact_directory:
            store = ContentAddressedArtifactStore(Path(artifact_directory))
            first = self._scan(vulnerable_source, workspaces, store)
            clean = self._scan(clean_source, workspaces, store)
            repeated = self._scan(vulnerable_source, workspaces, store)

        first_observations, first_gaps, first_artifacts, repository_digest = first
        repeated_observations, repeated_gaps, repeated_artifacts, repeated_digest = repeated
        vulnerable = evaluate_benchmark_case(
            case_id="vulnerable",
            corpus_digest=vulnerable_digest,
            expected_findings=ground_truth.expected_findings,
            observed_findings=first_observations,
            analysis_gap_count=first_gaps,
            raw_artifact_count=first_artifacts,
        )
        clean_case = evaluate_benchmark_case(
            case_id="clean",
            corpus_digest=clean_digest,
            expected_findings=(),
            observed_findings=clean[0],
            analysis_gap_count=clean[1],
            raw_artifact_count=clean[2],
        )
        repeated_case = evaluate_benchmark_case(
            case_id="vulnerable",
            corpus_digest=vulnerable_digest,
            expected_findings=ground_truth.expected_findings,
            observed_findings=repeated_observations,
            analysis_gap_count=repeated_gaps,
            raw_artifact_count=repeated_artifacts,
        )
        repeatability = benchmark_results_repeatable(
            vulnerable,
            repeated_case,
            first_repository_digest=repository_digest,
            repeated_repository_digest=repeated_digest,
        )
        workspace_clean = not any(workspaces.base_directory.iterdir())
        acceptance = curated_acceptance_passes(vulnerable, clean_case) and repeatability
        acceptance = acceptance and workspace_clean
        digest = release_evidence_digest(
            release_version=CORE_RELEASE_VERSION,
            benchmark_id=ground_truth.benchmark_id,
            vulnerable_case=vulnerable,
            clean_case=clean_case,
            repeatability_verified=repeatability,
            acceptance_passed=acceptance,
            limitations=CURATED_LIMITATIONS,
        )
        return CoreReleaseEvaluation(
            release_version=CORE_RELEASE_VERSION,
            benchmark_id=ground_truth.benchmark_id,
            vulnerable_case=vulnerable,
            clean_case=clean_case,
            repeatability_verified=repeatability,
            acceptance_passed=acceptance,
            limitations=CURATED_LIMITATIONS,
            release_evidence_digest=digest,
        )
