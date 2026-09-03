from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

import securescan.scanners.gitleaks.binding as binding_module
from securescan.benchmarks import gitleaks_benchmark as benchmark_module
from securescan.benchmarks import gitleaks_benchmark_cli
from securescan.benchmarks.gitleaks_benchmark import (
    GITLEAKS_BENCHMARK_BASELINE_PATH,
    GITLEAKS_BENCHMARK_REPORT_SCHEMA_VERSION,
    GITLEAKS_V04F2_BASELINE_COMMIT,
    GITLEAKS_V04F2_BASELINE_TAG,
    GitleaksBenchmarkCaseResult,
    GitleaksBenchmarkConfidentialityError,
    GitleaksBenchmarkError,
    GitleaksBenchmarkEvaluation,
    GitleaksBenchmarkReport,
    GitleaksObservationLocation,
    GitleaksPerRuleResult,
    _extract_fixture_sentinels,
    _GitleaksConfidentialityProof,
    _location,
    _run_with_dependencies,
    _validate_and_parse_controlled_execution,
    _validate_raw_output_confidentiality,
    build_gitleaks_benchmark_report,
    calculate_gitleaks_benchmark_metrics,
    check_controlled_gitleaks_benchmark,
    evaluate_gitleaks_benchmark,
    record_gitleaks_benchmark_report,
)
from securescan.benchmarks.gitleaks_contract import (
    GITLEAKS_BENCHMARK_CONTRACT_SHA256,
    GITLEAKS_BINDING_DIGEST,
    GitleaksBenchmarkClassification,
    load_benchmark_manifest,
)
from securescan.benchmarks.gitleaks_corpus import (
    GITLEAKS_CORPUS_DIGEST,
    GITLEAKS_CORPUS_MANIFEST_SHA256,
    GITLEAKS_CORPUS_PLAN_SHA256,
)
from securescan.execution import CancellableProcessRequest, CancellableProcessResult
from securescan.scanners.gitleaks import (
    GITLEAKS_SCANNER_ID,
    GITLEAKS_VERSION,
    GitleaksDetectionKind,
    GitleaksExecutionResultEnvelope,
    GitleaksExecutionStatus,
    GitleaksParseResult,
    NormalizedGitleaksFinding,
    TrustedGitleaksBinding,
    create_default_gitleaks_binding,
)
from securescan.source import PreparedSourceProjection
from securescan.workspaces import RepositoryWorkspaceManager

ROOT = Path(__file__).resolve().parents[1]
PROJECTION_ID = "securescan-source-projection-" + "3a" * 16
CONTEXT_DIGEST = "a" * 64
PROJECTION_DIGEST = "b" * 64


def _manifest():
    return load_benchmark_manifest(ROOT / "benchmarks/gitleaks/manifest.json")


def _finding(
    file_path: str,
    rule_id: str,
    *,
    detection_kind: GitleaksDetectionKind = GitleaksDetectionKind.CONTENT,
    start_line: int | None = 3,
    end_line: int | None = 3,
    start_column: int | None = None,
    end_column: int | None = None,
) -> NormalizedGitleaksFinding:
    if detection_kind is GitleaksDetectionKind.PATH:
        start_line = end_line = start_column = end_column = None
    return NormalizedGitleaksFinding(
        scanner_id=GITLEAKS_SCANNER_ID,
        scanner_version=GITLEAKS_VERSION,
        rule_id=rule_id,
        file_path=file_path,
        detection_kind=detection_kind,
        start_line=start_line,
        end_line=end_line,
        start_column=start_column,
        end_column=end_column,
        projection_id=PROJECTION_ID,
        context_digest=CONTEXT_DIGEST,
        projection_digest=PROJECTION_DIGEST,
    )


def _parse_result(
    findings: tuple[NormalizedGitleaksFinding, ...] = (),
) -> GitleaksParseResult:
    return GitleaksParseResult(
        scanner_id=GITLEAKS_SCANNER_ID,
        scanner_version=GITLEAKS_VERSION,
        binding_digest=GITLEAKS_BINDING_DIGEST,
        projection_id=PROJECTION_ID,
        context_digest=CONTEXT_DIGEST,
        projection_digest=PROJECTION_DIGEST,
        findings=findings,
        finding_count=len(findings),
    )


def _evaluate(
    findings: tuple[NormalizedGitleaksFinding, ...] = (),
) -> GitleaksBenchmarkEvaluation:
    return evaluate_gitleaks_benchmark(
        _manifest(),
        _parse_result(findings),
        execution_status=(
            GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS
            if findings
            else GitleaksExecutionStatus.COMPLETED_NO_FINDINGS
        ),
        return_code=1 if findings else 0,
    )


def _envelope_for_evaluation(
    evaluation: GitleaksBenchmarkEvaluation,
    *,
    stdout: bytes = b"[]\n",
    stderr: bytes = b"",
) -> GitleaksExecutionResultEnvelope:
    return GitleaksExecutionResultEnvelope(
        scanner_id=GITLEAKS_SCANNER_ID,
        scanner_version=GITLEAKS_VERSION,
        binding_digest=GITLEAKS_BINDING_DIGEST,
        execution_status=evaluation.execution_status,
        failure_code=None,
        return_code=evaluation.return_code,
        stdout_bytes=stdout,
        stderr_bytes=stderr,
        duration_ms=1,
        timed_out=False,
        output_limit_exceeded=False,
        termination_requested=False,
        force_killed=False,
        cancellation_requested=False,
        projection_id=evaluation.projection_id,
        context_digest=evaluation.context_digest,
        projection_digest=evaluation.projection_digest,
    )


def _controlled_evidence(
    findings: tuple[NormalizedGitleaksFinding, ...] = (),
) -> tuple[GitleaksBenchmarkEvaluation, _GitleaksConfidentialityProof]:
    with tempfile.TemporaryDirectory(prefix="securescan-gitleaks-test-") as name:
        temporary_root = Path(name).resolve()
        workspace_manager = RepositoryWorkspaceManager(temporary_root / "workspaces")
        workspace = workspace_manager.prepare_repository(ROOT / "benchmarks/gitleaks/corpus")
        projection_root = temporary_root / PROJECTION_ID
        projection_source = Path(
            shutil.copytree(workspace.source_directory, projection_root / "source")
        ).resolve()
        projection = PreparedSourceProjection(
            projection_id=PROJECTION_ID,
            root_directory=projection_root.resolve(),
            source_directory=projection_source,
            manifest=workspace.manifest,
            context_digest=CONTEXT_DIGEST,
            projection_digest=workspace.manifest.content_digest,
        )
        scanner_findings = []
        for finding in findings:
            row: dict[str, object] = {
                "File": finding.file_path.removeprefix("corpus/"),
                "Match": "REDACTED",
                "RuleID": finding.rule_id,
                "Secret": "REDACTED",
            }
            if finding.detection_kind is GitleaksDetectionKind.CONTENT:
                row["StartLine"] = finding.start_line
                if finding.end_line is not None:
                    row["EndLine"] = finding.end_line
                if finding.start_column is not None:
                    row["StartColumn"] = finding.start_column
                    row["EndColumn"] = finding.end_column
            else:
                row.update(
                    StartLine=0,
                    EndLine=0,
                    StartColumn=0,
                    EndColumn=0,
                )
            scanner_findings.append(row)
        stdout = json.dumps(scanner_findings, separators=(",", ":"), sort_keys=True).encode()
        status = (
            GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS
            if findings
            else GitleaksExecutionStatus.COMPLETED_NO_FINDINGS
        )
        result = GitleaksExecutionResultEnvelope(
            scanner_id=GITLEAKS_SCANNER_ID,
            scanner_version=GITLEAKS_VERSION,
            binding_digest=GITLEAKS_BINDING_DIGEST,
            execution_status=status,
            failure_code=None,
            return_code=1 if findings else 0,
            stdout_bytes=stdout,
            stderr_bytes=b"",
            duration_ms=1,
            timed_out=False,
            output_limit_exceeded=False,
            termination_requested=False,
            force_killed=False,
            cancellation_requested=False,
            projection_id=projection.projection_id,
            context_digest=projection.context_digest,
            projection_digest=projection.projection_digest,
        )
        parsed, proof = _validate_and_parse_controlled_execution(_manifest(), projection, result)
        evaluation = evaluate_gitleaks_benchmark(
            _manifest(),
            parsed,
            execution_status=status,
            return_code=result.return_code,
        )
        return evaluation, proof


def _report(
    findings: tuple[NormalizedGitleaksFinding, ...] = (),
) -> GitleaksBenchmarkReport:
    evaluation, proof = _controlled_evidence(findings)
    return build_gitleaks_benchmark_report(_manifest(), evaluation, proof)


def _row(
    evaluation: GitleaksBenchmarkEvaluation | GitleaksBenchmarkReport,
    case_id: str,
):
    return next(row for row in evaluation.cases if row.case_id == case_id)


def _trust_frozen_manifest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        benchmark_module,
        "verify_gitleaks_benchmark",
        lambda _root: _manifest(),
    )


def test_metric_classification_rounding_and_zero_denominators() -> None:
    classifications = (
        GitleaksBenchmarkClassification.TP,
        *(GitleaksBenchmarkClassification.FP for _ in range(5)),
        *(GitleaksBenchmarkClassification.FN for _ in range(2)),
        GitleaksBenchmarkClassification.TN,
        GitleaksBenchmarkClassification.OUT_OF_SCOPE,
    )

    metrics = calculate_gitleaks_benchmark_metrics(classifications)
    empty_positive_denominators = calculate_gitleaks_benchmark_metrics(
        (GitleaksBenchmarkClassification.TN,)
    )

    assert (metrics.tp, metrics.fp, metrics.fn, metrics.tn) == (1, 5, 2, 1)
    assert metrics.out_of_scope == 1
    assert (metrics.precision, metrics.recall, metrics.f1) == (
        "0.1667",
        "0.3333",
        "0.2222",
    )
    assert empty_positive_denominators.precision is None
    assert empty_positive_denominators.recall is None
    assert empty_positive_denominators.f1 is None
    assert empty_positive_denominators.canonical_data()["precision"] is None


def test_empty_observations_have_exact_core_scope_and_per_rule_accounting() -> None:
    report = _evaluate()

    assert report.overall.canonical_data() == {
        "f1": None,
        "fn": 25,
        "fp": 0,
        "out_of_scope": 0,
        "precision": None,
        "recall": "0.0000",
        "relation_count": 48,
        "tn": 23,
        "tp": 0,
    }
    assert (report.core.fn, report.core.tn, report.core.relation_count) == (21, 21, 42)
    assert (report.scope.fn, report.scope.tn, report.scope.relation_count) == (4, 2, 6)
    per_rule = {row.rule_id: row for row in report.per_rule}
    assert len(per_rule) == 7
    assert per_rule["github-pat"].metrics.relation_count == 12
    assert all(
        row.metrics.relation_count == 6
        for rule_id, row in per_rule.items()
        if rule_id != "github-pat"
    )


def test_repeated_intended_findings_count_one_relation_but_preserve_observations() -> None:
    finding = _finding("github-pat/positive-01.txt", "github-pat")
    report = _evaluate((finding, finding))
    row = _row(report, "github-pat-positive-01")

    assert row.classification is GitleaksBenchmarkClassification.TP
    assert row.same_rule_observation_count == 2
    assert len(row.same_rule_finding_instance_ids) == 2
    assert len(set(row.same_rule_finding_instance_ids)) == 1
    assert report.overall.tp == 1
    assert report.finding_observation_count == 2


def test_cross_rule_observation_is_separate_and_unselected_rule_is_accepted() -> None:
    report = _evaluate((_finding("github-pat/negative-01.txt", "upstream-valid-rule-99"),))
    row = _row(report, "github-pat-negative-01")

    assert row.classification is GitleaksBenchmarkClassification.TN
    assert row.same_rule_observation_count == 0
    assert len(report.unexpected_cross_rule_observations) == 1
    unexpected = report.unexpected_cross_rule_observations[0]
    assert unexpected.rule_id == "upstream-valid-rule-99"
    assert unexpected.file_path == "corpus/github-pat/negative-01.txt"
    assert report.overall.fp == 0


def test_unknown_path_and_incorrect_trusted_identities_fail_closed() -> None:
    with pytest.raises(GitleaksBenchmarkError, match="^Gitleaks benchmark execution failed$"):
        _evaluate((_finding("not-in-manifest.txt", "github-pat"),))

    result = _parse_result()
    object.__setattr__(result, "scanner_id", "not-gitleaks")
    with pytest.raises(GitleaksBenchmarkError):
        evaluate_gitleaks_benchmark(
            _manifest(),
            result,
            execution_status=GitleaksExecutionStatus.COMPLETED_NO_FINDINGS,
            return_code=0,
        )

    wrong_binding = _parse_result()
    object.__setattr__(wrong_binding, "binding_digest", "0" * 64)
    with pytest.raises(GitleaksBenchmarkError):
        evaluate_gitleaks_benchmark(
            _manifest(),
            wrong_binding,
            execution_status=GitleaksExecutionStatus.COMPLETED_NO_FINDINGS,
            return_code=0,
        )

    manifest = _manifest()
    object.__setattr__(manifest, "corpus_digest", "0" * 64)
    with pytest.raises(GitleaksBenchmarkError):
        evaluate_gitleaks_benchmark(
            manifest,
            _parse_result(),
            execution_status=GitleaksExecutionStatus.COMPLETED_NO_FINDINGS,
            return_code=0,
        )

    wrong_manifest = _manifest()
    object.__setattr__(wrong_manifest, "benchmark_id", "other-benchmark")
    with pytest.raises(GitleaksBenchmarkError):
        evaluate_gitleaks_benchmark(
            wrong_manifest,
            _parse_result(),
            execution_status=GitleaksExecutionStatus.COMPLETED_NO_FINDINGS,
            return_code=0,
        )


@pytest.mark.parametrize(
    ("status", "return_code"),
    (
        (GitleaksExecutionStatus.COMPLETED_NO_FINDINGS, 1),
        (GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS, 0),
        (GitleaksExecutionStatus.FAILED, 2),
    ),
)
def test_non_successful_or_contradictory_execution_cannot_produce_metrics(
    status: GitleaksExecutionStatus,
    return_code: int,
) -> None:
    with pytest.raises(GitleaksBenchmarkError):
        evaluate_gitleaks_benchmark(
            _manifest(),
            _parse_result(),
            execution_status=status,
            return_code=return_code,
        )


def test_canonical_report_is_order_independent_and_secret_safe() -> None:
    content = _finding("github-pat/positive-01.txt", "github-pat")
    path = _finding(
        "pkcs12-file/positive-01.p12",
        "pkcs12-file",
        detection_kind=GitleaksDetectionKind.PATH,
    )
    first = _report((path, content))
    second = _report((content, path))
    payload = first.canonical_json()
    document = json.loads(payload)

    assert payload == second.canonical_json()
    assert document["schema_version"] == GITLEAKS_BENCHMARK_REPORT_SCHEMA_VERSION
    assert [row["case_id"] for row in document["cases"]] == sorted(
        row["case_id"] for row in document["cases"]
    )
    assert [row["rule_id"] for row in document["per_rule"]] == sorted(
        row["rule_id"] for row in document["per_rule"]
    )
    path_row = _row(first, "pkcs12-file-positive-01")
    assert path_row.same_rule_observation_count == 1
    assert first.unexpected_cross_rule_observations == ()
    assert _location(path) is None
    assert _location(content).canonical_data() == {
        "end_column": None,
        "end_line": 3,
        "start_column": None,
        "start_line": 3,
    }

    forbidden_keys = {
        "Secret",
        "Match",
        "Fingerprint",
        "Entropy",
        "Description",
        "Tags",
        "Commit",
        "Author",
        "Email",
        "Message",
        "raw_stdout",
        "raw_stderr",
        "projection_id",
        "context_digest",
        "projection_digest",
        "parse_result_digest",
    }

    def keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value) | set().union(*(keys(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(keys(item) for item in value))
        return set()

    assert not (forbidden_keys & keys(document))
    assert str(ROOT).encode() not in payload
    for sentinel in _extract_fixture_sentinels(_manifest(), ROOT / "benchmarks/gitleaks/corpus"):
        assert sentinel not in payload


def test_frozen_report_and_f2_identifiers_are_exact() -> None:
    report = _report().canonical_data()

    assert report["benchmark_baseline_commit"] == GITLEAKS_V04F2_BASELINE_COMMIT
    assert report["benchmark_baseline_tag"] == GITLEAKS_V04F2_BASELINE_TAG
    assert report["contract_sha256"] == GITLEAKS_BENCHMARK_CONTRACT_SHA256
    assert report["binding_digest"] == GITLEAKS_BINDING_DIGEST
    assert report["binding_artifact_sha256"] == (
        "8d0e06a802158827bbe685b7970ffa075ae07f6393debbb088c3b9bf29f1bd44"
    )
    assert report["plan_sha256"] == GITLEAKS_CORPUS_PLAN_SHA256
    assert report["manifest_sha256"] == GITLEAKS_CORPUS_MANIFEST_SHA256
    assert report["corpus_digest"] == GITLEAKS_CORPUS_DIGEST
    assert report["case_relation_count"] == 48
    assert report["core_relation_count"] == 42
    assert report["scope_relation_count"] == 6


def test_fixture_sentinels_extract_values_without_assignment_names() -> None:
    sentinels = _extract_fixture_sentinels(_manifest(), ROOT / "benchmarks/gitleaks/corpus")

    assert b"AKIA7Q2W4E6R3T5Y7U2P" in sentinels
    assert b"aws_access_key_id" not in sentinels
    assert b"S3cUr3ScanF2Alpha9" in sentinels
    assert b"api_key" not in sentinels
    assert all(len(sentinel) >= 16 for sentinel in sentinels)


def test_pure_evaluation_has_no_confidentiality_claim_and_cannot_be_recorded(
    tmp_path: Path,
) -> None:
    evaluation = _evaluate()
    destination = tmp_path.resolve() / GITLEAKS_BENCHMARK_BASELINE_PATH

    assert isinstance(evaluation, GitleaksBenchmarkEvaluation)
    assert not isinstance(evaluation, GitleaksBenchmarkReport)
    assert not hasattr(evaluation, "canonical_data")
    assert not hasattr(evaluation, "canonical_json")
    assert "confidential" not in repr(evaluation).lower()
    with pytest.raises(GitleaksBenchmarkError):
        record_gitleaks_benchmark_report(tmp_path.resolve(), evaluation)  # type: ignore[arg-type]
    assert not destination.exists()


def test_final_report_requires_and_records_explicit_confidentiality_proof() -> None:
    manifest = _manifest()
    evaluation = _evaluate()

    with pytest.raises(GitleaksBenchmarkError):
        build_gitleaks_benchmark_report(
            manifest,
            evaluation,
            None,  # type: ignore[arg-type]
        )

    evaluation, proof = _controlled_evidence()
    report = build_gitleaks_benchmark_report(manifest, evaluation, proof)

    assert report.canonical_data()["confidentiality"] == {
        "raw_fixture_sentinels_absent_from_scanner_output": True,
        "raw_scanner_output_persisted": False,
    }

    different_evaluation = _evaluate((_finding("github-pat/positive-01.txt", "github-pat"),))
    with pytest.raises(GitleaksBenchmarkError):
        build_gitleaks_benchmark_report(
            manifest,
            different_evaluation,
            proof,
        )


def test_confidentiality_proof_cannot_be_reused_for_different_same_status_parse() -> None:
    manifest = _manifest()
    github = (_finding("github-pat/positive-01.txt", "github-pat"),)
    gitlab = (_finding("gitlab-pat/positive-01.txt", "gitlab-pat"),)
    evaluation_a, proof_a = _controlled_evidence(github)
    evaluation_b, _proof_b = _controlled_evidence(gitlab)

    report = build_gitleaks_benchmark_report(manifest, evaluation_a, proof_a)

    assert report.execution_status is (GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS)
    assert report.return_code == 1
    assert evaluation_b.execution_status is report.execution_status
    assert evaluation_b.return_code == report.return_code
    assert "parse_result_digest" not in report.canonical_json().decode()
    assert evaluation_a.parse_result_digest not in repr(evaluation_a)
    assert proof_a.parse_result_digest not in repr(proof_a)
    with pytest.raises(GitleaksBenchmarkError):
        build_gitleaks_benchmark_report(manifest, evaluation_b, proof_a)


def test_multiline_location_rejects_reverse_column_order() -> None:
    with pytest.raises(GitleaksBenchmarkError):
        GitleaksObservationLocation(
            start_line=3,
            end_line=4,
            start_column=9,
            end_column=2,
        )


def test_typed_evidence_is_deeply_immutable_and_rejects_arbitrary_fields() -> None:
    report = _report((_finding("github-pat/negative-01.txt", "upstream-valid-rule-99"),))
    case = report.cases[0]
    per_rule = report.per_rule[0]
    unexpected = report.unexpected_cross_rule_observations[0]

    with pytest.raises(FrozenInstanceError):
        case.case_id = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        per_rule.rule_id = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        unexpected.rule_id = "changed"  # type: ignore[misc]
    with pytest.raises(TypeError):
        GitleaksBenchmarkCaseResult(  # type: ignore[call-arg]
            case_id=case.case_id,
            relative_path=case.relative_path,
            expected_rule_id=case.expected_rule_id,
            expected_detection_kind=case.expected_detection_kind,
            expectation=case.expectation,
            classification=case.classification,
            same_rule_observation_count=case.same_rule_observation_count,
            same_rule_finding_instance_ids=case.same_rule_finding_instance_ids,
            secret="forbidden",
        )

    first = report.canonical_data()
    first["cases"][0]["Match"] = "forbidden"  # type: ignore[index]
    host_path = "/home/private-user-should-not-appear"
    first["per_rule"][0]["host_path"] = host_path  # type: ignore[index]
    first["unexpected_cross_rule_observations"][0]["secret"] = "forbidden"  # type: ignore[index]
    second = report.canonical_data()
    serialized = json.dumps(second)

    def nested_keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value) | set().union(*(nested_keys(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(nested_keys(item) for item in value))
        return set()

    assert "Match" not in serialized
    assert "host_path" not in serialized
    assert "secret" not in nested_keys(second)
    assert host_path not in serialized


def test_contradictory_metrics_and_case_sets_fail_closed() -> None:
    evaluation = _evaluate()
    all_tn = calculate_gitleaks_benchmark_metrics((GitleaksBenchmarkClassification.TN,) * 48)
    with pytest.raises(GitleaksBenchmarkError):
        replace(evaluation, overall=all_tn)

    wrong_rule_metrics = calculate_gitleaks_benchmark_metrics(
        (GitleaksBenchmarkClassification.TN,) * 6
    )
    wrong_rule = GitleaksPerRuleResult(
        rule_id=evaluation.per_rule[0].rule_id,
        metrics=wrong_rule_metrics,
    )
    with pytest.raises(GitleaksBenchmarkError):
        replace(
            evaluation,
            per_rule=(wrong_rule, *evaluation.per_rule[1:]),
        )

    with pytest.raises(GitleaksBenchmarkError):
        replace(evaluation, cases=evaluation.cases[:-1])
    with pytest.raises(GitleaksBenchmarkError):
        replace(
            evaluation,
            cases=(evaluation.cases[0], *evaluation.cases[:-1]),
        )
    with pytest.raises(GitleaksBenchmarkError):
        replace(
            evaluation.cases[0],
            classification=GitleaksBenchmarkClassification.TP,
        )


def _copy_corpus(destination: Path) -> Path:
    return Path(
        shutil.copytree(
            ROOT / "benchmarks/gitleaks/corpus",
            destination,
        )
    ).resolve()


def test_confidentiality_oracle_uses_immutable_projection_not_original_source(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    original = _copy_corpus(tmp_path / "original")
    projection = Path(shutil.copytree(original, tmp_path / "projection")).resolve()
    evaluation = _evaluate()
    envelope = _envelope_for_evaluation(evaluation)
    before = _validate_raw_output_confidentiality(manifest, projection, envelope)

    original_fixture = original / "github-pat/positive-01.txt"
    original_fixture.write_bytes(b"mutated source after projection\n")
    after = _validate_raw_output_confidentiality(manifest, projection, envelope)

    assert before == after
    projection_sentinel = (projection / "github-pat/positive-01.txt").read_bytes().splitlines()[-1]
    with pytest.raises(GitleaksBenchmarkConfidentialityError) as raised:
        _validate_raw_output_confidentiality(
            manifest,
            projection,
            _envelope_for_evaluation(evaluation, stdout=projection_sentinel),
        )
    assert projection_sentinel.decode() not in str(raised.value)
    assert "mutated source" not in str(raised.value)


@pytest.mark.parametrize("mutation", ("content", "symlink"))
def test_changed_or_symlinked_projection_fixture_fails_confidentiality_validation(
    tmp_path: Path,
    mutation: str,
) -> None:
    projection = _copy_corpus(tmp_path / "projection")
    fixture = projection / "github-pat/positive-01.txt"
    raw_secret = fixture.read_bytes().splitlines()[-1]
    if mutation == "content":
        fixture.write_bytes(b"changed projection bytes\n")
    else:
        target = tmp_path / "same-bytes-outside-projection.txt"
        target.write_bytes(fixture.read_bytes())
        fixture.unlink()
        fixture.symlink_to(target)

    with pytest.raises(
        GitleaksBenchmarkConfidentialityError,
        match="^Gitleaks benchmark confidentiality validation failed$",
    ) as raised:
        _validate_raw_output_confidentiality(
            _manifest(),
            projection,
            _envelope_for_evaluation(_evaluate()),
        )

    assert raw_secret.decode() not in str(raised.value)


class _Handle:
    def __init__(self, result: CancellableProcessResult) -> None:
        self.result = result
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    def poll(self):
        return self.result

    def wait(self, timeout_seconds: float | None = None):
        return self.result

    def terminate(self) -> None:
        pass

    def kill(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True


class _Executor:
    def __init__(self, scan_result: CancellableProcessResult) -> None:
        self.scan_result = scan_result
        self.requests: list[CancellableProcessRequest] = []

    def start(self, request: CancellableProcessRequest):
        self.requests.append(request)
        if request.argv[1] == "version":
            return _Handle(_process_result(stdout=b"8.30.1\n"))
        return _Handle(self.scan_result)


def _process_result(
    *,
    return_code: int = 0,
    stdout: bytes = b"[]\n",
    stderr: bytes = b"",
) -> CancellableProcessResult:
    return CancellableProcessResult(
        return_code=return_code,
        stdout=stdout,
        stderr=stderr,
        duration_ms=1,
        timed_out=False,
        output_limit_exceeded=False,
        termination_requested=False,
        force_killed=False,
    )


def _fake_binding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TrustedGitleaksBinding:
    executable = (tmp_path / "trusted/gitleaks").resolve()
    executable.parent.mkdir()
    executable.write_bytes(b"test-only-not-executed")
    executable.chmod(0o700)
    verified_identity = object()
    monkeypatch.setattr(
        binding_module,
        "_verify_regular_file",
        lambda *_args, **_kwargs: verified_identity,
    )
    return create_default_gitleaks_binding(executable)


def _scanner_finding() -> bytes:
    return json.dumps(
        [
            {
                "File": "github-pat/positive-01.txt",
                "Match": "REDACTED",
                "RuleID": "github-pat",
                "Secret": "REDACTED",
                "StartLine": 3,
            }
        ],
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def test_fake_execution_traverses_production_bridge_parser_identity_and_evaluator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _fake_binding(tmp_path, monkeypatch)
    executor = _Executor(_process_result(return_code=1, stdout=_scanner_finding()))
    confidentiality_roots: list[Path] = []
    validate_confidentiality = benchmark_module._validate_raw_output_confidentiality

    def observe_confidentiality_root(manifest, projection_root, result):
        confidentiality_roots.append(projection_root)
        return validate_confidentiality(manifest, projection_root, result)

    monkeypatch.setattr(
        benchmark_module,
        "_validate_raw_output_confidentiality",
        observe_confidentiality_root,
    )

    report = _run_with_dependencies(ROOT.resolve(), binding, executor)

    assert len(executor.requests) == 2
    assert executor.requests[0].argv == (str(binding.executable_path), "version")
    scan = executor.requests[1]
    assert scan.argv[1] == "dir"
    assert scan.environment == {}
    assert scan.stdin_data is None
    assert scan.argv[-1].endswith("/source")
    assert confidentiality_roots == [Path(scan.argv[-1])]
    assert confidentiality_roots[0] != ROOT / "benchmarks/gitleaks/corpus"
    assert _row(report, "github-pat-positive-01").classification is (
        GitleaksBenchmarkClassification.TP
    )
    assert len(_row(report, "github-pat-positive-01").same_rule_finding_instance_ids) == 1
    assert report.finding_observation_count == 1


def test_fake_execution_confidentiality_failure_is_fixed_and_precedes_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _fake_binding(tmp_path, monkeypatch)
    sentinel = (
        (ROOT / "benchmarks/gitleaks/corpus/github-pat/positive-01.txt")
        .read_bytes()
        .splitlines()[-1]
    )
    executor = _Executor(_process_result(return_code=1, stdout=sentinel))

    with pytest.raises(
        GitleaksBenchmarkConfidentialityError,
        match="^Gitleaks benchmark confidentiality validation failed$",
    ) as raised:
        _run_with_dependencies(ROOT.resolve(), binding, executor)

    assert sentinel.decode() not in str(raised.value)


def test_fake_failed_execution_never_becomes_zero_finding_metrics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _fake_binding(tmp_path, monkeypatch)
    executor = _Executor(_process_result(return_code=2, stderr=b"untrusted failure"))

    with pytest.raises(
        GitleaksBenchmarkError,
        match="^Gitleaks benchmark execution failed$",
    ):
        _run_with_dependencies(ROOT.resolve(), binding, executor)


def test_check_verifies_runtime_without_starting_a_corpus_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = (tmp_path / "gitleaks").resolve()
    calls: list[Path] = []

    def verify_runtime(self, executor=None) -> None:
        calls.append(self.executable_path)

    monkeypatch.setattr(TrustedGitleaksBinding, "verify_runtime", verify_runtime)
    result = check_controlled_gitleaks_benchmark(ROOT.resolve(), executable)

    assert calls == [executable]
    assert result["runtime_verified"] is True
    assert result["scanner_id"] == "gitleaks"
    assert result["scanner_version"] == "8.30.1"


def test_record_is_atomic_idempotent_and_never_replaces_different_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_frozen_manifest(monkeypatch)
    repository = (tmp_path / "repository").resolve()
    (repository / "benchmarks/gitleaks").mkdir(parents=True)
    report = _report()
    destination = record_gitleaks_benchmark_report(repository, report)

    assert destination.relative_to(repository).as_posix() == (GITLEAKS_BENCHMARK_BASELINE_PATH)
    assert destination.read_bytes() == report.canonical_json()
    assert record_gitleaks_benchmark_report(repository, report) == destination

    destination.write_bytes(b"different historical evidence\n")
    with pytest.raises(GitleaksBenchmarkError):
        record_gitleaks_benchmark_report(repository, report)


def test_record_rejects_symlink_and_real_repository_has_no_baseline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_frozen_manifest(monkeypatch)
    repository = (tmp_path / "repository").resolve()
    destination = repository / GITLEAKS_BENCHMARK_BASELINE_PATH
    destination.parent.mkdir(parents=True)
    target = tmp_path / "outside.json"
    target.write_bytes(b"outside\n")
    destination.symlink_to(target)

    with pytest.raises(GitleaksBenchmarkError):
        record_gitleaks_benchmark_report(repository, _report())

    assert target.read_bytes() == b"outside\n"
    assert not (ROOT / GITLEAKS_BENCHMARK_BASELINE_PATH).exists()


def test_record_race_cannot_replace_evidence_created_by_another_writer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_frozen_manifest(monkeypatch)
    repository = (tmp_path / "repository").resolve()
    destination = repository / GITLEAKS_BENCHMARK_BASELINE_PATH
    destination.parent.mkdir(parents=True)
    real_link = benchmark_module.os.link

    def racing_link(source, target, *, follow_symlinks: bool) -> None:
        Path(target).write_bytes(b"concurrent evidence\n")
        real_link(source, target, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(benchmark_module.os, "link", racing_link)

    with pytest.raises(GitleaksBenchmarkError):
        record_gitleaks_benchmark_report(repository, _report())

    assert destination.read_bytes() == b"concurrent evidence\n"


@pytest.mark.parametrize("contradiction", ("overall", "per-rule", "missing-case"))
def test_record_revalidates_all_evidence_before_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    contradiction: str,
) -> None:
    _trust_frozen_manifest(monkeypatch)
    repository = (tmp_path / "repository").resolve()
    (repository / "benchmarks/gitleaks").mkdir(parents=True)
    report = _report()
    if contradiction == "overall":
        object.__setattr__(
            report.evaluation,
            "overall",
            calculate_gitleaks_benchmark_metrics((GitleaksBenchmarkClassification.TN,) * 48),
        )
    elif contradiction == "per-rule":
        first = report.per_rule[0]
        replacement = GitleaksPerRuleResult(
            rule_id=first.rule_id,
            metrics=calculate_gitleaks_benchmark_metrics(
                (GitleaksBenchmarkClassification.TN,) * first.metrics.relation_count
            ),
        )
        object.__setattr__(
            report.evaluation,
            "per_rule",
            (replacement, *report.per_rule[1:]),
        )
    else:
        object.__setattr__(report.evaluation, "cases", report.cases[:-1])

    with pytest.raises(
        GitleaksBenchmarkError,
        match="^Gitleaks benchmark execution failed$",
    ):
        record_gitleaks_benchmark_report(repository, report)

    assert not (repository / GITLEAKS_BENCHMARK_BASELINE_PATH).exists()


def test_cli_check_is_non_scanning_and_report_does_not_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    repository = (tmp_path / "repository").resolve()
    repository.mkdir()
    executable = (tmp_path / "gitleaks").resolve()
    calls: list[tuple[str, Path]] = []

    monkeypatch.setattr(gitleaks_benchmark_cli, "repository_root", lambda: repository)

    def check(root: Path, path: Path) -> dict[str, object]:
        calls.append(("check", path))
        assert root == repository
        return {"runtime_verified": True}

    def run(root: Path, path: Path):
        calls.append(("report", path))
        assert root == repository
        return _report()

    monkeypatch.setattr(
        gitleaks_benchmark_cli,
        "check_controlled_gitleaks_benchmark",
        check,
    )
    monkeypatch.setattr(
        gitleaks_benchmark_cli,
        "run_controlled_gitleaks_benchmark",
        run,
    )

    assert gitleaks_benchmark_cli.main(["check", "--gitleaks", str(executable)]) == 0
    check_output = capfd.readouterr()
    assert check_output.out == '{"runtime_verified":true}\n'
    assert check_output.err == ""
    assert calls == [("check", executable)]

    assert gitleaks_benchmark_cli.main(["report", "--gitleaks", str(executable)]) == 0
    report_output = capfd.readouterr()
    assert json.loads(report_output.out)["schema_version"] == (
        GITLEAKS_BENCHMARK_REPORT_SCHEMA_VERSION
    )
    assert report_output.err == ""
    assert calls[-1] == ("report", executable)
    assert not (repository / GITLEAKS_BENCHMARK_BASELINE_PATH).exists()


def test_cli_record_uses_atomic_recorder_with_fake_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    _trust_frozen_manifest(monkeypatch)
    repository = (tmp_path / "repository").resolve()
    (repository / "benchmarks/gitleaks").mkdir(parents=True)
    executable = (tmp_path / "gitleaks").resolve()
    report = _report()
    monkeypatch.setattr(gitleaks_benchmark_cli, "repository_root", lambda: repository)
    monkeypatch.setattr(
        gitleaks_benchmark_cli,
        "run_controlled_gitleaks_benchmark",
        lambda root, path: report,
    )

    assert gitleaks_benchmark_cli.main(["record", "--gitleaks", str(executable)]) == 0
    output = capfd.readouterr()
    assert output.out == f"recorded {GITLEAKS_BENCHMARK_BASELINE_PATH}\n"
    assert output.err == ""
    assert (repository / GITLEAKS_BENCHMARK_BASELINE_PATH).read_bytes() == (report.canonical_json())
    assert not (ROOT / GITLEAKS_BENCHMARK_BASELINE_PATH).exists()


def test_shell_runner_is_narrow_and_contains_no_direct_scanner_invocation() -> None:
    runner = ROOT / "scripts/run-gitleaks-benchmark.sh"
    source = runner.read_text(encoding="utf-8")

    assert source.count(".venv/bin/python") == 1
    assert not any(line.startswith("PATH=") for line in source.splitlines())
    assert "[[ $# -ne 2 ]]" in source
    assert "gitleaks dir" not in source
    benchmark_source = (ROOT / "src/securescan/benchmarks/gitleaks_benchmark.py").read_text()
    assert "subprocess" not in benchmark_source

    completed = subprocess.run(
        (str(runner), "check", "relative/gitleaks"),
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    assert completed.stdout == ""
    assert completed.stderr == "Gitleaks executable path must be absolute\n"
