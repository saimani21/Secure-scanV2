from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

import securescan.scanners.gitleaks.binding as binding_module
from securescan.benchmarks import gitleaks_adversarial_benchmark as benchmark
from securescan.benchmarks import gitleaks_adversarial_cli
from securescan.benchmarks.gitleaks_adversarial import (
    GITLEAKS_ADVERSARIAL_CONTRACT_PATH,
    GITLEAKS_ADVERSARIAL_CONTRACT_SHA256,
    GITLEAKS_ADVERSARIAL_CORPUS_DIGEST,
    GITLEAKS_ADVERSARIAL_CORPUS_PATH,
    GITLEAKS_ADVERSARIAL_ID,
    GITLEAKS_ADVERSARIAL_MANIFEST_PATH,
    GITLEAKS_ADVERSARIAL_MANIFEST_SHA256,
    GITLEAKS_ADVERSARIAL_RESULT_PATH,
    GITLEAKS_F3B_BASELINE_PATH,
    GITLEAKS_F3B_BASELINE_SHA256,
    GitleaksAdversarialExpectation,
    verify_gitleaks_adversarial,
)
from securescan.benchmarks.gitleaks_adversarial_benchmark import (
    _CONFIDENTIALITY_PROOF_TOKEN,
    GITLEAKS_ADVERSARIAL_RESULT_SCHEMA_VERSION,
    GitleaksAdversarialBenchmarkError,
    GitleaksAdversarialCaseResultValue,
    GitleaksAdversarialConfidentialityError,
    GitleaksAdversarialEvaluation,
    GitleaksAdversarialReport,
    _GitleaksAdversarialConfidentialityProof,
    _run_with_dependencies,
    build_gitleaks_adversarial_report,
    check_controlled_gitleaks_adversarial,
    evaluate_gitleaks_adversarial,
    record_gitleaks_adversarial_report,
)
from securescan.benchmarks.gitleaks_contract import GITLEAKS_BINDING_DIGEST
from securescan.execution import CancellableProcessRequest, CancellableProcessResult
from securescan.scanners.gitleaks import (
    GITLEAKS_SCANNER_ID,
    GITLEAKS_VERSION,
    GitleaksDetectionKind,
    GitleaksExecutionStatus,
    GitleaksParseResult,
    NormalizedGitleaksFinding,
    TrustedGitleaksBinding,
    create_default_gitleaks_binding,
)

ROOT = Path(__file__).resolve().parents[1]
PROJECTION_ID = "securescan-source-projection-" + "4b" * 16
CONTEXT_DIGEST = "a" * 64
PROJECTION_DIGEST = "b" * 64


def _manifest():
    return verify_gitleaks_adversarial(ROOT.resolve())


def _finding(
    relative_path: str,
    rule_id: str,
    detection_kind: GitleaksDetectionKind,
    *,
    start_line: int | None = 1,
    end_line: int | None = 1,
    start_column: int | None = None,
    end_column: int | None = None,
) -> NormalizedGitleaksFinding:
    if detection_kind is GitleaksDetectionKind.PATH:
        start_line = end_line = start_column = end_column = None
    return NormalizedGitleaksFinding(
        scanner_id=GITLEAKS_SCANNER_ID,
        scanner_version=GITLEAKS_VERSION,
        rule_id=rule_id,
        file_path=relative_path.removeprefix("adversarial-corpus/"),
        detection_kind=detection_kind,
        start_line=start_line,
        end_line=end_line,
        start_column=start_column,
        end_column=end_column,
        projection_id=PROJECTION_ID,
        context_digest=CONTEXT_DIGEST,
        projection_digest=PROJECTION_DIGEST,
    )


def _all_pass_findings() -> tuple[NormalizedGitleaksFinding, ...]:
    return tuple(
        _finding(
            case.relative_path,
            case.expected_rule_id,
            case.expected_detection_kind,
        )
        for case in _manifest().cases
        if case.expectation is GitleaksAdversarialExpectation.EXPECTED_OBSERVED
    )


def _parse(
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
) -> GitleaksAdversarialEvaluation:
    return evaluate_gitleaks_adversarial(
        _manifest(),
        _parse(findings),
        execution_status=(
            GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS
            if findings
            else GitleaksExecutionStatus.COMPLETED_NO_FINDINGS
        ),
        return_code=1 if findings else 0,
    )


def _proof(
    evaluation: GitleaksAdversarialEvaluation,
) -> _GitleaksAdversarialConfidentialityProof:
    return _GitleaksAdversarialConfidentialityProof(
        projection_id=evaluation.projection_id,
        context_digest=evaluation.context_digest,
        projection_digest=evaluation.projection_digest,
        execution_status=evaluation.execution_status,
        return_code=evaluation.return_code,
        corpus_digest=GITLEAKS_ADVERSARIAL_CORPUS_DIGEST,
        parse_result_digest=evaluation.parse_result_digest,
        _token=_CONFIDENTIALITY_PROOF_TOKEN,
    )


def _report(
    findings: tuple[NormalizedGitleaksFinding, ...] | None = None,
) -> GitleaksAdversarialReport:
    evaluation = _evaluate(_all_pass_findings() if findings is None else findings)
    return build_gitleaks_adversarial_report(
        _manifest(),
        evaluation,
        _proof(evaluation),
    )


def _case(evaluation: GitleaksAdversarialEvaluation, case_id: str):
    return next(case for case in evaluation.cases if case.case_id == case_id)


def test_exact_all_pass_evaluation_and_case_accounting() -> None:
    evaluation = _evaluate(_all_pass_findings())

    assert len(evaluation.cases) == 13
    assert evaluation.pass_count == 13
    assert evaluation.fail_count == 0
    assert evaluation.parsed_finding_count == 5
    assert all(case.result == GitleaksAdversarialCaseResultValue.PASS for case in evaluation.cases)
    assert evaluation.unexpected_cross_rule_observations == ()
    assert evaluation.unexpected_detection_kind_observations == ()


def test_expected_observed_missing_and_expected_absent_observed_fail() -> None:
    empty = _evaluate()
    observed_absent = _evaluate(
        (
            _finding(
                "adversarial-corpus/generic-api-key/low-entropy.txt",
                "generic-api-key",
                GitleaksDetectionKind.CONTENT,
            ),
        )
    )

    assert _case(empty, "generic-high-entropy-control").result == "FAIL"
    assert _case(empty, "generic-low-entropy").result == "PASS"
    assert _case(observed_absent, "generic-low-entropy").result == "FAIL"


def test_duplicate_intended_observations_are_preserved_but_one_case_relation() -> None:
    finding = _finding(
        "adversarial-corpus/generic-api-key/high-entropy-control.txt",
        "generic-api-key",
        GitleaksDetectionKind.CONTENT,
    )
    evaluation = _evaluate((finding, finding))
    case = _case(evaluation, "generic-high-entropy-control")

    assert case.result == "PASS"
    assert case.matching_observation_count == 2
    assert len(case.matching_finding_instance_ids) == 2
    assert len(set(case.matching_finding_instance_ids)) == 1


def test_same_rule_wrong_kind_is_only_a_detection_kind_observation() -> None:
    finding = _finding(
        "adversarial-corpus/generic-api-key/high-entropy-control.txt",
        "generic-api-key",
        GitleaksDetectionKind.PATH,
    )
    evaluation = _evaluate((finding,))

    assert _case(evaluation, "generic-high-entropy-control").result == "FAIL"
    assert evaluation.unexpected_cross_rule_observations == ()
    assert len(evaluation.unexpected_detection_kind_observations) == 1
    unexpected = evaluation.unexpected_detection_kind_observations[0]
    assert unexpected.rule_id == "generic-api-key"
    assert unexpected.detection_kind is GitleaksDetectionKind.PATH
    assert unexpected.location is None


def test_wrong_rule_same_kind_is_only_a_cross_rule_observation() -> None:
    finding = _finding(
        "adversarial-corpus/generic-api-key/high-entropy-control.txt",
        "different-valid-rule",
        GitleaksDetectionKind.CONTENT,
    )
    evaluation = _evaluate((finding,))

    assert _case(evaluation, "generic-high-entropy-control").result == "FAIL"
    assert len(evaluation.unexpected_cross_rule_observations) == 1
    assert evaluation.unexpected_detection_kind_observations == ()
    unexpected = evaluation.unexpected_cross_rule_observations[0]
    assert unexpected.rule_id == "different-valid-rule"
    assert unexpected.detection_kind is GitleaksDetectionKind.CONTENT
    assert unexpected.location is not None


def test_wrong_rule_and_wrong_kind_is_only_a_cross_rule_observation() -> None:
    finding = _finding(
        "adversarial-corpus/generic-api-key/high-entropy-control.txt",
        "different-valid-rule",
        GitleaksDetectionKind.PATH,
    )
    evaluation = _evaluate((finding,))

    assert _case(evaluation, "generic-high-entropy-control").result == "FAIL"
    assert len(evaluation.unexpected_cross_rule_observations) == 1
    assert evaluation.unexpected_detection_kind_observations == ()
    unexpected = evaluation.unexpected_cross_rule_observations[0]
    assert unexpected.rule_id == "different-valid-rule"
    assert unexpected.detection_kind is GitleaksDetectionKind.PATH
    assert unexpected.location is None


def test_cross_rule_observation_does_not_invalidate_expected_absence() -> None:
    finding = _finding(
        "adversarial-corpus/generic-api-key/low-entropy.txt",
        "different-valid-rule",
        GitleaksDetectionKind.CONTENT,
    )
    evaluation = _evaluate((finding,))

    assert _case(evaluation, "generic-low-entropy").result == "PASS"
    assert len(evaluation.unexpected_cross_rule_observations) == 1
    assert evaluation.unexpected_detection_kind_observations == ()


def test_detection_kind_observation_does_not_invalidate_expected_absence() -> None:
    finding = _finding(
        "adversarial-corpus/generic-api-key/low-entropy.txt",
        "generic-api-key",
        GitleaksDetectionKind.PATH,
    )
    evaluation = _evaluate((finding,))

    assert _case(evaluation, "generic-low-entropy").result == "PASS"
    assert evaluation.unexpected_cross_rule_observations == ()
    assert len(evaluation.unexpected_detection_kind_observations) == 1


def test_intended_and_unexpected_categories_account_for_every_finding_once() -> None:
    relative_path = "adversarial-corpus/generic-api-key/high-entropy-control.txt"
    findings = (
        _finding(relative_path, "generic-api-key", GitleaksDetectionKind.CONTENT),
        _finding(relative_path, "generic-api-key", GitleaksDetectionKind.PATH),
        _finding(relative_path, "different-valid-rule", GitleaksDetectionKind.CONTENT),
        _finding(relative_path, "another-valid-rule", GitleaksDetectionKind.PATH),
    )
    evaluation = _evaluate(findings)
    case = _case(evaluation, "generic-high-entropy-control")

    assert evaluation.parsed_finding_count == 4
    assert case.matching_observation_count == 1
    assert len(evaluation.unexpected_cross_rule_observations) == 2
    assert len(evaluation.unexpected_detection_kind_observations) == 1
    assert (
        case.matching_observation_count
        + len(evaluation.unexpected_cross_rule_observations)
        + len(evaluation.unexpected_detection_kind_observations)
        == evaluation.parsed_finding_count
    )
    assert {
        row.finding_instance_id for row in evaluation.unexpected_cross_rule_observations
    }.isdisjoint(
        row.finding_instance_id
        for row in evaluation.unexpected_detection_kind_observations
    )


def test_unexpected_observation_canonical_ordering_is_deterministic() -> None:
    relative_path = "adversarial-corpus/generic-api-key/high-entropy-control.txt"
    findings = (
        _finding(relative_path, "z-rule", GitleaksDetectionKind.PATH),
        _finding(relative_path, "generic-api-key", GitleaksDetectionKind.PATH),
        _finding(relative_path, "a-rule", GitleaksDetectionKind.CONTENT),
    )

    assert _report(findings).canonical_json() == _report(tuple(reversed(findings))).canonical_json()


def test_content_and_path_location_semantics_are_preserved() -> None:
    content = _finding(
        "adversarial-corpus/generic-api-key/high-entropy-control.txt",
        "different-valid-rule",
        GitleaksDetectionKind.CONTENT,
        start_line=2,
        end_line=3,
        start_column=4,
        end_column=8,
    )
    path = _finding(
        "adversarial-corpus/pkcs12-file/one-byte.p12",
        "different-valid-rule",
        GitleaksDetectionKind.PATH,
    )
    rows = _evaluate((content, path)).unexpected_cross_rule_observations
    by_kind = {row.detection_kind: row for row in rows}

    assert by_kind[GitleaksDetectionKind.PATH].location is None
    assert by_kind[GitleaksDetectionKind.CONTENT].location.canonical_data() == {
        "end_column": 8,
        "end_line": 3,
        "start_column": 4,
        "start_line": 2,
    }


def test_unknown_path_and_failed_statuses_fail_closed() -> None:
    with pytest.raises(GitleaksAdversarialBenchmarkError):
        _evaluate(
            (
                _finding(
                    "adversarial-corpus/unknown.txt",
                    "generic-api-key",
                    GitleaksDetectionKind.CONTENT,
                ),
            )
        )
    for status, code in (
        (GitleaksExecutionStatus.FAILED, 2),
        (GitleaksExecutionStatus.TIMED_OUT, -1),
        (GitleaksExecutionStatus.CANCELLED, -1),
        (GitleaksExecutionStatus.OUTPUT_LIMIT_EXCEEDED, -1),
    ):
        with pytest.raises(GitleaksAdversarialBenchmarkError):
            evaluate_gitleaks_adversarial(
                _manifest(),
                _parse(),
                execution_status=status,
                return_code=code,
            )


def test_canonical_result_is_deterministic_safe_and_has_no_accuracy_metrics() -> None:
    findings = _all_pass_findings()
    first = _report(findings)
    second = _report(tuple(reversed(findings)))
    payload = first.canonical_json()
    document = json.loads(payload)

    assert payload == second.canonical_json()
    assert document["schema_version"] == GITLEAKS_ADVERSARIAL_RESULT_SCHEMA_VERSION
    assert document["adversarial_id"] == GITLEAKS_ADVERSARIAL_ID
    assert document["case_count"] == 13
    assert document["pass_count"] == 13
    assert document["fail_count"] == 0
    assert document["contract_sha256"] == GITLEAKS_ADVERSARIAL_CONTRACT_SHA256
    assert document["manifest_sha256"] == GITLEAKS_ADVERSARIAL_MANIFEST_SHA256
    assert document["f3b_baseline_sha256"] == GITLEAKS_F3B_BASELINE_SHA256
    assert document["f4a_baseline_commit"] == "526ce3192885c6fc04ae8b7ac84346466809ca4e"
    assert document["f4a_baseline_tag"] == "source-v0.4F4A-gitleaks-adversarial-prescan"
    assert document["f3b_baseline_commit"] == "d183336c129977c4279cd1058bbe060742de0e54"
    assert document["f3b_baseline_tag"] == "source-v0.4F3B-gitleaks-initial-baseline"
    assert "baseline_commit" not in document
    assert "baseline_tag" not in document
    assert document["unexpected_cross_rule_observations"] == []
    assert document["unexpected_detection_kind_observations"] == []

    def keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value) | set().union(*(keys(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(keys(item) for item in value))
        return set()

    assert not {
        "precision",
        "recall",
        "f1",
        "tp",
        "tn",
        "fp",
        "fn",
        "Secret",
        "Match",
        "Fingerprint",
        "raw_stdout",
        "raw_stderr",
        "projection_id",
        "projection_digest",
        "context_digest",
        "parse_result_digest",
    } & keys(document)
    assert str(ROOT).encode() not in payload
    assert b"ghp_" not in payload


def test_evidence_is_frozen_and_proof_cannot_cross_finding_sets() -> None:
    first = _evaluate(
        (
            _finding(
                "adversarial-corpus/generic-api-key/high-entropy-control.txt",
                "generic-api-key",
                GitleaksDetectionKind.CONTENT,
            ),
        )
    )
    second = _evaluate(
        (
            _finding(
                "adversarial-corpus/scope/docs/secret.txt",
                "github-pat",
                GitleaksDetectionKind.CONTENT,
            ),
        )
    )

    assert build_gitleaks_adversarial_report(_manifest(), first, _proof(first))
    with pytest.raises(GitleaksAdversarialBenchmarkError):
        build_gitleaks_adversarial_report(_manifest(), second, _proof(first))
    with pytest.raises(FrozenInstanceError):
        first.pass_count = 0  # type: ignore[misc]
    assert first.parse_result_digest not in repr(first)


class _Handle:
    def __init__(self, result: CancellableProcessResult) -> None:
        self.result = result

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def wait(self, timeout_seconds: float | None = None):
        return self.result

    def poll(self):
        return self.result

    def terminate(self) -> None:
        pass

    def kill(self) -> None:
        pass

    def close(self) -> None:
        pass


class _Executor:
    def __init__(self, result: CancellableProcessResult) -> None:
        self.result = result
        self.requests: list[CancellableProcessRequest] = []

    def start(self, request: CancellableProcessRequest):
        self.requests.append(request)
        if request.argv[1] == "version":
            return _Handle(_process_result(stdout=b"8.30.1\n"))
        return _Handle(self.result)


def _process_result(
    *,
    return_code: int = 0,
    stdout: bytes = b"[]\n",
    stderr: bytes = b"",
    timed_out: bool = False,
    output_limit_exceeded: bool = False,
    termination_requested: bool = False,
) -> CancellableProcessResult:
    return CancellableProcessResult(
        return_code=return_code,
        stdout=stdout,
        stderr=stderr,
        duration_ms=1,
        timed_out=timed_out,
        output_limit_exceeded=output_limit_exceeded,
        termination_requested=termination_requested,
        force_killed=False,
    )


def _fake_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> TrustedGitleaksBinding:
    executable = (tmp_path / "trusted/gitleaks").resolve()
    executable.parent.mkdir()
    executable.write_bytes(b"test-only-not-executed")
    executable.chmod(0o700)
    identity = object()
    monkeypatch.setattr(
        binding_module,
        "_verify_regular_file",
        lambda *_args, **_kwargs: identity,
    )
    return create_default_gitleaks_binding(executable)


def _scanner_all_pass() -> bytes:
    rows = []
    for finding in _all_pass_findings():
        row: dict[str, object] = {
            "File": finding.file_path,
            "Match": "REDACTED",
            "RuleID": finding.rule_id,
            "Secret": "REDACTED",
        }
        if finding.detection_kind is GitleaksDetectionKind.CONTENT:
            row["StartLine"] = 1
        else:
            row.update(StartLine=0, EndLine=0, StartColumn=0, EndColumn=0)
        rows.append(row)
    return json.dumps(rows, separators=(",", ":"), sort_keys=True).encode()


def test_fake_controlled_run_traverses_bridge_confidentiality_parser_and_evaluator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _fake_binding(tmp_path, monkeypatch)
    executor = _Executor(_process_result(return_code=1, stdout=_scanner_all_pass()))

    report = _run_with_dependencies(ROOT.resolve(), binding, executor)

    assert report.pass_count == 13
    assert report.fail_count == 0
    assert len(executor.requests) == 2
    assert executor.requests[0].argv == (str(binding.executable_path), "version")
    assert executor.requests[1].argv[1] == "dir"
    assert executor.requests[1].environment == {}
    assert executor.requests[1].argv[-1].endswith("/source")
    assert str(executor.requests[1].argv[-1]) not in report.canonical_json().decode()


@pytest.mark.parametrize(
    "result",
    (
        _process_result(return_code=2),
        _process_result(return_code=-1, timed_out=True),
        _process_result(return_code=-1, output_limit_exceeded=True),
        _process_result(return_code=-1, termination_requested=True),
        _process_result(return_code=1, stdout=b"not-json"),
        _process_result(
            return_code=1,
            stdout=b'[{"File":"scope/docs/secret.txt","RuleID":"github-pat","Secret":"raw","Match":"REDACTED","StartLine":1}]',
        ),
        _process_result(
            return_code=1,
            stdout=b'[{"File":"unknown.txt","RuleID":"github-pat","Secret":"REDACTED","Match":"REDACTED","StartLine":1}]',
        ),
    ),
)
def test_fake_failed_or_invalid_execution_cannot_produce_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    result: CancellableProcessResult,
) -> None:
    binding = _fake_binding(tmp_path, monkeypatch)
    with pytest.raises(GitleaksAdversarialBenchmarkError):
        _run_with_dependencies(ROOT.resolve(), binding, _Executor(result))


def test_raw_projection_sentinel_leak_fails_confidentiality(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _fake_binding(tmp_path, monkeypatch)
    raw = (ROOT / GITLEAKS_ADVERSARIAL_CORPUS_PATH / "scope/docs/secret.txt").read_bytes()

    with pytest.raises(
        GitleaksAdversarialConfidentialityError,
        match="^Gitleaks adversarial confidentiality validation failed$",
    ) as raised:
        _run_with_dependencies(
            ROOT.resolve(),
            binding,
            _Executor(_process_result(return_code=1, stdout=raw)),
        )
    assert raw.decode().strip() not in str(raised.value)


def _copy_checkpoint(tmp_path: Path) -> Path:
    root = (tmp_path / "repository").resolve()
    destination = root / "benchmarks/gitleaks"
    destination.mkdir(parents=True)
    for relative in (
        GITLEAKS_ADVERSARIAL_CONTRACT_PATH,
        GITLEAKS_ADVERSARIAL_MANIFEST_PATH,
        GITLEAKS_F3B_BASELINE_PATH,
    ):
        shutil.copy2(ROOT / relative, destination / Path(relative).name)
    shutil.copytree(
        ROOT / GITLEAKS_ADVERSARIAL_CORPUS_PATH,
        destination / "adversarial-corpus",
    )
    return root


@pytest.mark.parametrize("entry_kind", ("file", "directory", "valid-symlink", "broken-symlink"))
def test_record_refuses_every_existing_result_entry(
    tmp_path: Path,
    entry_kind: str,
) -> None:
    root = _copy_checkpoint(tmp_path)
    destination = root / GITLEAKS_ADVERSARIAL_RESULT_PATH
    if entry_kind == "file":
        destination.write_bytes(b"existing")
    elif entry_kind == "directory":
        destination.mkdir()
    elif entry_kind == "valid-symlink":
        target = tmp_path / "target"
        target.write_bytes(b"target")
        destination.symlink_to(target)
    else:
        destination.symlink_to(tmp_path / "missing")

    with pytest.raises(GitleaksAdversarialBenchmarkError):
        record_gitleaks_adversarial_report(root, _report())


def test_record_is_atomic_and_race_never_replaces_other_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_root = _copy_checkpoint(tmp_path / "first")
    report = _report()
    destination = record_gitleaks_adversarial_report(first_root, report)
    assert destination.read_bytes() == report.canonical_json()

    race_root = _copy_checkpoint(tmp_path / "race")
    race_destination = race_root / GITLEAKS_ADVERSARIAL_RESULT_PATH
    real_link = benchmark.os.link

    def racing_link(source, target, *, follow_symlinks: bool) -> None:
        Path(target).write_bytes(b"concurrent evidence\n")
        real_link(source, target, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(benchmark.os, "link", racing_link)
    with pytest.raises(GitleaksAdversarialBenchmarkError):
        record_gitleaks_adversarial_report(race_root, report)
    assert race_destination.read_bytes() == b"concurrent evidence\n"


def test_check_verifies_runtime_without_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = (tmp_path / "gitleaks").resolve()
    calls = []

    def verify_runtime(self, executor=None) -> None:
        calls.append(self.executable_path)

    monkeypatch.setattr(TrustedGitleaksBinding, "verify_runtime", verify_runtime)
    result = check_controlled_gitleaks_adversarial(ROOT.resolve(), executable)

    assert calls == [executable]
    assert result["runtime_verified"] is True
    assert result["case_count"] == 13


def test_cli_report_does_not_write_and_runner_has_no_direct_scanner_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path.resolve()
    executable = (tmp_path / "gitleaks").resolve()
    report = _report()
    monkeypatch.setattr(gitleaks_adversarial_cli, "repository_root", lambda: root)
    monkeypatch.setattr(
        gitleaks_adversarial_cli,
        "run_controlled_gitleaks_adversarial",
        lambda *_args: report,
    )

    assert gitleaks_adversarial_cli.main(["report", "--gitleaks", str(executable)]) == 0
    output = capfd.readouterr()
    assert json.loads(output.out)["schema_version"] == (GITLEAKS_ADVERSARIAL_RESULT_SCHEMA_VERSION)
    assert not os.path.lexists(root / GITLEAKS_ADVERSARIAL_RESULT_PATH)

    runner = (ROOT / "scripts/run-gitleaks-adversarial.sh").read_text()
    assert "gitleaks dir" not in runner
    assert runner.count(".venv/bin/python") == 1
    assert "check|test|report|record)" in runner


def test_f4b1_repository_has_no_result() -> None:
    assert not os.path.lexists(ROOT / GITLEAKS_ADVERSARIAL_RESULT_PATH)
    assert (
        hashlib.sha256((ROOT / GITLEAKS_F3B_BASELINE_PATH).read_bytes()).hexdigest()
        == GITLEAKS_F3B_BASELINE_SHA256
    )
