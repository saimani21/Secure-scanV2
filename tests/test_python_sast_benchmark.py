from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from securescan.benchmarks import python_sast_cli
from securescan.benchmarks.python_sast import (
    BENCHMARK_ID,
    EXPECTED_SCANNER_VERSION,
    PRODUCTION_RULE_IDS,
    SCANNER_ID,
    BenchmarkMetrics,
    calculate_corpus_digest,
    calculate_metrics,
    canonical_benchmark_report,
    classify_case,
    evaluate_benchmark,
    load_benchmark_manifest,
    run_frozen_semgrep_benchmark,
)

ROOT = Path(__file__).parent.parent
BENCHMARK_ROOT = ROOT / "benchmarks/python_sast"
MANIFEST = BENCHMARK_ROOT / "manifest.json"
UNCONTROLLED_REPORT = (
    BENCHMARK_ROOT / "initial-v0.3e-uncontrolled-observation.json"
)
CONTROLLED_REPORT = BENCHMARK_ROOT / "initial-v0.3e-baseline.json"
RUNNER = ROOT / "scripts/run-python-sast-benchmark.sh"
CORPUS_DIGEST = "2a3b3a3b001ce251a5fceafc82cfd1a1599cd9d8d3d6a81de424ae393113adec"


def _copied_manifest(tmp_path: Path) -> Path:
    destination = tmp_path / "python_sast"
    shutil.copytree(BENCHMARK_ROOT, destination)
    return destination / "manifest.json"


def _rewrite(path: Path, document: dict[str, object]) -> None:
    path.write_text(
        json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def test_manifest_is_independent_complete_and_content_addressed() -> None:
    manifest = load_benchmark_manifest(MANIFEST)

    assert manifest.benchmark_id == BENCHMARK_ID
    assert len(manifest.cases) == 102
    assert manifest.corpus_digest == CORPUS_DIGEST
    assert calculate_corpus_digest(manifest) == CORPUS_DIGEST
    assert {case.rule_id for case in manifest.cases} == PRODUCTION_RULE_IDS
    for rule_id in PRODUCTION_RULE_IDS:
        cases = [case for case in manifest.cases if case.rule_id == rule_id]
        assert sum(case.expected_match for case in cases) == 3
        assert sum(not case.expected_match for case in cases) == 3
    assert all("tests/fixtures" not in case.relative_path for case in manifest.cases)


@pytest.mark.parametrize(
    ("expected", "observed", "classification"),
    (
        (True, True, "TP"),
        (True, False, "FN"),
        (False, True, "FP"),
        (False, False, "TN"),
    ),
)
def test_case_classification_is_explicit(
    expected: bool,
    observed: bool,
    classification: str,
) -> None:
    assert classify_case(expected, observed) == classification


def test_metrics_include_tn_and_use_fixed_decimal_rounding() -> None:
    metrics = calculate_metrics(("TP",) * 16 + ("FP",) + ("FN",) + ("TN",) * 3)

    assert metrics == BenchmarkMetrics(
        tp=16,
        fp=1,
        fn=1,
        tn=3,
        precision="0.9412",
        recall="0.9412",
        f1="0.9412",
    )
    assert calculate_metrics(("TN",)).precision is None


def test_per_rule_aggregation_counts_each_case_relation_once() -> None:
    manifest = load_benchmark_manifest(MANIFEST)
    observed = (
        (case.relative_path, case.rule_id)
        for case in manifest.cases
        if case.expected_match
    )

    evaluation = evaluate_benchmark(manifest, observed)
    repeated = tuple(
        (case.relative_path, case.rule_id)
        for case in manifest.cases
        if case.expected_match
    ) * 2

    assert evaluation.overall == BenchmarkMetrics(
        tp=51,
        fp=0,
        fn=0,
        tn=51,
        precision="1.0000",
        recall="1.0000",
        f1="1.0000",
    )
    assert evaluate_benchmark(manifest, repeated).overall == evaluation.overall
    assert len(evaluation.per_rule) == 17
    assert all(
        metrics
        == BenchmarkMetrics(
            tp=3,
            fp=0,
            fn=0,
            tn=3,
            precision="1.0000",
            recall="1.0000",
            f1="1.0000",
        )
        for _, metrics in evaluation.per_rule
    )


def test_unexpected_cross_rule_match_is_reported_separately() -> None:
    manifest = load_benchmark_manifest(MANIFEST)
    case = next(
        item
        for item in manifest.cases
        if item.rule_id == "securescan.python.dangerous-eval"
        and not item.expected_match
    )

    evaluation = evaluate_benchmark(
        manifest,
        ((case.relative_path, "securescan.python.os-system"),),
    )

    result = next(item for item in evaluation.cases if item.case_id == case.case_id)
    assert result.classification == "TN"
    assert evaluation.unexpected_matches == (
        (case.case_id, "securescan.python.os-system"),
    )


def test_unknown_observed_rule_and_path_fail_closed() -> None:
    manifest = load_benchmark_manifest(MANIFEST)
    case = manifest.cases[0]

    with pytest.raises(ValueError, match="observation is invalid"):
        evaluate_benchmark(manifest, ((case.relative_path, "unknown.rule"),))
    with pytest.raises(ValueError, match="observation is invalid"):
        evaluate_benchmark(manifest, (("corpus/missing.py", case.rule_id),))


@pytest.mark.parametrize(
    "mutation",
    (
        "unknown_field",
        "duplicate_case",
        "unknown_rule",
        "path_traversal",
        "invalid_expected_match",
        "missing_case_file",
        "corpus_digest_mismatch",
        "ruleset_digest_mismatch",
    ),
)
def test_malformed_manifest_fails_closed(tmp_path: Path, mutation: str) -> None:
    path = _copied_manifest(tmp_path)
    document = json.loads(path.read_text(encoding="utf-8"))
    cases = document["cases"]
    assert isinstance(cases, list)
    first = deepcopy(cases[0])
    assert isinstance(first, dict)
    if mutation == "unknown_field":
        document["unknown"] = True
    elif mutation == "duplicate_case":
        cases.append(first)
    elif mutation == "unknown_rule":
        first["rule_id"] = "securescan.python.unknown"
        cases[0] = first
    elif mutation == "path_traversal":
        first["relative_path"] = "corpus/../outside.py"
        cases[0] = first
    elif mutation == "invalid_expected_match":
        first["expected_match"] = "true"
        cases[0] = first
    elif mutation == "missing_case_file":
        (path.parent / first["relative_path"]).unlink()
    elif mutation == "corpus_digest_mismatch":
        document["corpus_digest"] = "0" * 64
    else:
        ruleset = document["ruleset"]
        assert isinstance(ruleset, dict)
        ruleset["digest"] = "0" * 64
    _rewrite(path, document)

    with pytest.raises(ValueError, match="manifest is invalid"):
        load_benchmark_manifest(path)


def test_report_is_deterministic_and_contains_no_host_paths_or_source() -> None:
    manifest = load_benchmark_manifest(MANIFEST)
    observed = tuple(
        (case.relative_path, case.rule_id)
        for case in manifest.cases
        if case.expected_match
    )
    first = canonical_benchmark_report(evaluate_benchmark(manifest, observed))
    second = canonical_benchmark_report(evaluate_benchmark(manifest, reversed(observed)))

    assert first == second
    assert str(ROOT).encode() not in first
    assert b"source_code" not in first
    report = json.loads(first)
    assert report["failures"] == []
    assert report["scanner_id"] == SCANNER_ID == "semgrep-ce"
    assert report["scanner_version"] == EXPECTED_SCANNER_VERSION == "1.171.0"
    assert report["unexpected_matches"] == []


@pytest.mark.parametrize(
    ("stdout", "message"),
    (
        (b"not-json", "output is invalid"),
        (
            b'{"errors":[{"type":"ParseError"}],"results":[],"version":"1.171.0"}',
            "output contains analysis gaps",
        ),
    ),
)
def test_malformed_output_and_scanner_gaps_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    stdout: bytes,
    message: str,
) -> None:
    manifest = load_benchmark_manifest(MANIFEST)
    monkeypatch.setattr(
        "securescan.benchmarks.python_sast.shutil.which",
        lambda _name: "/usr/bin/semgrep",
    )
    monkeypatch.setattr(
        "securescan.benchmarks.python_sast.subprocess.run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=("semgrep",),
            returncode=0,
            stdout=stdout,
            stderr=b"",
        ),
    )

    with pytest.raises(ValueError, match=message):
        run_frozen_semgrep_benchmark(ROOT, manifest)


def test_scanner_version_mismatch_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = load_benchmark_manifest(MANIFEST)
    monkeypatch.setattr(
        "securescan.benchmarks.python_sast.shutil.which",
        lambda _name: "/usr/bin/semgrep",
    )
    monkeypatch.setattr(
        "securescan.benchmarks.python_sast.subprocess.run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=("semgrep",),
            returncode=0,
            stdout=b'{"errors":[],"results":[],"version":"9.9.9"}',
            stderr=b"",
        ),
    )

    with pytest.raises(ValueError, match="scanner identity is invalid"):
        run_frozen_semgrep_benchmark(ROOT, manifest)
    with pytest.raises(ValueError, match="scanner identity is invalid"):
        evaluate_benchmark(manifest, (), scanner_id="other-scanner")


def test_semgrep_execution_uses_only_controlled_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = load_benchmark_manifest(MANIFEST)
    captured: dict[str, object] = {}

    def run(*args, **kwargs):
        captured["command"] = args[0]
        captured["environment"] = kwargs["env"]
        return subprocess.CompletedProcess(
            args=("semgrep",),
            returncode=0,
            stdout=(
                b'{"errors":[],"results":[],"version":"'
                + EXPECTED_SCANNER_VERSION.encode("ascii")
                + b'"}'
            ),
            stderr=b"",
        )

    monkeypatch.setenv("SEMGREP_FAKE_HOST_CONFIGURATION", "must-not-pass-through")
    monkeypatch.setattr(
        "securescan.benchmarks.python_sast.shutil.which",
        lambda _name: "/opt/semgrep/bin/semgrep",
    )
    monkeypatch.setattr(
        "securescan.benchmarks.python_sast.subprocess.run",
        run,
    )

    evaluation = run_frozen_semgrep_benchmark(ROOT, manifest)

    environment = captured["environment"]
    assert isinstance(environment, dict)
    assert set(environment) == {
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "SEMGREP_LOG_FILE",
        "SEMGREP_SETTINGS_FILE",
    }
    assert "SEMGREP_FAKE_HOST_CONFIGURATION" not in environment
    command = captured["command"]
    assert isinstance(command, list)
    assert "--metrics=off" in command
    assert "--disable-version-check" in command
    assert "--no-git-ignore" in command
    assert "--jobs=1" in command
    assert "--no-rewrite-rule-ids" in command
    assert evaluation.scanner_version == EXPECTED_SCANNER_VERSION


def test_uncontrolled_initial_observation_is_preserved_but_not_trusted() -> None:
    report = json.loads(UNCONTROLLED_REPORT.read_bytes())

    assert report["overall"] == {
        "f1": "1.0000",
        "fn": 0,
        "fp": 0,
        "precision": "1.0000",
        "recall": "1.0000",
        "tn": 51,
        "tp": 51,
    }
    assert "scanner_id" not in report
    assert "scanner_version" not in report


def test_installed_semgrep_must_match_trusted_version_for_baseline() -> None:
    if shutil.which("semgrep") is None:
        pytest.skip("local Semgrep CLI is unavailable")
    manifest = load_benchmark_manifest(MANIFEST)

    try:
        evaluation = run_frozen_semgrep_benchmark(ROOT, manifest)
    except ValueError as exc:
        assert "scanner identity is invalid" in str(exc)
        return
    assert evaluation.scanner_id == SCANNER_ID
    assert evaluation.scanner_version == EXPECTED_SCANNER_VERSION
    if CONTROLLED_REPORT.exists():
        assert canonical_benchmark_report(evaluation) == CONTROLLED_REPORT.read_bytes()


def _write_executable(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _runner_repository(
    tmp_path: Path,
    *,
    project_python: bool = True,
    semgrep_version: str | None = EXPECTED_SCANNER_VERSION,
) -> Path:
    repository = tmp_path / "repository"
    runner = repository / "scripts/run-python-sast-benchmark.sh"
    runner.parent.mkdir(parents=True)
    shutil.copy2(RUNNER, runner)
    if project_python:
        _write_executable(
            repository / ".venv/bin/python",
            "#!/bin/sh\n"
            'if [ "$1" = "--version" ]; then\n'
            '    echo "Python 3.12.3"\n'
            "else\n"
            '    echo "expected_scanner=semgrep-ce version=1.171.0"\n'
            '    echo "ruleset=securescan-python-baseline-v2 version=2 digest='
            'e10fb04e6b5abb35e0b83bdd718c2e973a8026e3630e420dc398db95e59d01a5"\n'
            '    echo "corpus_digest='
            '2a3b3a3b001ce251a5fceafc82cfd1a1599cd9d8d3d6a81de424ae393113adec"\n'
            "fi\n",
        )
    if semgrep_version is not None:
        _write_executable(
            repository / ".venv-semgrep-1.171/bin/semgrep",
            f"#!/bin/sh\necho '{semgrep_version}'\n",
        )
    return runner


@pytest.mark.parametrize(
    ("project_python", "semgrep_version", "expected_error"),
    (
        (False, EXPECTED_SCANNER_VERSION, "project Python is unavailable"),
        (True, None, "benchmark Semgrep is unavailable"),
        (True, "9.9.9", "Semgrep version mismatch"),
    ),
)
def test_runner_fails_for_missing_or_mismatched_environments(
    tmp_path: Path,
    project_python: bool,
    semgrep_version: str | None,
    expected_error: str,
) -> None:
    runner = _runner_repository(
        tmp_path,
        project_python=project_python,
        semgrep_version=semgrep_version,
    )

    result = subprocess.run(
        (runner, "check"),
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )

    assert result.returncode != 0
    assert expected_error in result.stderr


def test_runner_keeps_project_python_and_semgrep_environments_separate(
    tmp_path: Path,
) -> None:
    runner = _runner_repository(tmp_path)

    result = subprocess.run(
        (runner, "check"),
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0
    assert "/.venv/bin/python version=Python 3.12.3" in result.stdout
    assert "/.venv-semgrep-1.171/bin/semgrep version=1.171.0" in result.stdout
    assert "expected_scanner=semgrep-ce version=1.171.0" in result.stdout


def test_report_mode_prints_only_and_does_not_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    payload = b'{"controlled":true}\n'
    monkeypatch.setattr(python_sast_cli, "repository_root", lambda: tmp_path)
    monkeypatch.setattr(
        python_sast_cli,
        "benchmark_report",
        lambda _root: payload,
    )

    before = tuple(tmp_path.rglob("*"))
    assert python_sast_cli.main(["report"]) == 0
    after = tuple(tmp_path.rglob("*"))

    assert capfd.readouterr().out.encode() == payload
    assert after == before


def test_record_mode_preserves_uncontrolled_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    benchmark_root = tmp_path / "benchmarks/python_sast"
    benchmark_root.mkdir(parents=True)
    uncontrolled = benchmark_root / "initial-v0.3e-uncontrolled-observation.json"
    uncontrolled.write_bytes(b'{"historical":true}\n')
    historical_digest = hashlib.sha256(uncontrolled.read_bytes()).hexdigest()
    payload = b'{"scanner_id":"semgrep-ce","scanner_version":"1.171.0"}\n'
    monkeypatch.setattr(python_sast_cli, "repository_root", lambda: tmp_path)
    monkeypatch.setattr(
        python_sast_cli,
        "benchmark_report",
        lambda _root: payload,
    )

    assert python_sast_cli.main(["record"]) == 0

    assert (benchmark_root / "initial-v0.3e-baseline.json").read_bytes() == payload
    assert hashlib.sha256(uncontrolled.read_bytes()).hexdigest() == historical_digest
