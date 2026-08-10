from __future__ import annotations

import shutil
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from securescan.release.benchmark import (
    CORE_BENCHMARK_ID,
    GroundTruth,
    calculate_corpus_digest,
    load_ground_truth,
)
from securescan.release.models import (
    BenchmarkCaseResult,
    BenchmarkExpectation,
    BenchmarkMetrics,
    BenchmarkObservation,
)

FIXTURES = Path(__file__).parent / "fixtures" / "release_benchmark"


def _expectation(path: str = "case.py", line: int = 4) -> BenchmarkExpectation:
    return BenchmarkExpectation(
        rule_id="securescan.python.dangerous-eval",
        relative_path=path,
        start_line=line,
    )


def _observation(path: str = "case.py", line: int = 4) -> BenchmarkObservation:
    return BenchmarkObservation(
        fingerprint="a" * 64,
        rule_id="securescan.python.dangerous-eval",
        relative_path=path,
        start_line=line,
        severity="high",
    )


def test_release_models_are_immutable_and_validate_consistency() -> None:
    metrics = BenchmarkMetrics(1, 0, 0, 1.0, 1.0, 1.0)
    result = BenchmarkCaseResult(
        case_id="vulnerable",
        corpus_digest="b" * 64,
        expected_findings=(_expectation(),),
        observed_findings=(_observation(),),
        metrics=metrics,
        analysis_gap_count=0,
        raw_artifact_count=1,
        deterministic=True,
    )

    with pytest.raises(FrozenInstanceError):
        result.case_id = "changed"  # type: ignore[misc]
    with pytest.raises(ValueError):
        BenchmarkMetrics(True, 0, 0, 1.0, 1.0, 1.0)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        _expectation("/home/private/repository")
    with pytest.raises(ValueError):
        BenchmarkObservation(
            fingerprint="NOT-A-DIGEST",
            rule_id="securescan.python.dangerous-eval",
            relative_path="case.py",
            start_line=1,
            severity="high",
        )


def test_ground_truth_is_canonical_and_matches_three_baseline_rules() -> None:
    ground_truth = load_ground_truth(FIXTURES / "ground_truth.json")

    assert ground_truth.benchmark_id == CORE_BENCHMARK_ID
    assert ground_truth.expected_finding_count == 3
    assert ground_truth.expected_clean_finding_count == 0
    assert {finding.rule_id for finding in ground_truth.expected_findings} == {
        "securescan.python.dangerous-eval",
        "securescan.python.subprocess-shell-true",
        "securescan.python.unsafe-yaml-load",
    }


def test_corpus_digest_is_stable_across_host_locations(tmp_path: Path) -> None:
    first = tmp_path / "host-a" / "corpus"
    second = tmp_path / "different-host-root" / "corpus"
    shutil.copytree(FIXTURES / "vulnerable", first)
    shutil.copytree(FIXTURES / "vulnerable", second)
    ground_truth = load_ground_truth(FIXTURES / "ground_truth.json")

    first_digest = calculate_corpus_digest(
        first,
        ground_truth,
        ground_truth.expected_findings,
    )
    second_digest = calculate_corpus_digest(
        second,
        ground_truth,
        ground_truth.expected_findings,
    )

    assert first_digest == second_digest


def test_corpus_digest_changes_for_content_path_or_ground_truth_change(
    tmp_path: Path,
) -> None:
    source = FIXTURES / "vulnerable"
    content_changed = tmp_path / "content"
    path_changed = tmp_path / "path"
    shutil.copytree(source, content_changed)
    shutil.copytree(source, path_changed)
    ground_truth = load_ground_truth(FIXTURES / "ground_truth.json")
    original = calculate_corpus_digest(source, ground_truth, ground_truth.expected_findings)

    (content_changed / "eval_case.py").write_text("value = 1\n", encoding="utf-8")
    (path_changed / "eval_case.py").rename(path_changed / "renamed.py")
    changed_truth = GroundTruth(
        schema_version=ground_truth.schema_version,
        benchmark_id=ground_truth.benchmark_id,
        expected_findings=(
            _expectation("eval_case.py", 6),
            *ground_truth.expected_findings[1:],
        ),
        expected_finding_count=3,
        expected_clean_finding_count=0,
    )

    assert calculate_corpus_digest(
        content_changed,
        ground_truth,
        ground_truth.expected_findings,
    ) != original
    assert calculate_corpus_digest(
        path_changed,
        ground_truth,
        ground_truth.expected_findings,
    ) != original
    assert calculate_corpus_digest(
        source,
        changed_truth,
        changed_truth.expected_findings,
    ) != original
