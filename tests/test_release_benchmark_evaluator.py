from __future__ import annotations

from dataclasses import replace

from securescan.release.benchmark import (
    CURATED_LIMITATIONS,
    benchmark_results_repeatable,
    curated_acceptance_passes,
    evaluate_benchmark_case,
    observations_from_report,
)
from securescan.release.models import BenchmarkExpectation, BenchmarkObservation


def _expected(rule: str, path: str, line: int) -> BenchmarkExpectation:
    return BenchmarkExpectation(rule_id=rule, relative_path=path, start_line=line)


def _observed(
    rule: str,
    path: str,
    line: int,
    fingerprint: str,
) -> BenchmarkObservation:
    return BenchmarkObservation(
        fingerprint=fingerprint,
        rule_id=rule,
        relative_path=path,
        start_line=line,
        severity="high",
    )


EXPECTED = (
    _expected("securescan.python.dangerous-eval", "eval_case.py", 5),
    _expected("securescan.python.subprocess-shell-true", "shell_case.py", 7),
    _expected("securescan.python.unsafe-yaml-load", "yaml_case.py", 7),
)
OBSERVED = tuple(
    _observed(item.rule_id, item.relative_path, item.start_line, f"{index}" * 64)
    for index, item in enumerate(EXPECTED, start=1)
)


def _case(
    *,
    expected: tuple[BenchmarkExpectation, ...] = EXPECTED,
    observed: tuple[BenchmarkObservation, ...] = OBSERVED,
    artifacts: int = 1,
):
    return evaluate_benchmark_case(
        case_id="vulnerable" if expected else "clean",
        corpus_digest="a" * 64,
        expected_findings=expected,
        observed_findings=observed,
        analysis_gap_count=0,
        raw_artifact_count=artifacts,
    )


def test_evaluator_reports_perfect_curated_vulnerable_metrics() -> None:
    metrics = _case().metrics

    assert (metrics.true_positives, metrics.false_positives, metrics.false_negatives) == (
        3,
        0,
        0,
    )
    assert (metrics.precision, metrics.recall, metrics.f1_score) == (1.0, 1.0, 1.0)


def test_evaluator_reports_false_positive_and_false_negative_metrics() -> None:
    observed = (
        OBSERVED[0],
        _observed("securescan.python.extra", "extra.py", 9, "f" * 64),
    )
    metrics = _case(observed=observed).metrics

    assert (metrics.true_positives, metrics.false_positives, metrics.false_negatives) == (
        1,
        1,
        2,
    )
    assert metrics.precision == 0.5
    assert metrics.recall == 1 / 3
    assert metrics.f1_score == 0.4


def test_evaluator_handles_empty_expected_and_observed_sets() -> None:
    empty = _case(expected=(), observed=()).metrics
    unexpected = _case(expected=(), observed=(OBSERVED[0],)).metrics
    missing = _case(expected=(EXPECTED[0],), observed=()).metrics

    assert (empty.precision, empty.recall, empty.f1_score) == (1.0, 1.0, 1.0)
    assert (unexpected.precision, unexpected.recall, unexpected.f1_score) == (
        0.0,
        1.0,
        0.0,
    )
    assert (missing.precision, missing.recall, missing.f1_score) == (1.0, 0.0, 0.0)


def test_evaluator_matching_ignores_order_message_and_scanner_fingerprint() -> None:
    reports = []
    for order, suffix in ((reversed(EXPECTED), "a"), (EXPECTED, "b")):
        reports.append(
            {
                "observations": [
                    {
                        "fingerprint": suffix * 64,
                        "rule_id": item.rule_id,
                        "path": item.relative_path,
                        "start_line": item.start_line,
                        "native_severity": "high",
                        "message": f"hostile scanner message {suffix}",
                    }
                    for item in order
                ]
            }
        )

    first = _case(observed=observations_from_report(reports[0]))
    second = _case(observed=observations_from_report(reports[1]))

    assert first.metrics == second.metrics
    assert first.metrics.true_positives == 3


def test_repeatability_requires_equal_fingerprints_order_and_metrics() -> None:
    first = _case()
    identical = _case(observed=tuple(reversed(OBSERVED)))
    changed_fingerprint = _case(
        observed=(replace(OBSERVED[0], fingerprint="f" * 64), *OBSERVED[1:])
    )

    assert benchmark_results_repeatable(
        first,
        identical,
        first_repository_digest="c" * 64,
        repeated_repository_digest="c" * 64,
    )
    assert not benchmark_results_repeatable(
        first,
        changed_fingerprint,
        first_repository_digest="c" * 64,
        repeated_repository_digest="c" * 64,
    )
    assert not benchmark_results_repeatable(
        first,
        identical,
        first_repository_digest="c" * 64,
        repeated_repository_digest="d" * 64,
    )


def test_release_acceptance_is_limited_to_curated_baseline_scope() -> None:
    vulnerable = _case()
    clean = _case(expected=(), observed=())

    assert curated_acceptance_passes(vulnerable, clean)
    assert not curated_acceptance_passes(
        _case(expected=EXPECTED[:2], observed=OBSERVED[:2]),
        clean,
    )
    assert any("exactly three Python demonstration rules" in item for item in CURATED_LIMITATIONS)
