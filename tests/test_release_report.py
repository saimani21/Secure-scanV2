from __future__ import annotations

import json
from dataclasses import replace

from securescan.release.benchmark import CORE_BENCHMARK_ID, CORE_RELEASE_VERSION
from securescan.release.core_v01 import run_cli
from securescan.release.models import (
    BenchmarkCaseResult,
    BenchmarkMetrics,
    BenchmarkObservation,
    CoreReleaseEvaluation,
)
from securescan.release.report import (
    canonical_release_json,
    release_evidence_digest,
    render_release_markdown,
)

HOSTILE_VALUES = (
    "postgresql://user:password@host/database",
    "token=secret-value",
    "/home/private/repository",
    "/var/run/docker.sock",
    f"semgrep/semgrep@sha256:{'d' * 64}",
    "securescan-container-secret",
)


def _case(case_id: str, *, finding: bool) -> BenchmarkCaseResult:
    observations = (
        BenchmarkObservation(
            fingerprint="a" * 64,
            rule_id="securescan.python.dangerous-eval",
            relative_path="eval_case.py",
            start_line=5,
            severity="high",
        ),
    ) if finding else ()
    return BenchmarkCaseResult(
        case_id=case_id,
        corpus_digest=("b" if finding else "c") * 64,
        expected_findings=(),
        observed_findings=observations,
        metrics=BenchmarkMetrics(
            0,
            int(finding),
            0,
            0.0 if finding else 1.0,
            1.0,
            0.0 if finding else 1.0,
        ),
        analysis_gap_count=0,
        raw_artifact_count=1,
        deterministic=True,
    )


def _evaluation() -> CoreReleaseEvaluation:
    vulnerable = _case("vulnerable", finding=True)
    clean = _case("clean", finding=False)
    limitations = ("Curated three-rule micro-benchmark only.",)
    digest = release_evidence_digest(
        release_version=CORE_RELEASE_VERSION,
        benchmark_id=CORE_BENCHMARK_ID,
        vulnerable_case=vulnerable,
        clean_case=clean,
        repeatability_verified=True,
        acceptance_passed=False,
        limitations=limitations,
    )
    return CoreReleaseEvaluation(
        release_version=CORE_RELEASE_VERSION,
        benchmark_id=CORE_BENCHMARK_ID,
        vulnerable_case=vulnerable,
        clean_case=clean,
        repeatability_verified=True,
        acceptance_passed=False,
        limitations=limitations,
        release_evidence_digest=digest,
    )


def test_release_json_report_is_canonical_and_hides_sensitive_values(
    capsys,
) -> None:
    first = canonical_release_json(_evaluation())
    second = canonical_release_json(_evaluation())
    parsed = json.loads(first)

    assert first == second
    assert first.endswith(b"\n")
    assert parsed["schema_version"] == "1.0.0"
    for hostile in HOSTILE_VALUES:
        assert hostile.encode() not in first

    exit_code = run_cli(
        [
            "--corpus-root",
            HOSTILE_VALUES[2],
            "--output-directory",
            "/tmp/securescan-release-public-output",
            "--semgrep-image",
            HOSTILE_VALUES[4],
            "--workspace-base",
            "/tmp/securescan-release-public-workspace",
        ]
    )
    public_error = capsys.readouterr().out
    assert exit_code != 0
    for hostile in HOSTILE_VALUES:
        assert hostile not in public_error


def test_release_markdown_states_scope_metrics_and_limitations() -> None:
    markdown = render_release_markdown(_evaluation())

    assert "100% precision and recall on the bundled three-rule curated micro-benchmark" in markdown
    assert "Known limitations" in markdown
    assert "Curated three-rule micro-benchmark only." in markdown
    assert "universal 100%" not in markdown


def test_release_evidence_digest_is_deterministic_and_sensitive() -> None:
    evaluation = _evaluation()
    arguments = {
        "release_version": evaluation.release_version,
        "benchmark_id": evaluation.benchmark_id,
        "vulnerable_case": evaluation.vulnerable_case,
        "clean_case": evaluation.clean_case,
        "repeatability_verified": evaluation.repeatability_verified,
        "acceptance_passed": evaluation.acceptance_passed,
        "limitations": evaluation.limitations,
    }

    first = release_evidence_digest(**arguments)
    assert first == release_evidence_digest(**arguments)
    changed = release_evidence_digest(
        **{
            **arguments,
            "clean_case": replace(
                evaluation.clean_case,
                corpus_digest="e" * 64,
            ),
        }
    )
    assert changed != first
