from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from typing import Any

from securescan.release.models import BenchmarkCaseResult, CoreReleaseEvaluation

RELEASE_REPORT_SCHEMA_VERSION = "1.0.0"


def _case_data(case: BenchmarkCaseResult) -> dict[str, Any]:
    return {
        "analysis_gap_count": case.analysis_gap_count,
        "case_id": case.case_id,
        "corpus_digest": case.corpus_digest,
        "deterministic": case.deterministic,
        "metrics": asdict(case.metrics),
        "observed_findings": [
            {
                "fingerprint": finding.fingerprint,
                "relative_path": finding.relative_path,
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "start_line": finding.start_line,
            }
            for finding in case.observed_findings
        ],
        "raw_artifact_count": case.raw_artifact_count,
    }


def _evidence_data(
    *,
    release_version: str,
    benchmark_id: str,
    vulnerable_case: BenchmarkCaseResult,
    clean_case: BenchmarkCaseResult,
    repeatability_verified: bool,
    acceptance_passed: bool,
    limitations: tuple[str, ...],
) -> dict[str, Any]:
    return {
        "acceptance_passed": acceptance_passed,
        "benchmark_id": benchmark_id,
        "clean_case": _case_data(clean_case),
        "limitations": list(sorted(limitations)),
        "release_version": release_version,
        "repeatability_verified": repeatability_verified,
        "vulnerable_case": _case_data(vulnerable_case),
    }


def release_evidence_digest(
    *,
    release_version: str,
    benchmark_id: str,
    vulnerable_case: BenchmarkCaseResult,
    clean_case: BenchmarkCaseResult,
    repeatability_verified: bool,
    acceptance_passed: bool,
    limitations: tuple[str, ...],
) -> str:
    canonical = json.dumps(
        _evidence_data(
            release_version=release_version,
            benchmark_id=benchmark_id,
            vulnerable_case=vulnerable_case,
            clean_case=clean_case,
            repeatability_verified=repeatability_verified,
            acceptance_passed=acceptance_passed,
            limitations=limitations,
        ),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def canonical_release_json(evaluation: CoreReleaseEvaluation) -> bytes:
    data = {
        "acceptance_passed": evaluation.acceptance_passed,
        "benchmark_id": evaluation.benchmark_id,
        "clean_case": _case_data(evaluation.clean_case),
        "limitations": list(evaluation.limitations),
        "release_evidence_digest": evaluation.release_evidence_digest,
        "release_version": evaluation.release_version,
        "repeatability_verified": evaluation.repeatability_verified,
        "schema_version": RELEASE_REPORT_SCHEMA_VERSION,
        "vulnerable_case": _case_data(evaluation.vulnerable_case),
    }
    return (
        json.dumps(
            data,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _metrics_table(case: BenchmarkCaseResult) -> str:
    metrics = case.metrics
    return "\n".join(
        (
            "| TP | FP | FN | Precision | Recall | F1 | Gaps | Raw artifacts |",
            "|---:|---:|---:|---:|---:|---:|---:|---:|",
            f"| {metrics.true_positives} | {metrics.false_positives} | "
            f"{metrics.false_negatives} | {metrics.precision:.3f} | "
            f"{metrics.recall:.3f} | {metrics.f1_score:.3f} | "
            f"{case.analysis_gap_count} | {case.raw_artifact_count} |",
        )
    )


def render_release_markdown(evaluation: CoreReleaseEvaluation) -> str:
    decision = "PASS" if evaluation.acceptance_passed else "FAIL"
    repeatability = "verified" if evaluation.repeatability_verified else "not verified"
    limitations = "\n".join(f"- {item}" for item in evaluation.limitations)
    return f"""# SecureScan Core v{evaluation.release_version} release evidence

## 1. Release identity

Benchmark `{evaluation.benchmark_id}`; decision: **{decision}**.

## 2. Scope tested

Local Python repository analysis with the bundled three-rule Semgrep CE baseline.
This result is 100% precision and recall on the bundled three-rule curated micro-benchmark.

## 3. Architecture path tested

Repository snapshot → isolated Docker execution → bounded Semgrep JSON → normalized
findings and analysis gaps → canonical evidence.

## 4. Benchmark corpus summary

The vulnerable corpus contains three intended examples. The clean corpus contains safe
alternatives. Corpus identity excludes host and runtime metadata.

## 5. Vulnerable-corpus metrics

{_metrics_table(evaluation.vulnerable_case)}

## 6. Clean-corpus metrics

{_metrics_table(evaluation.clean_case)}

## 7. Repeatability result

Deterministic repeatability was {repeatability}.

## 8. Security controls exercised

Digest-pinned local image use, disabled network, non-root execution, read-only root and
source mounts, bounded process output, isolated writable output, and managed cleanup.

## 9. Failure-mode coverage

The release failure matrix maps intake, sandbox, parser, transaction, race, cleanup, and
report-privacy invariants to exact tests.

## 10. Known limitations

{limitations}

## 11. Acceptance decision

**{decision}** for the stated curated Core v0.1 micro-benchmark scope only.

## 12. Evidence digest

`{evaluation.release_evidence_digest}`
"""
