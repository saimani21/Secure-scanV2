from __future__ import annotations

import json
import platform
import resource
import statistics
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from securescan.product_release.ai import AIContextBuilder, AITask
from securescan.product_release.models import CIResult
from securescan.product_release.presentation import (
    canonical_json_bytes,
    render_assessment_html,
    render_ci_summary,
)


def controlled_dashboard(finding_count: int) -> dict[str, Any]:
    findings = [
        {
            "finding_id": f"{index:064x}",
            "category": "DEPENDENCY_VULNERABILITY",
            "delta_state": "INTRODUCED",
            "cve_state": "CVE-2026-1000:KEV=NOT_LISTED_IN_SNAPSHOT;EPSS=SCORED",
            "policy_impact": "BLOCKING",
        }
        for index in range(finding_count)
    ]
    return {
        "decision": "FAIL",
        "scope": {"project_id": "project", "lineage_id": "lineage", "run_id": "run"},
        "delta": {
            "comparison_status": "COMPLETE",
            "INTRODUCED": finding_count,
            "PRESENT": 0,
            "REMOVED": 0,
            "NOT_COMPARABLE": 0,
        },
        "threat": {"cve_relationships": finding_count, "kev_listed": 0, "epss_policy_hits": 0},
        "governance": {"false_positive": 0, "accepted_risk": 0, "suppressed": 0},
        "coverage": {"complete": True, "gap_count": 0, "comparison_status": "COMPLETE"},
        "intelligence": {"bundle_id": "a" * 64},
        "proof_id": "b" * 64,
        "proof": {"decisions": []},
        "findings": findings,
    }


def _result(dashboard: dict[str, Any]) -> CIResult:
    return CIResult(
        schema_version="securescan-ci-result-v1",
        candidate_run_id="run",
        project_id="project",
        lineage_id="lineage",
        decision="FAIL",
        exit_code=1,
        evaluated_at=datetime(2026, 10, 3, tzinfo=UTC),
        baseline_id="baseline",
        baseline_revision=1,
        intelligence_bundle_id="a" * 64,
        threat_assessment_ids=(),
        policy_decision_proof_id="b" * 64,
        policy_decision_proof_sha256="c" * 64,
        coverage_summary=dashboard["coverage"],
        delta_summary=dashboard["delta"],
        threat_summary=dashboard["threat"],
        governance_summary=dashboard["governance"],
        blocking_finding_refs=(),
        error_reasons=(),
        artifacts={"summary": "summary.md"},
    )


def _median_ms(operation: Callable[[], object], iterations: int = 25) -> float:
    values = []
    for _ in range(iterations):
        started = time.perf_counter()
        operation()
        values.append((time.perf_counter() - started) * 1_000)
    return statistics.median(values)


def characterize() -> dict[str, Any]:
    large = controlled_dashboard(500)
    ai_dashboard = controlled_dashboard(50)
    result = _result(large)
    context_builder = AIContextBuilder()
    context = context_builder.build(
        task=AITask.SUMMARIZE_RUN,
        question="Summarize this controlled run.",
        dashboard=ai_dashboard,
    )
    return {
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        },
        "finding_count": 500,
        "ai_context_finding_count": 50,
        "median_ms": {
            "assessment_html": _median_ms(lambda: render_assessment_html(large)),
            "ci_summary": _median_ms(lambda: render_ci_summary(result, large)),
            "decision_proof_json": _median_ms(lambda: canonical_json_bytes(large["proof"])),
            "ai_context_build": _median_ms(
                lambda: context_builder.build(
                    task=AITask.SUMMARIZE_RUN,
                    question="Summarize this controlled run.",
                    dashboard=ai_dashboard,
                )
            ),
            "ai_context_serialize": _median_ms(lambda: canonical_json_bytes(context)),
        },
        "output_bytes": {
            "assessment_html": len(render_assessment_html(large)),
            "ci_summary": len(render_ci_summary(result, large)),
            "ai_context": len(canonical_json_bytes(context)),
        },
    }


def main() -> None:
    print(json.dumps(characterize(), allow_nan=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
