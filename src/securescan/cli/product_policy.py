"""Presentation-only CLI adapter for the frozen deterministic policy service."""

from __future__ import annotations

from datetime import UTC
from typing import Any

from securescan.product_core import PolicyEvaluation, PolicyResult


def policy_evaluation_data(evaluation: PolicyEvaluation) -> dict[str, Any]:
    """Expose the domain result without deriving a second policy decision."""

    return {
        "evaluation_id": evaluation.evaluation_id,
        "lineage_id": evaluation.lineage_id,
        "candidate_run_id": evaluation.candidate_run_id,
        "baseline_id": evaluation.baseline_id,
        "baseline_revision": evaluation.baseline_revision,
        "policy_id": evaluation.policy_id,
        "policy_version": evaluation.policy_version,
        "policy_digest": evaluation.policy_digest,
        "result": evaluation.result.value,
        "decisions": [decision.canonical_data() for decision in evaluation.decisions],
        "evaluated_at": evaluation.evaluated_at.astimezone(UTC).isoformat(),
    }


def policy_exit_code(result: PolicyResult) -> int:
    """Only explicit policy mode can use exit 1 for a proven policy failure."""

    if result is PolicyResult.PASS:
        return 0
    if result is PolicyResult.FAIL:
        return 1
    return 5
