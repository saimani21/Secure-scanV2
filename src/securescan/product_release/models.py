from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


class ProductAssuranceError(RuntimeError):
    pass


class ProductAssuranceNotFoundError(ProductAssuranceError):
    pass


class ProductAssuranceIntegrityError(ProductAssuranceError):
    pass


@dataclass(frozen=True, slots=True)
class CIResult:
    schema_version: str
    candidate_run_id: str
    project_id: str
    lineage_id: str
    decision: str
    exit_code: int
    evaluated_at: datetime
    baseline_id: str | None
    baseline_revision: int | None
    intelligence_bundle_id: str
    threat_assessment_ids: tuple[str, ...]
    policy_decision_proof_id: str
    policy_decision_proof_sha256: str
    coverage_summary: dict[str, Any]
    delta_summary: dict[str, int | str]
    threat_summary: dict[str, int]
    governance_summary: dict[str, int]
    blocking_finding_refs: tuple[str, ...]
    error_reasons: tuple[str, ...]
    artifacts: dict[str, str]

    def canonical_data(self) -> dict[str, Any]:
        return {
            "artifacts": dict(sorted(self.artifacts.items())),
            "baseline_id": self.baseline_id,
            "baseline_revision": self.baseline_revision,
            "blocking_finding_refs": list(self.blocking_finding_refs),
            "candidate_run_id": self.candidate_run_id,
            "coverage_summary": self.coverage_summary,
            "decision": self.decision,
            "delta_summary": self.delta_summary,
            "error_reasons": list(self.error_reasons),
            "evaluated_at": self.evaluated_at.isoformat(),
            "exit_code": self.exit_code,
            "governance_summary": self.governance_summary,
            "intelligence_bundle_id": self.intelligence_bundle_id,
            "lineage_id": self.lineage_id,
            "policy_decision_proof_id": self.policy_decision_proof_id,
            "policy_decision_proof_sha256": self.policy_decision_proof_sha256,
            "project_id": self.project_id,
            "schema_version": self.schema_version,
            "threat_assessment_ids": list(self.threat_assessment_ids),
            "threat_summary": self.threat_summary,
        }
