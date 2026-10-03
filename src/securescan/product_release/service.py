from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from datetime import datetime
from enum import Enum
from typing import Any

from securescan.intelligence import AssuranceService, IntelligenceService
from securescan.intelligence.assurance import FindingIntelligence
from securescan.product_core.effective_governance import EffectiveGovernanceService
from securescan.product_core.guidance import FindingGuidanceError, FindingGuidanceService
from securescan.product_core.interoperability import SourceInteroperabilityService

from .models import (
    CIResult,
    ProductAssuranceIntegrityError,
    ProductAssuranceNotFoundError,
)

_MAX_FINDINGS = 500
_PLAYBOOKS = {
    "CWE-89": (
        "Identify the untrusted input and database operation represented by the finding.",
        "Queries use parameter binding and input cannot change query structure.",
    ),
    "CWE-78": (
        "Identify the untrusted input and command/process operation represented by the finding.",
        "Process arguments are structured and no untrusted value is interpreted by a shell.",
    ),
    "CWE-22": (
        "Identify the user-controlled path and the intended storage boundary.",
        "Canonicalized access remains inside the approved root and rejects traversal.",
    ),
    "CWE-79": (
        "Identify the untrusted value and browser rendering context.",
        "Context-appropriate encoding keeps the value inert in the rendered document.",
    ),
    "CWE-918": (
        "Identify the user-controlled network destination and allowed destination policy.",
        "Only allowlisted destinations are reachable and redirects cannot escape policy.",
    ),
}


def _plain(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_plain(item) for item in value]
    return value


class ProductAssuranceService:
    """One read/presentation boundary over the frozen V1.5 assurance core."""

    def __init__(
        self,
        assurance: AssuranceService,
        intelligence: IntelligenceService,
        governance: EffectiveGovernanceService,
        guidance: FindingGuidanceService,
        interoperability: SourceInteroperabilityService,
    ) -> None:
        self._assurance = assurance
        self._intelligence = intelligence
        self._governance = governance
        self._guidance = guidance
        self._interoperability = interoperability

    def dashboard(
        self,
        *,
        project_id: str,
        lineage_id: str,
        run_id: str,
        bundle_id: str,
        proof_id: str,
    ) -> dict[str, Any]:
        view = self._assurance.run_assurance_view(
            project_id=project_id,
            lineage_id=lineage_id,
            run_id=run_id,
            bundle_id=bundle_id,
        )
        proof = self._assurance.get_policy_proof(proof_id)
        document = proof.proof
        if (
            document.get("project_id") != project_id
            or document.get("lineage_id") != lineage_id
            or document.get("candidate_run_id") != run_id
            or document.get("intelligence_bundle_id") != bundle_id
        ):
            raise ProductAssuranceIntegrityError("policy proof scope does not match assurance view")
        if len(view.finding_intelligence) > _MAX_FINDINGS:
            raise ProductAssuranceIntegrityError("assurance view exceeds presentation bound")

        governance_by_id = {
            item.finding_id: item
            for item in self._governance.get_many(
                project_id=project_id,
                lineage_id=lineage_id,
                finding_ids=tuple(item.finding_id for item in view.finding_intelligence),
                evaluated_at=proof.evaluated_at,
            )
        }

        delta_by_id = {
            item.finding_id: item.state.value
            for item in (() if view.delta is None else view.delta.findings)
        }
        decision_by_id: dict[str, list[dict[str, Any]]] = {}
        decisions = document.get("decisions")
        if not isinstance(decisions, list):
            raise ProductAssuranceIntegrityError("policy proof decisions are invalid")
        for decision in decisions:
            if not isinstance(decision, dict):
                raise ProductAssuranceIntegrityError("policy proof decision is invalid")
            finding_id = decision.get("finding_id")
            if isinstance(finding_id, str):
                decision_by_id.setdefault(finding_id, []).append(decision)

        governance_counts: Counter[str] = Counter()
        findings = []
        assessment_ids = []
        for finding in view.finding_intelligence:
            effective = governance_by_id[finding.finding_id]
            if effective.false_positive_effective:
                governance_counts["false_positive"] += 1
            elif effective.accepted_risk_effective:
                governance_counts["accepted_risk"] += 1
            else:
                governance_counts["unreviewed"] += 1
            if effective.suppression_effective:
                governance_counts["suppressed"] += 1
            if effective.review_required:
                governance_counts["review_required"] += 1
            assessments = list(finding.assessments)
            assessment_ids.extend(item.assessment_id for item in assessments)
            policy_decisions = decision_by_id.get(finding.finding_id, [])
            findings.append(
                {
                    "advisory_id": finding.advisory_id,
                    "assessment_ids": [item.assessment_id for item in assessments],
                    "authority": finding.authority,
                    "category": finding.category,
                    "component": finding.component,
                    "cve_ids": list(finding.cve_ids),
                    "cve_state": self._cve_state(assessments),
                    "delta_state": delta_by_id.get(finding.finding_id, "NOT_COMPARABLE"),
                    "finding_id": finding.finding_id,
                    "governance": _plain(asdict(effective)),
                    "policy_impact": self._policy_impact(policy_decisions),
                }
            )

        delta_counts: Counter[str] = Counter(delta_by_id.values())
        assessments = self._intelligence.list_assessments(project_id=project_id, run_id=run_id)
        selected = tuple(item for item in assessments if item.intelligence_bundle_id == bundle_id)
        threat = {
            "cve_relationships": len(selected),
            "exact_cve_count": len({item.cve_id for item in selected}),
            "epss_policy_hits": sum(
                1
                for item in decisions
                if item.get("rule_id") == "INTRODUCED_EPSS_THRESHOLD"
                and item.get("kind") in {"VIOLATION", "WARNING", "EXCLUSION"}
            ),
            "kev_listed": sum(1 for item in selected if item.kev_evidence.get("state") == "LISTED"),
        }
        bundle = self._intelligence.get_bundle(bundle_id)
        intelligence = {
            "bundle_id": bundle.bundle_id,
            "kev": self._snapshot_provenance(bundle.kev_snapshot_id),
            "epss": self._snapshot_provenance(bundle.epss_snapshot_id),
            "nvd_enrichment_ids": list(bundle.nvd_enrichment_ids),
        }
        toolchain = self._interoperability.toolchain_manifest(run_id=run_id)
        baseline = document.get("baseline")
        if not isinstance(baseline, dict):
            raise ProductAssuranceIntegrityError("policy proof baseline is invalid")
        return {
            "schema_version": "securescan-product-assurance-v1",
            "scope": {"project_id": project_id, "lineage_id": lineage_id, "run_id": run_id},
            "decision": proof.result,
            "evaluated_at": proof.evaluated_at.isoformat(),
            "proof_id": proof.proof_id,
            "proof_sha256": proof.proof_sha256,
            "proof": _plain(document),
            "baseline": _plain(baseline),
            "delta": {
                "comparison_status": view.delta_state,
                **{
                    state: delta_counts[state]
                    for state in ("INTRODUCED", "PRESENT", "REMOVED", "NOT_COMPARABLE")
                },
            },
            "coverage": {
                "complete": view.coverage_complete,
                "gap_count": view.gap_count,
                "comparison_status": view.delta_state,
                "report_artifact_sha256": view.report_artifact_sha256,
            },
            "threat": threat,
            "governance": {
                key: governance_counts[key]
                for key in (
                    "unreviewed",
                    "false_positive",
                    "accepted_risk",
                    "suppressed",
                    "review_required",
                )
            },
            "intelligence": intelligence,
            "toolchain": toolchain,
            "threat_assessment_ids": sorted(set(assessment_ids)),
            "findings": findings,
        }

    def knowledge_card(
        self,
        *,
        project_id: str,
        lineage_id: str,
        run_id: str,
        finding_id: str,
        bundle_id: str,
        proof_id: str,
    ) -> dict[str, Any]:
        dashboard = self.dashboard(
            project_id=project_id,
            lineage_id=lineage_id,
            run_id=run_id,
            bundle_id=bundle_id,
            proof_id=proof_id,
        )
        selected = next(
            (item for item in dashboard["findings"] if item["finding_id"] == finding_id), None
        )
        if selected is None:
            raise ProductAssuranceNotFoundError("finding is not present in this run")
        intelligence = self._assurance.finding_intelligence(
            project_id=project_id,
            lineage_id=lineage_id,
            run_id=run_id,
            bundle_id=bundle_id,
        )
        finding = next(item for item in intelligence if item.finding_id == finding_id)
        try:
            guidance = self._guidance.get_for_run(
                project_id=project_id,
                lineage_id=lineage_id,
                run_id=run_id,
                finding_id=finding_id,
            )
            guidance_data = _plain(asdict(guidance))
        except FindingGuidanceError:
            guidance_data = None
        cves = []
        for assessment in finding.assessments:
            nvd = (
                None
                if assessment.nvd_enrichment_id is None
                else self._intelligence.get_nvd(assessment.nvd_enrichment_id)
            )
            cves.append(
                {
                    "assessment_id": assessment.assessment_id,
                    "cve_id": assessment.cve_id,
                    "epss": _plain(assessment.epss_evidence),
                    "kev": _plain(assessment.kev_evidence),
                    "nvd": None if nvd is None else _plain(asdict(nvd)),
                }
            )
        proof_decisions = [
            item for item in dashboard["proof"]["decisions"] if item.get("finding_id") == finding_id
        ]
        return {
            "schema_version": "securescan-finding-knowledge-card-v1",
            **selected,
            "cves": cves,
            "guidance": guidance_data,
            "policy_decisions": proof_decisions,
            "provenance": dashboard["intelligence"],
            "verification_playbook": self._playbook(finding, guidance_data),
            "limitations": [
                "A scanner finding does not prove exploitability or reachability.",
                "Guidance is not a verified patch or manual penetration-test result.",
            ],
        }

    @staticmethod
    def ci_result(dashboard: dict[str, Any]) -> CIResult:
        proof = dashboard["proof"]
        baseline = dashboard["baseline"]
        decision = dashboard["decision"]
        if decision not in {"PASS", "FAIL", "ERROR"}:
            raise ProductAssuranceIntegrityError("policy result is invalid")
        blocking = tuple(
            sorted(
                {
                    item["finding_id"]
                    for item in proof["decisions"]
                    if item.get("kind") in {"VIOLATION", "ERROR"}
                    and isinstance(item.get("finding_id"), str)
                }
            )
        )
        error_reasons = tuple(
            sorted(
                {
                    item["reason_code"]
                    for item in proof["decisions"]
                    if item.get("kind") == "ERROR" and isinstance(item.get("reason_code"), str)
                }
            )
        )
        scope = dashboard["scope"]
        return CIResult(
            schema_version="securescan-ci-result-v1",
            candidate_run_id=scope["run_id"],
            project_id=scope["project_id"],
            lineage_id=scope["lineage_id"],
            decision=decision,
            exit_code={"PASS": 0, "FAIL": 1, "ERROR": 2}[decision],
            evaluated_at=datetime.fromisoformat(dashboard["evaluated_at"]),
            baseline_id=baseline.get("baseline_id"),
            baseline_revision=baseline.get("revision"),
            intelligence_bundle_id=dashboard["intelligence"]["bundle_id"],
            threat_assessment_ids=tuple(dashboard["threat_assessment_ids"]),
            policy_decision_proof_id=dashboard["proof_id"],
            policy_decision_proof_sha256=dashboard["proof_sha256"],
            coverage_summary=dict(dashboard["coverage"]),
            delta_summary=dict(dashboard["delta"]),
            threat_summary=dict(dashboard["threat"]),
            governance_summary=dict(dashboard["governance"]),
            blocking_finding_refs=blocking,
            error_reasons=error_reasons,
            artifacts={
                "assessment": "assessment.html",
                "cyclonedx": "sbom.cdx.json",
                "decision_proof": "decision-proof.json",
                "sarif": "results.sarif",
                "summary": "summary.md",
            },
        )

    def _snapshot_provenance(self, snapshot_id: str | None) -> dict[str, Any]:
        if snapshot_id is None:
            return {"state": "UNAVAILABLE", "snapshot_id": None}
        snapshot = self._intelligence.get_snapshot(snapshot_id)
        return {
            "content_sha256": snapshot.content_sha256,
            "record_count": snapshot.record_count,
            "retrieved_at": snapshot.retrieved_at.isoformat(),
            "snapshot_id": snapshot.snapshot_id,
            "source": snapshot.source.value,
            "source_effective_at": None
            if snapshot.source_effective_at is None
            else snapshot.source_effective_at.isoformat(),
            "state": snapshot.validity_state,
        }

    @staticmethod
    def _cve_state(assessments: list[Any]) -> str:
        if not assessments:
            return "NOT_APPLICABLE"
        values = []
        for item in assessments:
            values.append(
                f"{item.cve_id}:KEV={item.kev_evidence.get('state', 'UNKNOWN')};"
                f"EPSS={item.epss_evidence.get('state', 'UNKNOWN')}"
            )
        return " | ".join(values)

    @staticmethod
    def _policy_impact(decisions: list[dict[str, Any]]) -> str:
        kinds = {item.get("kind") for item in decisions}
        if "ERROR" in kinds:
            return "ERROR"
        if "VIOLATION" in kinds:
            return "BLOCKING"
        if "WARNING" in kinds:
            return "WARNING"
        if "EXCLUSION" in kinds:
            return "EXCLUDED_BY_EFFECTIVE_GOVERNANCE"
        return "NON_BLOCKING"

    @staticmethod
    def _playbook(finding: FindingIntelligence, guidance: dict[str, Any] | None) -> dict[str, Any]:
        if guidance is None:
            return {
                "applicability": "EVIDENCE_ONLY",
                "manual_verification": [],
                "expected_secure_behavior": "Not established by available evidence.",
                "retest": "Rerun the same authority with comparable coverage.",
            }
        cwes = tuple(guidance.get("cwe_ids") or ())
        selected = next(((_PLAYBOOKS[cwe], cwe) for cwe in cwes if cwe in _PLAYBOOKS), None)
        if selected is not None:
            (manual, expected), cwe = selected
            return {
                "applicability": "SUPPORTED_CLASSIFICATION",
                "classification": cwe,
                "manual_verification": [manual],
                "expected_secure_behavior": expected,
                "retest": "Apply a safe change and rerun the same rule with comparable coverage.",
            }
        if finding.category == "DEPENDENCY_VULNERABILITY":
            return {
                "applicability": "DEPENDENCY",
                "manual_verification": [
                    "Confirm the resolved component version in a rebuilt dependency inventory."
                ],
                "expected_secure_behavior": (
                    "The rebuilt version is outside the accepted OSV affected range."
                ),
                "retest": "Rerun Syft and OSV evaluation with comparable scope.",
            }
        if finding.category == "SECRET_EXPOSURE":
            return {
                "applicability": "SECRET_ROTATION",
                "manual_verification": [
                    "Verify removal from source and separately verify provider-side revocation."
                ],
                "expected_secure_behavior": "The credential is absent and cannot authenticate.",
                "retest": "Rerun Gitleaks; absence does not itself prove revocation.",
            }
        return {
            "applicability": "FAMILY",
            "manual_verification": list(guidance.get("verification_steps") or ())[:8],
            "expected_secure_behavior": "The identified unsafe condition is no longer present.",
            "retest": "Rerun the same authority with comparable coverage.",
        }
