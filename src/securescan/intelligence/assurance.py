from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.evidence import (
    CoverageState,
    EvidenceKind,
    FindingCategory,
    OsvAdvisoryGroupEvidencePayload,
    PackageComponentPayload,
)
from securescan.persistence.database import (
    SourceIntelligenceBundleRow,
    SourceIntelligenceSnapshotRow,
    SourcePolicyDecisionProofRow,
    SourceThreatAssessmentRow,
    utc_now,
)
from securescan.product_core.effective_governance import (
    EffectiveGovernance,
    EffectiveGovernanceService,
)
from securescan.product_core.lifecycle import SourceFindingLifecycleService
from securescan.product_core.policy import SourcePolicyService
from securescan.product_core.security_delta import (
    SecurityDelta,
    SecurityDeltaFinding,
    SecurityDeltaNotFoundError,
    SecurityDeltaState,
    SourceSecurityDeltaService,
)
from securescan.product_core.verified_read import VerifiedPublishedRunGateway

from .cve import exact_cve_aliases
from .models import EpssState, KevState, ThreatAssessment, as_utc, canonical_json
from .service import (
    IntelligenceIntegrityError,
    IntelligenceNotFoundError,
    IntelligenceService,
    IntelligenceServiceError,
)

_COMPLETE_COVERAGE_STATES = frozenset(
    {
        CoverageState.COMPLETE,
        CoverageState.COMPLETE_WITH_FINDINGS,
        CoverageState.COMPLETE_WITH_SUPPRESSIONS,
        CoverageState.NOT_APPLICABLE,
    }
)


class ThreatRuleAction(StrEnum):
    FAIL = "FAIL"
    WARN = "WARN"


class ThreatPolicySpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(pattern=r"^securescan-threat-policy-v1$")
    kev_introduced: ThreatRuleAction | None = None
    epss_introduced: ThreatRuleAction | None = None
    epss_threshold: float | None = Field(default=None, ge=0, le=1)
    minimum_priority: str | None = None
    require_kev: StrictBool = False
    require_epss: StrictBool = False
    kev_max_age_seconds: int | None = Field(default=None, ge=0)
    epss_max_age_seconds: int | None = Field(default=None, ge=0)

    @field_validator("minimum_priority")
    @classmethod
    def validate_priority(cls, value: str | None) -> str | None:
        if value not in {None, "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNRANKED"}:
            raise ValueError("invalid minimum priority")
        return value

    def model_post_init(self, __context: Any) -> None:
        if (self.epss_introduced is None) != (self.epss_threshold is None):
            raise ValueError("EPSS action and threshold must be configured together")


@dataclass(frozen=True, slots=True)
class FindingIntelligence:
    finding_id: str
    category: str
    authority: str
    component: dict[str, Any] | None
    advisory_id: str | None
    cve_ids: tuple[str, ...]
    assessments: tuple[ThreatAssessment, ...]


@dataclass(frozen=True, slots=True)
class RunAssuranceView:
    project_id: str
    lineage_id: str
    run_id: str
    report_artifact_sha256: str
    coverage_complete: bool
    gap_count: int
    finding_intelligence: tuple[FindingIntelligence, ...]
    delta: SecurityDelta | None
    delta_state: str


@dataclass(frozen=True, slots=True)
class PolicyDecisionProof:
    proof_id: str
    proof_sha256: str
    result: str
    evaluated_at: datetime
    proof: dict[str, Any]


class AssuranceService:
    """Read-only assurance aggregation plus immutable deterministic policy proof."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        artifact_store: ContentAddressedArtifactStore,
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._sessions = session_factory
        self._artifacts = artifact_store
        self._verified = VerifiedPublishedRunGateway(session_factory, artifact_store)
        self._intelligence = IntelligenceService(session_factory, artifact_store, clock=clock)
        self._delta = SourceSecurityDeltaService(session_factory, artifact_store)
        self._lifecycle = SourceFindingLifecycleService(session_factory, artifact_store)
        self._governance = EffectiveGovernanceService(session_factory, clock=clock)
        self._clock = clock

    def finding_intelligence(
        self,
        *,
        project_id: str,
        lineage_id: str,
        run_id: str,
        bundle_id: str | None = None,
    ) -> tuple[FindingIntelligence, ...]:
        verified = self._verified.load(
            run_id=run_id,
            expected_project_id=project_id,
            expected_lineage_id=lineage_id,
        )
        if bundle_id is not None:
            self._intelligence.get_bundle(bundle_id)
        assessments = self._intelligence.list_assessments(project_id=project_id, run_id=run_id)
        if bundle_id is not None:
            assessments = tuple(
                item for item in assessments if item.intelligence_bundle_id == bundle_id
            )
        by_finding: dict[str, list[ThreatAssessment]] = {}
        for assessment in assessments:
            by_finding.setdefault(assessment.finding_id, []).append(assessment)
        evidence = {item.evidence_id: item for item in verified.report.evidence}
        components = {item.component_ref: item for item in verified.report.components}
        result = []
        for finding in verified.report.findings:
            advisory_id = None
            cves: tuple[str, ...] = ()
            component = None
            if finding.category is FindingCategory.DEPENDENCY_VULNERABILITY:
                groups = []
                for reference in finding.primary_evidence_refs:
                    item = evidence.get(reference)
                    if item is not None and item.evidence_kind is EvidenceKind.OSV_ADVISORY_GROUP:
                        if not isinstance(item.payload, OsvAdvisoryGroupEvidencePayload):
                            raise IntelligenceIntegrityError("OSV evidence type mismatch")
                        groups.append(item)
                if len(groups) != 1:
                    raise IntelligenceIntegrityError(
                        "dependency finding has ambiguous OSV evidence"
                    )
                group = groups[0]
                advisory_id = group.payload.canonical_advisory_id
                cves = exact_cve_aliases(group.payload.aliases)
                package_components = []
                for reference in group.component_refs:
                    found = components.get(reference)
                    if found is not None and isinstance(found.payload, PackageComponentPayload):
                        package_components.append(found.payload.canonical_data())
                if len(package_components) != 1:
                    raise IntelligenceIntegrityError("dependency component is ambiguous")
                component = package_components[0]
            selected = tuple(
                sorted(
                    by_finding.get(finding.finding_id, ()),
                    key=lambda item: (item.cve_id, item.evaluated_at, item.assessment_id),
                )
            )
            if any(item.cve_id not in cves for item in selected):
                raise IntelligenceIntegrityError("assessment CVE is not proven by OSV aliases")
            result.append(
                FindingIntelligence(
                    finding_id=finding.finding_id,
                    category=finding.category.value,
                    authority=finding.authority.value,
                    component=component,
                    advisory_id=advisory_id,
                    cve_ids=cves,
                    assessments=selected,
                )
            )
        return tuple(result)

    def run_assurance_view(
        self,
        *,
        project_id: str,
        lineage_id: str,
        run_id: str,
        bundle_id: str | None = None,
    ) -> RunAssuranceView:
        verified = self._verified.load(
            run_id=run_id,
            expected_project_id=project_id,
            expected_lineage_id=lineage_id,
        )
        findings = self.finding_intelligence(
            project_id=project_id,
            lineage_id=lineage_id,
            run_id=run_id,
            bundle_id=bundle_id,
        )
        try:
            delta = self._delta.evaluate(
                project_id=project_id,
                lineage_id=lineage_id,
                candidate_run_id=run_id,
            )
            delta_state = delta.comparison_status.value
        except SecurityDeltaNotFoundError:
            delta = None
            delta_state = "BASELINE_UNAVAILABLE"
        return RunAssuranceView(
            project_id=project_id,
            lineage_id=lineage_id,
            run_id=run_id,
            report_artifact_sha256=verified.report_artifact_sha256,
            coverage_complete=all(
                item.state in _COMPLETE_COVERAGE_STATES
                for item in verified.report.coverage_outcomes
            ),
            gap_count=len(verified.report.gaps),
            finding_intelligence=findings,
            delta=delta,
            delta_state=delta_state,
        )

    def evaluate_policy(
        self,
        *,
        project_id: str,
        lineage_id: str,
        run_id: str,
        bundle_id: str,
        threat_policy: ThreatPolicySpec,
        evaluated_at: datetime | None = None,
    ) -> PolicyDecisionProof:
        at = as_utc(self._clock() if evaluated_at is None else evaluated_at)
        # Verify both CAS-backed run and bundle before opening the policy snapshot.
        self._verified.load(
            run_id=run_id,
            expected_project_id=project_id,
            expected_lineage_id=lineage_id,
        )
        self._intelligence.get_bundle(bundle_id)
        try:
            with self._sessions.begin() as session:
                if session.get_bind().dialect.name == "postgresql":
                    session.connection(execution_options={"isolation_level": "REPEATABLE READ"})
                bundle = session.get(SourceIntelligenceBundleRow, bundle_id)
                if bundle is None:
                    raise IntelligenceNotFoundError("intelligence bundle is unavailable")
                policy = SourcePolicyService._current_policy(session, lineage_id)
                delta = self._delta.evaluate_in_session(
                    session,
                    project_id=project_id,
                    lineage_id=lineage_id,
                    candidate_run_id=run_id,
                )
                facts = self._lifecycle.load_candidate_facts_in_session(
                    session,
                    project_id=project_id,
                    lineage_id=lineage_id,
                    run_id=run_id,
                )
                governance = self._governance.get_many_in_session(
                    session,
                    project_id=project_id,
                    lineage_id=lineage_id,
                    finding_ids=tuple(item.finding_id for item in facts),
                    evaluated_at=at,
                )
                base_decisions = SourcePolicyService._decide(
                    policy.definition, delta, facts, governance
                )
                assessments = session.scalars(
                    select(SourceThreatAssessmentRow).where(
                        SourceThreatAssessmentRow.project_id == project_id,
                        SourceThreatAssessmentRow.lineage_id == lineage_id,
                        SourceThreatAssessmentRow.run_id == run_id,
                        SourceThreatAssessmentRow.bundle_id == bundle_id,
                    )
                ).all()
                threat_decisions = self._threat_decisions(
                    session,
                    threat_policy,
                    delta,
                    facts,
                    governance,
                    assessments,
                    bundle,
                    at,
                )
                decisions = [
                    {"source": "BASE_POLICY", **item.canonical_data()} for item in base_decisions
                ] + threat_decisions
                result = (
                    "ERROR"
                    if any(item["kind"] == "ERROR" for item in decisions)
                    else "FAIL"
                    if any(item["kind"] == "VIOLATION" for item in decisions)
                    else "PASS"
                )
                threat_definition = threat_policy.model_dump(mode="json")
                threat_digest = hashlib.sha256(canonical_json(threat_definition)).hexdigest()
                proof = {
                    "schema_version": "securescan-policy-decision-proof-v1",
                    "result": result,
                    "candidate_run_id": run_id,
                    "project_id": project_id,
                    "lineage_id": lineage_id,
                    "evaluated_at": at.isoformat(),
                    "baseline": {
                        "baseline_id": delta.baseline_id,
                        "run_id": delta.baseline_run_id,
                        "revision": delta.baseline_revision,
                    },
                    "policy": {
                        "policy_id": policy.policy_id,
                        "version": policy.version,
                        "digest": policy.digest,
                        "threat_definition": threat_definition,
                        "threat_digest": threat_digest,
                    },
                    "intelligence_bundle_id": bundle_id,
                    "coverage": {
                        "comparison_status": delta.comparison_status.value,
                        "authority_summaries": [
                            {
                                "authority": item.authority,
                                "comparison_status": item.comparison_status.value,
                                "reason_codes": list(item.reason_codes),
                            }
                            for item in delta.authority_summaries
                        ],
                    },
                    "decisions": sorted(
                        decisions,
                        key=lambda item: (
                            item["kind"],
                            item.get("finding_id") or "",
                            item["rule_id"],
                            item.get("cve_id") or "",
                        ),
                    ),
                }
                proof_bytes = canonical_json(proof)
                proof_sha = hashlib.sha256(proof_bytes).hexdigest()
                proof_id = hashlib.sha256(
                    b"securescan-policy-decision-proof-v1\0" + proof_bytes
                ).hexdigest()
                row = session.get(SourcePolicyDecisionProofRow, proof_id)
                if row is None:
                    row = SourcePolicyDecisionProofRow(
                        proof_id=proof_id,
                        proof_sha256=proof_sha,
                        lineage_id=lineage_id,
                        candidate_run_id=run_id,
                        bundle_id=bundle_id,
                        policy_id=policy.policy_id,
                        policy_version=policy.version,
                        policy_digest=policy.digest,
                        result=result,
                        proof_json=proof,
                        evaluated_at=at,
                    )
                    session.add(row)
                    session.flush()
                elif row.proof_json != proof or row.proof_sha256 != proof_sha:
                    raise IntelligenceIntegrityError("policy proof identity collision")
                return PolicyDecisionProof(proof_id, proof_sha, result, at, proof)
        except (
            IntelligenceNotFoundError,
            IntelligenceIntegrityError,
            SecurityDeltaNotFoundError,
        ):
            raise
        except (IntegrityError, SQLAlchemyError, TypeError, ValueError) as error:
            raise IntelligenceIntegrityError("policy decision proof failed") from error

    def get_policy_proof(self, proof_id: str) -> PolicyDecisionProof:
        """Read and integrity-check one immutable policy decision proof."""
        try:
            with self._sessions() as session:
                row = session.get(SourcePolicyDecisionProofRow, proof_id)
                if row is None:
                    raise IntelligenceNotFoundError("policy decision proof is unavailable")
                proof_bytes = canonical_json(row.proof_json)
                proof_sha = hashlib.sha256(proof_bytes).hexdigest()
                expected_id = hashlib.sha256(
                    b"securescan-policy-decision-proof-v1\0" + proof_bytes
                ).hexdigest()
                if expected_id != row.proof_id or proof_sha != row.proof_sha256:
                    raise IntelligenceIntegrityError("policy decision proof is corrupt")
                return PolicyDecisionProof(
                    proof_id=row.proof_id,
                    proof_sha256=row.proof_sha256,
                    result=row.result,
                    evaluated_at=as_utc(row.evaluated_at),
                    proof=dict(row.proof_json),
                )
        except IntelligenceServiceError:
            raise
        except (SQLAlchemyError, TypeError, ValueError) as error:
            raise IntelligenceIntegrityError("policy decision proof read failed") from error

    @staticmethod
    def _threat_decisions(
        session: Session,
        spec: ThreatPolicySpec,
        delta: SecurityDelta,
        candidate_facts: tuple[Any, ...],
        governance: tuple[EffectiveGovernance, ...],
        assessment_rows: list[SourceThreatAssessmentRow],
        bundle: SourceIntelligenceBundleRow,
        evaluated_at: datetime,
    ) -> list[dict[str, Any]]:
        by_finding: dict[str, list[SourceThreatAssessmentRow]] = {}
        for row in assessment_rows:
            if (
                row.bundle_id != bundle.bundle_id
                or row.kev_evidence_json.get("snapshot_id") != bundle.kev_snapshot_id
                or row.epss_evidence_json.get("snapshot_id") != bundle.epss_snapshot_id
            ):
                raise IntelligenceIntegrityError("assessment bundle evidence is inconsistent")
            by_finding.setdefault(row.finding_id, []).append(row)
        governance_by_id = {item.finding_id: item for item in governance}
        priorities = {item.finding_id: item.priority_band.value for item in candidate_facts}
        priority_order = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFO": 4,
            "UNRANKED": 5,
        }
        decisions: list[dict[str, Any]] = []
        for source, required, maximum, snapshot_id in (
            ("KEV", spec.require_kev, spec.kev_max_age_seconds, bundle.kev_snapshot_id),
            ("EPSS", spec.require_epss, spec.epss_max_age_seconds, bundle.epss_snapshot_id),
        ):
            if required and snapshot_id is None:
                decisions.append(
                    AssuranceService._decision(
                        "ERROR", f"{source}_REQUIRED", f"{source}_UNAVAILABLE"
                    )
                )
                continue
            if snapshot_id is not None and maximum is not None:
                snapshot = session.get(SourceIntelligenceSnapshotRow, snapshot_id)
                if snapshot is None:
                    decisions.append(
                        AssuranceService._decision(
                            "ERROR", f"{source}_FRESHNESS", f"{source}_UNAVAILABLE"
                        )
                    )
                else:
                    age = (evaluated_at - as_utc(snapshot.source_effective_at)).total_seconds()
                    if age > maximum:
                        decisions.append(
                            AssuranceService._decision(
                                "ERROR",
                                f"{source}_FRESHNESS",
                                f"{source}_SNAPSHOT_TOO_OLD",
                                evidence={"snapshot_id": snapshot_id, "age_seconds": age},
                            )
                        )
        facts = {
            item.finding_id: item
            for item in delta.findings
            if item.state is SecurityDeltaState.INTRODUCED
            and item.category == FindingCategory.DEPENDENCY_VULNERABILITY.value
        }
        for finding_id, finding in sorted(facts.items()):
            rows = sorted(by_finding.get(finding_id, []), key=lambda item: item.cve_id)
            if not rows and (spec.require_kev or spec.require_epss):
                decisions.append(
                    AssuranceService._decision(
                        "ERROR",
                        "THREAT_ASSESSMENT_REQUIRED",
                        "THREAT_ASSESSMENT_UNAVAILABLE",
                        finding=finding,
                    )
                )
                continue
            effective = governance_by_id.get(finding_id)
            exclusion = AssuranceService._exclusion(effective)
            priority = priorities.get(finding_id)
            if spec.minimum_priority is not None and (
                priority not in priority_order
                or priority_order[priority] > priority_order[spec.minimum_priority]
            ):
                continue
            for row in rows:
                kev_state = row.kev_evidence_json.get("state")
                epss_state = row.epss_evidence_json.get("state")
                if spec.require_kev and kev_state == KevState.UNAVAILABLE.value:
                    decisions.append(
                        AssuranceService._decision(
                            "ERROR", "KEV_REQUIRED", "KEV_UNAVAILABLE", finding=finding, row=row
                        )
                    )
                if spec.require_epss and epss_state != EpssState.SCORED.value:
                    decisions.append(
                        AssuranceService._decision(
                            "ERROR", "EPSS_REQUIRED", "EPSS_UNAVAILABLE", finding=finding, row=row
                        )
                    )
                if spec.kev_introduced is not None and kev_state == KevState.LISTED.value:
                    kind = (
                        "EXCLUSION"
                        if exclusion and spec.kev_introduced is ThreatRuleAction.FAIL
                        else "VIOLATION"
                        if spec.kev_introduced is ThreatRuleAction.FAIL
                        else "WARNING"
                    )
                    decisions.append(
                        AssuranceService._decision(
                            kind,
                            "INTRODUCED_KEV_LISTED",
                            exclusion or "EXACT_CVE_LISTED_IN_KEV",
                            finding=finding,
                            row=row,
                            evidence={"priority": priority, **row.kev_evidence_json},
                        )
                    )
                epss_record = row.epss_evidence_json.get("record")
                if (
                    spec.epss_introduced is not None
                    and epss_state == EpssState.SCORED.value
                    and isinstance(epss_record, dict)
                    and epss_record.get("epss") >= spec.epss_threshold
                ):
                    kind = (
                        "EXCLUSION"
                        if exclusion and spec.epss_introduced is ThreatRuleAction.FAIL
                        else "VIOLATION"
                        if spec.epss_introduced is ThreatRuleAction.FAIL
                        else "WARNING"
                    )
                    decisions.append(
                        AssuranceService._decision(
                            kind,
                            "INTRODUCED_EPSS_THRESHOLD",
                            exclusion or "EPSS_THRESHOLD_MET",
                            finding=finding,
                            row=row,
                            evidence={"priority": priority, **row.epss_evidence_json},
                        )
                    )
        return decisions

    @staticmethod
    def _exclusion(effective: EffectiveGovernance | None) -> str | None:
        if effective is None:
            return None
        if effective.false_positive_effective:
            return "EXCLUDED_EFFECTIVE_FALSE_POSITIVE"
        if effective.accepted_risk_effective:
            return "EXCLUDED_EFFECTIVE_ACCEPTED_RISK"
        if effective.suppression_effective:
            return "EXCLUDED_EFFECTIVE_SUPPRESSION"
        return None

    @staticmethod
    def _decision(
        kind: str,
        rule_id: str,
        reason_code: str,
        *,
        finding: SecurityDeltaFinding | None = None,
        row: SourceThreatAssessmentRow | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "source": "THREAT_POLICY",
            "kind": kind,
            "rule_id": rule_id,
            "reason_code": reason_code,
            "finding_id": None if finding is None else finding.finding_id,
            "authority": None if finding is None else finding.authority,
            "category": None if finding is None else finding.category,
            "delta_state": None if finding is None else finding.state.value,
            "cve_id": None if row is None else row.cve_id,
            "advisory_id": None if row is None else row.advisory_id,
            "assessment_id": None if row is None else row.assessment_id,
            "evidence": evidence,
        }
