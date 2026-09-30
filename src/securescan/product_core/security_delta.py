from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import RunStatus
from securescan.evidence import (
    CoverageState,
    EvidenceAuthority,
    SecureScanCoverageOutcome,
    SecureScanEvidenceReport,
    SecureScanFinding,
)
from securescan.orchestration.models import (
    OrchestrationContainmentState,
    OrchestrationLifecycleState,
    OrchestrationNodeDisposition,
    OrchestrationNodeLifecycleState,
    OrchestrationTerminalOutcome,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    SourceLineageRunRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationRow,
    SourceScanSubmissionRow,
    SourceTargetLineageRow,
    SourceTrustedBaselinePromotionRow,
)

from .finding_index import ProductCoreIndexError, SourceFindingIndexService
from .lifecycle import (
    _COMPLETE_COVERAGE,
    ProductCoreLifecycleError,
    SourceFindingLifecycleService,
)

_FINDING_AUTHORITIES = (
    EvidenceAuthority.CHECKOV,
    EvidenceAuthority.GITLEAKS,
    EvidenceAuthority.OSV,
    EvidenceAuthority.SEMGREP,
)
_FINALIZED_RUN_STATUS = {
    OrchestrationTerminalOutcome.COMPLETED.value: RunStatus.COMPLETED.value,
    OrchestrationTerminalOutcome.PARTIAL.value: RunStatus.PARTIAL.value,
}


class SecurityDeltaState(StrEnum):
    INTRODUCED = "INTRODUCED"
    PRESENT = "PRESENT"
    REMOVED = "REMOVED"
    NOT_COMPARABLE = "NOT_COMPARABLE"


class SecurityDeltaComparisonStatus(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    NOT_COMPARABLE = "NOT_COMPARABLE"


class SecurityDeltaError(Exception):
    pass


class SecurityDeltaNotFoundError(SecurityDeltaError):
    pass


class SecurityDeltaValidationError(SecurityDeltaError):
    pass


class SecurityDeltaPersistenceError(SecurityDeltaError):
    pass


@dataclass(frozen=True, slots=True)
class SecurityDeltaFinding:
    finding_id: str
    authority: str
    category: str
    state: SecurityDeltaState
    reason_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SecurityDeltaAuthoritySummary:
    authority: str
    comparison_status: SecurityDeltaComparisonStatus
    introduced_count: int
    present_count: int
    removed_count: int
    not_comparable_count: int
    reason_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SecurityDelta:
    baseline_id: str
    baseline_run_id: str
    baseline_revision: int
    baseline_sequence_number: int
    candidate_run_id: str
    candidate_sequence_number: int
    comparison_status: SecurityDeltaComparisonStatus
    authority_summaries: tuple[SecurityDeltaAuthoritySummary, ...]
    findings: tuple[SecurityDeltaFinding, ...]


class SourceSecurityDeltaService:
    """Derive candidate-vs-current-baseline truth without lifecycle shortcuts."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        artifact_store: ContentAddressedArtifactStore,
    ) -> None:
        if not isinstance(artifact_store, ContentAddressedArtifactStore):
            raise SecurityDeltaPersistenceError
        self._sessions = session_factory
        self._index = SourceFindingIndexService(session_factory, artifact_store)
        self._lifecycle = SourceFindingLifecycleService(session_factory, artifact_store)

    def evaluate(self, *, project_id: str, lineage_id: str, candidate_run_id: str) -> SecurityDelta:
        self._validate_identifiers(project_id, lineage_id, candidate_run_id)
        try:
            with self._sessions() as session:
                if session.get_bind().dialect.name == "postgresql":
                    session.connection(execution_options={"isolation_level": "REPEATABLE READ"})
                return self.evaluate_in_session(
                    session,
                    project_id=project_id,
                    lineage_id=lineage_id,
                    candidate_run_id=candidate_run_id,
                )
        except SecurityDeltaError:
            raise
        except (
            ProductCoreIndexError,
            ProductCoreLifecycleError,
            SQLAlchemyError,
            TypeError,
            ValueError,
        ):
            raise SecurityDeltaPersistenceError from None

    def evaluate_in_session(
        self,
        session: Session,
        *,
        project_id: str,
        lineage_id: str,
        candidate_run_id: str,
    ) -> SecurityDelta:
        """Evaluate using the caller's transaction and statement snapshot."""
        self._validate_identifiers(project_id, lineage_id, candidate_run_id)
        try:
            lineage = session.get(SourceTargetLineageRow, lineage_id)
            if lineage is None or lineage.project_id != project_id:
                raise SecurityDeltaNotFoundError
            promotion = session.scalar(
                select(SourceTrustedBaselinePromotionRow)
                .where(SourceTrustedBaselinePromotionRow.lineage_id == lineage_id)
                .order_by(SourceTrustedBaselinePromotionRow.revision.desc())
                .limit(1)
            )
            if promotion is None:
                raise SecurityDeltaNotFoundError
            baseline = session.get(SourceLineageRunRow, promotion.run_id)
            candidate = session.get(SourceLineageRunRow, candidate_run_id)
            if (
                baseline is None
                or baseline.lineage_id != lineage_id
                or candidate is None
                or candidate.lineage_id != lineage_id
            ):
                raise SecurityDeltaNotFoundError
            baseline_report = self._verified_report(session, baseline)
            candidate_report = self._verified_report(session, candidate)
            if candidate.sequence_number < baseline.sequence_number:
                return self._ordered_failure(
                    promotion,
                    baseline,
                    candidate,
                    baseline_report,
                    candidate_report,
                )
            findings = self._findings(
                session,
                baseline,
                candidate,
                baseline_report,
                candidate_report,
            )
            summaries = self._authority_summaries(
                session,
                baseline,
                candidate,
                baseline_report,
                candidate_report,
                findings,
            )
            status = self._overall_status(summaries)
            return SecurityDelta(
                baseline_id=promotion.baseline_id,
                baseline_run_id=promotion.run_id,
                baseline_revision=promotion.revision,
                baseline_sequence_number=baseline.sequence_number,
                candidate_run_id=candidate.run_id,
                candidate_sequence_number=candidate.sequence_number,
                comparison_status=status,
                authority_summaries=summaries,
                findings=findings,
            )
        except SecurityDeltaError:
            raise
        except (
            ProductCoreIndexError,
            ProductCoreLifecycleError,
            SQLAlchemyError,
            TypeError,
            ValueError,
        ):
            raise SecurityDeltaPersistenceError from None

    def _verified_report(
        self, session: Session, membership: SourceLineageRunRow
    ) -> SecureScanEvidenceReport:
        if (
            membership.indexing_state != "INDEXED"
            or membership.indexed_at is None
            or membership.lifecycle_evaluated_at is None
        ):
            raise SecurityDeltaPersistenceError
        report = self._index._rebuild_trusted_report(membership.run_id, session=session)
        run = session.get(AnalysisRunRow, membership.run_id)
        parent = session.get(SourceOrchestrationRow, membership.run_id)
        submission = session.get(SourceScanSubmissionRow, membership.run_id)
        if (
            run is None
            or parent is None
            or submission is None
            or submission.lineage_id != membership.lineage_id
            or submission.submission_sequence_number != membership.sequence_number
            or submission.finalized_at is None
            or parent.lifecycle_state != OrchestrationLifecycleState.TERMINAL.value
            or parent.terminal_outcome not in _FINALIZED_RUN_STATUS
            or run.status != _FINALIZED_RUN_STATUS[parent.terminal_outcome]
            or parent.published_at is None
        ):
            raise SecurityDeltaPersistenceError
        self._index._verify_published_report(run, parent, report)
        if report.schema_version != membership.report_schema_version:
            raise SecurityDeltaPersistenceError
        return report

    def _findings(
        self,
        session: Session,
        baseline: SourceLineageRunRow,
        candidate: SourceLineageRunRow,
        baseline_report: SecureScanEvidenceReport,
        candidate_report: SecureScanEvidenceReport,
    ) -> tuple[SecurityDeltaFinding, ...]:
        baseline_findings = {item.finding_id: item for item in baseline_report.findings}
        candidate_findings = {item.finding_id: item for item in candidate_report.findings}
        results: list[SecurityDeltaFinding] = []
        for finding_id in sorted(set(baseline_findings) | set(candidate_findings)):
            baseline_finding = baseline_findings.get(finding_id)
            candidate_finding = candidate_findings.get(finding_id)
            if baseline_finding is not None and candidate_finding is not None:
                if (
                    baseline_finding.authority is not candidate_finding.authority
                    or baseline_finding.category is not candidate_finding.category
                    or baseline_finding.native_identity_schema
                    != candidate_finding.native_identity_schema
                ):
                    raise SecurityDeltaPersistenceError
                state = SecurityDeltaState.PRESENT
                reasons = ("EXACT_FINDING_OBSERVED_BOTH",)
                finding = candidate_finding
            elif candidate_finding is not None:
                reasons = self._absence_reasons(
                    session,
                    observed_membership=candidate,
                    absence_membership=baseline,
                    observed_report=candidate_report,
                    absence_report=baseline_report,
                    finding=candidate_finding,
                    absence_label="BASELINE",
                )
                state = (
                    SecurityDeltaState.NOT_COMPARABLE if reasons else SecurityDeltaState.INTRODUCED
                )
                reasons = reasons or ("COMPARABLE_BASELINE_ABSENCE",)
                finding = candidate_finding
            else:
                assert baseline_finding is not None
                reasons = self._absence_reasons(
                    session,
                    observed_membership=baseline,
                    absence_membership=candidate,
                    observed_report=baseline_report,
                    absence_report=candidate_report,
                    finding=baseline_finding,
                    absence_label="CANDIDATE",
                )
                state = SecurityDeltaState.NOT_COMPARABLE if reasons else SecurityDeltaState.REMOVED
                reasons = reasons or ("COMPARABLE_CANDIDATE_ABSENCE",)
                finding = baseline_finding
            results.append(
                SecurityDeltaFinding(
                    finding_id=finding_id,
                    authority=finding.authority.value,
                    category=finding.category.value,
                    state=state,
                    reason_codes=tuple(sorted(reasons)),
                )
            )
        return tuple(results)

    def _absence_reasons(
        self,
        session: Session,
        *,
        observed_membership: SourceLineageRunRow,
        absence_membership: SourceLineageRunRow,
        observed_report: SecureScanEvidenceReport,
        absence_report: SecureScanEvidenceReport,
        finding: SecureScanFinding,
        absence_label: str,
    ) -> tuple[str, ...]:
        reasons: set[str] = set()
        if observed_membership.lineage_id != absence_membership.lineage_id:
            reasons.add("LINEAGE_MISMATCH")
        if observed_membership.report_schema_version != absence_membership.report_schema_version:
            reasons.add("S4_SCHEMA_MISMATCH")
        observed_outcome = self._lifecycle._relevant_outcome(observed_report, finding)
        if observed_outcome is None:
            reasons.add("OBSERVED_COVERAGE_MISSING")
            return tuple(sorted(reasons))
        if observed_outcome.state not in _COMPLETE_COVERAGE:
            reasons.add("OBSERVED_COVERAGE_NOT_COMPLETE")
        absence_outcome = self._lifecycle._matching_outcome(absence_report, observed_outcome)
        if absence_outcome is None:
            reasons.add("SELECTED_SCOPE_MISMATCH")
            return tuple(sorted(reasons))
        if self._lifecycle._relevant_gap(absence_report, finding, absence_outcome):
            reasons.add(f"{absence_label}_RELEVANT_GAP_PRESENT")
        if self._lifecycle._relevant_suppression(absence_report, finding):
            reasons.add(f"{absence_label}_RELEVANT_SUPPRESSION_PRESENT")
        observed_node = self._lifecycle._relevant_node(
            session, observed_membership.run_id, observed_report, observed_outcome
        )
        absence_node = self._lifecycle._relevant_node(
            session, absence_membership.run_id, absence_report, absence_outcome
        )
        if observed_node is None or absence_node is None:
            reasons.add("AUTHORITY_NODE_MISSING")
            return tuple(sorted(reasons))
        if (
            observed_node.analyzer_id != absence_node.analyzer_id
            or observed_node.contract_digest != absence_node.contract_digest
        ):
            reasons.add("AUTHORITY_CONTRACT_MISMATCH")
        if self._lifecycle._selected_paths(observed_node) != self._lifecycle._selected_paths(
            absence_node
        ):
            reasons.add("SELECTED_SCOPE_MISMATCH")
        reasons.update(
            self._translated_completion_reasons(session, observed_node, label="OBSERVED")
        )
        if finding.authority is EvidenceAuthority.OSV:
            zero_package = self._lifecycle._osv_zero_package_reasons(
                session,
                observed_membership.run_id,
                absence_membership.run_id,
                absence_report,
                absence_outcome,
                absence_node,
            )
            if zero_package is not None:
                reasons.update(
                    self._translate_reasons(
                        zero_package,
                        predecessor_label="OBSERVED",
                        current_label=absence_label,
                    )
                )
                return tuple(sorted(reasons))
            reasons.update(
                self._translate_reasons(
                    self._lifecycle._osv_prerequisite_reasons(
                        session,
                        observed_membership.run_id,
                        absence_membership.run_id,
                    ),
                    predecessor_label="OBSERVED",
                    current_label=absence_label,
                )
            )
        if absence_outcome.state not in _COMPLETE_COVERAGE:
            reasons.add(f"{absence_label}_COVERAGE_NOT_COMPLETE")
        reasons.update(
            self._translated_completion_reasons(session, absence_node, label=absence_label)
        )
        return tuple(sorted(reasons))

    def _authority_summaries(
        self,
        session: Session,
        baseline: SourceLineageRunRow,
        candidate: SourceLineageRunRow,
        baseline_report: SecureScanEvidenceReport,
        candidate_report: SecureScanEvidenceReport,
        findings: tuple[SecurityDeltaFinding, ...],
    ) -> tuple[SecurityDeltaAuthoritySummary, ...]:
        summaries = []
        for authority in _FINDING_AUTHORITIES:
            authority_findings = tuple(
                item for item in findings if item.authority == authority.value
            )
            reasons = self._authority_reasons(
                session,
                baseline,
                candidate,
                baseline_report,
                candidate_report,
                authority,
            )
            comparable = sum(
                item.state is not SecurityDeltaState.NOT_COMPARABLE for item in authority_findings
            )
            not_comparable = sum(
                item.state is SecurityDeltaState.NOT_COMPARABLE for item in authority_findings
            )
            if not reasons and not not_comparable:
                status = SecurityDeltaComparisonStatus.COMPLETE
            elif comparable:
                status = SecurityDeltaComparisonStatus.PARTIAL
            else:
                status = SecurityDeltaComparisonStatus.NOT_COMPARABLE
            combined_reasons = set(reasons)
            for item in authority_findings:
                if item.state is SecurityDeltaState.NOT_COMPARABLE:
                    combined_reasons.update(item.reason_codes)
            summaries.append(
                SecurityDeltaAuthoritySummary(
                    authority=authority.value,
                    comparison_status=status,
                    introduced_count=sum(
                        item.state is SecurityDeltaState.INTRODUCED for item in authority_findings
                    ),
                    present_count=sum(
                        item.state is SecurityDeltaState.PRESENT for item in authority_findings
                    ),
                    removed_count=sum(
                        item.state is SecurityDeltaState.REMOVED for item in authority_findings
                    ),
                    not_comparable_count=not_comparable,
                    reason_codes=tuple(sorted(combined_reasons)),
                )
            )
        return tuple(summaries)

    def _authority_reasons(
        self,
        session: Session,
        baseline: SourceLineageRunRow,
        candidate: SourceLineageRunRow,
        baseline_report: SecureScanEvidenceReport,
        candidate_report: SecureScanEvidenceReport,
        authority: EvidenceAuthority,
    ) -> tuple[str, ...]:
        reasons: set[str] = set()
        baseline_outcomes = {
            self._outcome_key(item): item
            for item in baseline_report.coverage_outcomes
            if item.authority is authority
        }
        candidate_outcomes = {
            self._outcome_key(item): item
            for item in candidate_report.coverage_outcomes
            if item.authority is authority
        }
        if not baseline_outcomes:
            reasons.add("BASELINE_AUTHORITY_COVERAGE_MISSING")
        if not candidate_outcomes:
            reasons.add("CANDIDATE_AUTHORITY_COVERAGE_MISSING")
        if set(baseline_outcomes) != set(candidate_outcomes):
            reasons.add("AUTHORITY_SCOPE_MISMATCH")
        for key in sorted(set(baseline_outcomes) & set(candidate_outcomes), key=repr):
            baseline_outcome = baseline_outcomes[key]
            candidate_outcome = candidate_outcomes[key]
            if baseline_outcome.state not in (*_COMPLETE_COVERAGE, CoverageState.NOT_APPLICABLE):
                reasons.add("BASELINE_COVERAGE_NOT_COMPLETE")
            if candidate_outcome.state not in (*_COMPLETE_COVERAGE, CoverageState.NOT_APPLICABLE):
                reasons.add("CANDIDATE_COVERAGE_NOT_COMPLETE")
            if baseline_outcome.gap_count:
                reasons.add("BASELINE_AUTHORITY_GAPS_PRESENT")
            if candidate_outcome.gap_count:
                reasons.add("CANDIDATE_AUTHORITY_GAPS_PRESENT")
            baseline_node = self._lifecycle._relevant_node(
                session, baseline.run_id, baseline_report, baseline_outcome
            )
            candidate_node = self._lifecycle._relevant_node(
                session, candidate.run_id, candidate_report, candidate_outcome
            )
            if baseline_node is None or candidate_node is None:
                reasons.add("AUTHORITY_NODE_MISSING")
                continue
            if (
                baseline_node.analyzer_id != candidate_node.analyzer_id
                or baseline_node.contract_digest != candidate_node.contract_digest
            ):
                reasons.add("AUTHORITY_CONTRACT_MISMATCH")
            if self._lifecycle._selected_paths(baseline_node) != self._lifecycle._selected_paths(
                candidate_node
            ):
                reasons.add("SELECTED_SCOPE_MISMATCH")
            reasons.update(
                self._summary_node_reasons(
                    session,
                    baseline_node,
                    baseline_outcome,
                    label="BASELINE",
                )
            )
            reasons.update(
                self._summary_node_reasons(
                    session,
                    candidate_node,
                    candidate_outcome,
                    label="CANDIDATE",
                )
            )
        if authority is EvidenceAuthority.OSV and baseline_outcomes and candidate_outcomes:
            reasons.update(
                self._translate_reasons(
                    self._lifecycle._osv_prerequisite_reasons(
                        session, baseline.run_id, candidate.run_id
                    ),
                    predecessor_label="BASELINE",
                    current_label="CANDIDATE",
                )
            )
        return tuple(sorted(reasons))

    def _summary_node_reasons(
        self,
        session: Session,
        node: SourceOrchestrationNodeRow,
        outcome: SecureScanCoverageOutcome,
        *,
        label: str,
    ) -> set[str]:
        if outcome.state is CoverageState.NOT_APPLICABLE:
            if not (
                node.lifecycle_state
                in {
                    OrchestrationNodeLifecycleState.NOT_APPLICABLE.value,
                    OrchestrationNodeLifecycleState.TERMINAL.value,
                }
                and node.terminal_disposition == OrchestrationNodeDisposition.NOT_APPLICABLE.value
                and node.containment_state == OrchestrationContainmentState.CLEAN.value
            ):
                return {f"{label}_NODE_NOT_APPLICABLE"}
            return set()
        return self._translated_completion_reasons(session, node, label=label)

    def _translated_completion_reasons(
        self, session: Session, node: SourceOrchestrationNodeRow, *, label: str
    ) -> set[str]:
        return self._translate_reasons(
            self._lifecycle._node_completion_reasons(session, node),
            predecessor_label=label,
            current_label=label,
        )

    @staticmethod
    def _translate_reasons(
        reasons: set[str], *, predecessor_label: str, current_label: str
    ) -> set[str]:
        translated = set()
        for reason in reasons:
            if reason.startswith("PREDECESSOR_"):
                reason = predecessor_label + reason.removeprefix("PREDECESSOR")
            elif reason.startswith("CURRENT_"):
                reason = current_label + reason.removeprefix("CURRENT")
            translated.add(reason)
        return translated

    @staticmethod
    def _outcome_key(outcome: SecureScanCoverageOutcome) -> tuple[object, ...]:
        return (
            outcome.capability,
            outcome.framework,
            outcome.component_ref,
            tuple(repr(item.canonical_data()) for item in outcome.selected_scope),
        )

    @staticmethod
    def _overall_status(
        summaries: tuple[SecurityDeltaAuthoritySummary, ...],
    ) -> SecurityDeltaComparisonStatus:
        statuses = {item.comparison_status for item in summaries}
        if statuses == {SecurityDeltaComparisonStatus.COMPLETE}:
            return SecurityDeltaComparisonStatus.COMPLETE
        if statuses <= {SecurityDeltaComparisonStatus.NOT_COMPARABLE}:
            return SecurityDeltaComparisonStatus.NOT_COMPARABLE
        return SecurityDeltaComparisonStatus.PARTIAL

    def _ordered_failure(
        self,
        promotion: SourceTrustedBaselinePromotionRow,
        baseline: SourceLineageRunRow,
        candidate: SourceLineageRunRow,
        baseline_report: SecureScanEvidenceReport,
        candidate_report: SecureScanEvidenceReport,
    ) -> SecurityDelta:
        combined_findings = {
            item.finding_id: item
            for item in (*baseline_report.findings, *candidate_report.findings)
        }
        findings = tuple(
            SecurityDeltaFinding(
                finding_id=item.finding_id,
                authority=item.authority.value,
                category=item.category.value,
                state=SecurityDeltaState.NOT_COMPARABLE,
                reason_codes=("CANDIDATE_BEFORE_BASELINE",),
            )
            for item in sorted(combined_findings.values(), key=lambda item: item.finding_id)
        )
        summaries = tuple(
            SecurityDeltaAuthoritySummary(
                authority=authority.value,
                comparison_status=SecurityDeltaComparisonStatus.NOT_COMPARABLE,
                introduced_count=0,
                present_count=0,
                removed_count=0,
                not_comparable_count=sum(item.authority == authority.value for item in findings),
                reason_codes=("CANDIDATE_BEFORE_BASELINE",),
            )
            for authority in _FINDING_AUTHORITIES
        )
        return SecurityDelta(
            baseline_id=promotion.baseline_id,
            baseline_run_id=promotion.run_id,
            baseline_revision=promotion.revision,
            baseline_sequence_number=baseline.sequence_number,
            candidate_run_id=candidate.run_id,
            candidate_sequence_number=candidate.sequence_number,
            comparison_status=SecurityDeltaComparisonStatus.NOT_COMPARABLE,
            authority_summaries=summaries,
            findings=findings,
        )

    @staticmethod
    def _validate_identifiers(*values: str) -> None:
        try:
            valid = all(isinstance(value, str) and str(UUID(value)) == value for value in values)
        except (AttributeError, TypeError, ValueError):
            valid = False
        if not valid:
            raise SecurityDeltaValidationError("invalid security-delta identifier")
