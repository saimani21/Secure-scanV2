from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.evidence import (
    CoverageState,
    EvidenceAuthority,
    OsvAdvisoryGroupEvidencePayload,
    SecureScanCoverageOutcome,
    SecureScanEvidenceReport,
    SecureScanFinding,
)
from securescan.orchestration.dependency_evaluation import (
    DependencyEvaluationDecision,
    SourceDependencyEvaluationError,
    SourceDependencyEvaluationService,
)
from securescan.orchestration.models import (
    OrchestrationContainmentState,
    OrchestrationNodeDisposition,
    OrchestrationNodeLifecycleState,
    SourceAuthority,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    SourceFindingLifecycleEventRow,
    SourceFindingLifecycleRow,
    SourceFindingOccurrenceRow,
    SourceLineageRunRow,
    SourceOrchestrationAttemptRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationRow,
    SourceOrchestrationScannerJobRow,
    SourceTargetLineageRow,
    utc_now,
)

from .finding_index import ProductCoreIndexError, SourceFindingIndexService

LIFECYCLE_EVALUATION_SCHEMA_VERSION = "securescan-product-core-lifecycle-pc2-v1"


class ProductCoreLifecycleError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Source Product Core lifecycle evaluation failed")


class FindingLifecycleState(StrEnum):
    NEW = "NEW"
    EXISTING = "EXISTING"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"


class LifecycleEventKind(StrEnum):
    TRANSITION = "TRANSITION"
    RESOLUTION_WITHHELD = "RESOLUTION_WITHHELD"


class PriorityBand(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNRANKED = "UNRANKED"


class PriorityReasonCode(StrEnum):
    SCANNER_NORMALIZED_SEVERITY = "SCANNER_NORMALIZED_SEVERITY"
    VALIDATED_CVSS_BASE_SCORE = "VALIDATED_CVSS_BASE_SCORE"
    NO_VALIDATED_CVSS = "NO_VALIDATED_CVSS"
    NO_NORMALIZED_SEVERITY = "NO_NORMALIZED_SEVERITY"
    CATEGORY_POLICY_SECRET_EXPOSURE = "CATEGORY_POLICY_SECRET_EXPOSURE"


_COMPLETE_COVERAGE = {
    CoverageState.COMPLETE,
    CoverageState.COMPLETE_WITH_FINDINGS,
    CoverageState.COMPLETE_WITH_SUPPRESSIONS,
}


@dataclass(frozen=True, slots=True)
class FindingPriority:
    band: PriorityBand
    reason_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FindingLifecycle:
    lineage_id: str
    finding_id: str
    authority: str
    category: str
    native_identity_schema: str
    current_state: FindingLifecycleState
    first_seen_run_id: str
    last_seen_run_id: str
    resolved_run_id: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None
    transition_version: int


@dataclass(frozen=True, slots=True)
class FindingLifecycleEvent:
    lineage_id: str
    run_id: str
    finding_id: str
    event_kind: LifecycleEventKind
    previous_state: FindingLifecycleState | None
    resulting_state: FindingLifecycleState
    reason_codes: tuple[str, ...]
    transition_version: int
    created_at: datetime


@dataclass(frozen=True, slots=True)
class LifecycleEvaluationResult:
    lineage_id: str
    run_id: str
    evaluation_sha256: str
    event_count: int
    transition_count: int
    withheld_count: int
    evaluated_at: datetime
    created: bool


@dataclass(frozen=True, slots=True)
class _EventMaterial:
    finding_id: str
    event_kind: str
    previous_state: str | None
    resulting_state: str
    reason_codes: tuple[str, ...]
    transition_version: int

    def canonical_data(self) -> dict[str, Any]:
        return {
            "event_kind": self.event_kind,
            "finding_id": self.finding_id,
            "previous_state": self.previous_state,
            "reason_codes": list(self.reason_codes),
            "resulting_state": self.resulting_state,
            "transition_version": self.transition_version,
        }


@dataclass(frozen=True, slots=True)
class _ComparisonResult:
    reasons: tuple[str, ...]
    resolution_reason: str


class SourceFindingLifecycleService:
    """Evaluate S4 finding lifecycle only where absence is safely comparable."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        artifact_store: ContentAddressedArtifactStore,
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._sessions = session_factory
        self._index = SourceFindingIndexService(session_factory, artifact_store)
        self._dependency_evaluations = SourceDependencyEvaluationService(
            session_factory, artifact_store
        )
        self._clock = clock

    def evaluate(self, *, lineage_id: str, run_id: str) -> LifecycleEvaluationResult:
        self._require_uuid(lineage_id)
        self._require_uuid(run_id)
        current_report = self._trusted_report(run_id)
        now = self._now()
        try:
            with self._sessions.begin() as session:
                lineage = session.scalar(
                    select(SourceTargetLineageRow)
                    .where(SourceTargetLineageRow.lineage_id == lineage_id)
                    .with_for_update()
                )
                membership = session.scalar(
                    select(SourceLineageRunRow)
                    .where(SourceLineageRunRow.run_id == run_id)
                    .with_for_update()
                )
                if (
                    lineage is None
                    or membership is None
                    or membership.lineage_id != lineage_id
                    or membership.indexing_state != "INDEXED"
                    or membership.indexed_at is None
                ):
                    raise ProductCoreLifecycleError
                run, parent = self._locked_run_and_parent(session, run_id)
                self._verify_report(run, parent, current_report)
                transition_at = self._published_at(parent)
                self._verify_occurrence_index(session, membership, current_report)
                predecessor = self._predecessor(session, membership)
                if membership.lifecycle_evaluated_at is not None:
                    return self._load_completed_evaluation(session, membership)
                later_evaluation = session.scalar(
                    select(SourceLineageRunRow.run_id)
                    .where(
                        SourceLineageRunRow.lineage_id == lineage_id,
                        SourceLineageRunRow.sequence_number
                        > membership.sequence_number,
                        SourceLineageRunRow.lifecycle_evaluated_at.is_not(None),
                    )
                    .limit(1)
                )
                if (
                    later_evaluation is not None
                    or membership.lifecycle_evaluation_sha256 is not None
                    or membership.lifecycle_event_count is not None
                    or tuple(
                        session.scalars(
                            select(SourceFindingLifecycleEventRow).where(
                                SourceFindingLifecycleEventRow.run_id == run_id
                            )
                        )
                    )
                ):
                    raise ProductCoreLifecycleError
                if predecessor is not None and predecessor.lifecycle_evaluated_at is None:
                    raise ProductCoreLifecycleError

                occurrences = tuple(
                    session.scalars(
                        select(SourceFindingOccurrenceRow)
                        .where(SourceFindingOccurrenceRow.run_id == run_id)
                        .order_by(SourceFindingOccurrenceRow.finding_id)
                    )
                )
                if any(
                    item.priority_band is not None
                    or item.priority_reason_codes_json is not None
                    for item in occurrences
                ):
                    raise ProductCoreLifecycleError
                lifecycles = {
                    item.finding_id: item
                    for item in session.scalars(
                        select(SourceFindingLifecycleRow)
                        .where(SourceFindingLifecycleRow.lineage_id == lineage_id)
                        .order_by(SourceFindingLifecycleRow.finding_id)
                        .with_for_update()
                    )
                }
                if membership.sequence_number == 1 and lifecycles:
                    raise ProductCoreLifecycleError
                for lifecycle in lifecycles.values():
                    self._validate_lifecycle_row(session, lifecycle)
                    if self._as_utc(lifecycle.last_seen_at) > transition_at or (
                        lifecycle.resolved_at is not None
                        and self._as_utc(lifecycle.resolved_at) > transition_at
                    ):
                        raise ProductCoreLifecycleError

                report_findings = {item.finding_id: item for item in current_report.findings}
                events: list[_EventMaterial] = []
                priorities: dict[str, FindingPriority] = {}
                for occurrence in occurrences:
                    finding = report_findings[occurrence.finding_id]
                    priority = self.priority_for_finding(current_report, finding)
                    priorities[occurrence.finding_id] = priority
                    occurrence.priority_band = priority.band.value
                    occurrence.priority_reason_codes_json = list(priority.reason_codes)
                    lifecycle = lifecycles.get(occurrence.finding_id)
                    if lifecycle is None:
                        lifecycle = SourceFindingLifecycleRow(
                            lineage_id=lineage_id,
                            finding_id=occurrence.finding_id,
                            authority=occurrence.authority,
                            category=occurrence.category,
                            native_identity_schema=occurrence.native_identity_schema,
                            current_state=FindingLifecycleState.NEW.value,
                            first_seen_run_id=run_id,
                            last_seen_run_id=run_id,
                            resolved_run_id=None,
                            first_seen_at=transition_at,
                            last_seen_at=transition_at,
                            resolved_at=None,
                            transition_version=1,
                        )
                        session.add(lifecycle)
                        lifecycles[occurrence.finding_id] = lifecycle
                        events.append(
                            _EventMaterial(
                                occurrence.finding_id,
                                LifecycleEventKind.TRANSITION.value,
                                None,
                                FindingLifecycleState.NEW.value,
                                ("FIRST_OBSERVATION",),
                                1,
                            )
                        )
                        continue
                    self._verify_lifecycle_identity(lifecycle, occurrence)
                    self._verify_lifecycle_order(session, lifecycle, membership)
                    previous = FindingLifecycleState(lifecycle.current_state)
                    resulting = (
                        FindingLifecycleState.REOPENED
                        if previous is FindingLifecycleState.RESOLVED
                        else FindingLifecycleState.EXISTING
                    )
                    lifecycle.current_state = resulting.value
                    lifecycle.last_seen_run_id = run_id
                    lifecycle.last_seen_at = transition_at
                    lifecycle.resolved_run_id = None
                    lifecycle.resolved_at = None
                    lifecycle.transition_version += 1
                    events.append(
                        _EventMaterial(
                            occurrence.finding_id,
                            LifecycleEventKind.TRANSITION.value,
                            previous.value,
                            resulting.value,
                            (
                                "RETURNED_AFTER_RESOLUTION"
                                if resulting is FindingLifecycleState.REOPENED
                                else "OBSERVED_AGAIN",
                            ),
                            lifecycle.transition_version,
                        )
                    )

                current_ids = set(report_findings)
                for lifecycle in sorted(lifecycles.values(), key=lambda item: item.finding_id):
                    if (
                        lifecycle.finding_id in current_ids
                        or lifecycle.current_state == FindingLifecycleState.RESOLVED.value
                    ):
                        continue
                    origin_membership = session.get(
                        SourceLineageRunRow, lifecycle.last_seen_run_id
                    )
                    if (
                        origin_membership is None
                        or origin_membership.lineage_id != lineage_id
                        or origin_membership.sequence_number >= membership.sequence_number
                        or origin_membership.indexing_state != "INDEXED"
                    ):
                        raise ProductCoreLifecycleError
                    origin_report = self._trusted_report(origin_membership.run_id)
                    origin_run, origin_parent = self._locked_run_and_parent(
                        session, origin_membership.run_id
                    )
                    self._verify_report(origin_run, origin_parent, origin_report)
                    origin_finding = next(
                        (
                            item
                            for item in origin_report.findings
                            if item.finding_id == lifecycle.finding_id
                        ),
                        None,
                    )
                    if origin_finding is None:
                        raise ProductCoreLifecycleError
                    origin_occurrence = session.get(
                        SourceFindingOccurrenceRow,
                        (origin_membership.run_id, lifecycle.finding_id),
                    )
                    if origin_occurrence is None:
                        raise ProductCoreLifecycleError
                    self._verify_lifecycle_identity(lifecycle, origin_occurrence)
                    comparison = self._comparison(
                        session,
                        origin_membership,
                        membership,
                        origin_report,
                        current_report,
                        origin_finding,
                    )
                    previous = FindingLifecycleState(lifecycle.current_state)
                    if comparison.reasons:
                        events.append(
                            _EventMaterial(
                                lifecycle.finding_id,
                                LifecycleEventKind.RESOLUTION_WITHHELD.value,
                                previous.value,
                                previous.value,
                                comparison.reasons,
                                lifecycle.transition_version,
                            )
                        )
                        continue
                    lifecycle.current_state = FindingLifecycleState.RESOLVED.value
                    lifecycle.resolved_run_id = run_id
                    lifecycle.resolved_at = transition_at
                    lifecycle.transition_version += 1
                    events.append(
                        _EventMaterial(
                            lifecycle.finding_id,
                            LifecycleEventKind.TRANSITION.value,
                            previous.value,
                            FindingLifecycleState.RESOLVED.value,
                            (comparison.resolution_reason,),
                            lifecycle.transition_version,
                        )
                    )

                events.sort(key=lambda item: item.finding_id)
                # The event table references lifecycle rows through a composite
                # foreign key. Flush the current-state rows first because no ORM
                # relationship is needed solely to convey insert ordering.
                session.flush()
                for item in events:
                    session.add(
                        SourceFindingLifecycleEventRow(
                            run_id=run_id,
                            finding_id=item.finding_id,
                            lineage_id=lineage_id,
                            event_kind=item.event_kind,
                            previous_state=item.previous_state,
                            resulting_state=item.resulting_state,
                            reason_codes_json=list(item.reason_codes),
                            transition_version=item.transition_version,
                            created_at=transition_at,
                        )
                    )
                digest = self._evaluation_digest(
                    run_id, events, priorities, transition_at
                )
                membership.lifecycle_evaluated_at = now
                membership.lifecycle_evaluation_sha256 = digest
                membership.lifecycle_event_count = len(events)
                session.flush()
                return self._result(membership, events, created=True)
        except ProductCoreLifecycleError:
            raise
        except (KeyError, SQLAlchemyError, TypeError, ValueError):
            raise ProductCoreLifecycleError from None

    @staticmethod
    def priority_for_finding(
        report: SecureScanEvidenceReport, finding: SecureScanFinding
    ) -> FindingPriority:
        if finding.authority is EvidenceAuthority.GITLEAKS:
            return FindingPriority(
                PriorityBand.HIGH,
                (PriorityReasonCode.CATEGORY_POLICY_SECRET_EXPOSURE.value,),
            )
        if finding.authority in {EvidenceAuthority.SEMGREP, EvidenceAuthority.CHECKOV}:
            if finding.severity is None or finding.severity.value == "UNKNOWN":
                return FindingPriority(
                    PriorityBand.UNRANKED,
                    (PriorityReasonCode.NO_NORMALIZED_SEVERITY.value,),
                )
            band = {
                "CRITICAL": PriorityBand.CRITICAL,
                "HIGH": PriorityBand.HIGH,
                "MEDIUM": PriorityBand.MEDIUM,
                "LOW": PriorityBand.LOW,
                "INFORMATIONAL": PriorityBand.INFO,
            }.get(finding.severity.value)
            if band is None:
                raise ProductCoreLifecycleError
            return FindingPriority(
                band,
                (PriorityReasonCode.SCANNER_NORMALIZED_SEVERITY.value,),
            )
        if finding.authority is not EvidenceAuthority.OSV:
            raise ProductCoreLifecycleError
        evidence = {item.evidence_id: item for item in report.evidence}
        groups = tuple(
            item.payload
            for reference in finding.primary_evidence_refs
            if (item := evidence.get(reference)) is not None
            and isinstance(item.payload, OsvAdvisoryGroupEvidencePayload)
        )
        if len(groups) != 1:
            raise ProductCoreLifecycleError
        scores = tuple(item.base_score for item in groups[0].cvss)
        if not scores:
            return FindingPriority(
                PriorityBand.UNRANKED,
                (PriorityReasonCode.NO_VALIDATED_CVSS.value,),
            )
        maximum = max(scores)
        band = (
            PriorityBand.CRITICAL
            if maximum >= 9.0
            else PriorityBand.HIGH
            if maximum >= 7.0
            else PriorityBand.MEDIUM
            if maximum >= 4.0
            else PriorityBand.LOW
            if maximum > 0.0
            else PriorityBand.INFO
        )
        return FindingPriority(
            band,
            (PriorityReasonCode.VALIDATED_CVSS_BASE_SCORE.value,),
        )

    def load_lifecycle(self, *, lineage_id: str, finding_id: str) -> FindingLifecycle:
        self._require_uuid(lineage_id)
        try:
            with self._sessions() as session:
                row = session.get(SourceFindingLifecycleRow, (lineage_id, finding_id))
                if row is None:
                    raise ProductCoreLifecycleError
                self._validate_lifecycle_row(session, row)
                return self._lifecycle_record(row)
        except ProductCoreLifecycleError:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise ProductCoreLifecycleError from None

    def list_events(
        self, *, lineage_id: str, run_id: str
    ) -> tuple[FindingLifecycleEvent, ...]:
        self._require_uuid(lineage_id)
        self._require_uuid(run_id)
        try:
            with self._sessions() as session:
                rows = tuple(
                    session.scalars(
                        select(SourceFindingLifecycleEventRow)
                        .where(
                            SourceFindingLifecycleEventRow.lineage_id == lineage_id,
                            SourceFindingLifecycleEventRow.run_id == run_id,
                        )
                        .order_by(SourceFindingLifecycleEventRow.finding_id)
                    )
                )
                return tuple(self._event_record(item) for item in rows)
        except (SQLAlchemyError, TypeError, ValueError):
            raise ProductCoreLifecycleError from None

    def _comparison(
        self,
        session: Session,
        origin_membership: SourceLineageRunRow,
        current_membership: SourceLineageRunRow,
        origin_report: SecureScanEvidenceReport,
        current_report: SecureScanEvidenceReport,
        finding: SecureScanFinding,
    ) -> _ComparisonResult:
        reasons: set[str] = set()
        if (
            origin_membership.lineage_id != current_membership.lineage_id
            or current_membership.predecessor_run_id is None
        ):
            reasons.add("LINEAGE_PREDECESSOR_INVALID")
        if origin_membership.report_schema_version != current_membership.report_schema_version:
            reasons.add("S4_SCHEMA_MISMATCH")
        current_parent = session.get(SourceOrchestrationRow, current_membership.run_id)
        if current_parent is None:
            reasons.add("CURRENT_ORCHESTRATION_MISSING")
        elif current_parent.cancel_requested:
            reasons.add("PARENT_CANCELLED")
        elif current_parent.deadline_exceeded_at is not None:
            reasons.add("PARENT_DEADLINE_EXCEEDED")
        origin_outcome = self._relevant_outcome(origin_report, finding)
        if origin_outcome is None:
            reasons.add("PREDECESSOR_COVERAGE_MISSING")
            return _ComparisonResult(tuple(sorted(reasons)), "COMPARABLE_SCOPE_ABSENCE")
        if origin_outcome.state not in _COMPLETE_COVERAGE:
            reasons.add("PREDECESSOR_COVERAGE_NOT_COMPLETE")
        current_outcome = self._matching_outcome(current_report, origin_outcome)
        if current_outcome is None:
            reasons.add("SELECTED_SCOPE_MISMATCH")
            return _ComparisonResult(tuple(sorted(reasons)), "COMPARABLE_SCOPE_ABSENCE")
        if self._relevant_gap(current_report, finding, current_outcome):
            reasons.add("RELEVANT_GAP_PRESENT")
        if self._relevant_suppression(current_report, finding):
            reasons.add("RELEVANT_SUPPRESSION_PRESENT")
        origin_node = self._relevant_node(
            session, origin_membership.run_id, origin_report, origin_outcome
        )
        current_node = self._relevant_node(
            session, current_membership.run_id, current_report, current_outcome
        )
        if origin_node is None or current_node is None:
            reasons.add("AUTHORITY_NODE_MISSING")
            return _ComparisonResult(tuple(sorted(reasons)), "COMPARABLE_SCOPE_ABSENCE")
        if (
            origin_node.analyzer_id != current_node.analyzer_id
            or origin_node.contract_digest != current_node.contract_digest
        ):
            reasons.add("AUTHORITY_CONTRACT_MISMATCH")
        if self._selected_paths(origin_node) != self._selected_paths(current_node):
            reasons.add("SELECTED_SCOPE_MISMATCH")
        reasons.update(self._node_completion_reasons(session, origin_node, predecessor=True))
        if finding.authority is EvidenceAuthority.OSV:
            zero_package_reasons = self._osv_zero_package_reasons(
                session,
                origin_membership.run_id,
                current_membership.run_id,
                current_report,
                current_outcome,
                current_node,
            )
            if zero_package_reasons is not None:
                reasons.update(zero_package_reasons)
                return _ComparisonResult(
                    tuple(sorted(reasons)), "DEPENDENCY_REMOVED_ZERO_PACKAGE_PROOF"
                )
            reasons.update(
                self._osv_prerequisite_reasons(
                    session, origin_membership.run_id, current_membership.run_id
                )
            )
        if current_outcome.state not in _COMPLETE_COVERAGE:
            reasons.add("CURRENT_COVERAGE_NOT_COMPLETE")
        reasons.update(self._node_completion_reasons(session, current_node))
        return _ComparisonResult(tuple(sorted(reasons)), "COMPARABLE_SCOPE_ABSENCE")

    @staticmethod
    def _relevant_outcome(
        report: SecureScanEvidenceReport, finding: SecureScanFinding
    ) -> SecureScanCoverageOutcome | None:
        framework = getattr(finding.subject, "framework", None)
        locations = tuple(item.canonical_data() for item in finding.locations)
        candidates = tuple(
            item
            for item in report.coverage_outcomes
            if item.authority is finding.authority
            and (framework is None or item.framework == framework)
            and (
                finding.authority is EvidenceAuthority.OSV
                or SourceFindingLifecycleService._locations_covered(
                    locations,
                    tuple(value.canonical_data() for value in item.selected_scope),
                )
            )
        )
        return candidates[0] if len(candidates) == 1 else None

    @staticmethod
    def _matching_outcome(
        report: SecureScanEvidenceReport, expected: SecureScanCoverageOutcome
    ) -> SecureScanCoverageOutcome | None:
        scope = tuple(item.canonical_data() for item in expected.selected_scope)
        candidates = tuple(
            item
            for item in report.coverage_outcomes
            if item.authority is expected.authority
            and item.capability == expected.capability
            and item.framework == expected.framework
            and item.component_ref == expected.component_ref
            and tuple(value.canonical_data() for value in item.selected_scope) == scope
        )
        return candidates[0] if len(candidates) == 1 else None

    @staticmethod
    def _locations_covered(
        locations: tuple[dict[str, Any], ...], scope: tuple[dict[str, Any], ...]
    ) -> bool:
        if any(item.get("kind") == "REPOSITORY_SCOPE" for item in scope):
            return True
        paths = {item.get("path") for item in scope if item.get("path") is not None}
        finding_paths = {
            item.get("path") for item in locations if item.get("path") is not None
        }
        return bool(finding_paths) and finding_paths <= paths

    @staticmethod
    def _relevant_gap(
        report: SecureScanEvidenceReport,
        finding: SecureScanFinding,
        outcome: SecureScanCoverageOutcome,
    ) -> bool:
        finding_paths = {
            item.canonical_data().get("path")
            for item in finding.locations
            if item.canonical_data().get("path") is not None
        }
        component_ref = getattr(finding.subject, "component_ref", None)
        framework = getattr(finding.subject, "framework", None)
        for gap in report.gaps:
            if gap.authority is not finding.authority:
                continue
            if gap.scope.kind.value == "REPOSITORY":
                return True
            if gap.scope.kind.value == "CAPABILITY" and gap.scope.value == outcome.capability:
                return True
            if gap.scope.kind.value == "PACKAGE" and gap.scope.component_ref == component_ref:
                return True
            if gap.scope.kind.value == "FRAMEWORK" and gap.scope.value == framework:
                return True
            if (
                gap.scope.kind.value == "PATH"
                and gap.scope.value in finding_paths
                and (gap.scope.framework is None or gap.scope.framework == framework)
            ):
                return True
        return False

    @staticmethod
    def _relevant_suppression(
        report: SecureScanEvidenceReport, finding: SecureScanFinding
    ) -> bool:
        subject = finding.subject.canonical_data()
        finding_paths = {
            item.canonical_data().get("path")
            for item in finding.locations
            if item.canonical_data().get("path") is not None
        }
        return any(
            item.authority is finding.authority
            and item.subject.canonical_data() == subject
            and any(
                location.canonical_data().get("path") in finding_paths
                for location in item.locations
            )
            for item in report.suppressions
        )

    @staticmethod
    def _relevant_node(
        session: Session,
        run_id: str,
        report: SecureScanEvidenceReport,
        outcome: SecureScanCoverageOutcome,
    ) -> SourceOrchestrationNodeRow | None:
        component_id = None
        if outcome.component_ref is not None:
            component = next(
                (
                    item
                    for item in report.components
                    if item.component_ref == outcome.component_ref
                ),
                None,
            )
            component_id = getattr(
                None if component is None else component.payload, "component_id", None
            )
            if component_id is None:
                return None
        nodes = tuple(
            session.scalars(
                select(SourceOrchestrationNodeRow).where(
                    SourceOrchestrationNodeRow.run_id == run_id,
                    SourceOrchestrationNodeRow.authority == outcome.authority.value,
                    SourceOrchestrationNodeRow.capability == outcome.capability,
                    SourceOrchestrationNodeRow.component_id == component_id,
                )
            )
        )
        return nodes[0] if len(nodes) == 1 else None

    @staticmethod
    def _selected_paths(node: SourceOrchestrationNodeRow) -> tuple[str, ...]:
        values = node.selected_paths_json
        if (
            not isinstance(values, list)
            or any(not isinstance(item, str) for item in values)
            or values != sorted(set(values))
        ):
            raise ProductCoreLifecycleError
        return tuple(values)

    @staticmethod
    def _node_completion_reasons(
        session: Session,
        node: SourceOrchestrationNodeRow,
        *,
        predecessor: bool = False,
    ) -> set[str]:
        prefix = "PREDECESSOR" if predecessor else "CURRENT"
        reasons: set[str] = set()
        if (
            node.lifecycle_state != OrchestrationNodeLifecycleState.TERMINAL.value
            or node.terminal_disposition != OrchestrationNodeDisposition.COMPLETE.value
        ):
            reasons.add(f"{prefix}_NODE_NOT_COMPLETE")
            if (
                node.terminal_disposition
                == OrchestrationNodeDisposition.BLOCKED_BY_DEPENDENCY.value
            ):
                reasons.add("DEPENDENCY_BLOCKED")
        if node.containment_state != OrchestrationContainmentState.CLEAN.value:
            reasons.add(f"{prefix}_CONTAINMENT_NOT_CLEAN")
        mapping = session.scalar(
            select(SourceOrchestrationScannerJobRow).where(
                SourceOrchestrationScannerJobRow.run_id == node.run_id,
                SourceOrchestrationScannerJobRow.node_id == node.node_id,
            )
        )
        attempt = (
            None
            if mapping is None or mapping.selected_attempt_number is None
            else session.get(
                SourceOrchestrationAttemptRow,
                (mapping.job_id, mapping.selected_attempt_number),
            )
        )
        if (
            mapping is None
            or mapping.run_id != node.run_id
            or mapping.node_id != node.node_id
            or mapping.authority != node.authority
            or mapping.capability != node.capability
            or mapping.analyzer_id != node.analyzer_id
            or mapping.contract_digest != node.contract_digest
            or attempt is None
            or attempt.run_id != node.run_id
            or attempt.node_id != node.node_id
            or attempt.acceptance_state != "ACCEPTED"
            or attempt.containment_state != OrchestrationContainmentState.CLEAN.value
            or attempt.native_result_sha256 is None
        ):
            reasons.add(f"{prefix}_ACCEPTED_RESULT_MISSING")
        return reasons

    def _osv_prerequisite_reasons(
        self, session: Session, origin_run_id: str, current_run_id: str
    ) -> set[str]:
        nodes = {}
        for run_id in (origin_run_id, current_run_id):
            values = tuple(
                session.scalars(
                    select(SourceOrchestrationNodeRow).where(
                        SourceOrchestrationNodeRow.run_id == run_id,
                        SourceOrchestrationNodeRow.authority == SourceAuthority.SYFT.value,
                    )
                )
            )
            if len(values) != 1:
                return {"OSV_PREREQUISITE_MISSING"}
            nodes[run_id] = values[0]
        origin = nodes[origin_run_id]
        current = nodes[current_run_id]
        reasons = self._node_completion_reasons(session, current)
        reasons.update(self._node_completion_reasons(session, origin, predecessor=True))
        if (
            origin.analyzer_id != current.analyzer_id
            or origin.contract_digest != current.contract_digest
            or self._selected_paths(origin) != self._selected_paths(current)
        ):
            reasons.add("OSV_PREREQUISITE_SCOPE_MISMATCH")
        return reasons

    def _osv_zero_package_reasons(
        self,
        session: Session,
        origin_run_id: str,
        current_run_id: str,
        current_report: SecureScanEvidenceReport,
        current_outcome: SecureScanCoverageOutcome,
        current_osv_node: SourceOrchestrationNodeRow,
    ) -> set[str] | None:
        if not (
            current_outcome.state is CoverageState.NOT_APPLICABLE
            and current_outcome.reason_code == "NO_PACKAGES_OBSERVED"
            and current_outcome.finding_count == 0
            and current_outcome.gap_count == 0
            and current_osv_node.lifecycle_state
            == OrchestrationNodeLifecycleState.TERMINAL.value
            and current_osv_node.terminal_disposition
            == OrchestrationNodeDisposition.NOT_APPLICABLE.value
            and current_osv_node.terminal_reason_code == "NO_PACKAGES_OBSERVED"
        ):
            return None
        reasons = self._osv_prerequisite_reasons(
            session, origin_run_id, current_run_id
        )
        current_syft_nodes = tuple(
            session.scalars(
                select(SourceOrchestrationNodeRow).where(
                    SourceOrchestrationNodeRow.run_id == current_run_id,
                    SourceOrchestrationNodeRow.authority == SourceAuthority.SYFT.value,
                )
            )
        )
        if len(current_syft_nodes) != 1:
            reasons.add("OSV_PREREQUISITE_MISSING")
            return reasons
        current_syft = current_syft_nodes[0]
        syft_mapping = session.scalar(
            select(SourceOrchestrationScannerJobRow).where(
                SourceOrchestrationScannerJobRow.run_id == current_run_id,
                SourceOrchestrationScannerJobRow.node_id == current_syft.node_id,
            )
        )
        syft_attempt = (
            None
            if syft_mapping is None or syft_mapping.selected_attempt_number is None
            else session.get(
                SourceOrchestrationAttemptRow,
                (syft_mapping.job_id, syft_mapping.selected_attempt_number),
            )
        )
        syft_outcomes = tuple(
            item
            for item in current_report.coverage_outcomes
            if item.authority is EvidenceAuthority.SYFT
            and item.capability == current_syft.capability
            and tuple(value.canonical_data() for value in item.selected_scope)
            == tuple(value.canonical_data() for value in current_outcome.selected_scope)
        )
        if (
            len(syft_outcomes) != 1
            or syft_outcomes[0].state is not CoverageState.COMPLETE
            or syft_outcomes[0].finding_count != 0
            or syft_outcomes[0].gap_count != 0
            or any(
                item.authority is EvidenceAuthority.SYFT
                for item in current_report.evidence
            )
        ):
            reasons.add("ZERO_PACKAGE_S4_EVIDENCE_INVALID")
        osv_mapping = session.scalar(
            select(SourceOrchestrationScannerJobRow).where(
                SourceOrchestrationScannerJobRow.run_id == current_run_id,
                SourceOrchestrationScannerJobRow.node_id == current_osv_node.node_id,
            )
        )
        if osv_mapping is not None:
            reasons.add("ZERO_PACKAGE_OSV_JOB_PRESENT")
        try:
            evaluation = self._dependency_evaluations.load(
                run_id=current_run_id,
                osv_node_id=current_osv_node.node_id,
            ).evaluation
        except SourceDependencyEvaluationError:
            reasons.add("ZERO_PACKAGE_DEPENDENCY_EVIDENCE_INVALID")
            return reasons
        if not (
            evaluation.decision
            is DependencyEvaluationDecision.NOT_APPLICABLE_NO_PACKAGES
            and not evaluation.coverage_limited
            and evaluation.syft_prerequisite.prerequisite_complete
            and evaluation.syft_prerequisite.node_id == current_syft.node_id
            and syft_mapping is not None
            and syft_attempt is not None
            and evaluation.syft_prerequisite.job_id == syft_mapping.job_id
            and evaluation.syft_prerequisite.selected_attempt_number
            == syft_mapping.selected_attempt_number
            and evaluation.syft_prerequisite.native_result_sha256
            == syft_attempt.native_result_sha256
            and not evaluation.observations
            and not evaluation.mixed_scope_gaps
            and not evaluation.eligible_package_observation_ids
            and not evaluation.candidate_ids
            and not evaluation.coordinate_gaps
            and evaluation.scope.selected_paths == self._selected_paths(current_syft)
            and evaluation.scope.selected_paths
            == self._selected_paths(current_osv_node)
        ):
            reasons.add("ZERO_PACKAGE_DEPENDENCY_EVIDENCE_INVALID")
        return reasons

    def _verify_occurrence_index(
        self,
        session: Session,
        membership: SourceLineageRunRow,
        report: SecureScanEvidenceReport,
    ) -> None:
        rows = tuple(
            session.scalars(
                select(SourceFindingOccurrenceRow)
                .where(SourceFindingOccurrenceRow.run_id == membership.run_id)
                .order_by(SourceFindingOccurrenceRow.finding_ordinal)
            )
        )
        expected = self._index._occurrence_material(report)
        self._index._verify_existing_occurrences(rows, membership, expected)

    def _trusted_report(self, run_id: str) -> SecureScanEvidenceReport:
        try:
            return self._index._rebuild_trusted_report(run_id)
        except ProductCoreIndexError:
            raise ProductCoreLifecycleError from None

    def _verify_report(
        self,
        run: AnalysisRunRow,
        parent: SourceOrchestrationRow,
        report: SecureScanEvidenceReport,
    ) -> None:
        try:
            self._index._verify_published_report(run, parent, report)
        except ProductCoreIndexError:
            raise ProductCoreLifecycleError from None

    @staticmethod
    def _predecessor(
        session: Session, membership: SourceLineageRunRow
    ) -> SourceLineageRunRow | None:
        if membership.sequence_number == 1:
            if (
                membership.predecessor_run_id is not None
                or membership.predecessor_sequence_number is not None
            ):
                raise ProductCoreLifecycleError
            return None
        predecessor = session.scalar(
            select(SourceLineageRunRow)
            .where(SourceLineageRunRow.run_id == membership.predecessor_run_id)
            .with_for_update()
        )
        if (
            predecessor is None
            or predecessor.lineage_id != membership.lineage_id
            or predecessor.sequence_number != membership.predecessor_sequence_number
            or predecessor.sequence_number >= membership.sequence_number
            or predecessor.indexing_state != "INDEXED"
            or predecessor.indexed_at is None
        ):
            raise ProductCoreLifecycleError
        return predecessor

    @staticmethod
    def _verify_lifecycle_identity(
        lifecycle: SourceFindingLifecycleRow, occurrence: SourceFindingOccurrenceRow
    ) -> None:
        if (
            lifecycle.authority != occurrence.authority
            or lifecycle.category != occurrence.category
            or lifecycle.native_identity_schema != occurrence.native_identity_schema
        ):
            raise ProductCoreLifecycleError

    @staticmethod
    def _verify_lifecycle_order(
        session: Session,
        lifecycle: SourceFindingLifecycleRow,
        current: SourceLineageRunRow,
    ) -> None:
        last_seen = session.get(SourceLineageRunRow, lifecycle.last_seen_run_id)
        if (
            last_seen is None
            or last_seen.lineage_id != current.lineage_id
            or last_seen.sequence_number >= current.sequence_number
        ):
            raise ProductCoreLifecycleError

    @staticmethod
    def _evaluation_digest(
        run_id: str,
        events: list[_EventMaterial],
        priorities: Mapping[str, FindingPriority],
        transition_at: datetime,
    ) -> str:
        document = {
            "events": [item.canonical_data() for item in events],
            "priorities": [
                {
                    "finding_id": finding_id,
                    "priority_band": priorities[finding_id].band.value,
                    "reason_codes": list(priorities[finding_id].reason_codes),
                }
                for finding_id in sorted(priorities)
            ],
            "run_id": run_id,
            "schema_version": LIFECYCLE_EVALUATION_SCHEMA_VERSION,
            "transition_at": transition_at.isoformat(),
        }
        return hashlib.sha256(
            json.dumps(
                document,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).hexdigest()

    def _load_completed_evaluation(
        self, session: Session, membership: SourceLineageRunRow
    ) -> LifecycleEvaluationResult:
        if (
            membership.lifecycle_evaluation_sha256 is None
            or membership.lifecycle_event_count is None
        ):
            raise ProductCoreLifecycleError
        rows = tuple(
            session.scalars(
                select(SourceFindingLifecycleEventRow)
                .where(SourceFindingLifecycleEventRow.run_id == membership.run_id)
                .order_by(SourceFindingLifecycleEventRow.finding_id)
            )
        )
        occurrences = tuple(
            session.scalars(
                select(SourceFindingOccurrenceRow)
                .where(SourceFindingOccurrenceRow.run_id == membership.run_id)
                .order_by(SourceFindingOccurrenceRow.finding_id)
            )
        )
        if len(rows) != membership.lifecycle_event_count or any(
            item.priority_band is None or item.priority_reason_codes_json is None
            for item in occurrences
        ):
            raise ProductCoreLifecycleError
        for event in rows:
            event_parent = session.get(SourceOrchestrationRow, event.run_id)
            if (
                event.lineage_id != membership.lineage_id
                or event_parent is None
                or event_parent.published_at is None
                or self._as_utc(event.created_at)
                != self._published_at(event_parent)
            ):
                raise ProductCoreLifecycleError
            lifecycle = session.get(
                SourceFindingLifecycleRow,
                (membership.lineage_id, event.finding_id),
            )
            if lifecycle is None:
                raise ProductCoreLifecycleError
            self._validate_lifecycle_row(session, lifecycle)
            if lifecycle.transition_version < event.transition_version:
                raise ProductCoreLifecycleError
        events = [
            _EventMaterial(
                item.finding_id,
                item.event_kind,
                item.previous_state,
                item.resulting_state,
                tuple(item.reason_codes_json),
                item.transition_version,
            )
            for item in rows
        ]
        priorities = {
            item.finding_id: FindingPriority(
                PriorityBand(item.priority_band), tuple(item.priority_reason_codes_json)
            )
            for item in occurrences
        }
        parent = session.get(SourceOrchestrationRow, membership.run_id)
        if parent is None or (
            self._evaluation_digest(
                membership.run_id,
                events,
                priorities,
                self._published_at(parent),
            )
            != membership.lifecycle_evaluation_sha256
        ):
            raise ProductCoreLifecycleError
        return self._result(membership, events, created=False)

    @staticmethod
    def _validate_lifecycle_row(
        session: Session, lifecycle: SourceFindingLifecycleRow
    ) -> None:
        events = tuple(
            session.scalars(
                select(SourceFindingLifecycleEventRow).where(
                    SourceFindingLifecycleEventRow.lineage_id == lifecycle.lineage_id,
                    SourceFindingLifecycleEventRow.finding_id == lifecycle.finding_id,
                )
            )
        )
        ordered: list[tuple[int, SourceFindingLifecycleEventRow]] = []
        for event in events:
            membership = session.get(SourceLineageRunRow, event.run_id)
            parent = session.get(SourceOrchestrationRow, event.run_id)
            if (
                membership is None
                or membership.lineage_id != lifecycle.lineage_id
                or parent is None
                or parent.published_at is None
                or SourceFindingLifecycleService._as_utc(event.created_at)
                != SourceFindingLifecycleService._published_at(parent)
            ):
                raise ProductCoreLifecycleError
            ordered.append((membership.sequence_number, event))
        ordered.sort(key=lambda item: item[0])
        if not ordered or len({item[0] for item in ordered}) != len(ordered):
            raise ProductCoreLifecycleError

        state: FindingLifecycleState | None = None
        version = 0
        first_seen_run_id: str | None = None
        last_seen_run_id: str | None = None
        resolved_run_id: str | None = None
        first_seen_at: datetime | None = None
        last_seen_at: datetime | None = None
        resolved_at: datetime | None = None
        for _sequence, event in ordered:
            event_state = FindingLifecycleState(event.resulting_state)
            event_at = SourceFindingLifecycleService._as_utc(event.created_at)
            if state is None:
                if (
                    event.event_kind != LifecycleEventKind.TRANSITION.value
                    or event.previous_state is not None
                    or event_state is not FindingLifecycleState.NEW
                    or event.transition_version != 1
                    or session.get(
                        SourceFindingOccurrenceRow,
                        (event.run_id, lifecycle.finding_id),
                    )
                    is None
                ):
                    raise ProductCoreLifecycleError
                state = event_state
                version = 1
                first_seen_run_id = last_seen_run_id = event.run_id
                first_seen_at = last_seen_at = event_at
                continue
            if event.previous_state != state.value:
                raise ProductCoreLifecycleError
            if event.event_kind == LifecycleEventKind.RESOLUTION_WITHHELD.value:
                if event_state is not state or event.transition_version != version:
                    raise ProductCoreLifecycleError
                continue
            if (
                event.event_kind != LifecycleEventKind.TRANSITION.value
                or event.transition_version != version + 1
            ):
                raise ProductCoreLifecycleError
            version += 1
            if event_state is FindingLifecycleState.RESOLVED:
                if state is FindingLifecycleState.RESOLVED:
                    raise ProductCoreLifecycleError
                resolved_run_id = event.run_id
                resolved_at = event_at
            else:
                expected = (
                    FindingLifecycleState.REOPENED
                    if state is FindingLifecycleState.RESOLVED
                    else FindingLifecycleState.EXISTING
                )
                if (
                    event_state is not expected
                    or session.get(
                        SourceFindingOccurrenceRow,
                        (event.run_id, lifecycle.finding_id),
                    )
                    is None
                ):
                    raise ProductCoreLifecycleError
                last_seen_run_id = event.run_id
                last_seen_at = event_at
                resolved_run_id = None
                resolved_at = None
            state = event_state

        occurrence = session.get(
            SourceFindingOccurrenceRow,
            (last_seen_run_id, lifecycle.finding_id),
        )
        if occurrence is None:
            raise ProductCoreLifecycleError
        SourceFindingLifecycleService._verify_lifecycle_identity(lifecycle, occurrence)
        if (
            lifecycle.current_state != state.value
            or lifecycle.transition_version != version
            or lifecycle.first_seen_run_id != first_seen_run_id
            or lifecycle.last_seen_run_id != last_seen_run_id
            or lifecycle.resolved_run_id != resolved_run_id
            or SourceFindingLifecycleService._as_utc(lifecycle.first_seen_at)
            != first_seen_at
            or SourceFindingLifecycleService._as_utc(lifecycle.last_seen_at) != last_seen_at
            or (
                None
                if lifecycle.resolved_at is None
                else SourceFindingLifecycleService._as_utc(lifecycle.resolved_at)
            )
            != resolved_at
        ):
            raise ProductCoreLifecycleError

    @staticmethod
    def _result(
        membership: SourceLineageRunRow,
        events: list[_EventMaterial],
        *,
        created: bool,
    ) -> LifecycleEvaluationResult:
        if (
            membership.lifecycle_evaluation_sha256 is None
            or membership.lifecycle_evaluated_at is None
        ):
            raise ProductCoreLifecycleError
        return LifecycleEvaluationResult(
            lineage_id=membership.lineage_id,
            run_id=membership.run_id,
            evaluation_sha256=membership.lifecycle_evaluation_sha256,
            event_count=len(events),
            transition_count=sum(
                item.event_kind == LifecycleEventKind.TRANSITION.value for item in events
            ),
            withheld_count=sum(
                item.event_kind == LifecycleEventKind.RESOLUTION_WITHHELD.value
                for item in events
            ),
            evaluated_at=SourceFindingLifecycleService._as_utc(
                membership.lifecycle_evaluated_at
            ),
            created=created,
        )

    @staticmethod
    def _locked_run_and_parent(
        session: Session, run_id: str
    ) -> tuple[AnalysisRunRow, SourceOrchestrationRow]:
        run = session.scalar(
            select(AnalysisRunRow).where(AnalysisRunRow.id == run_id).with_for_update()
        )
        parent = session.scalar(
            select(SourceOrchestrationRow)
            .where(SourceOrchestrationRow.run_id == run_id)
            .with_for_update()
        )
        if run is None or parent is None:
            raise ProductCoreLifecycleError
        return run, parent

    @staticmethod
    def _require_uuid(value: object) -> None:
        try:
            valid = isinstance(value, str) and str(UUID(value)) == value
        except (AttributeError, TypeError, ValueError):
            valid = False
        if not valid:
            raise ProductCoreLifecycleError

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ProductCoreLifecycleError
        return value.astimezone(UTC)

    @staticmethod
    def _published_at(parent: SourceOrchestrationRow) -> datetime:
        value = parent.published_at
        if not isinstance(value, datetime):
            raise ProductCoreLifecycleError
        return SourceFindingLifecycleService._as_utc(value)

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    @staticmethod
    def _lifecycle_record(row: SourceFindingLifecycleRow) -> FindingLifecycle:
        return FindingLifecycle(
            lineage_id=row.lineage_id,
            finding_id=row.finding_id,
            authority=row.authority,
            category=row.category,
            native_identity_schema=row.native_identity_schema,
            current_state=FindingLifecycleState(row.current_state),
            first_seen_run_id=row.first_seen_run_id,
            last_seen_run_id=row.last_seen_run_id,
            resolved_run_id=row.resolved_run_id,
            first_seen_at=SourceFindingLifecycleService._as_utc(row.first_seen_at),
            last_seen_at=SourceFindingLifecycleService._as_utc(row.last_seen_at),
            resolved_at=(
                None
                if row.resolved_at is None
                else SourceFindingLifecycleService._as_utc(row.resolved_at)
            ),
            transition_version=row.transition_version,
        )

    @staticmethod
    def _event_record(row: SourceFindingLifecycleEventRow) -> FindingLifecycleEvent:
        return FindingLifecycleEvent(
            lineage_id=row.lineage_id,
            run_id=row.run_id,
            finding_id=row.finding_id,
            event_kind=LifecycleEventKind(row.event_kind),
            previous_state=(
                None
                if row.previous_state is None
                else FindingLifecycleState(row.previous_state)
            ),
            resulting_state=FindingLifecycleState(row.resulting_state),
            reason_codes=tuple(row.reason_codes_json),
            transition_version=row.transition_version,
            created_at=SourceFindingLifecycleService._as_utc(row.created_at),
        )
