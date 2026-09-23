from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import TargetType
from securescan.orchestration.models import (
    OrchestrationLifecycleState,
    OrchestrationTerminalOutcome,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    ProjectRow,
    SourceFindingLifecycleRow,
    SourceFindingOccurrenceRow,
    SourceLineageRunRow,
    SourceOrchestrationRow,
    SourceScanSubmissionRow,
    SourceTargetLineageRow,
    TargetRow,
)

from .finding_index import ProductCoreIndexError, SourceFindingIndexService
from .projects import InvalidProjectIdentifierError, SourceProjectNotFoundError
from .submission import SourceIntakeKind

DEFAULT_QUERY_LIMIT = 50
MAX_QUERY_LIMIT = 200
_COMPLETE_COVERAGE_STATES = frozenset(
    {
        "COMPLETE",
        "COMPLETE_WITH_FINDINGS",
        "COMPLETE_WITH_SUPPRESSIONS",
        "NOT_APPLICABLE",
    }
)
_AUTHORITIES = frozenset({"semgrep-ce", "gitleaks", "syft", "osv.dev", "checkov"})
_FINDING_AUTHORITIES = _AUTHORITIES - {"syft"}
_CATEGORIES = frozenset(
    {
        "CODE_SECURITY",
        "SECRET_EXPOSURE",
        "DEPENDENCY_VULNERABILITY",
        "CONFIGURATION_SECURITY",
    }
)
_PRIORITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNRANKED"})
_LIFECYCLE_STATES = frozenset({"NEW", "EXISTING", "RESOLVED", "REOPENED"})


class SourceProductStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    PUBLISHED_PENDING_FINALIZATION = "PUBLISHED_PENDING_FINALIZATION"
    BLOCKED_BY_PREDECESSOR = "BLOCKED_BY_PREDECESSOR"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class SourceScanQueryErrorCode(StrEnum):
    SCAN_NOT_FOUND = "SCAN_NOT_FOUND"
    SCAN_NOT_PUBLISHED = "SCAN_NOT_PUBLISHED"
    PRODUCT_CORE_NOT_READY = "PRODUCT_CORE_NOT_READY"
    INVALID_FILTER = "INVALID_FILTER"
    INVALID_PAGINATION = "INVALID_PAGINATION"
    QUERY_UNAVAILABLE = "QUERY_UNAVAILABLE"


class SourceScanQueryError(RuntimeError):
    def __init__(self, code: SourceScanQueryErrorCode, message: str) -> None:
        self.code = code
        super().__init__(message)


class ScanNotFoundError(SourceScanQueryError):
    def __init__(self) -> None:
        super().__init__(SourceScanQueryErrorCode.SCAN_NOT_FOUND, "Source scan was not found")


class ScanNotPublishedError(SourceScanQueryError):
    def __init__(self) -> None:
        super().__init__(
            SourceScanQueryErrorCode.SCAN_NOT_PUBLISHED,
            "Source scan report is not published",
        )


class ProductCoreNotReadyError(SourceScanQueryError):
    def __init__(self) -> None:
        super().__init__(
            SourceScanQueryErrorCode.PRODUCT_CORE_NOT_READY,
            "Source Product Core data is not ready",
        )


class InvalidScanFilterError(SourceScanQueryError):
    def __init__(self) -> None:
        super().__init__(
            SourceScanQueryErrorCode.INVALID_FILTER, "Source scan filter is invalid"
        )


class InvalidScanPaginationError(SourceScanQueryError):
    def __init__(self) -> None:
        super().__init__(
            SourceScanQueryErrorCode.INVALID_PAGINATION,
            "Source scan pagination is invalid",
        )


class SourceScanQueryPersistenceError(SourceScanQueryError):
    def __init__(self) -> None:
        super().__init__(
            SourceScanQueryErrorCode.QUERY_UNAVAILABLE,
            "Source scan query is unavailable",
        )


@dataclass(frozen=True, slots=True)
class SourceScanPage[T]:
    items: tuple[T, ...]
    total: int
    limit: int
    offset: int


@dataclass(frozen=True, slots=True)
class SourceScanSummary:
    run_id: str
    target_id: str
    project_id: str
    lineage_id: str
    submission_sequence_number: int
    predecessor_run_id: str | None
    product_status: SourceProductStatus
    created_at: datetime
    published_at: datetime | None
    finalized_at: datetime | None
    indexed: bool
    lifecycle_evaluated: bool
    finding_count: int
    priority_counts: Mapping[str, int]
    category_counts: Mapping[str, int]
    coverage_complete: bool | None
    coverage_counts: Mapping[str, int]
    gap_count: int | None


@dataclass(frozen=True, slots=True)
class SourceScanListItem:
    """Bounded navigation projection without per-run report reconstruction."""

    run_id: str
    target_id: str
    project_id: str
    lineage_id: str
    submission_sequence_number: int
    predecessor_run_id: str | None
    product_status: SourceProductStatus
    created_at: datetime
    published_at: datetime | None
    finalized_at: datetime | None
    indexed: bool
    lifecycle_evaluated: bool


@dataclass(frozen=True, slots=True)
class SourceFindingSummary:
    finding_id: str
    authority: str
    category: str
    severity: str | None
    priority_band: str
    priority_reason_codes: tuple[str, ...]
    lifecycle_state: str
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None
    subject: Mapping[str, Any]
    primary_location: Mapping[str, Any] | None


@dataclass(frozen=True, slots=True)
class SourceComponentSummary:
    component_ref: str
    component_kind: str
    payload: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class SourceDependencySummary:
    component_ref: str
    name: str
    version: str | None
    package_type: str
    purl: str | None
    locations: tuple[Mapping[str, Any], ...]
    vulnerability_evaluation: str
    vulnerability_evaluation_reason: str | None
    known_vulnerability_count: int | None
    advisory_aliases: tuple[str, ...]
    fixed_versions: tuple[str, ...]
    priority_bands: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SourceCoverageSummary:
    complete: bool
    counts_by_state: Mapping[str, int]
    outcomes: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True, slots=True)
class SourceGapSummary:
    gap_id: str
    authority: str
    code: str
    scope: Mapping[str, Any]
    message: str | None


@dataclass(frozen=True, slots=True)
class SourcePublishedReport:
    run_id: str
    report: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class _ScanContext:
    run: AnalysisRunRow
    target: TargetRow
    submission: SourceScanSubmissionRow
    parent: SourceOrchestrationRow
    membership: SourceLineageRunRow | None


class SourceScanQueryService:
    """Read-only Product Core projection for the later HTTP and CLI surfaces."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        artifact_store: ContentAddressedArtifactStore,
    ) -> None:
        if not isinstance(artifact_store, ContentAddressedArtifactStore):
            raise SourceScanQueryPersistenceError
        self._sessions = session_factory
        self._index = SourceFindingIndexService(session_factory, artifact_store)

    def get_scan(self, run_id: str) -> SourceScanSummary:
        normalized = self._normalize_run_id(run_id)
        try:
            with self._sessions() as session:
                context = self._context(session, normalized)
                status = self._status(session, context)
                finding_count, priorities, categories = self._finding_counts(
                    session, context
                )
                published_at = context.parent.published_at
                finalized_at = context.submission.finalized_at
                created_at = context.submission.created_at
                indexed = (
                    context.membership is not None
                    and context.membership.indexing_state == "INDEXED"
                    and context.membership.indexed_at is not None
                )
                lifecycle_evaluated = (
                    context.membership is not None
                    and context.membership.lifecycle_evaluated_at is not None
                )
            coverage_complete: bool | None = None
            coverage_counts: Mapping[str, int] = MappingProxyType({})
            gap_count: int | None = None
            if published_at is not None:
                report = self._published_document(normalized)
                outcomes = self._list_field(report, "coverage_outcomes")
                states = Counter(self._required_string(item, "state") for item in outcomes)
                coverage_complete = all(state in _COMPLETE_COVERAGE_STATES for state in states)
                coverage_counts = MappingProxyType(dict(sorted(states.items())))
                gap_count = len(self._list_field(report, "gaps"))
                if not indexed:
                    findings = self._list_field(report, "findings")
                    finding_count = len(findings)
                    categories = Counter(
                        self._required_string(item, "category") for item in findings
                    )
            return SourceScanSummary(
                run_id=normalized,
                target_id=context.target.id,
                project_id=context.target.project_id,
                lineage_id=context.submission.lineage_id,
                submission_sequence_number=context.submission.submission_sequence_number,
                predecessor_run_id=context.submission.predecessor_run_id,
                product_status=status,
                created_at=self._as_utc(created_at),
                published_at=None if published_at is None else self._as_utc(published_at),
                finalized_at=None if finalized_at is None else self._as_utc(finalized_at),
                indexed=indexed,
                lifecycle_evaluated=lifecycle_evaluated,
                finding_count=finding_count,
                priority_counts=MappingProxyType(dict(sorted(priorities.items()))),
                category_counts=MappingProxyType(dict(sorted(categories.items()))),
                coverage_complete=coverage_complete,
                coverage_counts=coverage_counts,
                gap_count=gap_count,
            )
        except SourceScanQueryError:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise SourceScanQueryPersistenceError from None

    def list_scans(
        self,
        *,
        project_id: str | None = None,
        limit: int = DEFAULT_QUERY_LIMIT,
        offset: int = 0,
    ) -> SourceScanPage[SourceScanListItem]:
        self._validate_pagination(limit, offset)
        normalized_project = (
            None if project_id is None else self._normalize_project_id(project_id)
        )
        try:
            with self._sessions() as session:
                if (
                    normalized_project is not None
                    and session.get(ProjectRow, normalized_project) is None
                ):
                    raise SourceProjectNotFoundError

                predicates = self._source_scan_predicates(normalized_project)
                total = session.scalar(
                    select(func.count())
                    .select_from(SourceScanSubmissionRow)
                    .join(
                        AnalysisRunRow,
                        AnalysisRunRow.id == SourceScanSubmissionRow.run_id,
                    )
                    .join(TargetRow, TargetRow.id == AnalysisRunRow.target_id)
                    .join(
                        SourceOrchestrationRow,
                        SourceOrchestrationRow.run_id == SourceScanSubmissionRow.run_id,
                    )
                    .join(
                        SourceTargetLineageRow,
                        SourceTargetLineageRow.lineage_id
                        == SourceScanSubmissionRow.lineage_id,
                    )
                    .where(*predicates)
                )
                rows = tuple(
                    session.execute(
                        select(
                            AnalysisRunRow,
                            TargetRow,
                            SourceScanSubmissionRow,
                            SourceOrchestrationRow,
                            SourceTargetLineageRow,
                            SourceLineageRunRow,
                        )
                        .select_from(SourceScanSubmissionRow)
                        .join(
                            AnalysisRunRow,
                            AnalysisRunRow.id == SourceScanSubmissionRow.run_id,
                        )
                        .join(TargetRow, TargetRow.id == AnalysisRunRow.target_id)
                        .join(
                            SourceOrchestrationRow,
                            SourceOrchestrationRow.run_id
                            == SourceScanSubmissionRow.run_id,
                        )
                        .join(
                            SourceTargetLineageRow,
                            SourceTargetLineageRow.lineage_id
                            == SourceScanSubmissionRow.lineage_id,
                        )
                        .outerjoin(
                            SourceLineageRunRow,
                            SourceLineageRunRow.run_id == SourceScanSubmissionRow.run_id,
                        )
                        .where(*predicates)
                        .order_by(
                            AnalysisRunRow.created_at.desc(),
                            AnalysisRunRow.id.desc(),
                        )
                        .limit(limit)
                        .offset(offset)
                    ).all()
                )
                contexts: list[_ScanContext] = []
                for run, target, submission, parent, lineage, membership in rows:
                    if (
                        target.project_id != lineage.project_id
                        or parent.run_id != run.id
                        or (
                            membership is not None
                            and (
                                membership.lineage_id != submission.lineage_id
                                or membership.sequence_number
                                != submission.submission_sequence_number
                                or membership.predecessor_run_id
                                != submission.predecessor_run_id
                                or membership.predecessor_sequence_number
                                != submission.predecessor_sequence_number
                            )
                        )
                    ):
                        raise SourceScanQueryPersistenceError
                    contexts.append(
                        _ScanContext(run, target, submission, parent, membership)
                    )

                predecessor_ids = tuple(
                    context.submission.predecessor_run_id
                    for context in contexts
                    if context.submission.predecessor_run_id is not None
                )
                predecessor_submissions: dict[str, SourceScanSubmissionRow] = {}
                predecessor_memberships: dict[str, SourceLineageRunRow] = {}
                if predecessor_ids:
                    predecessor_rows = session.execute(
                        select(SourceScanSubmissionRow, SourceLineageRunRow)
                        .outerjoin(
                            SourceLineageRunRow,
                            SourceLineageRunRow.run_id == SourceScanSubmissionRow.run_id,
                        )
                        .where(SourceScanSubmissionRow.run_id.in_(predecessor_ids))
                    )
                    for predecessor_submission, predecessor_membership in predecessor_rows:
                        predecessor_submissions[
                            predecessor_submission.run_id
                        ] = predecessor_submission
                        if predecessor_membership is not None:
                            predecessor_memberships[
                                predecessor_membership.run_id
                            ] = predecessor_membership

                items = tuple(
                    self._list_item(
                        context,
                        predecessor_submissions.get(
                            context.submission.predecessor_run_id or ""
                        ),
                        predecessor_memberships.get(
                            context.submission.predecessor_run_id or ""
                        ),
                    )
                    for context in contexts
                )
            return SourceScanPage(items, int(total or 0), limit, offset)
        except (SourceScanQueryError, SourceProjectNotFoundError):
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise SourceScanQueryPersistenceError from None

    def list_findings(
        self,
        run_id: str,
        *,
        authority: str | None = None,
        category: str | None = None,
        priority: str | None = None,
        lifecycle_state: str | None = None,
        limit: int = DEFAULT_QUERY_LIMIT,
        offset: int = 0,
    ) -> SourceScanPage[SourceFindingSummary]:
        normalized = self._normalize_run_id(run_id)
        self._validate_pagination(limit, offset)
        authority = self._normalize_filter(authority, _FINDING_AUTHORITIES)
        category = self._normalize_filter(category, _CATEGORIES)
        priority = self._normalize_filter(priority, _PRIORITIES)
        lifecycle_state = self._normalize_filter(
            lifecycle_state, _LIFECYCLE_STATES
        )
        try:
            with self._sessions() as session:
                context = self._context(session, normalized)
                self._require_product_ready(context)
                predicates = [
                    SourceFindingOccurrenceRow.run_id == normalized,
                    SourceFindingOccurrenceRow.lineage_id == context.submission.lineage_id,
                ]
                optional = (
                    (SourceFindingOccurrenceRow.authority, authority),
                    (SourceFindingOccurrenceRow.category, category),
                    (SourceFindingOccurrenceRow.priority_band, priority),
                    (SourceFindingLifecycleRow.current_state, lifecycle_state),
                )
                predicates.extend(column == value for column, value in optional if value)
                join_condition = and_(
                    SourceFindingLifecycleRow.lineage_id
                    == SourceFindingOccurrenceRow.lineage_id,
                    SourceFindingLifecycleRow.finding_id
                    == SourceFindingOccurrenceRow.finding_id,
                )
                total = session.scalar(
                    select(func.count())
                    .select_from(SourceFindingOccurrenceRow)
                    .join(SourceFindingLifecycleRow, join_condition)
                    .where(*predicates)
                )
                rows = tuple(
                    session.execute(
                        select(SourceFindingOccurrenceRow, SourceFindingLifecycleRow)
                        .join(SourceFindingLifecycleRow, join_condition)
                        .where(*predicates)
                        .order_by(
                            SourceFindingOccurrenceRow.authority,
                            SourceFindingOccurrenceRow.category,
                            SourceFindingOccurrenceRow.finding_id,
                        )
                        .limit(limit)
                        .offset(offset)
                    ).all()
                )
                items = tuple(self._finding(item, lifecycle) for item, lifecycle in rows)
            return SourceScanPage(items, int(total or 0), limit, offset)
        except SourceScanQueryError:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise SourceScanQueryPersistenceError from None

    def list_components(
        self, run_id: str, *, limit: int = DEFAULT_QUERY_LIMIT, offset: int = 0
    ) -> SourceScanPage[SourceComponentSummary]:
        report = self._page_report(run_id, limit, offset)
        values = sorted(
            self._list_field(report, "components"),
            key=lambda item: self._required_string(item, "component_ref"),
        )
        page = values[offset : offset + limit]
        return SourceScanPage(
            tuple(
                SourceComponentSummary(
                    self._required_string(item, "component_ref"),
                    self._required_string(item, "component_kind"),
                    self._mapping(self._required_mapping(item, "payload")),
                )
                for item in page
            ),
            len(values),
            limit,
            offset,
        )

    def list_dependencies(
        self, run_id: str, *, limit: int = DEFAULT_QUERY_LIMIT, offset: int = 0
    ) -> SourceScanPage[SourceDependencySummary]:
        normalized = self._normalize_run_id(run_id)
        self._validate_pagination(limit, offset)
        report = self._published_document(normalized)
        evidence = {
            self._required_string(item, "evidence_id"): item
            for item in self._list_field(report, "evidence")
        }
        osv_by_component: dict[str, list[Mapping[str, Any]]] = {}
        for finding in self._list_field(report, "findings"):
            if finding.get("authority") != "osv.dev":
                continue
            subject = self._required_mapping(finding, "subject")
            component_ref = self._required_string(subject, "component_ref")
            osv_by_component.setdefault(component_ref, []).append(finding)
        priorities = self._priorities(normalized)
        osv_outcomes = tuple(
            item
            for item in self._list_field(report, "coverage_outcomes")
            if item.get("authority") == "osv.dev"
        )
        if len(osv_outcomes) != 1:
            raise SourceScanQueryPersistenceError
        osv_state = self._required_string(osv_outcomes[0], "state")
        evaluation_state = {
            "COMPLETE": "COMPLETE",
            "COMPLETE_WITH_FINDINGS": "COMPLETE",
            "COMPLETE_WITH_SUPPRESSIONS": "COMPLETE",
            "PARTIAL": "PARTIAL",
            "FAILED": "FAILED",
            "NOT_APPLICABLE": "NOT_APPLICABLE",
        }.get(osv_state)
        if evaluation_state is None:
            raise SourceScanQueryPersistenceError
        evaluation_reason = self._optional_string(osv_outcomes[0], "reason_code")
        dependencies = []
        for component in self._list_field(report, "components"):
            if component.get("component_kind") != "PACKAGE":
                continue
            component_ref = self._required_string(component, "component_ref")
            payload = self._required_mapping(component, "payload")
            aliases: set[str] = set()
            fixed: set[str] = set()
            bands: set[str] = set()
            for finding in osv_by_component.get(component_ref, []):
                finding_id = self._required_string(finding, "finding_id")
                if finding_id in priorities:
                    bands.add(priorities[finding_id])
                for evidence_ref in self._required_string_list(
                    finding, "primary_evidence_refs"
                ):
                    item = evidence.get(evidence_ref)
                    if item is None:
                        raise SourceScanQueryPersistenceError
                    osv_payload = self._required_mapping(item, "payload")
                    if osv_payload.get("kind") == "OSV_ADVISORY_GROUP":
                        aliases.update(self._required_string_list(osv_payload, "aliases"))
                        aliases.update(
                            self._required_string_list(osv_payload, "cve_aliases")
                        )
                        aliases.update(
                            self._required_string_list(osv_payload, "ghsa_aliases")
                        )
                        fixed.update(
                            self._required_string_list(osv_payload, "fixed_versions")
                        )
            locations = {
                self._canonical_location(location)
                for item in self._list_field(report, "evidence")
                if item.get("authority") == "syft"
                and component_ref in item.get("component_refs", [])
                for location in self._list_field(item, "locations")
            }
            dependencies.append(
                SourceDependencySummary(
                    component_ref=component_ref,
                    name=self._required_string(payload, "package_name"),
                    version=self._optional_string(payload, "package_version"),
                    package_type=self._required_string(payload, "package_type"),
                    purl=self._optional_string(payload, "purl"),
                    locations=tuple(
                        self._mapping(dict(value)) for value in sorted(locations)
                    ),
                    vulnerability_evaluation=evaluation_state,
                    vulnerability_evaluation_reason=evaluation_reason,
                    known_vulnerability_count=(
                        len(osv_by_component.get(component_ref, []))
                        if evaluation_state == "COMPLETE"
                        else None
                    ),
                    advisory_aliases=tuple(sorted(aliases)),
                    fixed_versions=tuple(sorted(fixed)),
                    priority_bands=tuple(sorted(bands)),
                )
            )
        dependencies.sort(key=lambda item: item.component_ref)
        return SourceScanPage(
            tuple(dependencies[offset : offset + limit]),
            len(dependencies),
            limit,
            offset,
        )

    def get_coverage(self, run_id: str) -> SourceCoverageSummary:
        report = self._published_document(self._normalize_run_id(run_id))
        outcomes = tuple(
            self._mapping(item) for item in self._list_field(report, "coverage_outcomes")
        )
        states = Counter(self._required_string(item, "state") for item in outcomes)
        return SourceCoverageSummary(
            complete=all(state in _COMPLETE_COVERAGE_STATES for state in states),
            counts_by_state=MappingProxyType(dict(sorted(states.items()))),
            outcomes=outcomes,
        )

    def list_gaps(
        self,
        run_id: str,
        *,
        authority: str | None = None,
        limit: int = DEFAULT_QUERY_LIMIT,
        offset: int = 0,
    ) -> SourceScanPage[SourceGapSummary]:
        normalized = self._normalize_run_id(run_id)
        self._validate_pagination(limit, offset)
        authority = self._normalize_filter(authority, _AUTHORITIES)
        report = self._published_document(normalized)
        gaps = [
            item
            for item in self._list_field(report, "gaps")
            if authority is None or item.get("authority") == authority
        ]
        gaps.sort(key=lambda item: self._required_string(item, "gap_id"))
        return SourceScanPage(
            tuple(
                SourceGapSummary(
                    gap_id=self._required_string(item, "gap_id"),
                    authority=self._required_string(item, "authority"),
                    code=self._required_string(item, "code"),
                    scope=self._mapping(self._required_mapping(item, "scope")),
                    message=self._optional_string(item, "message"),
                )
                for item in gaps[offset : offset + limit]
            ),
            len(gaps),
            limit,
            offset,
        )

    def get_report(self, run_id: str) -> SourcePublishedReport:
        normalized = self._normalize_run_id(run_id)
        return SourcePublishedReport(
            normalized, self._mapping(self._published_document(normalized))
        )

    def _page_report(self, run_id: str, limit: int, offset: int) -> dict[str, Any]:
        normalized = self._normalize_run_id(run_id)
        self._validate_pagination(limit, offset)
        return self._published_document(normalized)

    def _published_document(self, run_id: str) -> dict[str, Any]:
        try:
            with self._sessions() as session:
                context = self._context(session, run_id)
                if context.parent.published_at is None:
                    raise ScanNotPublishedError
            report = self._index.load_verified_published_report(run_id=run_id)
            return report.canonical_data()
        except SourceScanQueryError:
            raise
        except (ProductCoreIndexError, OSError, TypeError, ValueError):
            raise SourceScanQueryPersistenceError from None

    def _context(self, session: Session, run_id: str) -> _ScanContext:
        run = session.get(AnalysisRunRow, run_id)
        submission = session.get(SourceScanSubmissionRow, run_id)
        parent = session.get(SourceOrchestrationRow, run_id)
        if run is None or submission is None or parent is None:
            raise ScanNotFoundError
        target = session.get(TargetRow, run.target_id)
        lineage = session.get(SourceTargetLineageRow, submission.lineage_id)
        membership = session.get(SourceLineageRunRow, run_id)
        if (
            target is None
            or lineage is None
            or target.project_id != lineage.project_id
            or parent.run_id != run.id
            or (
                membership is not None
                and (
                    membership.lineage_id != submission.lineage_id
                    or membership.sequence_number
                    != submission.submission_sequence_number
                    or membership.predecessor_run_id
                    != submission.predecessor_run_id
                    or membership.predecessor_sequence_number
                    != submission.predecessor_sequence_number
                )
            )
        ):
            raise SourceScanQueryPersistenceError
        return _ScanContext(run, target, submission, parent, membership)

    def _status(self, session: Session, context: _ScanContext) -> SourceProductStatus:
        predecessor_submission: SourceScanSubmissionRow | None = None
        predecessor_membership: SourceLineageRunRow | None = None
        predecessor = context.submission.predecessor_run_id
        if predecessor is not None:
            predecessor_submission = session.get(SourceScanSubmissionRow, predecessor)
            predecessor_membership = session.get(SourceLineageRunRow, predecessor)
        return self._status_from_material(
            context, predecessor_submission, predecessor_membership
        )

    @staticmethod
    def _status_from_material(
        context: _ScanContext,
        predecessor_submission: SourceScanSubmissionRow | None,
        predecessor_membership: SourceLineageRunRow | None,
    ) -> SourceProductStatus:
        parent = context.parent
        if (
            parent.lifecycle_state == OrchestrationLifecycleState.TERMINAL.value
            and parent.terminal_outcome == OrchestrationTerminalOutcome.CANCELLED.value
        ):
            return SourceProductStatus.CANCELLED
        if (
            parent.lifecycle_state == OrchestrationLifecycleState.TERMINAL.value
            and parent.terminal_outcome == OrchestrationTerminalOutcome.FAILED.value
        ):
            return SourceProductStatus.FAILED
        membership = context.membership
        complete = (
            parent.published_at is not None
            and context.submission.finalized_at is not None
            and membership is not None
            and membership.indexing_state == "INDEXED"
            and membership.indexed_at is not None
            and membership.lifecycle_evaluated_at is not None
        )
        if complete:
            return SourceProductStatus.COMPLETED
        if parent.published_at is not None:
            predecessor = context.submission.predecessor_run_id
            if predecessor is not None and (
                predecessor_membership is None
                or predecessor_membership.lineage_id != context.submission.lineage_id
                or predecessor_membership.sequence_number
                != context.submission.predecessor_sequence_number
                or predecessor_membership.lifecycle_evaluated_at is None
                or (
                    predecessor_submission is not None
                    and predecessor_submission.finalized_at is None
                )
            ):
                return SourceProductStatus.BLOCKED_BY_PREDECESSOR
            return SourceProductStatus.PUBLISHED_PENDING_FINALIZATION
        if parent.lifecycle_state == OrchestrationLifecycleState.PREPARED.value:
            return SourceProductStatus.QUEUED
        return SourceProductStatus.RUNNING

    @classmethod
    def _list_item(
        cls,
        context: _ScanContext,
        predecessor_submission: SourceScanSubmissionRow | None,
        predecessor_membership: SourceLineageRunRow | None,
    ) -> SourceScanListItem:
        membership = context.membership
        return SourceScanListItem(
            run_id=context.run.id,
            target_id=context.target.id,
            project_id=context.target.project_id,
            lineage_id=context.submission.lineage_id,
            submission_sequence_number=context.submission.submission_sequence_number,
            predecessor_run_id=context.submission.predecessor_run_id,
            product_status=cls._status_from_material(
                context, predecessor_submission, predecessor_membership
            ),
            created_at=cls._as_utc(context.submission.created_at),
            published_at=(
                None
                if context.parent.published_at is None
                else cls._as_utc(context.parent.published_at)
            ),
            finalized_at=(
                None
                if context.submission.finalized_at is None
                else cls._as_utc(context.submission.finalized_at)
            ),
            indexed=(
                membership is not None
                and membership.indexing_state == "INDEXED"
                and membership.indexed_at is not None
            ),
            lifecycle_evaluated=(
                membership is not None
                and membership.lifecycle_evaluated_at is not None
            ),
        )

    @staticmethod
    def _finding_counts(
        session: Session, context: _ScanContext
    ) -> tuple[int, Counter[str], Counter[str]]:
        if context.membership is None or context.membership.indexing_state != "INDEXED":
            return 0, Counter(), Counter()
        rows = tuple(
            session.execute(
                select(
                    SourceFindingOccurrenceRow.priority_band,
                    SourceFindingOccurrenceRow.category,
                ).where(SourceFindingOccurrenceRow.run_id == context.run.id)
            )
        )
        return (
            len(rows),
            Counter(priority or "UNRANKED" for priority, _category in rows),
            Counter(category for _priority, category in rows),
        )

    @staticmethod
    def _require_product_ready(context: _ScanContext) -> None:
        membership = context.membership
        if (
            context.submission.finalized_at is None
            or membership is None
            or membership.indexing_state != "INDEXED"
            or membership.indexed_at is None
            or membership.lifecycle_evaluated_at is None
        ):
            raise ProductCoreNotReadyError

    @staticmethod
    def _finding(
        occurrence: SourceFindingOccurrenceRow, lifecycle: SourceFindingLifecycleRow
    ) -> SourceFindingSummary:
        if occurrence.priority_band is None or occurrence.priority_reason_codes_json is None:
            raise SourceScanQueryPersistenceError
        return SourceFindingSummary(
            finding_id=occurrence.finding_id,
            authority=occurrence.authority,
            category=occurrence.category,
            severity=occurrence.severity,
            priority_band=occurrence.priority_band,
            priority_reason_codes=tuple(occurrence.priority_reason_codes_json),
            lifecycle_state=lifecycle.current_state,
            first_seen_at=SourceScanQueryService._as_utc(lifecycle.first_seen_at),
            last_seen_at=SourceScanQueryService._as_utc(lifecycle.last_seen_at),
            resolved_at=(
                None
                if lifecycle.resolved_at is None
                else SourceScanQueryService._as_utc(lifecycle.resolved_at)
            ),
            subject=SourceScanQueryService._mapping(occurrence.subject_summary_json),
            primary_location=(
                None
                if occurrence.primary_location_json is None
                else SourceScanQueryService._mapping(occurrence.primary_location_json)
            ),
        )

    def _priorities(self, run_id: str) -> dict[str, str]:
        try:
            with self._sessions() as session:
                return {
                    finding_id: band
                    for finding_id, band in session.execute(
                        select(
                            SourceFindingOccurrenceRow.finding_id,
                            SourceFindingOccurrenceRow.priority_band,
                        ).where(
                            SourceFindingOccurrenceRow.run_id == run_id,
                            SourceFindingOccurrenceRow.priority_band.is_not(None),
                        )
                    )
                    if band is not None
                }
        except SQLAlchemyError:
            raise SourceScanQueryPersistenceError from None

    @staticmethod
    def _normalize_run_id(value: object) -> str:
        try:
            valid = isinstance(value, str) and str(UUID(value)) == value
        except ValueError:
            valid = False
        if not valid:
            raise ScanNotFoundError
        return value

    @staticmethod
    def _normalize_project_id(value: object) -> str:
        try:
            valid = isinstance(value, str) and str(UUID(value)) == value
        except ValueError:
            valid = False
        if not valid:
            raise InvalidProjectIdentifierError
        return value

    @staticmethod
    def _source_scan_predicates(project_id: str | None):
        predicates = (
            TargetRow.target_type == TargetType.SOURCE_REPOSITORY.value,
            SourceScanSubmissionRow.intake_kind
            == SourceIntakeKind.MANAGED_WORKSPACE_V1.value,
            SourceScanSubmissionRow.intake_ref == TargetRow.source_path,
            TargetRow.project_id == SourceTargetLineageRow.project_id,
        )
        if project_id is None:
            return predicates
        return (*predicates, TargetRow.project_id == project_id)

    @staticmethod
    def _validate_pagination(limit: int, offset: int) -> None:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_QUERY_LIMIT
            or isinstance(offset, bool)
            or not isinstance(offset, int)
            or offset < 0
        ):
            raise InvalidScanPaginationError

    @staticmethod
    def _normalize_filter(
        value: str | None, allowed: frozenset[str]
    ) -> str | None:
        if value is None:
            return None
        if (
            not isinstance(value, str)
            or value != value.strip()
            or not value
            or len(value) > 128
            or any(ord(character) < 32 for character in value)
            or value not in allowed
        ):
            raise InvalidScanFilterError
        return value

    @staticmethod
    def _mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
        return MappingProxyType(deepcopy(dict(value)))

    @staticmethod
    def _list_field(value: Mapping[str, Any], key: str) -> list[dict[str, Any]]:
        result = value.get(key)
        if not isinstance(result, list) or any(not isinstance(item, dict) for item in result):
            raise SourceScanQueryPersistenceError
        return result

    @staticmethod
    def _required_mapping(value: Mapping[str, Any], key: str) -> dict[str, Any]:
        result = value.get(key)
        if not isinstance(result, dict):
            raise SourceScanQueryPersistenceError
        return result

    @staticmethod
    def _required_string(value: Mapping[str, Any], key: str) -> str:
        result = value.get(key)
        if not isinstance(result, str) or not result:
            raise SourceScanQueryPersistenceError
        return result

    @staticmethod
    def _optional_string(value: Mapping[str, Any], key: str) -> str | None:
        result = value.get(key)
        if result is not None and (not isinstance(result, str) or not result):
            raise SourceScanQueryPersistenceError
        return result

    @staticmethod
    def _required_string_list(value: Mapping[str, Any], key: str) -> tuple[str, ...]:
        result = value.get(key)
        if not isinstance(result, list) or any(not isinstance(item, str) for item in result):
            raise SourceScanQueryPersistenceError
        return tuple(result)

    @staticmethod
    def _canonical_location(value: Mapping[str, Any]) -> tuple[tuple[str, Any], ...]:
        if not isinstance(value, dict):
            raise SourceScanQueryPersistenceError
        try:
            return tuple(sorted(value.items()))
        except TypeError:
            raise SourceScanQueryPersistenceError from None

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
