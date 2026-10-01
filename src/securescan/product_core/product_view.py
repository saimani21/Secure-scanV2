"""Bounded exact-run finding projection for V1.2H presentation surfaces.

This reads stored occurrence and lifecycle-event facts. It does not evaluate a
new lifecycle, priority, governance, delta, policy, or guidance decision.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.persistence.database import (
    SourceFindingLifecycleEventRow,
    SourceFindingOccurrenceRow,
    SourceLineageRunRow,
    SourceTargetLineageRow,
)
from securescan.product_core.lifecycle import (
    ProductCoreLifecycleError,
    SourceFindingLifecycleService,
)

_AUTHORITIES = frozenset({"semgrep-ce", "gitleaks", "osv.dev", "checkov"})
_CATEGORIES = frozenset(
    {"CODE_SECURITY", "SECRET_EXPOSURE", "DEPENDENCY_VULNERABILITY", "CONFIGURATION_SECURITY"}
)
_PRIORITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNRANKED"})
_LIFECYCLE = frozenset({"NEW", "EXISTING", "RESOLVED", "REOPENED"})


class ProductViewError(RuntimeError):
    pass


class ProductViewNotFoundError(ProductViewError):
    pass


class ProductViewNotReadyError(ProductViewError):
    pass


class ProductViewValidationError(ProductViewError):
    pass


class ProductViewUnavailableError(ProductViewError):
    pass


@dataclass(frozen=True, slots=True)
class FindingProductView:
    project_id: str
    lineage_id: str
    run_id: str
    finding_id: str
    authority: str
    category: str
    severity: str | None
    priority_band: str
    priority_reason_codes: tuple[str, ...]
    subject: dict[str, Any]
    primary_location: dict[str, Any] | None
    lifecycle_state_at_run: str
    lifecycle_event_kind: str
    lifecycle_transition_version: int
    lifecycle_reason_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FindingProductPage:
    items: tuple[FindingProductView, ...]
    total: int
    limit: int
    offset: int


class SourceFindingProductViewService:
    """One transaction and bounded SQL page over immutable exact-run facts."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        artifact_store: ContentAddressedArtifactStore,
    ) -> None:
        self._sessions = session_factory
        self._lifecycle = SourceFindingLifecycleService(session_factory, artifact_store)

    def list_for_run(
        self,
        *,
        project_id: str,
        lineage_id: str,
        run_id: str,
        authority: str | None = None,
        category: str | None = None,
        priority: str | None = None,
        lifecycle_state: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> FindingProductPage:
        for value in (project_id, lineage_id, run_id):
            if not isinstance(value, str):
                raise ProductViewValidationError
            try:
                if str(UUID(value)) != value:
                    raise ProductViewValidationError
            except ValueError:
                raise ProductViewValidationError from None
        if type(limit) is not int or not 1 <= limit <= 200 or type(offset) is not int or offset < 0:
            raise ProductViewValidationError
        for value, allowed in (
            (authority, _AUTHORITIES),
            (category, _CATEGORIES),
            (priority, _PRIORITIES),
            (lifecycle_state, _LIFECYCLE),
        ):
            if value is not None and value not in allowed:
                raise ProductViewValidationError

        occurrence = SourceFindingOccurrenceRow
        event = SourceFindingLifecycleEventRow
        join_on = and_(
            event.run_id == occurrence.run_id,
            event.lineage_id == occurrence.lineage_id,
            event.finding_id == occurrence.finding_id,
        )
        predicates = [occurrence.run_id == run_id, occurrence.lineage_id == lineage_id]
        for column, value in (
            (occurrence.authority, authority),
            (occurrence.category, category),
            (occurrence.priority_band, priority),
            (event.resulting_state, lifecycle_state),
        ):
            if value is not None:
                predicates.append(column == value)
        try:
            with self._sessions() as session:
                if session.get_bind().dialect.name == "postgresql":
                    session.connection(execution_options={"isolation_level": "REPEATABLE READ"})
                lineage = session.get(SourceTargetLineageRow, lineage_id)
                membership = session.get(SourceLineageRunRow, run_id)
                if (
                    lineage is None
                    or lineage.project_id != project_id
                    or membership is None
                    or membership.lineage_id != lineage_id
                ):
                    raise ProductViewNotFoundError
                if (
                    membership.indexing_state != "INDEXED"
                    or membership.indexed_at is None
                    or membership.lifecycle_evaluated_at is None
                ):
                    raise ProductViewNotReadyError
                # Reuse the frozen lifecycle digest and transition-chain validator.
                # A simple occurrence/event join would expose tampered history.
                self._lifecycle.load_candidate_facts_in_session(
                    session,
                    project_id=project_id,
                    lineage_id=lineage_id,
                    run_id=run_id,
                )
                occurrence_total = session.scalar(
                    select(func.count())
                    .select_from(occurrence)
                    .where(
                        occurrence.run_id == run_id,
                        occurrence.lineage_id == lineage_id,
                    )
                )
                joined_total = session.scalar(
                    select(func.count())
                    .select_from(occurrence)
                    .join(event, join_on)
                    .where(
                        occurrence.run_id == run_id,
                        occurrence.lineage_id == lineage_id,
                    )
                )
                if occurrence_total != joined_total:
                    raise ProductViewUnavailableError
                total = session.scalar(
                    select(func.count())
                    .select_from(occurrence)
                    .join(event, join_on)
                    .where(*predicates)
                )
                rows = session.execute(
                    select(occurrence, event)
                    .join(event, join_on)
                    .where(*predicates)
                    .order_by(occurrence.authority, occurrence.category, occurrence.finding_id)
                    .limit(limit)
                    .offset(offset)
                ).all()
                items = tuple(
                    self._item(project_id, lineage_id, run_id, found, state)
                    for found, state in rows
                )
                return FindingProductPage(items, int(total or 0), limit, offset)
        except ProductViewError:
            raise
        except (ProductCoreLifecycleError, SQLAlchemyError, TypeError, ValueError):
            raise ProductViewUnavailableError from None

    @staticmethod
    def _item(
        project_id: str,
        lineage_id: str,
        run_id: str,
        occurrence: SourceFindingOccurrenceRow,
        event: SourceFindingLifecycleEventRow,
    ) -> FindingProductView:
        if occurrence.priority_band is None or occurrence.priority_reason_codes_json is None:
            raise ProductViewUnavailableError
        return FindingProductView(
            project_id=project_id,
            lineage_id=lineage_id,
            run_id=run_id,
            finding_id=occurrence.finding_id,
            authority=occurrence.authority,
            category=occurrence.category,
            severity=occurrence.severity,
            priority_band=occurrence.priority_band,
            priority_reason_codes=tuple(occurrence.priority_reason_codes_json),
            subject=deepcopy(occurrence.subject_summary_json),
            primary_location=deepcopy(occurrence.primary_location_json),
            lifecycle_state_at_run=event.resulting_state,
            lifecycle_event_kind=event.event_kind,
            lifecycle_transition_version=event.transition_version,
            lifecycle_reason_codes=tuple(event.reason_codes_json),
        )
