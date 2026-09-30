from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import RunStatus
from securescan.evidence import SecureScanEvidenceReport
from securescan.orchestration.assembly import (
    SOURCE_FINAL_RESULT_MEDIA_TYPE,
    SOURCE_FINAL_RESULT_SCHEMA_VERSION,
    SourceResultAssemblyError,
    SourceResultAssemblyService,
)
from securescan.orchestration.models import (
    OrchestrationLifecycleState,
    OrchestrationTerminalOutcome,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    ProjectRow,
    SourceFindingOccurrenceRow,
    SourceLineageRunRow,
    SourceOrchestrationRow,
    SourceTargetLineageRow,
    TargetRow,
    utc_now,
)


class ProductCoreIndexError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Source Product Core index operation failed")


class _IndexingState(StrEnum):
    ATTACHED = "ATTACHED"
    INDEXED = "INDEXED"


_EXPECTED_RUN_STATUS = {
    OrchestrationTerminalOutcome.COMPLETED.value: RunStatus.COMPLETED.value,
    OrchestrationTerminalOutcome.PARTIAL.value: RunStatus.PARTIAL.value,
    OrchestrationTerminalOutcome.FAILED.value: RunStatus.FAILED.value,
}
_PREDECESSOR_UNSPECIFIED = object()


@dataclass(frozen=True, slots=True)
class SourceLineage:
    lineage_id: str
    project_id: str
    created_at: datetime
    created: bool


@dataclass(frozen=True, slots=True)
class SourceLineageRun:
    lineage_id: str
    run_id: str
    sequence_number: int
    predecessor_run_id: str | None
    report_artifact_sha256: str
    report_artifact_size_bytes: int
    report_schema_version: str
    indexing_state: str
    indexed_at: datetime | None
    lifecycle_evaluated_at: datetime | None
    lifecycle_evaluation_sha256: str | None
    lifecycle_event_count: int | None
    created_at: datetime
    created: bool


@dataclass(frozen=True, slots=True)
class SourceFindingOccurrence:
    run_id: str
    lineage_id: str
    finding_id: str
    authority: str
    category: str
    native_identity_schema: str
    severity: str | None
    subject_kind: str
    subject_summary: Mapping[str, Any]
    primary_location: Mapping[str, Any] | None
    report_artifact_sha256: str
    finding_ordinal: int
    indexed_at: datetime
    priority_band: str | None
    priority_reason_codes: tuple[str, ...] | None


@dataclass(frozen=True, slots=True)
class _OccurrenceMaterial:
    finding_id: str
    authority: str
    category: str
    native_identity_schema: str
    severity: str | None
    subject_kind: str
    subject_summary: dict[str, Any]
    primary_location: dict[str, Any] | None
    finding_ordinal: int


class SourceFindingIndexService:
    """Index query-safe S4 finding metadata without replacing S4 authority."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        artifact_store: ContentAddressedArtifactStore,
        *,
        clock: Callable[[], datetime] = utc_now,
        lineage_id_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        if not isinstance(artifact_store, ContentAddressedArtifactStore):
            raise ProductCoreIndexError
        self._sessions = session_factory
        self._artifacts = artifact_store
        self._clock = clock
        self._lineage_id_factory = lineage_id_factory

    def create_lineage(self, *, project_id: str) -> SourceLineage:
        self._require_uuid(project_id)
        lineage_id = str(self._lineage_id_factory())
        self._require_uuid(lineage_id)
        now = self._now()
        try:
            with self._sessions.begin() as session:
                if session.get(ProjectRow, project_id) is None:
                    raise ProductCoreIndexError
                row = SourceTargetLineageRow(
                    lineage_id=lineage_id,
                    project_id=project_id,
                    created_at=now,
                )
                session.add(row)
                session.flush()
                return self._lineage_record(row, created=True)
        except ProductCoreIndexError:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise ProductCoreIndexError from None

    def load_verified_published_report(
        self, *, run_id: str
    ) -> SecureScanEvidenceReport:
        """Load S4 only after typed, CAS, and published-JSON bytes agree."""

        self._require_uuid(run_id)
        report = self._rebuild_trusted_report(run_id)
        try:
            with self._sessions() as session:
                run = session.get(AnalysisRunRow, run_id)
                parent = session.get(SourceOrchestrationRow, run_id)
                if run is None or parent is None:
                    raise ProductCoreIndexError
                self._verify_published_report(run, parent, report)
            return report
        except ProductCoreIndexError:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise ProductCoreIndexError from None

    def attach_published_run(
        self,
        *,
        lineage_id: str,
        run_id: str,
        expected_predecessor_run_id: str | None | object = _PREDECESSOR_UNSPECIFIED,
    ) -> SourceLineageRun:
        self._require_uuid(lineage_id)
        self._require_uuid(run_id)
        if (
            expected_predecessor_run_id is not _PREDECESSOR_UNSPECIFIED
            and expected_predecessor_run_id is not None
        ):
            self._require_uuid(expected_predecessor_run_id)
        report = self._rebuild_trusted_report(run_id)
        try:
            with self._sessions.begin() as session:
                lineage = self._locked_lineage(session, lineage_id)
                run, parent = self._locked_run_and_parent(session, run_id)
                self._require_lineage_project(session, lineage, run)
                self._verify_published_report(run, parent, report)

                existing = session.get(SourceLineageRunRow, run_id)
                if existing is not None:
                    self._verify_existing_membership(
                        existing,
                        lineage_id=lineage_id,
                        parent=parent,
                        expected_predecessor_run_id=expected_predecessor_run_id,
                    )
                    return self._lineage_run_record(existing, created=False)

                tail = session.scalar(
                    select(SourceLineageRunRow)
                    .where(SourceLineageRunRow.lineage_id == lineage_id)
                    .order_by(SourceLineageRunRow.sequence_number.desc())
                    .limit(1)
                    .with_for_update()
                )
                predecessor_run_id = None if tail is None else tail.run_id
                if (
                    expected_predecessor_run_id is not _PREDECESSOR_UNSPECIFIED
                    and expected_predecessor_run_id != predecessor_run_id
                ):
                    raise ProductCoreIndexError
                row = SourceLineageRunRow(
                    run_id=run_id,
                    lineage_id=lineage_id,
                    sequence_number=1 if tail is None else tail.sequence_number + 1,
                    predecessor_run_id=predecessor_run_id,
                    predecessor_sequence_number=(
                        None if tail is None else tail.sequence_number
                    ),
                    report_artifact_sha256=parent.assembly_artifact_sha256,
                    report_artifact_size_bytes=parent.assembly_artifact_size_bytes,
                    report_schema_version=parent.assembly_schema_version,
                    indexing_state=_IndexingState.ATTACHED.value,
                    indexed_at=None,
                    created_at=self._now(),
                )
                session.add(row)
                session.flush()
                return self._lineage_run_record(row, created=True)
        except ProductCoreIndexError:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise ProductCoreIndexError from None

    def index_attached_run(self, *, lineage_id: str, run_id: str) -> SourceLineageRun:
        self._require_uuid(lineage_id)
        self._require_uuid(run_id)
        report = self._rebuild_trusted_report(run_id)
        material = self._occurrence_material(report)
        now = self._now()
        try:
            with self._sessions.begin() as session:
                self._locked_lineage(session, lineage_id)
                membership = session.scalar(
                    select(SourceLineageRunRow)
                    .where(SourceLineageRunRow.run_id == run_id)
                    .with_for_update()
                )
                if membership is None or membership.lineage_id != lineage_id:
                    raise ProductCoreIndexError
                run, parent = self._locked_run_and_parent(session, run_id)
                self._verify_published_report(run, parent, report)
                self._verify_membership_artifact(membership, parent)

                existing = tuple(
                    session.scalars(
                        select(SourceFindingOccurrenceRow)
                        .where(SourceFindingOccurrenceRow.run_id == run_id)
                        .order_by(SourceFindingOccurrenceRow.finding_ordinal)
                    )
                )
                if membership.indexing_state == _IndexingState.INDEXED.value:
                    self._verify_existing_occurrences(existing, membership, material)
                    return self._lineage_run_record(membership, created=False)
                if membership.indexing_state != _IndexingState.ATTACHED.value or existing:
                    raise ProductCoreIndexError

                session.add_all(
                    SourceFindingOccurrenceRow(
                        run_id=run_id,
                        lineage_id=lineage_id,
                        finding_id=item.finding_id,
                        authority=item.authority,
                        category=item.category,
                        native_identity_schema=item.native_identity_schema,
                        severity=item.severity,
                        subject_kind=item.subject_kind,
                        subject_summary_json=deepcopy(item.subject_summary),
                        primary_location_json=deepcopy(item.primary_location),
                        report_artifact_sha256=membership.report_artifact_sha256,
                        finding_ordinal=item.finding_ordinal,
                        indexed_at=now,
                    )
                    for item in material
                )
                membership.indexing_state = _IndexingState.INDEXED.value
                membership.indexed_at = now
                session.flush()
                return self._lineage_run_record(membership, created=True)
        except ProductCoreIndexError:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise ProductCoreIndexError from None

    def load_lineage_run(self, *, lineage_id: str, run_id: str) -> SourceLineageRun:
        self._require_uuid(lineage_id)
        self._require_uuid(run_id)
        try:
            with self._sessions() as session:
                row = session.get(SourceLineageRunRow, run_id)
                if row is None or row.lineage_id != lineage_id:
                    raise ProductCoreIndexError
                return self._lineage_run_record(row, created=False)
        except ProductCoreIndexError:
            raise
        except SQLAlchemyError:
            raise ProductCoreIndexError from None

    def list_indexed_occurrences(
        self, *, lineage_id: str, run_id: str
    ) -> tuple[SourceFindingOccurrence, ...]:
        self._require_uuid(lineage_id)
        self._require_uuid(run_id)
        try:
            with self._sessions() as session:
                membership = session.get(SourceLineageRunRow, run_id)
                if (
                    membership is None
                    or membership.lineage_id != lineage_id
                    or membership.indexing_state != _IndexingState.INDEXED.value
                    or membership.indexed_at is None
                ):
                    raise ProductCoreIndexError
                rows = tuple(
                    session.scalars(
                        select(SourceFindingOccurrenceRow)
                        .where(
                            SourceFindingOccurrenceRow.lineage_id == lineage_id,
                            SourceFindingOccurrenceRow.run_id == run_id,
                        )
                        .order_by(SourceFindingOccurrenceRow.finding_ordinal)
                    )
                )
                return tuple(self._occurrence_record(row) for row in rows)
        except ProductCoreIndexError:
            raise
        except SQLAlchemyError:
            raise ProductCoreIndexError from None

    def _rebuild_trusted_report(
        self,
        run_id: str,
        *,
        session: Session | None = None,
    ) -> SecureScanEvidenceReport:
        try:
            # The frozen S6D builder is the strict S4 validation boundary. PC1
            # deliberately does not deserialize a weaker subset of report JSON.
            report = SourceResultAssemblyService(
                self._sessions, self._artifacts
            )._build_report(run_id, session=session)
        except (OSError, SourceResultAssemblyError, TypeError, UnicodeError, ValueError):
            raise ProductCoreIndexError from None
        if not isinstance(report, SecureScanEvidenceReport):
            raise ProductCoreIndexError
        return report

    def _verify_published_report(
        self,
        run: AnalysisRunRow,
        parent: SourceOrchestrationRow,
        report: SecureScanEvidenceReport,
    ) -> None:
        if (
            parent.run_id != run.id
            or parent.cancel_requested
            or parent.lifecycle_state != OrchestrationLifecycleState.TERMINAL.value
            or parent.terminal_outcome not in _EXPECTED_RUN_STATUS
            or run.status != _EXPECTED_RUN_STATUS[parent.terminal_outcome]
            or parent.published_at is None
            or parent.assembled_at is None
            or run.report_json is None
            or parent.assembly_artifact_sha256 is None
            or parent.assembly_artifact_size_bytes is None
            or parent.assembly_artifact_media_type != SOURCE_FINAL_RESULT_MEDIA_TYPE
            or parent.assembly_schema_version != SOURCE_FINAL_RESULT_SCHEMA_VERSION
            or parent.assembly_artifact_storage_path
            != (
                "sha256/"
                f"{parent.assembly_artifact_sha256[:2]}/"
                f"{parent.assembly_artifact_sha256}"
            )
            or report.scope.source_run_id != run.id
            or report.scope.repository_digest != parent.repository_digest
            or report.scope.profile_digest != parent.profile_digest
            or report.scope.plan_digest != parent.plan_digest
        ):
            raise ProductCoreIndexError
        payload = report.canonical_json()
        try:
            stored = self._artifacts.read_by_sha256(
                parent.assembly_artifact_sha256,
                expected_size_bytes=parent.assembly_artifact_size_bytes,
            )
            published = self._canonical_json(run.report_json)
        except (OSError, TypeError, ValueError, UnicodeError):
            raise ProductCoreIndexError from None
        if stored != payload or published != payload:
            raise ProductCoreIndexError

    @staticmethod
    def _occurrence_material(
        report: SecureScanEvidenceReport,
    ) -> tuple[_OccurrenceMaterial, ...]:
        finding_ids = tuple(item.finding_id for item in report.findings)
        if len(finding_ids) != len(set(finding_ids)):
            raise ProductCoreIndexError
        return tuple(
            _OccurrenceMaterial(
                finding_id=finding.finding_id,
                authority=finding.authority.value,
                category=finding.category.value,
                native_identity_schema=finding.native_identity_schema,
                severity=None if finding.severity is None else finding.severity.value,
                subject_kind=finding.subject.canonical_data()["kind"],
                subject_summary=finding.subject.canonical_data(),
                primary_location=(
                    None
                    if not finding.locations
                    else finding.locations[0].canonical_data()
                ),
                finding_ordinal=ordinal,
            )
            for ordinal, finding in enumerate(report.findings)
        )

    @staticmethod
    def _verify_existing_occurrences(
        existing: tuple[SourceFindingOccurrenceRow, ...],
        membership: SourceLineageRunRow,
        expected: tuple[_OccurrenceMaterial, ...],
    ) -> None:
        actual = tuple(
            _OccurrenceMaterial(
                finding_id=row.finding_id,
                authority=row.authority,
                category=row.category,
                native_identity_schema=row.native_identity_schema,
                severity=row.severity,
                subject_kind=row.subject_kind,
                subject_summary=row.subject_summary_json,
                primary_location=row.primary_location_json,
                finding_ordinal=row.finding_ordinal,
            )
            for row in existing
        )
        if (
            membership.indexed_at is None
            or actual != expected
            or any(
                row.lineage_id != membership.lineage_id
                or row.report_artifact_sha256 != membership.report_artifact_sha256
                or row.indexed_at != membership.indexed_at
                for row in existing
            )
        ):
            raise ProductCoreIndexError

    @staticmethod
    def _verify_existing_membership(
        existing: SourceLineageRunRow,
        *,
        lineage_id: str,
        parent: SourceOrchestrationRow,
        expected_predecessor_run_id: str | None | object,
    ) -> None:
        if (
            existing.lineage_id != lineage_id
            or existing.report_artifact_sha256 != parent.assembly_artifact_sha256
            or existing.report_artifact_size_bytes != parent.assembly_artifact_size_bytes
            or existing.report_schema_version != parent.assembly_schema_version
            or (
                expected_predecessor_run_id is not _PREDECESSOR_UNSPECIFIED
                and existing.predecessor_run_id != expected_predecessor_run_id
            )
        ):
            raise ProductCoreIndexError

    @staticmethod
    def _verify_membership_artifact(
        membership: SourceLineageRunRow, parent: SourceOrchestrationRow
    ) -> None:
        if (
            membership.report_artifact_sha256 != parent.assembly_artifact_sha256
            or membership.report_artifact_size_bytes
            != parent.assembly_artifact_size_bytes
            or membership.report_schema_version != parent.assembly_schema_version
        ):
            raise ProductCoreIndexError

    @staticmethod
    def _require_lineage_project(
        session: Session, lineage: SourceTargetLineageRow, run: AnalysisRunRow
    ) -> None:
        target = session.get(TargetRow, run.target_id)
        if target is None or target.project_id != lineage.project_id:
            raise ProductCoreIndexError

    @staticmethod
    def _locked_lineage(session: Session, lineage_id: str) -> SourceTargetLineageRow:
        row = session.scalar(
            select(SourceTargetLineageRow)
            .where(SourceTargetLineageRow.lineage_id == lineage_id)
            .with_for_update()
        )
        if row is None:
            raise ProductCoreIndexError
        return row

    @staticmethod
    def _locked_run_and_parent(
        session: Session, run_id: str
    ) -> tuple[AnalysisRunRow, SourceOrchestrationRow]:
        run = session.scalar(
            select(AnalysisRunRow)
            .where(AnalysisRunRow.id == run_id)
            .with_for_update()
        )
        parent = session.scalar(
            select(SourceOrchestrationRow)
            .where(SourceOrchestrationRow.run_id == run_id)
            .with_for_update()
        )
        if run is None or parent is None:
            raise ProductCoreIndexError
        return run, parent

    @staticmethod
    def _canonical_json(value: object) -> bytes:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )

    @staticmethod
    def _require_uuid(value: object) -> None:
        try:
            valid = isinstance(value, str) and str(UUID(value)) == value
        except (AttributeError, TypeError, ValueError):
            valid = False
        if not valid:
            raise ProductCoreIndexError

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ProductCoreIndexError
        return value

    @staticmethod
    def _lineage_record(row: SourceTargetLineageRow, *, created: bool) -> SourceLineage:
        return SourceLineage(
            row.lineage_id,
            row.project_id,
            SourceFindingIndexService._as_utc(row.created_at),
            created,
        )

    @staticmethod
    def _lineage_run_record(
        row: SourceLineageRunRow, *, created: bool
    ) -> SourceLineageRun:
        return SourceLineageRun(
            lineage_id=row.lineage_id,
            run_id=row.run_id,
            sequence_number=row.sequence_number,
            predecessor_run_id=row.predecessor_run_id,
            report_artifact_sha256=row.report_artifact_sha256,
            report_artifact_size_bytes=row.report_artifact_size_bytes,
            report_schema_version=row.report_schema_version,
            indexing_state=row.indexing_state,
            indexed_at=(
                None
                if row.indexed_at is None
                else SourceFindingIndexService._as_utc(row.indexed_at)
            ),
            lifecycle_evaluated_at=(
                None
                if row.lifecycle_evaluated_at is None
                else SourceFindingIndexService._as_utc(row.lifecycle_evaluated_at)
            ),
            lifecycle_evaluation_sha256=row.lifecycle_evaluation_sha256,
            lifecycle_event_count=row.lifecycle_event_count,
            created_at=SourceFindingIndexService._as_utc(row.created_at),
            created=created,
        )

    @staticmethod
    def _occurrence_record(row: SourceFindingOccurrenceRow) -> SourceFindingOccurrence:
        return SourceFindingOccurrence(
            run_id=row.run_id,
            lineage_id=row.lineage_id,
            finding_id=row.finding_id,
            authority=row.authority,
            category=row.category,
            native_identity_schema=row.native_identity_schema,
            severity=row.severity,
            subject_kind=row.subject_kind,
            subject_summary=MappingProxyType(deepcopy(row.subject_summary_json)),
            primary_location=(
                None
                if row.primary_location_json is None
                else MappingProxyType(deepcopy(row.primary_location_json))
            ),
            report_artifact_sha256=row.report_artifact_sha256,
            finding_ordinal=row.finding_ordinal,
            indexed_at=SourceFindingIndexService._as_utc(row.indexed_at),
            priority_band=row.priority_band,
            priority_reason_codes=(
                None
                if row.priority_reason_codes_json is None
                else tuple(row.priority_reason_codes_json)
            ),
        )

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
