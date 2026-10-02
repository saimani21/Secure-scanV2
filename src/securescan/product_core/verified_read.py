"""Single trust boundary for reading a published Source S4 report."""

from __future__ import annotations

import json
from dataclasses import dataclass

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
    SourceLineageRunRow,
    SourceOrchestrationRow,
    TargetRow,
)


class VerifiedPublishedRunError(RuntimeError):
    """A published run could not be proven from its authoritative evidence."""

    def __init__(self) -> None:
        super().__init__("Verified published Source run is unavailable")


@dataclass(frozen=True, slots=True)
class VerifiedPublishedRun:
    """Typed S4 evidence plus the ownership and artifact facts just verified."""

    run_id: str
    target_id: str
    project_id: str
    lineage_id: str | None
    report_artifact_sha256: str
    report_artifact_size_bytes: int
    report: SecureScanEvidenceReport


_EXPECTED_RUN_STATUS = {
    OrchestrationTerminalOutcome.COMPLETED.value: RunStatus.COMPLETED.value,
    OrchestrationTerminalOutcome.PARTIAL.value: RunStatus.PARTIAL.value,
    OrchestrationTerminalOutcome.FAILED.value: RunStatus.FAILED.value,
}


class VerifiedPublishedRunGateway:
    """Reconstruct, verify, and scope every public read of published S4 evidence."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        artifact_store: ContentAddressedArtifactStore,
    ) -> None:
        if not isinstance(artifact_store, ContentAddressedArtifactStore):
            raise VerifiedPublishedRunError
        self._sessions = session_factory
        self._artifacts = artifact_store

    def load(
        self,
        *,
        run_id: str,
        expected_project_id: str | None = None,
        expected_lineage_id: str | None = None,
    ) -> VerifiedPublishedRun:
        report = self._rebuild_unverified(run_id)
        try:
            with self._sessions() as session:
                run_row = session.execute(
                    select(AnalysisRunRow, TargetRow)
                    .join(TargetRow, TargetRow.id == AnalysisRunRow.target_id)
                    .where(AnalysisRunRow.id == run_id)
                ).one_or_none()
                publication_row = session.execute(
                    select(SourceOrchestrationRow, SourceLineageRunRow)
                    .outerjoin(
                        SourceLineageRunRow,
                        SourceLineageRunRow.run_id == SourceOrchestrationRow.run_id,
                    )
                    .where(SourceOrchestrationRow.run_id == run_id)
                ).one_or_none()
                if run_row is None or publication_row is None:
                    raise VerifiedPublishedRunError
                run, target = run_row
                parent, membership = publication_row
                return self.verify_loaded(
                    session,
                    run,
                    parent,
                    report,
                    target=target,
                    membership=membership,
                    ownership_loaded=True,
                    expected_project_id=expected_project_id,
                    expected_lineage_id=expected_lineage_id,
                )
        except VerifiedPublishedRunError:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise VerifiedPublishedRunError from None

    def _rebuild_unverified(
        self, run_id: str, *, session: Session | None = None
    ) -> SecureScanEvidenceReport:
        try:
            report = SourceResultAssemblyService(
                self._sessions, self._artifacts
            )._build_report(run_id, session=session)
        except (OSError, SourceResultAssemblyError, TypeError, UnicodeError, ValueError):
            raise VerifiedPublishedRunError from None
        if not isinstance(report, SecureScanEvidenceReport):
            raise VerifiedPublishedRunError
        return report

    def verify_loaded(
        self,
        session: Session,
        run: AnalysisRunRow,
        parent: SourceOrchestrationRow,
        report: SecureScanEvidenceReport,
        *,
        target: TargetRow | None = None,
        membership: SourceLineageRunRow | None = None,
        ownership_loaded: bool = False,
        expected_project_id: str | None = None,
        expected_lineage_id: str | None = None,
    ) -> VerifiedPublishedRun:
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
            raise VerifiedPublishedRunError

        if not ownership_loaded:
            target = session.get(TargetRow, run.target_id)
            membership = session.get(SourceLineageRunRow, run.id)
        if (
            target is None
            or (expected_project_id is not None and target.project_id != expected_project_id)
            or (
                expected_lineage_id is not None
                and (membership is None or membership.lineage_id != expected_lineage_id)
            )
        ):
            raise VerifiedPublishedRunError

        payload = report.canonical_json()
        try:
            stored = self._artifacts.read_by_sha256(
                parent.assembly_artifact_sha256,
                expected_size_bytes=parent.assembly_artifact_size_bytes,
            )
            published = self._canonical_json(run.report_json)
        except (OSError, TypeError, ValueError, UnicodeError):
            raise VerifiedPublishedRunError from None
        if stored != payload or published != payload:
            raise VerifiedPublishedRunError

        return VerifiedPublishedRun(
            run_id=run.id,
            target_id=target.id,
            project_id=target.project_id,
            lineage_id=None if membership is None else membership.lineage_id,
            report_artifact_sha256=parent.assembly_artifact_sha256,
            report_artifact_size_bytes=parent.assembly_artifact_size_bytes,
            report=report,
        )

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
