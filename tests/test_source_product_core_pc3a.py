from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.config import Settings
from securescan.domain.enums import RunStatus, TargetType
from securescan.persistence.database import (
    AnalysisRunRow,
    ProjectRow,
    SourceLineageRunRow,
    SourceScanSubmissionRow,
    SourceTargetLineageRow,
    TargetRow,
    create_session_factory,
    initialize_database,
)
from securescan.product_core import (
    ProductCoreFinalizationNotReadyError,
    ProductCoreSubmissionError,
    SourceFindingLifecycleService,
    SourcePreparedScanRequest,
    SourceScanSubmissionService,
)
from securescan.workspaces import ForeignWorkspaceError, RepositoryWorkspaceManager
from tests.test_source_orchestration_s6b import _Environment
from tests.test_source_product_core_pc1 import (
    _clone_published_run,
    _publish_environment,
)
from tests.test_source_product_core_pc2 import _clone_gitleaks_runtime

_NOW = datetime(2026, 9, 9, tzinfo=UTC)
_RUN_A = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaa1"
_RUN_B = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaa2"


@pytest.fixture
def reservation_context(tmp_path: Path):
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'pc3a.db'}",
        artifact_root=tmp_path / "artifacts",
    )
    initialize_database(settings)
    engine, factory = create_session_factory(settings)
    manager = RepositoryWorkspaceManager(
        (tmp_path / "managed").resolve(), workspace_id_factory=lambda: "1" * 32
    )
    source = tmp_path / "repository"
    source.mkdir()
    (source / "app.py").write_text("value = 1\n")
    workspace = manager.prepare_repository(source)
    with factory.begin() as session:
        project = ProjectRow(name="PC3A")
        session.add(project)
        session.flush()
        lineage = SourceTargetLineageRow(
            lineage_id="bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb",
            project_id=project.id,
            created_at=_NOW,
        )
        target = TargetRow(
            project_id=project.id,
            target_type=TargetType.SOURCE_REPOSITORY.value,
            content_digest=workspace.manifest.content_digest,
            source_path=workspace.workspace_id,
            metadata_json={},
        )
        session.add_all((lineage, target))
        session.flush()
        for run_id in (_RUN_A, _RUN_B):
            session.add(
                AnalysisRunRow(
                    id=run_id,
                    target_id=target.id,
                    status=RunStatus.QUEUED.value,
                    report_json=None,
                    created_at=_NOW,
                )
            )
        project_id = project.id
        target_id = target.id
        lineage_id = lineage.lineage_id
    service = SourceScanSubmissionService(
        factory,
        ContentAddressedArtifactStore(settings.artifact_root),
        manager,
        clock=lambda: _NOW,
    )
    try:
        yield service, factory, manager, workspace, project_id, target_id, lineage_id
    finally:
        manager.cleanup_workspace(workspace)
        engine.dispose()


def test_submission_reserves_first_and_subsequent_order(reservation_context) -> None:
    service, _factory, _manager, workspace, _project, _target, lineage = (
        reservation_context
    )
    first = service.reserve(
        run_id=_RUN_A, lineage_id=lineage, intake_ref=workspace.workspace_id
    )
    second = service.reserve(
        run_id=_RUN_B, lineage_id=lineage, intake_ref=workspace.workspace_id
    )

    assert first.submission_sequence_number == 1
    assert first.predecessor_run_id is None
    assert first.predecessor_sequence_number is None
    assert second.submission_sequence_number == 2
    assert second.predecessor_run_id == _RUN_A
    assert second.predecessor_sequence_number == 1


def test_existing_finalized_pc1_tail_sets_next_submission_order(
    reservation_context,
) -> None:
    service, factory, _manager, workspace, _project, _target, lineage = (
        reservation_context
    )
    with factory.begin() as session:
        session.add(
            SourceLineageRunRow(
                run_id=_RUN_A,
                lineage_id=lineage,
                sequence_number=1,
                predecessor_run_id=None,
                predecessor_sequence_number=None,
                report_artifact_sha256="a" * 64,
                report_artifact_size_bytes=1,
                report_schema_version="securescan-unified-evidence-s4-v1",
                indexing_state="INDEXED",
                indexed_at=_NOW,
                lifecycle_evaluated_at=_NOW,
                lifecycle_evaluation_sha256="b" * 64,
                lifecycle_event_count=0,
                created_at=_NOW,
            )
        )

    result = service.reserve(
        run_id=_RUN_B, lineage_id=lineage, intake_ref=workspace.workspace_id
    )

    assert result.submission_sequence_number == 2
    assert result.predecessor_run_id == _RUN_A
    assert result.predecessor_sequence_number == 1


def test_persistence_rejects_nonadjacent_predecessor_sequence(
    reservation_context,
) -> None:
    _service, factory, _manager, workspace, _project, _target, lineage = (
        reservation_context
    )
    with pytest.raises(IntegrityError), factory.begin() as session:
        session.add(
            SourceScanSubmissionRow(
                run_id=_RUN_B,
                lineage_id=lineage,
                submission_sequence_number=3,
                predecessor_run_id=_RUN_A,
                predecessor_sequence_number=1,
                intake_kind="MANAGED_WORKSPACE_V1",
                intake_ref=workspace.workspace_id,
                created_at=_NOW,
                finalized_at=None,
            )
        )


def test_exact_replay_converges_and_conflicting_rebind_fails(
    reservation_context,
) -> None:
    service, factory, _manager, workspace, project_id, _target, lineage = (
        reservation_context
    )
    created = service.reserve(
        run_id=_RUN_A, lineage_id=lineage, intake_ref=workspace.workspace_id
    )
    replay = service.reserve(
        run_id=_RUN_A, lineage_id=lineage, intake_ref=workspace.workspace_id
    )
    assert created.created is True
    assert replay.created is False
    assert replay.submission_sequence_number == created.submission_sequence_number

    with factory.begin() as session:
        alternate = SourceTargetLineageRow(
            lineage_id="bbbbbbbb-1111-4111-8111-bbbbbbbbbbb2",
            project_id=project_id,
            created_at=_NOW,
        )
        session.add(alternate)
    with pytest.raises(ProductCoreSubmissionError):
        service.reserve(
            run_id=_RUN_A,
            lineage_id=alternate.lineage_id,
            intake_ref=workspace.workspace_id,
        )


def test_project_mismatch_and_nonopaque_intake_fail_closed(reservation_context) -> None:
    service, factory, _manager, workspace, _project, target_id, lineage = (
        reservation_context
    )
    with pytest.raises(ProductCoreSubmissionError):
        service.reserve(run_id=_RUN_A, lineage_id=lineage, intake_ref="/etc")

    with factory.begin() as session:
        other = ProjectRow(name="Other")
        session.add(other)
        session.flush()
        session.get(TargetRow, target_id).project_id = other.id  # type: ignore[union-attr]
    with pytest.raises(ProductCoreSubmissionError):
        service.reserve(
            run_id=_RUN_A, lineage_id=lineage, intake_ref=workspace.workspace_id
        )


def test_only_opaque_workspace_id_is_persisted_and_resolved(
    reservation_context,
) -> None:
    service, factory, manager, workspace, _project, _target, lineage = (
        reservation_context
    )
    service.reserve(
        run_id=_RUN_A, lineage_id=lineage, intake_ref=workspace.workspace_id
    )
    with factory() as session:
        row = session.get(SourceScanSubmissionRow, _RUN_A)
        assert row is not None
        assert row.intake_ref == workspace.workspace_id
        assert str(workspace.source_directory) not in row.intake_ref
        assert str(workspace.root_directory) not in row.intake_ref

    resolved = manager.resolve_workspace(workspace.workspace_id, workspace.manifest)
    assert resolved == workspace
    with pytest.raises(ForeignWorkspaceError):
        manager.resolve_workspace("../../etc", workspace.manifest)


def test_unpublished_run_cannot_finalize(reservation_context) -> None:
    service, _factory, _manager, workspace, _project, _target, lineage = (
        reservation_context
    )
    service.reserve(
        run_id=_RUN_A, lineage_id=lineage, intake_ref=workspace.workspace_id
    )
    with pytest.raises(ProductCoreFinalizationNotReadyError):
        service.finalize(run_id=_RUN_A)


def test_prepared_submission_creates_opaque_target_and_active_orchestration(
    tmp_path: Path,
) -> None:
    environment = _Environment(tmp_path)
    try:
        with environment.factory.begin() as session:
            project = ProjectRow(name="PC3A prepared submission")
            session.add(project)
            session.flush()
            project_id = project.id
        service = SourceScanSubmissionService(
            environment.factory,
            environment.store,
            environment.workspace_manager,
            clock=lambda: _NOW,
        )
        lineage = service.create_lineage(project_id=project_id)
        submission = service.submit_prepared(
            SourcePreparedScanRequest(
                project_id=project_id,
                lineage_id=lineage.lineage_id,
                workspace=environment.workspace,
                profile=environment.profile,
                plan=environment.plan,
                idempotency_key="9" * 64,
                deadline_at=datetime(2099, 1, 1, tzinfo=UTC),
            )
        )

        with environment.factory() as session:
            run = session.get(AnalysisRunRow, submission.run_id)
            assert run is not None
            target = session.get(TargetRow, run.target_id)
            assert target is not None
            assert target.source_path == environment.workspace.workspace_id
            assert str(environment.workspace.source_directory) not in target.source_path
        assert service.resolve_workspace(run_id=submission.run_id) == environment.workspace
    finally:
        environment.close()


def test_published_finalizer_runs_pc1_then_pc2_and_replays(tmp_path: Path) -> None:
    environment = _Environment(tmp_path)
    _publish_environment(environment)
    try:
        with environment.factory.begin() as session:
            run = session.get(AnalysisRunRow, str(environment.snapshot.run_id))
            assert run is not None
            target = session.get(TargetRow, run.target_id)
            assert target is not None
            target.source_path = environment.workspace.workspace_id
            project_id = target.project_id
        service = SourceScanSubmissionService(
            environment.factory,
            environment.store,
            environment.workspace_manager,
            clock=lambda: _NOW,
        )
        lineage = service.create_lineage(project_id=project_id)
        service.reserve(
            run_id=str(environment.snapshot.run_id),
            lineage_id=lineage.lineage_id,
            intake_ref=environment.workspace.workspace_id,
        )

        first = service.finalize(run_id=str(environment.snapshot.run_id))
        replay = service.finalize(run_id=str(environment.snapshot.run_id))

        assert first.finalized_at == _NOW
        assert replay == first
        lifecycle = SourceFindingLifecycleService(
            environment.factory, environment.store
        ).list_events(lineage_id=lineage.lineage_id, run_id=first.run_id)
        assert lifecycle
    finally:
        environment.close()


def test_out_of_order_publication_uses_real_pc1_and_pc2_finalization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment = _Environment(tmp_path)
    _publish_environment(environment)
    second_run_id = "cccccccc-1111-4111-8111-cccccccccccc"
    try:
        with environment.factory.begin() as session:
            first_run = session.get(AnalysisRunRow, str(environment.snapshot.run_id))
            assert first_run is not None
            target = session.get(TargetRow, first_run.target_id)
            assert target is not None
            target.source_path = environment.workspace.workspace_id
            project_id = target.project_id

        service = SourceScanSubmissionService(
            environment.factory,
            environment.store,
            environment.workspace_manager,
            clock=lambda: _NOW,
        )
        lineage = service.create_lineage(project_id=project_id)
        first = service.reserve(
            run_id=str(environment.snapshot.run_id),
            lineage_id=lineage.lineage_id,
            intake_ref=environment.workspace.workspace_id,
        )
        first_report = service._index._rebuild_trusted_report(first.run_id)
        second_report = _clone_published_run(
            environment, first_report, second_run_id
        )
        _clone_gitleaks_runtime(environment, second_run_id, 31)
        second = service.reserve(
            run_id=second_run_id,
            lineage_id=lineage.lineage_id,
            intake_ref=environment.workspace.workspace_id,
        )
        assert second.predecessor_run_id == first.run_id

        reports = {first.run_id: first_report, second.run_id: second_report}
        monkeypatch.setattr(
            service._index, "_rebuild_trusted_report", reports.__getitem__
        )
        monkeypatch.setattr(
            service._lifecycle, "_trusted_report", reports.__getitem__
        )

        with pytest.raises(ProductCoreFinalizationNotReadyError):
            service.finalize(run_id=second_run_id)

        finalized_first = service.finalize(run_id=first.run_id)
        finalized_second = service.finalize(run_id=second_run_id)
        replay = service.finalize(run_id=second_run_id)

        assert finalized_first.finalized_at is not None
        assert finalized_second.finalized_at is not None
        assert replay == finalized_second
        with environment.factory() as session:
            memberships = tuple(
                session.scalars(
                    select(SourceLineageRunRow)
                    .where(SourceLineageRunRow.lineage_id == lineage.lineage_id)
                    .order_by(SourceLineageRunRow.sequence_number)
                )
            )
        assert [(item.run_id, item.sequence_number) for item in memberships] == [
            (first.run_id, 1),
            (second_run_id, 2),
        ]
        assert memberships[1].predecessor_run_id == first.run_id
        assert all(item.indexing_state == "INDEXED" for item in memberships)
        assert all(item.lifecycle_evaluated_at is not None for item in memberships)
    finally:
        environment.close()
