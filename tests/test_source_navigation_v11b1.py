from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.config import Settings
from securescan.domain.enums import RunStatus, TargetType
from securescan.orchestration.models import (
    OrchestrationLifecycleState,
    OrchestrationTerminalOutcome,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    ProjectRow,
    SourceLineageRunRow,
    SourceOrchestrationRow,
    SourceScanSubmissionRow,
    SourceTargetLineageRow,
    TargetRow,
    create_session_factory,
    initialize_database,
)
from securescan.product_core import (
    InvalidProjectIdentifierError,
    InvalidProjectPaginationError,
    InvalidScanPaginationError,
    SourceProductStatus,
    SourceProjectNotFoundError,
    SourceProjectService,
    SourceScanQueryService,
)

_BASE = datetime(2026, 9, 23, 12, tzinfo=UTC)


def _uuid(number: int) -> str:
    return f"00000000-0000-4000-8000-{number:012d}"


@dataclass
class _Database:
    engine: Engine
    sessions: sessionmaker[Session]
    projects: SourceProjectService
    scans: SourceScanQueryService

    def close(self) -> None:
        self.engine.dispose()


def _database(tmp_path: Path) -> _Database:
    settings = Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'navigation.db'}",
        artifact_root=tmp_path / "artifacts",
    )
    initialize_database(settings)
    engine, sessions = create_session_factory(settings)
    return _Database(
        engine,
        sessions,
        SourceProjectService(sessions),
        SourceScanQueryService(sessions, ContentAddressedArtifactStore(settings.artifact_root)),
    )


def _add_project(session: Session, number: int, name: str, created_at: datetime) -> ProjectRow:
    project = ProjectRow(id=_uuid(number), name=name, created_at=created_at)
    session.add(project)
    session.flush()
    return project


def _add_scan(
    session: Session,
    *,
    project_id: str,
    number: int,
    created_at: datetime,
    lifecycle: OrchestrationLifecycleState,
    terminal: OrchestrationTerminalOutcome | None = None,
    lineage_id: str | None = None,
    sequence_number: int = 1,
    predecessor_run_id: str | None = None,
    predecessor_sequence_number: int | None = None,
) -> str:
    run_id = _uuid(1_000 + number)
    target_id = _uuid(2_000 + number)
    lineage_id = _uuid(3_000 + number) if lineage_id is None else lineage_id
    digest = hashlib.sha256(run_id.encode()).hexdigest()
    source_path = f"securescan-workspace-{digest[:48]}"
    session.add(
        TargetRow(
            id=target_id,
            project_id=project_id,
            target_type=TargetType.SOURCE_REPOSITORY.value,
            content_digest=digest,
            source_path=source_path,
            metadata_json={"private": True},
            created_at=created_at,
        )
    )
    session.flush()
    session.add(
        AnalysisRunRow(
            id=run_id,
            target_id=target_id,
            status=(
                RunStatus.FAILED.value
                if terminal is OrchestrationTerminalOutcome.FAILED
                else RunStatus.RUNNING.value
            ),
            created_at=created_at,
        )
    )
    lineage = session.get(SourceTargetLineageRow, lineage_id)
    if lineage is None:
        session.add(
            SourceTargetLineageRow(
                lineage_id=lineage_id,
                project_id=project_id,
                created_at=created_at,
            )
        )
    elif lineage.project_id != project_id:
        raise AssertionError("test fixture lineage must belong to the target project")
    session.flush()
    session.add_all(
        (
            SourceScanSubmissionRow(
                run_id=run_id,
                lineage_id=lineage_id,
                submission_sequence_number=sequence_number,
                predecessor_run_id=predecessor_run_id,
                predecessor_sequence_number=predecessor_sequence_number,
                intake_kind="MANAGED_WORKSPACE_V1",
                intake_ref=source_path,
                created_at=created_at,
            ),
            SourceOrchestrationRow(
                run_id=run_id,
                idempotency_key=digest,
                creation_request_digest=digest,
                repository_digest=digest,
                profile_digest=digest,
                plan_digest=digest,
                roster_digest=digest,
                planning_snapshot_sha256=digest,
                snapshot_size_bytes=1,
                snapshot_media_type="application/json",
                snapshot_schema_version="test-navigation-v1",
                snapshot_storage_path=f"sha256/{digest[:2]}/{digest}",
                lifecycle_state=lifecycle.value,
                terminal_outcome=None if terminal is None else terminal.value,
                cancel_requested=False,
                state_version=1,
                assembly_attempt_count=0,
                max_active_jobs=2,
                deadline_at=created_at + timedelta(hours=1),
                created_at=created_at,
                updated_at=created_at,
            ),
        )
    )
    return run_id


def _add_non_source_run(
    session: Session, *, project_id: str, number: int, created_at: datetime
) -> str:
    target_id = _uuid(8_000 + number)
    run_id = _uuid(9_000 + number)
    session.add(
        TargetRow(
            id=target_id,
            project_id=project_id,
            target_type=TargetType.LIVE_API.value,
            content_digest=hashlib.sha256(target_id.encode()).hexdigest(),
            source_path="https://example.invalid/api",
            metadata_json={},
            created_at=created_at,
        )
    )
    session.flush()
    session.add(
        AnalysisRunRow(
            id=run_id,
            target_id=target_id,
            status=RunStatus.RUNNING.value,
            created_at=created_at,
        )
    )
    return run_id


def _mark_partial_scan_finalized(session: Session, *, run_id: str, finalized_at: datetime) -> None:
    run = session.get(AnalysisRunRow, run_id)
    parent = session.get(SourceOrchestrationRow, run_id)
    submission = session.get(SourceScanSubmissionRow, run_id)
    assert run is not None and parent is not None and submission is not None
    digest = hashlib.sha256(f"report:{run_id}".encode()).hexdigest()
    run.status = RunStatus.PARTIAL.value
    run.report_json = {"safe_test_report": True}
    parent.lifecycle_state = OrchestrationLifecycleState.TERMINAL.value
    parent.terminal_outcome = OrchestrationTerminalOutcome.PARTIAL.value
    parent.assembly_artifact_sha256 = digest
    parent.assembly_artifact_size_bytes = 1
    parent.assembly_artifact_media_type = "application/json"
    parent.assembly_schema_version = "securescan-unified-evidence-s4-v1"
    parent.assembly_artifact_storage_path = f"sha256/{digest[:2]}/{digest}"
    parent.assembled_at = finalized_at
    parent.published_at = finalized_at
    parent.updated_at = finalized_at
    submission.finalized_at = finalized_at
    session.add(
        SourceLineageRunRow(
            run_id=run_id,
            lineage_id=submission.lineage_id,
            sequence_number=submission.submission_sequence_number,
            predecessor_run_id=submission.predecessor_run_id,
            predecessor_sequence_number=submission.predecessor_sequence_number,
            report_artifact_sha256=digest,
            report_artifact_size_bytes=1,
            report_schema_version="securescan-unified-evidence-s4-v1",
            indexing_state="INDEXED",
            indexed_at=finalized_at,
            lifecycle_evaluated_at=finalized_at,
            lifecycle_evaluation_sha256=digest,
            lifecycle_event_count=0,
            created_at=finalized_at,
        )
    )


def test_project_get_and_page_are_bounded_recent_and_deterministic(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with database.sessions.begin() as session:
            first = _add_project(session, 1, "First", _BASE)
            second = _add_project(session, 2, "Second", _BASE + timedelta(seconds=1))
            third = _add_project(session, 3, "Third", _BASE + timedelta(seconds=1))
            project_ids = (first.id, second.id, third.id)

        assert database.projects.get(project_ids[0]).name == "First"
        page = database.projects.list_page(limit=2, offset=0)
        assert page.total == 3
        assert page.limit == 2
        assert page.offset == 0
        assert tuple(item.project_id for item in page.items) == (
            project_ids[2],
            project_ids[1],
        )
        assert database.projects.list_page(limit=2, offset=3).items == ()
        assert tuple(item.project_id for item in database.projects.list(limit=3)) == project_ids

        with pytest.raises(SourceProjectNotFoundError):
            database.projects.get(_uuid(999))
        with pytest.raises(InvalidProjectIdentifierError):
            database.projects.get("not-a-uuid")
        with pytest.raises(InvalidProjectPaginationError):
            database.projects.list_page(limit=0)
        with pytest.raises(InvalidProjectPaginationError):
            database.projects.list_page(offset=-1)
    finally:
        database.close()


def test_scan_pages_are_global_filterable_stable_and_truthful(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with database.sessions.begin() as session:
            project_a = _add_project(session, 11, "A", _BASE)
            project_b = _add_project(session, 12, "B", _BASE)
            project_empty = _add_project(session, 13, "Empty", _BASE)
            older = _add_scan(
                session,
                project_id=project_b.id,
                number=1,
                created_at=_BASE,
                lifecycle=OrchestrationLifecycleState.PREPARED,
            )
            running = _add_scan(
                session,
                project_id=project_a.id,
                number=2,
                created_at=_BASE + timedelta(seconds=1),
                lifecycle=OrchestrationLifecycleState.ACTIVE,
            )
            failed = _add_scan(
                session,
                project_id=project_a.id,
                number=3,
                created_at=_BASE + timedelta(seconds=1),
                lifecycle=OrchestrationLifecycleState.TERMINAL,
                terminal=OrchestrationTerminalOutcome.FAILED,
            )

        global_page = database.scans.list_scans(limit=3)
        assert global_page.total == 3
        assert tuple(item.run_id for item in global_page.items) == (
            failed,
            running,
            older,
        )
        assert tuple(item.product_status for item in global_page.items) == (
            SourceProductStatus.FAILED,
            SourceProductStatus.RUNNING,
            SourceProductStatus.QUEUED,
        )
        assert all("private" not in repr(item) for item in global_page.items)

        project_page = database.scans.list_scans(project_id=project_a.id, limit=10, offset=0)
        assert project_page.total == 2
        assert {item.project_id for item in project_page.items} == {project_a.id}
        assert database.scans.list_scans(project_id=project_empty.id).items == ()
        assert database.scans.list_scans(project_id=project_empty.id).total == 0

        adjacent = tuple(
            database.scans.list_scans(limit=1, offset=offset).items[0].run_id for offset in range(3)
        )
        assert adjacent == (failed, running, older)
        assert len(set(adjacent)) == 3

        with pytest.raises(SourceProjectNotFoundError):
            database.scans.list_scans(project_id=_uuid(999))
        with pytest.raises(InvalidProjectIdentifierError):
            database.scans.list_scans(project_id="not-a-uuid")
        with pytest.raises(InvalidScanPaginationError):
            database.scans.list_scans(limit=201)
        with pytest.raises(InvalidScanPaginationError):
            database.scans.list_scans(offset=-1)
    finally:
        database.close()


def test_scan_page_sql_query_count_is_independent_of_page_size(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with database.sessions.begin() as session:
            project = _add_project(session, 21, "Query count", _BASE)
            for number in range(1, 11):
                _add_scan(
                    session,
                    project_id=project.id,
                    number=number,
                    created_at=_BASE + timedelta(seconds=number),
                    lifecycle=OrchestrationLifecycleState.ACTIVE,
                )

        query_count = 0

        def count_query(*_args: object, **_kwargs: object) -> None:
            nonlocal query_count
            query_count += 1

        event.listen(database.engine, "before_cursor_execute", count_query)
        try:
            database.scans.list_scans(limit=1)
            one_item_count = query_count
            query_count = 0
            database.scans.list_scans(limit=10)
            ten_item_count = query_count
        finally:
            event.remove(database.engine, "before_cursor_execute", count_query)

        assert one_item_count == ten_item_count == 2
    finally:
        database.close()


def test_canonical_scan_universe_count_paging_and_project_isolation(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    try:
        with database.sessions.begin() as session:
            project_a = _add_project(session, 51, "Project A", _BASE)
            project_b = _add_project(session, 52, "Project B", _BASE)
            project_c = _add_project(session, 53, "Empty Project C", _BASE)
            lineage_a = _uuid(6_001)
            lineage_b = _uuid(6_002)
            a1 = _add_scan(
                session,
                project_id=project_a.id,
                number=51,
                created_at=_BASE,
                lifecycle=OrchestrationLifecycleState.ACTIVE,
                lineage_id=lineage_a,
            )
            b1 = _add_scan(
                session,
                project_id=project_b.id,
                number=52,
                created_at=_BASE,
                lifecycle=OrchestrationLifecycleState.ACTIVE,
                lineage_id=lineage_b,
            )
            a2 = _add_scan(
                session,
                project_id=project_a.id,
                number=53,
                created_at=_BASE,
                lifecycle=OrchestrationLifecycleState.ACTIVE,
                lineage_id=lineage_a,
                sequence_number=2,
                predecessor_run_id=a1,
                predecessor_sequence_number=1,
            )
            b2 = _add_scan(
                session,
                project_id=project_b.id,
                number=54,
                created_at=_BASE,
                lifecycle=OrchestrationLifecycleState.ACTIVE,
                lineage_id=lineage_b,
                sequence_number=2,
                predecessor_run_id=b1,
                predecessor_sequence_number=1,
            )
            a3 = _add_scan(
                session,
                project_id=project_a.id,
                number=55,
                created_at=_BASE,
                lifecycle=OrchestrationLifecycleState.ACTIVE,
                lineage_id=lineage_a,
                sequence_number=3,
                predecessor_run_id=a2,
                predecessor_sequence_number=2,
            )
            unrelated = _add_non_source_run(
                session,
                project_id=project_a.id,
                number=51,
                created_at=_BASE + timedelta(seconds=10),
            )

            cross_project = _add_scan(
                session,
                project_id=project_a.id,
                number=56,
                created_at=_BASE + timedelta(seconds=10),
                lifecycle=OrchestrationLifecycleState.ACTIVE,
            )
            project_b_lineage = SourceTargetLineageRow(
                lineage_id=_uuid(6_003),
                project_id=project_b.id,
                created_at=_BASE,
            )
            session.add(project_b_lineage)
            session.flush()
            cross_submission = session.get(SourceScanSubmissionRow, cross_project)
            assert cross_submission is not None
            cross_submission.lineage_id = project_b_lineage.lineage_id

            wrong_target_type = _add_scan(
                session,
                project_id=project_a.id,
                number=57,
                created_at=_BASE + timedelta(seconds=10),
                lifecycle=OrchestrationLifecycleState.ACTIVE,
            )
            wrong_run = session.get(AnalysisRunRow, wrong_target_type)
            assert wrong_run is not None
            wrong_target = session.get(TargetRow, wrong_run.target_id)
            assert wrong_target is not None
            wrong_target.target_type = TargetType.LIVE_API.value

        expected = (a3, b2, a2, b1, a1)
        page = database.scans.list_scans(limit=200)
        assert page.total == len(expected)
        assert tuple(item.run_id for item in page.items) == expected
        assert unrelated not in expected
        assert cross_project not in expected
        assert wrong_target_type not in expected

        paged = tuple(
            item.run_id
            for offset in (0, 2, 4)
            for item in database.scans.list_scans(limit=2, offset=offset).items
        )
        assert paged == expected
        assert len(set(paged)) == len(expected)

        project_a_page = database.scans.list_scans(project_id=project_a.id)
        project_b_page = database.scans.list_scans(project_id=project_b.id)
        empty_page = database.scans.list_scans(project_id=project_c.id)
        assert project_a_page.total == 3
        assert tuple(item.run_id for item in project_a_page.items) == (a3, a2, a1)
        assert project_b_page.total == 2
        assert tuple(item.run_id for item in project_b_page.items) == (b2, b1)
        assert empty_page.total == 0
        assert empty_page.items == ()
    finally:
        database.close()


def test_scan_list_partial_result_is_completed_without_invented_aggregates(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    try:
        with database.sessions.begin() as session:
            project = _add_project(session, 61, "Partial", _BASE)
            run_id = _add_scan(
                session,
                project_id=project.id,
                number=61,
                created_at=_BASE,
                lifecycle=OrchestrationLifecycleState.ACTIVE,
            )
            _mark_partial_scan_finalized(
                session,
                run_id=run_id,
                finalized_at=_BASE + timedelta(seconds=1),
            )

        item = database.scans.list_scans(limit=1).items[0]
        assert item.run_id == run_id
        assert item.product_status is SourceProductStatus.COMPLETED
        assert item.published_at == _BASE + timedelta(seconds=1)
        assert item.finalized_at == _BASE + timedelta(seconds=1)
        assert item.indexed is True
        assert item.lifecycle_evaluated is True
        for absent in ("finding_count", "coverage_complete", "gap_count"):
            assert not hasattr(item, absent)
    finally:
        database.close()


def test_scan_page_predecessor_query_count_is_bounded(tmp_path: Path) -> None:
    database = _database(tmp_path)
    try:
        with database.sessions.begin() as session:
            project = _add_project(session, 71, "Predecessors", _BASE)
            lineage_id = _uuid(7_001)
            predecessor: str | None = None
            for sequence in range(1, 11):
                predecessor = _add_scan(
                    session,
                    project_id=project.id,
                    number=70 + sequence,
                    created_at=_BASE + timedelta(seconds=sequence),
                    lifecycle=OrchestrationLifecycleState.ACTIVE,
                    lineage_id=lineage_id,
                    sequence_number=sequence,
                    predecessor_run_id=predecessor,
                    predecessor_sequence_number=(None if sequence == 1 else sequence - 1),
                )

        query_count = 0

        def count_query(*_args: object, **_kwargs: object) -> None:
            nonlocal query_count
            query_count += 1

        def measured(*, limit: int, project_id: str | None = None) -> int:
            nonlocal query_count
            query_count = 0
            database.scans.list_scans(project_id=project_id, limit=limit)
            return query_count

        event.listen(database.engine, "before_cursor_execute", count_query)
        try:
            assert tuple(measured(limit=limit) for limit in (1, 10, 50)) == (
                3,
                3,
                3,
            )
            assert tuple(measured(limit=limit, project_id=project.id) for limit in (1, 10, 50)) == (
                4,
                4,
                4,
            )
        finally:
            event.remove(database.engine, "before_cursor_execute", count_query)
    finally:
        database.close()


def test_scan_list_joins_are_one_to_one_by_durable_keys() -> None:
    for row_type in (
        AnalysisRunRow,
        SourceScanSubmissionRow,
        SourceOrchestrationRow,
        SourceTargetLineageRow,
        SourceLineageRunRow,
        TargetRow,
    ):
        assert len(row_type.__table__.primary_key.columns) == 1
