from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from securescan.persistence.database import (
    AnalysisRunRow,
    ProjectRow,
    SourceFindingLifecycleRow,
    SourceFindingSuppressionEventRow,
    SourceFindingSuppressionRow,
    SourceLineageRunRow,
    SourceTargetLineageRow,
    TargetRow,
)
from securescan.product_core import (
    FindingSuppressionConflictError,
    SourceFindingSuppressionService,
)
from tests.test_source_suppression_v12c import _NOW, _Clock

pytestmark = pytest.mark.postgres
pytest_plugins = ("tests.test_postgres_source_governance_v12b",)


@pytest.fixture
def postgres_suppression(postgres_governance):
    environment, _governance, project_id, lineage_id, finding_id = postgres_governance
    clock = _Clock(_NOW)
    service = SourceFindingSuppressionService(environment.factory, clock=clock)
    return environment, service, clock, project_id, lineage_id, finding_id


def _suppress_attempt(context, barrier, *, reason, expires_at, expected_revision):
    _environment, service, _clock, project_id, lineage_id, finding_id = context
    barrier.wait()
    try:
        state = service.suppress(
            project_id=project_id,
            lineage_id=lineage_id,
            finding_id=finding_id,
            reason=reason,
            expires_at=expires_at,
            expected_revision=expected_revision,
        )
        return "SUCCESS", state.revision, state.suppression_id
    except FindingSuppressionConflictError:
        return "CONFLICT", None, None


def test_concurrent_first_and_active_suppression_writes_converge(
    postgres_suppression,
) -> None:
    for expected_revision in (0, 1):
        barrier = threading.Barrier(2)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = tuple(
                pool.map(
                    lambda reason, barrier=barrier, revision=expected_revision: _suppress_attempt(
                        postgres_suppression,
                        barrier,
                        reason=reason,
                        expires_at=_NOW + timedelta(days=revision + 2),
                        expected_revision=revision,
                    ),
                    (f"writer-a-{expected_revision}", f"writer-b-{expected_revision}"),
                )
            )
        assert sorted(item[0] for item in results) == ["CONFLICT", "SUCCESS"]

    environment, service, _clock, project_id, lineage_id, finding_id = postgres_suppression
    state = service.get(project_id=project_id, lineage_id=lineage_id, finding_id=finding_id)
    assert state.revision == 2 and state.active is True
    successful_ids = [item[2] for item in results if item[0] == "SUCCESS"]
    assert successful_ids == [state.suppression_id]
    with environment.factory() as session:
        assert session.scalar(select(func.count()).select_from(SourceFindingSuppressionRow)) == 1
        assert (
            session.scalar(select(func.count()).select_from(SourceFindingSuppressionEventRow)) == 2
        )


def test_concurrent_new_episode_after_expiry_gets_one_new_id(
    postgres_suppression,
) -> None:
    _environment, service, clock, project_id, lineage_id, finding_id = postgres_suppression
    first = service.suppress(
        project_id=project_id,
        lineage_id=lineage_id,
        finding_id=finding_id,
        reason="first episode",
        expires_at=_NOW + timedelta(hours=1),
        expected_revision=0,
    )
    clock.value = _NOW + timedelta(hours=2)
    barrier = threading.Barrier(2)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(
            pool.map(
                lambda reason: _suppress_attempt(
                    postgres_suppression,
                    barrier,
                    reason=reason,
                    expires_at=clock.value + timedelta(days=1),
                    expected_revision=1,
                ),
                ("new episode a", "new episode b"),
            )
        )
    assert sorted(item[0] for item in results) == ["CONFLICT", "SUCCESS"]
    winner = next(item for item in results if item[0] == "SUCCESS")
    assert winner[2] != first.suppression_id
    state = service.get(project_id=project_id, lineage_id=lineage_id, finding_id=finding_id)
    assert state.revision == 2 and state.suppression_id == winner[2]


def test_concurrent_revoke_and_modify_have_one_winner(postgres_suppression) -> None:
    environment, service, _clock, project_id, lineage_id, finding_id = postgres_suppression
    service.suppress(
        project_id=project_id,
        lineage_id=lineage_id,
        finding_id=finding_id,
        reason="initial",
        expires_at=_NOW + timedelta(days=1),
        expected_revision=0,
    )
    barrier = threading.Barrier(2)

    def revoke():
        barrier.wait()
        try:
            state = service.revoke(
                project_id=project_id,
                lineage_id=lineage_id,
                finding_id=finding_id,
                expected_revision=1,
            )
            return "SUCCESS", state.revision
        except FindingSuppressionConflictError:
            return "CONFLICT", None

    def modify():
        barrier.wait()
        try:
            state = service.suppress(
                project_id=project_id,
                lineage_id=lineage_id,
                finding_id=finding_id,
                reason="modified",
                expires_at=_NOW + timedelta(days=2),
                expected_revision=1,
            )
            return "SUCCESS", state.revision
        except FindingSuppressionConflictError:
            return "CONFLICT", None

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = (pool.submit(revoke), pool.submit(modify))
        results = tuple(future.result() for future in futures)
    assert sorted(item[0] for item in results) == ["CONFLICT", "SUCCESS"]
    state = service.get(project_id=project_id, lineage_id=lineage_id, finding_id=finding_id)
    assert state.revision == 2
    with environment.factory() as session:
        assert (
            session.scalar(select(func.count()).select_from(SourceFindingSuppressionEventRow)) == 2
        )


def test_new_episode_after_revocation_and_stale_revoke(postgres_suppression) -> None:
    _environment, service, _clock, project_id, lineage_id, finding_id = postgres_suppression
    first = service.suppress(
        project_id=project_id,
        lineage_id=lineage_id,
        finding_id=finding_id,
        reason="first",
        expires_at=_NOW + timedelta(days=1),
        expected_revision=0,
    )
    service.revoke(
        project_id=project_id,
        lineage_id=lineage_id,
        finding_id=finding_id,
        expected_revision=1,
    )
    with pytest.raises(FindingSuppressionConflictError):
        service.revoke(
            project_id=project_id,
            lineage_id=lineage_id,
            finding_id=finding_id,
            expected_revision=1,
        )
    second = service.suppress(
        project_id=project_id,
        lineage_id=lineage_id,
        finding_id=finding_id,
        reason="second",
        expires_at=_NOW + timedelta(days=2),
        expected_revision=2,
    )
    assert second.revision == 3
    assert second.suppression_id != first.suppression_id


def test_same_finding_id_isolated_across_projects_and_lineages(
    postgres_suppression,
) -> None:
    environment, service, _clock, project_a, lineage_a, finding_id = postgres_suppression
    project_b = "88888888-8888-4888-8888-888888888881"
    target_b = "88888888-8888-4888-8888-888888888882"
    run_b = "88888888-8888-4888-8888-888888888883"
    lineage_b = "88888888-8888-4888-8888-888888888884"
    with environment.factory.begin() as session:
        original = session.get(SourceFindingLifecycleRow, (lineage_a, finding_id))
        assert original is not None
        session.add(ProjectRow(id=project_b, name="isolated-suppression-project", created_at=_NOW))
        session.flush()
        session.add(
            TargetRow(
                id=target_b,
                project_id=project_b,
                target_type="source_repository",
                content_digest="7" * 64,
                source_path="securescan-suppression-isolated",
                metadata_json={},
                created_at=_NOW,
            )
        )
        session.flush()
        session.add(
            AnalysisRunRow(
                id=run_b,
                target_id=target_b,
                status="completed",
                report_json={},
                created_at=_NOW,
            )
        )
        session.flush()
        session.add(
            SourceTargetLineageRow(lineage_id=lineage_b, project_id=project_b, created_at=_NOW)
        )
        session.flush()
        session.add(
            SourceLineageRunRow(
                run_id=run_b,
                lineage_id=lineage_b,
                sequence_number=1,
                predecessor_run_id=None,
                predecessor_sequence_number=None,
                report_artifact_sha256="7" * 64,
                report_artifact_size_bytes=1,
                report_schema_version="securescan-unified-evidence-s4-v1",
                indexing_state="INDEXED",
                indexed_at=_NOW,
                lifecycle_evaluated_at=_NOW,
                lifecycle_evaluation_sha256="6" * 64,
                lifecycle_event_count=1,
                created_at=_NOW,
            )
        )
        session.flush()
        session.add(
            SourceFindingLifecycleRow(
                lineage_id=lineage_b,
                finding_id=finding_id,
                authority=original.authority,
                category=original.category,
                native_identity_schema=original.native_identity_schema,
                current_state="NEW",
                first_seen_run_id=run_b,
                last_seen_run_id=run_b,
                resolved_run_id=None,
                first_seen_at=_NOW,
                last_seen_at=_NOW,
                resolved_at=None,
                transition_version=1,
            )
        )
    service.suppress(
        project_id=project_a,
        lineage_id=lineage_a,
        finding_id=finding_id,
        reason="project A only",
        expires_at=_NOW + timedelta(days=1),
        expected_revision=0,
    )
    isolated = service.get(project_id=project_b, lineage_id=lineage_b, finding_id=finding_id)
    assert isolated.active is False
    assert isolated.suppression_id is None and isolated.revision == 0
