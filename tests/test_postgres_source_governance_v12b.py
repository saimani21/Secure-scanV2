from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from postgres_test_guard import validated_postgres_test_url
from sqlalchemy import func, select

from securescan.persistence.database import (
    AnalysisRunRow,
    ProjectRow,
    SourceFindingGovernanceEventRow,
    SourceFindingGovernanceRow,
    SourceFindingLifecycleRow,
    SourceLineageRunRow,
    SourceTargetLineageRow,
    TargetRow,
)
from securescan.product_core import (
    AnalystDisposition,
    FindingGovernanceConflictError,
    SourceFindingGovernanceService,
    SourceFindingIndexService,
    SourceFindingLifecycleService,
)
from tests.test_postgres_source_product_core_pc1 import _reset
from tests.test_source_governance_v12b import _NOW
from tests.test_source_orchestration_s6b import _RUN_ID, _Environment
from tests.test_source_product_core_pc1 import _INDEXED_AT, _LINEAGE_IDS, _publish_environment
from tests.test_source_product_core_pc2 import _PC2_TIME

pytestmark = pytest.mark.postgres


@pytest.fixture
def postgres_governance(tmp_path: Path):
    database_url = validated_postgres_test_url()
    _reset(database_url)
    environment = _Environment(tmp_path, database_url=database_url)
    _publish_environment(environment)
    index = SourceFindingIndexService(
        environment.factory,
        environment.store,
        clock=lambda: _INDEXED_AT,
        lineage_id_factory=lambda: _LINEAGE_IDS[0],
    )
    with environment.factory() as session:
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        assert run is not None
        target = session.get(TargetRow, run.target_id)
        assert target is not None
        project_id = target.project_id
    lineage = index.create_lineage(project_id=project_id)
    index.attach_published_run(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    index.index_attached_run(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    lifecycle = SourceFindingLifecycleService(
        environment.factory, environment.store, clock=lambda: _PC2_TIME
    )
    report = lifecycle._trusted_report(str(_RUN_ID))
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    finding_id = report.findings[0].finding_id
    service = SourceFindingGovernanceService(environment.factory, clock=lambda: _NOW)
    try:
        yield environment, service, project_id, lineage.lineage_id, finding_id
    finally:
        environment.close()
        _reset(database_url)


def _attempt(context, barrier, *, reason, expected_revision):
    _environment, service, project_id, lineage_id, finding_id = context
    barrier.wait()
    try:
        result = service.mutate(
            project_id=project_id,
            lineage_id=lineage_id,
            finding_id=finding_id,
            disposition=AnalystDisposition.FALSE_POSITIVE,
            reason=reason,
            expires_at=None,
            expected_revision=expected_revision,
        )
        return ("SUCCESS", result.revision)
    except FindingGovernanceConflictError:
        return ("CONFLICT", None)


def test_concurrent_initial_and_same_revision_writes_converge(postgres_governance) -> None:
    for expected_revision in (0, 1):
        barrier = threading.Barrier(2)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = tuple(
                pool.map(
                    lambda reason, barrier=barrier, revision=expected_revision: _attempt(
                        postgres_governance,
                        barrier,
                        reason=reason,
                        expected_revision=revision,
                    ),
                    (f"writer-a-{expected_revision}", f"writer-b-{expected_revision}"),
                )
            )
        assert sorted(item[0] for item in results) == ["CONFLICT", "SUCCESS"]
    environment, service, project_id, lineage_id, finding_id = postgres_governance
    state = service.get(project_id=project_id, lineage_id=lineage_id, finding_id=finding_id)
    assert state.revision == 2
    with environment.factory() as session:
        assert session.scalar(select(func.count()).select_from(SourceFindingGovernanceRow)) == 1
        assert (
            session.scalar(select(func.count()).select_from(SourceFindingGovernanceEventRow)) == 2
        )


def test_same_finding_id_isolated_across_projects_and_lineages(
    postgres_governance,
) -> None:
    environment, service, project_a, lineage_a, finding_id = postgres_governance
    project_b = "99999999-9999-4999-8999-999999999991"
    target_b = "99999999-9999-4999-8999-999999999992"
    run_b = "99999999-9999-4999-8999-999999999993"
    lineage_b = "99999999-9999-4999-8999-999999999994"
    with environment.factory.begin() as session:
        original = session.get(SourceFindingLifecycleRow, (lineage_a, finding_id))
        assert original is not None
        session.add(ProjectRow(id=project_b, name="isolated-project", created_at=_NOW))
        session.flush()
        session.add(
            TargetRow(
                id=target_b,
                project_id=project_b,
                target_type="source_repository",
                content_digest="9" * 64,
                source_path="securescan-workspace-isolated",
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
                report_artifact_sha256="9" * 64,
                report_artifact_size_bytes=1,
                report_schema_version="securescan-unified-evidence-s4-v1",
                indexing_state="INDEXED",
                indexed_at=_NOW,
                lifecycle_evaluated_at=_NOW,
                lifecycle_evaluation_sha256="8" * 64,
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
    service.mutate(
        project_id=project_a,
        lineage_id=lineage_a,
        finding_id=finding_id,
        disposition=AnalystDisposition.FALSE_POSITIVE,
        reason="project A only",
        expires_at=None,
        expected_revision=0,
    )
    isolated = service.get(project_id=project_b, lineage_id=lineage_b, finding_id=finding_id)
    assert isolated.disposition is AnalystDisposition.UNREVIEWED
    assert isolated.revision == 0
