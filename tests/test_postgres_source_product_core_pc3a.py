from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from postgres_test_guard import validated_postgres_test_url

from securescan.domain.enums import RunStatus
from securescan.persistence.database import AnalysisRunRow, TargetRow
from securescan.product_core import SourceScanSubmissionService
from tests.test_postgres_source_product_core_pc1 import _reset
from tests.test_source_orchestration_s6b import _NOW, _RUN_ID, _Environment
from tests.test_source_product_core_pc1 import _publish_environment

pytestmark = pytest.mark.postgres


@pytest.fixture
def postgres_pc3a(tmp_path: Path):
    database_url = validated_postgres_test_url()
    _reset(database_url)
    environment = _Environment(tmp_path, database_url=database_url)
    try:
        with environment.factory.begin() as session:
            original = session.get(AnalysisRunRow, str(_RUN_ID))
            assert original is not None
            target = session.get(TargetRow, original.target_id)
            assert target is not None
            target.source_path = environment.workspace.workspace_id
            for run_id in (
                "aaaaaaaa-2222-4222-8222-aaaaaaaaaaa1",
                "aaaaaaaa-2222-4222-8222-aaaaaaaaaaa2",
            ):
                session.add(
                    AnalysisRunRow(
                        id=run_id,
                        target_id=target.id,
                        status=RunStatus.QUEUED.value,
                        report_json=None,
                        created_at=_NOW,
                    )
                )
            project_id = target.project_id
        service = SourceScanSubmissionService(
            environment.factory,
            environment.store,
            environment.workspace_manager,
            clock=lambda: _NOW,
        )
        lineage = service.create_lineage(project_id=project_id)
        yield environment, service, lineage.lineage_id
    finally:
        environment.close()
        _reset(database_url)


def test_concurrent_submissions_reserve_distinct_lineage_order(postgres_pc3a) -> None:
    environment, service, lineage_id = postgres_pc3a
    run_ids = (
        "aaaaaaaa-2222-4222-8222-aaaaaaaaaaa1",
        "aaaaaaaa-2222-4222-8222-aaaaaaaaaaa2",
    )
    barrier = threading.Barrier(2)

    def reserve(run_id: str):
        barrier.wait()
        return service.reserve(
            run_id=run_id,
            lineage_id=lineage_id,
            intake_ref=environment.workspace.workspace_id,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(reserve, run_ids))

    ordered = sorted(results, key=lambda item: item.submission_sequence_number)
    assert [item.submission_sequence_number for item in ordered] == [1, 2]
    assert ordered[0].predecessor_run_id is None
    assert ordered[1].predecessor_run_id == ordered[0].run_id


def test_duplicate_finalizers_converge(postgres_pc3a) -> None:
    environment, service, lineage_id = postgres_pc3a
    _publish_environment(environment)
    service.reserve(
        run_id=str(_RUN_ID),
        lineage_id=lineage_id,
        intake_ref=environment.workspace.workspace_id,
    )
    barrier = threading.Barrier(2)

    def finalize(_value: int):
        barrier.wait()
        return service.finalize(run_id=str(_RUN_ID))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(finalize, range(2)))

    assert results[0] == results[1]
    assert results[0].finalized_at is not None
