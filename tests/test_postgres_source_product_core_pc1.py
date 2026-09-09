from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import UUID

import pytest
from postgres_test_guard import validated_postgres_test_url
from sqlalchemy import create_engine, select, text

from securescan.persistence.database import (
    AnalysisRunRow,
    SourceFindingOccurrenceRow,
    TargetRow,
)
from securescan.product_core import ProductCoreIndexError, SourceFindingIndexService
from tests.test_source_orchestration_s6b import _RUN_ID, _Environment
from tests.test_source_product_core_pc1 import (
    _INDEXED_AT,
    _clone_published_run,
    _publish_environment,
)

pytestmark = pytest.mark.postgres


def _reset(database_url: str) -> None:
    engine = create_engine(database_url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
    finally:
        engine.dispose()


@pytest.fixture
def postgres_pc1(tmp_path: Path):
    database_url = validated_postgres_test_url()
    _reset(database_url)
    environment = _Environment(tmp_path, database_url=database_url)
    _publish_environment(environment)
    try:
        yield environment
    finally:
        environment.close()
        _reset(database_url)


def _service(environment: _Environment, lineage_uuid: str) -> SourceFindingIndexService:
    return SourceFindingIndexService(
        environment.factory,
        environment.store,
        clock=lambda: _INDEXED_AT,
        lineage_id_factory=lambda: UUID(lineage_uuid),
    )


def _project_id(environment: _Environment) -> str:
    with environment.factory() as session:
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        assert run is not None
        target = session.get(TargetRow, run.target_id)
        assert target is not None
        return target.project_id


def test_concurrent_attachments_receive_distinct_ordered_sequences(
    postgres_pc1: _Environment, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(postgres_pc1, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1")
    lineage = service.create_lineage(project_id=_project_id(postgres_pc1))
    original = service._rebuild_trusted_report(str(_RUN_ID))
    run_ids = (
        "44444444-4444-4444-8444-444444444441",
        "55555555-5555-4555-8555-555555555552",
    )
    reports = {
        run_id: _clone_published_run(postgres_pc1, original, run_id)
        for run_id in run_ids
    }
    monkeypatch.setattr(service, "_rebuild_trusted_report", reports.__getitem__)
    barrier = threading.Barrier(2)

    def attach(run_id: str):
        barrier.wait()
        return service.attach_published_run(
            lineage_id=lineage.lineage_id, run_id=run_id
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(attach, run_ids))
    ordered = sorted(results, key=lambda item: item.sequence_number)
    assert [item.sequence_number for item in ordered] == [1, 2]
    assert ordered[0].predecessor_run_id is None
    assert ordered[1].predecessor_run_id == ordered[0].run_id


def test_same_run_competing_for_two_lineages_has_one_winner(
    postgres_pc1: _Environment,
) -> None:
    ids = iter(
        (
            UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1"),
            UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2"),
        )
    )
    service = SourceFindingIndexService(
        postgres_pc1.factory,
        postgres_pc1.store,
        clock=lambda: _INDEXED_AT,
        lineage_id_factory=lambda: next(ids),
    )
    project_id = _project_id(postgres_pc1)
    lineages = (
        service.create_lineage(project_id=project_id),
        service.create_lineage(project_id=project_id),
    )
    barrier = threading.Barrier(2)

    def attach(lineage_id: str):
        barrier.wait()
        try:
            return service.attach_published_run(
                lineage_id=lineage_id, run_id=str(_RUN_ID)
            ).lineage_id
        except ProductCoreIndexError:
            return "REJECTED"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(attach, (item.lineage_id for item in lineages)))
    assert results.count("REJECTED") == 1
    assert len(set(results) - {"REJECTED"}) == 1


def test_duplicate_indexers_converge_on_one_occurrence_set(
    postgres_pc1: _Environment,
) -> None:
    service = _service(postgres_pc1, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1")
    lineage = service.create_lineage(project_id=_project_id(postgres_pc1))
    service.attach_published_run(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    barrier = threading.Barrier(2)

    def index():
        barrier.wait()
        return service.index_attached_run(
            lineage_id=lineage.lineage_id, run_id=str(_RUN_ID)
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(lambda _value: index(), range(2)))
    assert sorted(item.created for item in results) == [False, True]
    with postgres_pc1.factory() as session:
        assert len(tuple(session.scalars(select(SourceFindingOccurrenceRow)))) == 1


def test_conflicting_index_material_fails_closed(postgres_pc1: _Environment) -> None:
    service = _service(postgres_pc1, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1")
    lineage = service.create_lineage(project_id=_project_id(postgres_pc1))
    service.attach_published_run(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    service.index_attached_run(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    with postgres_pc1.factory.begin() as session:
        occurrence = session.scalar(select(SourceFindingOccurrenceRow))
        assert occurrence is not None
        occurrence.native_identity_schema = "tampered-schema"
    with pytest.raises(ProductCoreIndexError):
        service.index_attached_run(
            lineage_id=lineage.lineage_id, run_id=str(_RUN_ID)
        )
