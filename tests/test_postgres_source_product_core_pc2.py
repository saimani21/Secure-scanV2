from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from postgres_test_guard import validated_postgres_test_url
from sqlalchemy import func, select

from securescan.persistence.database import (
    AnalysisRunRow,
    SourceFindingLifecycleEventRow,
    SourceFindingLifecycleRow,
    TargetRow,
)
from securescan.product_core import (
    SourceFindingIndexService,
    SourceFindingLifecycleService,
)
from tests.test_postgres_source_product_core_pc1 import _reset
from tests.test_source_orchestration_s6b import _RUN_ID, _Environment
from tests.test_source_product_core_pc1 import (
    _INDEXED_AT,
    _LINEAGE_IDS,
    _publish_environment,
)
from tests.test_source_product_core_pc2 import _PC2_TIME

pytestmark = pytest.mark.postgres


@pytest.fixture
def postgres_pc2(tmp_path: Path):
    database_url = validated_postgres_test_url()
    _reset(database_url)
    environment = _Environment(tmp_path, database_url=database_url)
    _publish_environment(environment)
    try:
        yield environment
    finally:
        environment.close()
        _reset(database_url)


def test_concurrent_lifecycle_evaluators_converge_on_one_durable_result(
    postgres_pc2: _Environment,
) -> None:
    index = SourceFindingIndexService(
        postgres_pc2.factory,
        postgres_pc2.store,
        clock=lambda: _INDEXED_AT,
        lineage_id_factory=lambda: _LINEAGE_IDS[0],
    )
    with postgres_pc2.factory() as session:
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        assert run is not None
        target = session.get(TargetRow, run.target_id)
        assert target is not None
        project_id = target.project_id
    lineage = index.create_lineage(project_id=project_id)
    index.attach_published_run(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    index.index_attached_run(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    service = SourceFindingLifecycleService(
        postgres_pc2.factory,
        postgres_pc2.store,
        clock=lambda: _PC2_TIME,
    )
    barrier = threading.Barrier(2)

    def evaluate():
        barrier.wait()
        return service.evaluate(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(lambda _value: evaluate(), range(2)))

    assert sorted(item.created for item in results) == [False, True]
    assert len({item.evaluation_sha256 for item in results}) == 1
    with postgres_pc2.factory() as session:
        assert session.scalar(select(func.count()).select_from(SourceFindingLifecycleRow)) == 1
        assert (
            session.scalar(select(func.count()).select_from(SourceFindingLifecycleEventRow))
            == 1
        )
