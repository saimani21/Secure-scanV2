from __future__ import annotations

import pytest
from test_source_orchestration_s6b import _RUN_ID

from securescan.product_core.guidance import (
    FindingGuidanceNotFoundError,
    FindingGuidanceService,
    GuidanceBasis,
)
from tests.test_guidance_v12g import _database_snapshot, _serialized
from tests.test_postgres_source_product_core_pc1 import (
    _project_id,
    _service,
    postgres_pc1,  # noqa: F401
)

pytestmark = pytest.mark.postgres


def test_postgres_guidance_uses_verified_run_without_writes(postgres_pc1) -> None:  # noqa: F811
    index = _service(postgres_pc1, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1")
    project_id = _project_id(postgres_pc1)
    lineage = index.create_lineage(project_id=project_id)
    index.attach_published_run(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    index.index_attached_run(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    finding = index.load_verified_published_report(run_id=str(_RUN_ID)).findings[0]
    service = FindingGuidanceService(postgres_pc1.factory, postgres_pc1.store)
    before = _database_snapshot(postgres_pc1)
    guidance = service.get_for_run(
        project_id=project_id,
        lineage_id=lineage.lineage_id,
        run_id=str(_RUN_ID),
        finding_id=finding.finding_id,
    )
    assert guidance.basis_level is GuidanceBasis.FAMILY
    assert _serialized(guidance) == _serialized(
        FindingGuidanceService(postgres_pc1.factory, postgres_pc1.store).get_for_run(
            project_id=project_id,
            lineage_id=lineage.lineage_id,
            run_id=str(_RUN_ID),
            finding_id=finding.finding_id,
        )
    )
    with pytest.raises(FindingGuidanceNotFoundError):
        service.get_for_run(
            project_id="99999999-9999-4999-8999-999999999999",
            lineage_id=lineage.lineage_id,
            run_id=str(_RUN_ID),
            finding_id=finding.finding_id,
        )
    assert _database_snapshot(postgres_pc1) == before
