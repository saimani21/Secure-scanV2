from __future__ import annotations

from types import SimpleNamespace
from uuid import UUID

import pytest
from fastapi import HTTPException

from securescan.api.product_view_routes import list_run_product_findings, router
from securescan.persistence.database import SourceFindingLifecycleRow
from securescan.product_core.product_view import (
    ProductViewNotFoundError,
    ProductViewUnavailableError,
    ProductViewValidationError,
    SourceFindingProductViewService,
)
from tests.test_source_orchestration_s6b import _RUN_ID
from tests.test_source_product_core_pc2 import _RUN_IDS, _add_run

pytest_plugins = ("test_source_governance_v12b", "test_source_product_core_pc2")


def test_run_product_findings_reject_tampered_current_aggregate(
    governance_context,
) -> None:
    environment, _governance, project_id, lineage_id, finding_id = governance_context
    with environment.factory() as session:
        lifecycle = session.get(SourceFindingLifecycleRow, (lineage_id, finding_id))
        assert lifecycle is not None
        run_id = lifecycle.first_seen_run_id
        original_state = lifecycle.current_state
    service = SourceFindingProductViewService(environment.factory, environment.store)
    first = service.list_for_run(project_id=project_id, lineage_id=lineage_id, run_id=run_id)
    assert first.total == 1
    assert first.items[0].finding_id == finding_id
    assert first.items[0].lifecycle_state_at_run == original_state
    assert first.items[0].lifecycle_transition_version >= 1
    assert original_state == "NEW"

    # A current aggregate edit without its immutable transition event is tampering.
    with environment.factory.begin() as session:
        lifecycle = session.get(SourceFindingLifecycleRow, (lineage_id, finding_id))
        assert lifecycle is not None
        lifecycle.current_state = "EXISTING"
    with pytest.raises(ProductViewUnavailableError):
        service.list_for_run(
            project_id=project_id,
            lineage_id=lineage_id,
            run_id=run_id,
            lifecycle_state=original_state,
        )


def test_historical_run_state_survives_real_later_transition(
    pc2_context, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment, _index, lifecycle, lineage, reports = pc2_context
    first_run = str(_RUN_ID)
    finding_id = reports[first_run].findings[0].finding_id
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=first_run)
    _add_run(pc2_context, monkeypatch, _RUN_IDS[0], present=True, ordinal=2)
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=_RUN_IDS[0])

    service = SourceFindingProductViewService(environment.factory, environment.store)
    historical = service.list_for_run(
        project_id=lineage.project_id,
        lineage_id=lineage.lineage_id,
        run_id=first_run,
        lifecycle_state="NEW",
    )
    assert any(
        item.finding_id == finding_id and item.lifecycle_state_at_run == "NEW"
        for item in historical.items
    )
    current = service.list_for_run(
        project_id=lineage.project_id,
        lineage_id=lineage.lineage_id,
        run_id=_RUN_IDS[0],
        lifecycle_state="EXISTING",
    )
    assert any(
        item.finding_id == finding_id and item.lifecycle_state_at_run == "EXISTING"
        for item in current.items
    )


def test_product_view_scope_and_bounds(governance_context) -> None:
    environment, _governance, project_id, lineage_id, finding_id = governance_context
    with environment.factory() as session:
        lifecycle = session.get(SourceFindingLifecycleRow, (lineage_id, finding_id))
        assert lifecycle is not None
        run_id = lifecycle.first_seen_run_id
    service = SourceFindingProductViewService(environment.factory, environment.store)
    with pytest.raises(ProductViewNotFoundError):
        service.list_for_run(project_id=str(UUID(int=1)), lineage_id=lineage_id, run_id=run_id)
    with pytest.raises(ProductViewValidationError):
        service.list_for_run(project_id=project_id, lineage_id=lineage_id, run_id=run_id, limit=201)
    page = service.list_for_run(
        project_id=project_id, lineage_id=lineage_id, run_id=run_id, limit=1, offset=1
    )
    assert page.total == 1 and page.items == ()


def test_product_view_route_uses_scoped_service_and_stable_errors() -> None:
    project, lineage, run = (UUID(int=value) for value in (1, 2, 3))
    calls = []

    def list_for_run(**kwargs):
        calls.append(kwargs)
        raise ProductViewNotFoundError

    with pytest.raises(HTTPException) as error:
        list_run_product_findings(project, lineage, run, SimpleNamespace(list_for_run=list_for_run))
    assert error.value.status_code == 404
    assert error.value.detail["code"] == "PRODUCT_RUN_NOT_FOUND"
    assert calls[0]["project_id"] == str(project)
    assert calls[0]["lineage_id"] == str(lineage)
    assert calls[0]["run_id"] == str(run)
    assert any(route.path.endswith("/runs/{run_id}/findings") for route in router.routes)
