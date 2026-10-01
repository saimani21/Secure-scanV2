"""Real PostgreSQL acceptance for H's historical read boundary."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from securescan.product_core import (
    AnalystDisposition,
    SourceFindingGovernanceService,
    SourcePolicyService,
    SourceSecurityDeltaService,
)
from securescan.product_core.product_view import SourceFindingProductViewService
from tests.test_postgres_trusted_baseline_v12e import _promote
from tests.test_source_orchestration_s6b import _RUN_ID
from tests.test_source_product_core_pc2 import _RUN_IDS, _add_run

pytest_plugins = (
    "tests.test_postgres_effective_governance_v12d",
    "tests.test_postgres_source_governance_v12b",
    "tests.test_postgres_trusted_baseline_v12e",
)
pytestmark = pytest.mark.postgres


def test_postgres_historical_finding_is_stable_after_real_later_scan(
    postgres_effective, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = postgres_effective
    environment = context["environment"]
    lineage_id = context["lineage_id"]
    project_id = context["project_id"]
    finding_id = context["finding_id"]
    service = SourceFindingProductViewService(environment.factory, environment.store)
    first = service.list_for_run(project_id=project_id, lineage_id=lineage_id, run_id=str(_RUN_ID))
    old = next(item for item in first.items if item.finding_id == finding_id)
    assert old.lifecycle_state_at_run == "NEW"

    _add_run(context["pc2"], monkeypatch, _RUN_IDS[0], present=True, ordinal=2)
    context["lifecycle"].evaluate(lineage_id=lineage_id, run_id=_RUN_IDS[0])
    previous = service.list_for_run(
        project_id=project_id, lineage_id=lineage_id, run_id=str(_RUN_ID)
    )
    later = service.list_for_run(project_id=project_id, lineage_id=lineage_id, run_id=_RUN_IDS[0])
    assert previous == first
    assert (
        next(item for item in later.items if item.finding_id == finding_id).lifecycle_state_at_run
        == "EXISTING"
    )


def test_postgres_h_view_is_unchanged_by_current_governance_baseline_and_policy(
    postgres_baseline,
) -> None:
    environment, _baselines, project_id, lineage_id = postgres_baseline
    run_id = str(_RUN_ID)
    view = SourceFindingProductViewService(environment.factory, environment.store)
    before = view.list_for_run(project_id=project_id, lineage_id=lineage_id, run_id=run_id)
    assert before.total >= 1
    finding_id = before.items[0].finding_id

    governance = SourceFindingGovernanceService(
        environment.factory, clock=lambda: datetime(2026, 10, 3, tzinfo=UTC)
    )
    governance.mutate(
        project_id=project_id,
        lineage_id=lineage_id,
        finding_id=finding_id,
        disposition=AnalystDisposition.FALSE_POSITIVE,
        reason="H disposable current decision",
        expires_at=None,
        expected_revision=0,
    )
    assert view.list_for_run(project_id=project_id, lineage_id=lineage_id, run_id=run_id) == before

    baseline = _promote(postgres_baseline, 0)
    delta = SourceSecurityDeltaService(environment.factory, environment.store).evaluate(
        project_id=project_id, lineage_id=lineage_id, candidate_run_id=run_id
    )
    policy = SourcePolicyService(environment.factory, environment.store).evaluate(
        project_id=project_id, lineage_id=lineage_id, candidate_run_id=run_id
    )
    assert delta.baseline_id == baseline.baseline_id
    assert delta.baseline_revision == baseline.revision
    assert policy.baseline_id == baseline.baseline_id
    assert policy.baseline_revision == baseline.revision
    assert view.list_for_run(project_id=project_id, lineage_id=lineage_id, run_id=run_id) == before
