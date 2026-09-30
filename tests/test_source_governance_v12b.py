from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import func, select

from securescan.persistence.database import (
    AnalysisRunRow,
    SourceFindingGovernanceEventRow,
    SourceFindingGovernanceRow,
    TargetRow,
)
from securescan.product_core import (
    AnalystDisposition,
    FindingGovernanceConflictError,
    FindingGovernanceNotFoundError,
    FindingGovernanceValidationError,
    SourceFindingGovernanceService,
    SourceFindingIndexService,
    SourceFindingLifecycleService,
)
from tests.test_source_orchestration_s6b import _RUN_ID, _Environment
from tests.test_source_product_core_pc1 import _INDEXED_AT, _LINEAGE_IDS, _publish_environment
from tests.test_source_product_core_pc2 import _PC2_TIME

_NOW = datetime(2026, 9, 29, 12, tzinfo=UTC)
_EVENT_IDS = (
    UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1"),
    UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee2"),
    UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee3"),
)


@pytest.fixture
def governance_context(tmp_path: Path):
    environment = _Environment(tmp_path)
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
    event_ids = iter(_EVENT_IDS)
    service = SourceFindingGovernanceService(
        environment.factory,
        clock=lambda: _NOW,
        event_id_factory=lambda: next(event_ids),
    )
    try:
        yield environment, service, project_id, lineage.lineage_id, finding_id
    finally:
        environment.close()


def _get(context):
    _environment, service, project_id, lineage_id, finding_id = context
    return service.get(project_id=project_id, lineage_id=lineage_id, finding_id=finding_id)


def _mutate(context, **changes):
    _environment, service, project_id, lineage_id, finding_id = context
    values = {
        "project_id": project_id,
        "lineage_id": lineage_id,
        "finding_id": finding_id,
        "disposition": AnalystDisposition.FALSE_POSITIVE,
        "reason": "reviewed locally",
        "expires_at": None,
        "expected_revision": 0,
    }
    values.update(changes)
    return service.mutate(**values)


def test_default_false_positive_clear_and_ordered_audit(governance_context) -> None:
    initial = _get(governance_context)
    assert initial.disposition is AnalystDisposition.UNREVIEWED
    assert initial.revision == 0 and initial.created_at is None

    hostile = '<script>alert("x")</script>\n\x1b[31mnot markup'
    first = _mutate(governance_context, reason=hostile)
    assert first.disposition is AnalystDisposition.FALSE_POSITIVE
    assert first.reason == hostile and first.revision == 1

    cleared = _mutate(
        governance_context,
        disposition=AnalystDisposition.UNREVIEWED,
        reason=None,
        expected_revision=1,
    )
    assert cleared.disposition is AnalystDisposition.UNREVIEWED
    assert cleared.reason is None and cleared.revision == 2

    _environment, service, project_id, lineage_id, finding_id = governance_context
    page = service.list_events(project_id=project_id, lineage_id=lineage_id, finding_id=finding_id)
    assert page.total == 2
    assert [item.resulting_revision for item in page.items] == [1, 2]
    assert [item.lifecycle_transition_version for item in page.items] == [1, 1]
    assert page.items[0].new_reason == hostile
    assert page.items[1].previous_reason == hostile


def test_accepted_risk_requires_reason_future_expiry_and_can_clear(
    governance_context,
) -> None:
    expiry = _NOW + timedelta(days=7)
    accepted = _mutate(
        governance_context,
        disposition=AnalystDisposition.ACCEPTED_RISK,
        reason="temporary local acceptance",
        expires_at=expiry,
    )
    assert accepted.disposition is AnalystDisposition.ACCEPTED_RISK
    assert accepted.expires_at == expiry and accepted.revision == 1
    cleared = _mutate(
        governance_context,
        disposition=AnalystDisposition.UNREVIEWED,
        reason=None,
        expires_at=None,
        expected_revision=1,
    )
    assert cleared.disposition is AnalystDisposition.UNREVIEWED

    for reason, expires_at in ((None, expiry), ("reason", None), ("reason", _NOW)):
        with pytest.raises(FindingGovernanceValidationError):
            _mutate(
                governance_context,
                disposition=AnalystDisposition.ACCEPTED_RISK,
                reason=reason,
                expires_at=expires_at,
                expected_revision=2,
            )


def test_reason_bounds_and_false_positive_material(governance_context) -> None:
    for reason in (None, "", " ", "x" * 1001):
        with pytest.raises(FindingGovernanceValidationError):
            _mutate(governance_context, reason=reason)
    with pytest.raises(FindingGovernanceValidationError):
        _mutate(governance_context, expires_at=_NOW + timedelta(days=1))


def test_stale_revision_conflicts_without_extra_event(governance_context) -> None:
    _mutate(governance_context)
    with pytest.raises(FindingGovernanceConflictError):
        _mutate(governance_context, reason="stale", expected_revision=0)
    environment, service, project_id, lineage_id, finding_id = governance_context
    assert _get(governance_context).revision == 1
    assert (
        service.list_events(
            project_id=project_id, lineage_id=lineage_id, finding_id=finding_id
        ).total
        == 1
    )
    with environment.factory() as session:
        assert (
            session.scalar(select(func.count()).select_from(SourceFindingGovernanceEventRow)) == 1
        )


def test_event_failure_rolls_back_current_state(governance_context) -> None:
    environment, _service, project_id, lineage_id, finding_id = governance_context
    duplicate_id = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
    service = SourceFindingGovernanceService(
        environment.factory, clock=lambda: _NOW, event_id_factory=lambda: duplicate_id
    )
    service.mutate(
        project_id=project_id,
        lineage_id=lineage_id,
        finding_id=finding_id,
        disposition=AnalystDisposition.FALSE_POSITIVE,
        reason="first",
        expires_at=None,
        expected_revision=0,
    )
    with pytest.raises(FindingGovernanceConflictError):
        service.mutate(
            project_id=project_id,
            lineage_id=lineage_id,
            finding_id=finding_id,
            disposition=AnalystDisposition.FALSE_POSITIVE,
            reason="must roll back",
            expires_at=None,
            expected_revision=1,
        )
    state = service.get(project_id=project_id, lineage_id=lineage_id, finding_id=finding_id)
    assert state.reason == "first" and state.revision == 1
    with environment.factory() as session:
        assert session.scalar(select(func.count()).select_from(SourceFindingGovernanceRow)) == 1
        assert (
            session.scalar(select(func.count()).select_from(SourceFindingGovernanceEventRow)) == 1
        )


def test_wrong_project_lineage_unknown_and_malformed_identity_rejected(
    governance_context,
) -> None:
    _environment, service, project_id, lineage_id, finding_id = governance_context
    for values in (
        {"project_id": "99999999-9999-4999-8999-999999999999"},
        {"lineage_id": "99999999-9999-4999-8999-999999999999"},
        {"finding_id": "f" * 64},
    ):
        request = {"project_id": project_id, "lineage_id": lineage_id, "finding_id": finding_id}
        request.update(values)
        with pytest.raises(FindingGovernanceNotFoundError):
            service.get(**request)
    for values in (
        {"lineage_id": "not-a-uuid"},
        {"finding_id": "not-a-finding"},
    ):
        request = {"project_id": project_id, "lineage_id": lineage_id, "finding_id": finding_id}
        request.update(values)
        with pytest.raises(FindingGovernanceValidationError):
            service.get(**request)
