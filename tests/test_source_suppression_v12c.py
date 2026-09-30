from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import func, select

from securescan.persistence.database import (
    AnalysisRunRow,
    SourceFindingGovernanceRow,
    SourceFindingLifecycleRow,
    SourceFindingSuppressionEventRow,
    SourceFindingSuppressionRow,
    TargetRow,
)
from securescan.product_core import (
    AnalystDisposition,
    FindingSuppressionConflictError,
    FindingSuppressionNotFoundError,
    FindingSuppressionStateError,
    FindingSuppressionValidationError,
    SourceFindingGovernanceService,
    SourceFindingIndexService,
    SourceFindingLifecycleService,
    SourceFindingSuppressionService,
    SuppressionOperation,
)
from tests.test_source_orchestration_s6b import _RUN_ID, _Environment
from tests.test_source_product_core_pc1 import _INDEXED_AT, _LINEAGE_IDS, _publish_environment
from tests.test_source_product_core_pc2 import _PC2_TIME

_NOW = datetime(2026, 9, 29, 12, tzinfo=UTC)
_SUPPRESSION_IDS = (
    UUID("cccccccc-cccc-4ccc-8ccc-ccccccccccc1"),
    UUID("cccccccc-cccc-4ccc-8ccc-ccccccccccc2"),
    UUID("cccccccc-cccc-4ccc-8ccc-ccccccccccc3"),
)
_EVENT_IDS = tuple(
    UUID(f"dddddddd-dddd-4ddd-8ddd-ddddddddddd{index}") for index in range(1, 9)
)


class _Clock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


@pytest.fixture
def suppression_context(tmp_path: Path):
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
    clock = _Clock(_NOW)
    suppression_ids = iter(_SUPPRESSION_IDS)
    event_ids = iter(_EVENT_IDS)
    service = SourceFindingSuppressionService(
        environment.factory,
        clock=clock,
        suppression_id_factory=lambda: next(suppression_ids),
        event_id_factory=lambda: next(event_ids),
    )
    try:
        yield environment, service, clock, project_id, lineage.lineage_id, finding_id
    finally:
        environment.close()


def _get(context):
    _environment, service, _clock, project_id, lineage_id, finding_id = context
    return service.get(project_id=project_id, lineage_id=lineage_id, finding_id=finding_id)


def _suppress(context, **changes):
    _environment, service, _clock, project_id, lineage_id, finding_id = context
    values = {
        "project_id": project_id,
        "lineage_id": lineage_id,
        "finding_id": finding_id,
        "reason": "temporary local exception",
        "expires_at": _NOW + timedelta(days=7),
        "expected_revision": 0,
    }
    values.update(changes)
    return service.suppress(**values)


def _revoke(context, *, expected_revision):
    _environment, service, _clock, project_id, lineage_id, finding_id = context
    return service.revoke(
        project_id=project_id,
        lineage_id=lineage_id,
        finding_id=finding_id,
        expected_revision=expected_revision,
    )


def test_absent_create_update_revoke_and_ordered_audit(suppression_context) -> None:
    initial = _get(suppression_context)
    assert initial.active is False
    assert initial.suppression_id is None and initial.revision == 0

    hostile = '<script>alert("x")</script>\n\x1b[31mnot markup'
    created = _suppress(suppression_context, reason=hostile)
    assert created.active is True
    assert created.suppression_id == str(_SUPPRESSION_IDS[0])
    assert created.reason == hostile and created.revision == 1

    updated = _suppress(
        suppression_context,
        reason="updated reason",
        expires_at=_NOW + timedelta(days=3),
        expected_revision=1,
    )
    assert updated.suppression_id == created.suppression_id
    assert updated.revision == 2 and updated.active is True

    revoked = _revoke(suppression_context, expected_revision=2)
    assert revoked.suppression_id == created.suppression_id
    assert revoked.revision == 3 and revoked.active is False
    assert revoked.revoked_at == _NOW

    _environment, service, _clock, project_id, lineage_id, finding_id = suppression_context
    page = service.list_events(
        project_id=project_id, lineage_id=lineage_id, finding_id=finding_id
    )
    assert page.total == 3
    assert [item.operation for item in page.items] == [
        SuppressionOperation.CREATE,
        SuppressionOperation.UPDATE,
        SuppressionOperation.REVOKE,
    ]
    assert [item.resulting_revision for item in page.items] == [1, 2, 3]
    assert [item.lifecycle_transition_version for item in page.items] == [1, 1, 1]
    assert page.items[0].new_reason == hostile


def test_expiry_is_derived_without_database_mutation(suppression_context) -> None:
    expires_at = _NOW + timedelta(hours=1)
    created = _suppress(suppression_context, expires_at=expires_at)
    assert created.active is True
    environment, service, clock, project_id, lineage_id, finding_id = suppression_context
    with environment.factory() as session:
        before = session.get(SourceFindingSuppressionRow, (lineage_id, finding_id))
        assert before is not None
        before_updated_at = before.updated_at

    clock.value = expires_at
    at_expiry = service.get(
        project_id=project_id, lineage_id=lineage_id, finding_id=finding_id
    )
    assert at_expiry.active is False
    assert at_expiry.revision == 1 and at_expiry.revoked_at is None
    with environment.factory() as session:
        after = session.get(SourceFindingSuppressionRow, (lineage_id, finding_id))
        assert after is not None and after.updated_at == before_updated_at
        assert (
            session.scalar(select(func.count()).select_from(SourceFindingSuppressionEventRow)) == 1
        )


def test_reason_expiry_and_revision_validation(suppression_context) -> None:
    for reason in (None, "", " ", "x" * 1001):
        with pytest.raises(FindingSuppressionValidationError):
            _suppress(suppression_context, reason=reason)
    for expires_at in (None, datetime(2026, 10, 1), _NOW, _NOW - timedelta(seconds=1)):
        with pytest.raises(FindingSuppressionValidationError):
            _suppress(suppression_context, expires_at=expires_at)
    for revision in (-1, True, "0"):
        with pytest.raises(FindingSuppressionValidationError):
            _suppress(suppression_context, expected_revision=revision)


def test_revoke_conflicts_do_not_append_events(suppression_context) -> None:
    with pytest.raises(FindingSuppressionStateError):
        _revoke(suppression_context, expected_revision=0)
    _suppress(suppression_context)
    with pytest.raises(FindingSuppressionConflictError):
        _revoke(suppression_context, expected_revision=0)
    _revoke(suppression_context, expected_revision=1)
    with pytest.raises(FindingSuppressionStateError):
        _revoke(suppression_context, expected_revision=2)
    _environment, service, _clock, project_id, lineage_id, finding_id = suppression_context
    assert service.list_events(
        project_id=project_id, lineage_id=lineage_id, finding_id=finding_id
    ).total == 2


def test_new_episodes_after_revocation_and_expiry_receive_new_ids(
    suppression_context,
) -> None:
    first = _suppress(suppression_context)
    _revoke(suppression_context, expected_revision=1)
    second = _suppress(suppression_context, expected_revision=2)
    assert second.suppression_id != first.suppression_id
    assert second.revision == 3 and second.active is True

    _environment, _service, clock, _project_id, _lineage_id, _finding_id = suppression_context
    clock.value = second.expires_at
    third = _suppress(
        suppression_context,
        expires_at=clock.value + timedelta(days=1),
        expected_revision=3,
    )
    assert third.suppression_id not in {first.suppression_id, second.suppression_id}
    assert third.revision == 4 and third.active is True


def test_event_failure_rolls_back_current_suppression(suppression_context) -> None:
    environment, _service, _clock, project_id, lineage_id, finding_id = suppression_context
    duplicate_event = UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
    service = SourceFindingSuppressionService(
        environment.factory,
        clock=lambda: _NOW,
        suppression_id_factory=lambda: UUID("ffffffff-ffff-4fff-8fff-ffffffffffff"),
        event_id_factory=lambda: duplicate_event,
    )
    first = service.suppress(
        project_id=project_id,
        lineage_id=lineage_id,
        finding_id=finding_id,
        reason="first",
        expires_at=_NOW + timedelta(days=1),
        expected_revision=0,
    )
    with pytest.raises(FindingSuppressionConflictError):
        service.suppress(
            project_id=project_id,
            lineage_id=lineage_id,
            finding_id=finding_id,
            reason="must roll back",
            expires_at=_NOW + timedelta(days=2),
            expected_revision=1,
        )
    state = service.get(project_id=project_id, lineage_id=lineage_id, finding_id=finding_id)
    assert state.reason == "first" and state.revision == 1
    assert state.suppression_id == first.suppression_id
    with environment.factory() as session:
        assert session.scalar(select(func.count()).select_from(SourceFindingSuppressionRow)) == 1
        assert (
            session.scalar(select(func.count()).select_from(SourceFindingSuppressionEventRow)) == 1
        )


def test_unknown_scope_and_malformed_identity_are_rejected(suppression_context) -> None:
    _environment, service, _clock, project_id, lineage_id, finding_id = suppression_context
    for values in (
        {"project_id": "99999999-9999-4999-8999-999999999999"},
        {"lineage_id": "99999999-9999-4999-8999-999999999999"},
        {"finding_id": "f" * 64},
    ):
        request = {"project_id": project_id, "lineage_id": lineage_id, "finding_id": finding_id}
        request.update(values)
        with pytest.raises(FindingSuppressionNotFoundError):
            service.get(**request)
    for values in ({"lineage_id": "not-a-uuid"}, {"finding_id": "not-a-finding"}):
        request = {"project_id": project_id, "lineage_id": lineage_id, "finding_id": finding_id}
        request.update(values)
        with pytest.raises(FindingSuppressionValidationError):
            service.get(**request)


def test_suppression_does_not_mutate_lifecycle_or_disposition(suppression_context) -> None:
    environment, _service, _clock, project_id, lineage_id, finding_id = suppression_context
    governance = SourceFindingGovernanceService(environment.factory, clock=lambda: _NOW)
    disposition = governance.mutate(
        project_id=project_id,
        lineage_id=lineage_id,
        finding_id=finding_id,
        disposition=AnalystDisposition.FALSE_POSITIVE,
        reason="independent analyst disposition",
        expires_at=None,
        expected_revision=0,
    )
    with environment.factory() as session:
        lifecycle_before = session.get(SourceFindingLifecycleRow, (lineage_id, finding_id))
        governance_before = session.get(SourceFindingGovernanceRow, (lineage_id, finding_id))
        assert lifecycle_before is not None and governance_before is not None
        lifecycle_material = (
            lifecycle_before.current_state,
            lifecycle_before.transition_version,
            lifecycle_before.last_seen_run_id,
        )
        governance_material = (
            governance_before.disposition,
            governance_before.reason,
            governance_before.revision,
        )

    _suppress(suppression_context)
    with environment.factory() as session:
        lifecycle_after = session.get(SourceFindingLifecycleRow, (lineage_id, finding_id))
        governance_after = session.get(SourceFindingGovernanceRow, (lineage_id, finding_id))
        assert lifecycle_after is not None and governance_after is not None
        assert (
            lifecycle_after.current_state,
            lifecycle_after.transition_version,
            lifecycle_after.last_seen_run_id,
        ) == lifecycle_material
        assert (
            governance_after.disposition,
            governance_after.reason,
            governance_after.revision,
        ) == governance_material
    assert disposition.disposition is AnalystDisposition.FALSE_POSITIVE
