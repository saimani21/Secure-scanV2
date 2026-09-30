from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import event, func, select

from securescan.persistence.database import (
    SourceFindingGovernanceEventRow,
    SourceFindingGovernanceRow,
    SourceFindingLifecycleEventRow,
    SourceFindingSuppressionEventRow,
    SourceFindingSuppressionRow,
    SourceTargetLineageRow,
)
from securescan.product_core import (
    AnalystDisposition,
    EffectiveGovernanceNotFoundError,
    EffectiveGovernanceReasonCode,
    EffectiveGovernanceService,
    EffectiveGovernanceValidationError,
    FindingLifecycleState,
    SourceFindingGovernanceService,
    SourceFindingSuppressionService,
)
from tests.test_source_product_core_pc1 import _INDEXED_AT
from tests.test_source_product_core_pc2 import _RUN_IDS, _add_run

pytest_plugins = ("tests.test_source_product_core_pc2",)

_NOW = datetime(2026, 10, 1, 12, tzinfo=UTC)
_SECOND_RESOLVED_RUN = "55555555-5555-4555-8555-555555555555"
_SECOND_REOPENED_RUN = "66666666-6666-4666-8666-666666666666"


class _Clock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


@pytest.fixture
def effective_context(pc2_context):
    environment, _index, lifecycle, lineage, reports = pc2_context
    first_run_id = next(iter(reports))
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=first_run_id)
    finding_id = reports[first_run_id].findings[0].finding_id
    with environment.factory() as session:
        lineage_row = session.get(SourceTargetLineageRow, lineage.lineage_id)
        assert lineage_row is not None
        project_id = lineage_row.project_id
    clock = _Clock(_NOW)
    governance = SourceFindingGovernanceService(environment.factory, clock=clock)
    suppression = SourceFindingSuppressionService(environment.factory, clock=clock)
    effective = EffectiveGovernanceService(environment.factory, clock=clock)
    return {
        "pc2": pc2_context,
        "environment": environment,
        "lifecycle": lifecycle,
        "lineage_id": lineage.lineage_id,
        "finding_id": finding_id,
        "project_id": project_id,
        "clock": clock,
        "governance": governance,
        "suppression": suppression,
        "effective": effective,
    }


def _read(context):
    return context["effective"].get(
        project_id=context["project_id"],
        lineage_id=context["lineage_id"],
        finding_id=context["finding_id"],
    )


def _govern(context, disposition, *, reason, expiry=None, revision=0):
    return context["governance"].mutate(
        project_id=context["project_id"],
        lineage_id=context["lineage_id"],
        finding_id=context["finding_id"],
        disposition=disposition,
        reason=reason,
        expires_at=expiry,
        expected_revision=revision,
    )


def _suppress(context, *, reason="temporary", expiry=None, revision=0):
    return context["suppression"].suppress(
        project_id=context["project_id"],
        lineage_id=context["lineage_id"],
        finding_id=context["finding_id"],
        reason=reason,
        expires_at=expiry or context["clock"].value + timedelta(days=30),
        expected_revision=revision,
    )


def _advance(context, monkeypatch, run_id, *, present, ordinal):
    _add_run(context["pc2"], monkeypatch, run_id, present=present, ordinal=ordinal)
    context["lifecycle"].evaluate(lineage_id=context["lineage_id"], run_id=run_id)


def _resolve_and_reopen(context, monkeypatch):
    _advance(context, monkeypatch, _RUN_IDS[0], present=False, ordinal=2)
    _advance(context, monkeypatch, _RUN_IDS[1], present=True, ordinal=3)


def test_default_read_is_one_statement_and_side_effect_free(effective_context) -> None:
    environment = effective_context["environment"]
    statements: list[str] = []

    def capture(_connection, _cursor, statement, _parameters, _context, _executemany):
        statements.append(statement)

    event.listen(environment.engine, "before_cursor_execute", capture)
    try:
        state = _read(effective_context)
    finally:
        event.remove(environment.engine, "before_cursor_execute", capture)
    assert len(statements) == 1
    assert statements[0].lstrip().upper().startswith("SELECT")
    assert state.lifecycle_state is FindingLifecycleState.NEW
    assert state.disposition is AnalystDisposition.UNREVIEWED
    assert state.false_positive_effective is False
    assert state.accepted_risk_effective is False
    assert state.suppression_present is False
    assert state.suppression_effective is False
    assert state.review_required is False
    assert state.reason_codes == (EffectiveGovernanceReasonCode.NO_GOVERNANCE,)
    with environment.factory() as session:
        assert session.scalar(select(func.count()).select_from(SourceFindingGovernanceRow)) == 0
        assert session.scalar(select(func.count()).select_from(SourceFindingSuppressionRow)) == 0
        assert (
            session.scalar(select(func.count()).select_from(SourceFindingGovernanceEventRow)) == 0
        )
        assert (
            session.scalar(select(func.count()).select_from(SourceFindingSuppressionEventRow)) == 0
        )
        assert (
            session.scalar(select(func.count()).select_from(SourceFindingLifecycleEventRow)) == 1
        )


def test_new_existing_and_resolved_inheritance(effective_context, monkeypatch) -> None:
    _govern(
        effective_context,
        AnalystDisposition.FALSE_POSITIVE,
        reason="reviewed",
    )
    suppression = _suppress(effective_context)
    new = _read(effective_context)
    assert new.false_positive_effective is True
    assert new.suppression_effective is True
    assert new.governance_lifecycle_transition_version == 1
    assert new.suppression_lifecycle_transition_version == 1

    _advance(effective_context, monkeypatch, _RUN_IDS[0], present=True, ordinal=2)
    existing = _read(effective_context)
    assert existing.lifecycle_state is FindingLifecycleState.EXISTING
    assert existing.false_positive_effective is True
    assert existing.suppression_effective is True
    assert existing.suppression_id == suppression.suppression_id

    _advance(effective_context, monkeypatch, _RUN_IDS[1], present=False, ordinal=3)
    resolved = _read(effective_context)
    assert resolved.lifecycle_state is FindingLifecycleState.RESOLVED
    assert resolved.false_positive_effective is False
    assert resolved.suppression_effective is False
    assert resolved.reason_codes.count(EffectiveGovernanceReasonCode.FINDING_RESOLVED) == 1
    with effective_context["environment"].factory() as session:
        governance = session.get(
            SourceFindingGovernanceRow,
            (effective_context["lineage_id"], effective_context["finding_id"]),
        )
        persisted = session.get(
            SourceFindingSuppressionRow,
            (effective_context["lineage_id"], effective_context["finding_id"]),
        )
        assert governance is not None and governance.disposition == "FALSE_POSITIVE"
        assert persisted is not None and persisted.suppression_id == suppression.suppression_id


def test_reopened_same_timestamp_is_dormant_then_same_value_reaffirms(
    effective_context, monkeypatch
) -> None:
    reopen_timestamp = _INDEXED_AT + timedelta(days=2)
    effective_context["clock"].value = reopen_timestamp
    _govern(
        effective_context,
        AnalystDisposition.FALSE_POSITIVE,
        reason="before reopen",
    )
    _resolve_and_reopen(effective_context, monkeypatch)
    reopened = _read(effective_context)
    assert reopened.lifecycle_state is FindingLifecycleState.REOPENED
    assert reopened.current_episode_transition_version == 3
    assert reopened.governance_lifecycle_transition_version == 1
    assert reopened.false_positive_effective is False
    assert reopened.review_required is True
    assert EffectiveGovernanceReasonCode.PRE_REOPEN_GOVERNANCE_DORMANT in reopened.reason_codes

    reaffirmed = _govern(
        effective_context,
        AnalystDisposition.FALSE_POSITIVE,
        reason="explicit reaffirmation",
        revision=1,
    )
    assert reaffirmed.revision == 2
    current = _read(effective_context)
    assert current.false_positive_effective is True
    assert current.review_required is False
    assert current.governance_lifecycle_transition_version == 3


def test_accepted_risk_pre_reopen_dormant_and_post_reopen_effective(
    effective_context, monkeypatch
) -> None:
    expiry = _NOW + timedelta(days=60)
    _govern(
        effective_context,
        AnalystDisposition.ACCEPTED_RISK,
        reason="old acceptance",
        expiry=expiry,
    )
    _resolve_and_reopen(effective_context, monkeypatch)
    historical = _read(effective_context)
    assert historical.accepted_risk_effective is False
    assert historical.review_required is True

    _govern(
        effective_context,
        AnalystDisposition.ACCEPTED_RISK,
        reason="new acceptance",
        expiry=expiry + timedelta(days=1),
        revision=1,
    )
    reaffirmed = _read(effective_context)
    assert reaffirmed.accepted_risk_effective is True
    assert reaffirmed.review_required is False
    assert reaffirmed.governance_lifecycle_transition_version == 3


def test_old_unexpired_suppression_requires_new_post_reopen_episode(
    effective_context, monkeypatch
) -> None:
    first = _suppress(effective_context, expiry=_NOW + timedelta(days=90))
    _resolve_and_reopen(effective_context, monkeypatch)
    historical = _read(effective_context)
    assert historical.suppression_present is True
    assert historical.suppression_effective is False
    assert historical.review_required is True
    assert EffectiveGovernanceReasonCode.PRE_REOPEN_SUPPRESSION_DORMANT in historical.reason_codes

    second = _suppress(
        effective_context,
        reason="explicit post-reopen episode",
        expiry=_NOW + timedelta(days=91),
        revision=1,
    )
    assert second.suppression_id != first.suppression_id
    current = _read(effective_context)
    assert current.suppression_effective is True
    assert current.review_required is False
    assert current.suppression_lifecycle_transition_version == 3


def test_legacy_null_marker_is_eligible_only_without_reopen(
    effective_context, monkeypatch
) -> None:
    _govern(
        effective_context,
        AnalystDisposition.FALSE_POSITIVE,
        reason="legacy governance",
    )
    _suppress(effective_context, reason="legacy suppression")
    with effective_context["environment"].factory.begin() as session:
        governance_event = session.scalar(select(SourceFindingGovernanceEventRow))
        suppression_event = session.scalar(select(SourceFindingSuppressionEventRow))
        assert governance_event is not None and suppression_event is not None
        governance_event.lifecycle_transition_version = None
        suppression_event.lifecycle_transition_version = None

    first_episode = _read(effective_context)
    assert first_episode.false_positive_effective is True
    assert first_episode.suppression_effective is True

    _resolve_and_reopen(effective_context, monkeypatch)
    reopened = _read(effective_context)
    assert reopened.false_positive_effective is False
    assert reopened.suppression_effective is False
    assert reopened.review_required is True


def test_only_latest_reopen_episode_can_be_effective(effective_context, monkeypatch) -> None:
    _govern(
        effective_context,
        AnalystDisposition.FALSE_POSITIVE,
        reason="episode one",
    )
    _resolve_and_reopen(effective_context, monkeypatch)
    _govern(
        effective_context,
        AnalystDisposition.FALSE_POSITIVE,
        reason="episode two",
        revision=1,
    )
    assert _read(effective_context).false_positive_effective is True

    _advance(
        effective_context,
        monkeypatch,
        _SECOND_RESOLVED_RUN,
        present=False,
        ordinal=4,
    )
    _advance(
        effective_context,
        monkeypatch,
        _SECOND_REOPENED_RUN,
        present=True,
        ordinal=5,
    )
    second_reopen = _read(effective_context)
    assert second_reopen.current_episode_transition_version == 5
    assert second_reopen.false_positive_effective is False
    assert second_reopen.review_required is True

    _govern(
        effective_context,
        AnalystDisposition.FALSE_POSITIVE,
        reason="episode three",
        revision=2,
    )
    assert _read(effective_context).false_positive_effective is True


def test_exact_expiry_boundaries_and_revocation(effective_context) -> None:
    expiry = _NOW + timedelta(hours=1)
    _govern(
        effective_context,
        AnalystDisposition.ACCEPTED_RISK,
        reason="temporary risk",
        expiry=expiry,
    )
    _suppress(effective_context, expiry=expiry)

    effective_context["clock"].value = expiry - timedelta(microseconds=1)
    before = _read(effective_context)
    assert before.accepted_risk_effective is True
    assert before.suppression_effective is True

    effective_context["clock"].value = expiry
    exact = _read(effective_context)
    assert exact.accepted_risk_effective is False
    assert exact.suppression_effective is False
    assert EffectiveGovernanceReasonCode.ACCEPTED_RISK_EXPIRED in exact.reason_codes
    assert EffectiveGovernanceReasonCode.SUPPRESSION_EXPIRED in exact.reason_codes

    effective_context["clock"].value = expiry + timedelta(microseconds=1)
    after = _read(effective_context)
    assert after.accepted_risk_effective is False
    assert after.suppression_effective is False

    active = _suppress(
        effective_context,
        reason="new episode",
        expiry=effective_context["clock"].value + timedelta(days=2),
        revision=1,
    )
    effective_context["suppression"].revoke(
        project_id=effective_context["project_id"],
        lineage_id=effective_context["lineage_id"],
        finding_id=effective_context["finding_id"],
        expected_revision=active.revision,
    )
    revoked = _read(effective_context)
    assert revoked.suppression_effective is False
    assert EffectiveGovernanceReasonCode.SUPPRESSION_REVOKED in revoked.reason_codes


def test_scope_and_identifier_validation(effective_context) -> None:
    with pytest.raises(EffectiveGovernanceNotFoundError):
        effective_context["effective"].get(
            project_id="99999999-9999-4999-8999-999999999999",
            lineage_id=effective_context["lineage_id"],
            finding_id=effective_context["finding_id"],
        )
    with pytest.raises(EffectiveGovernanceValidationError):
        effective_context["effective"].get(
            project_id=effective_context["project_id"],
            lineage_id="not-a-uuid",
            finding_id=effective_context["finding_id"],
        )


def test_explicit_unreviewed_row_remains_normal_non_exclusionary_state(
    effective_context,
) -> None:
    _govern(
        effective_context,
        AnalystDisposition.FALSE_POSITIVE,
        reason="temporary decision",
    )
    _govern(
        effective_context,
        AnalystDisposition.UNREVIEWED,
        reason=None,
        revision=1,
    )
    state = _read(effective_context)
    assert state.disposition is AnalystDisposition.UNREVIEWED
    assert state.disposition_revision == 2
    assert state.false_positive_effective is False
    assert state.accepted_risk_effective is False
    assert state.reason_codes == (EffectiveGovernanceReasonCode.NO_GOVERNANCE,)
