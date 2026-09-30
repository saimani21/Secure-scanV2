from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest
from sqlalchemy import func, select

from securescan.persistence.database import (
    SourcePolicyDefinitionRow,
    SourcePolicyEvaluationRow,
    SourceTrustedBaselinePromotionRow,
)
from securescan.product_core import (
    DEFAULT_POLICY,
    AnalystDisposition,
    PolicyConflictError,
    PolicyDecisionKind,
    PolicyNotFoundError,
    PolicyResult,
    SourceFindingGovernanceService,
    SourceFindingSuppressionService,
    SourcePolicyService,
)
from tests.test_postgres_trusted_baseline_v12e import _promote
from tests.test_source_orchestration_s6b import _RUN_ID

pytest_plugins = ("tests.test_postgres_trusted_baseline_v12e",)
pytestmark = pytest.mark.postgres
_NOW = datetime(2026, 10, 3, tzinfo=UTC)


def test_default_policy_self_comparison_is_persisted_without_baseline_change(
    postgres_baseline,
) -> None:
    baseline = _promote(postgres_baseline, 0)
    environment, _baselines, project_id, lineage_id = postgres_baseline
    service = SourcePolicyService(environment.factory, environment.store, clock=lambda: _NOW)
    trusted = service.get_policy(project_id=project_id, lineage_id=lineage_id)
    assert trusted.version == 1 and trusted.actor_type == "BUILTIN"
    first = service.evaluate(
        project_id=project_id, lineage_id=lineage_id, candidate_run_id=str(_RUN_ID)
    )
    second = service.evaluate(
        project_id=project_id, lineage_id=lineage_id, candidate_run_id=str(_RUN_ID)
    )
    assert first.result is PolicyResult.ERROR
    assert first.baseline_id == baseline.baseline_id
    assert first.baseline_revision == 1
    assert first.policy_digest == trusted.digest
    assert first.decisions == second.decisions
    assert first.result == second.result
    assert (
        service.get_evaluation(
            project_id=project_id, lineage_id=lineage_id, evaluation_id=first.evaluation_id
        )
        == first
    )
    definition = DEFAULT_POLICY.model_dump(mode="json")
    definition["required_authorities"] = ["gitleaks"]
    updated = service.update_policy(
        project_id=project_id,
        lineage_id=lineage_id,
        expected_version=1,
        definition=definition,
    )
    assert updated.version == 2 and updated.digest != trusted.digest
    narrowed = service.evaluate(
        project_id=project_id, lineage_id=lineage_id, candidate_run_id=str(_RUN_ID)
    )
    assert narrowed.result is PolicyResult.PASS
    assert narrowed.policy_digest == updated.digest
    with environment.factory() as session:
        assert session.scalar(select(func.count()).select_from(SourcePolicyDefinitionRow)) == 1
        assert session.scalar(select(func.count()).select_from(SourcePolicyEvaluationRow)) == 3
        assert (
            session.scalar(select(func.count()).select_from(SourceTrustedBaselinePromotionRow)) == 1
        )


def _during_delta(service, monkeypatch, operation):
    original = service._delta.evaluate_in_session
    called = False

    def hooked(session, **kwargs):
        nonlocal called
        if not called:
            called = True
            with ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(operation).result(timeout=30)
        return original(session, **kwargs)

    monkeypatch.setattr(service._delta, "evaluate_in_session", hooked)


def test_policy_evaluation_pins_policy_revision_across_concurrent_update(
    postgres_baseline, monkeypatch
) -> None:
    _promote(postgres_baseline, 0)
    environment, _baselines, project_id, lineage_id = postgres_baseline
    service = SourcePolicyService(environment.factory, environment.store, clock=lambda: _NOW)
    old = service.get_policy(project_id=project_id, lineage_id=lineage_id)
    definition = DEFAULT_POLICY.model_dump(mode="json")
    definition["required_authorities"] = ["gitleaks"]
    _during_delta(
        service,
        monkeypatch,
        lambda: service.update_policy(
            project_id=project_id,
            lineage_id=lineage_id,
            expected_version=1,
            definition=definition,
        ),
    )
    evaluation = service.evaluate(
        project_id=project_id, lineage_id=lineage_id, candidate_run_id=str(_RUN_ID)
    )
    assert evaluation.policy_version == 1
    assert evaluation.policy_digest == old.digest
    assert service.get_policy(project_id=project_id, lineage_id=lineage_id).version == 2
    with pytest.raises(PolicyConflictError):
        service.update_policy(
            project_id=project_id,
            lineage_id=lineage_id,
            expected_version=1,
            definition=definition,
        )


def test_policy_evaluation_pins_baseline_across_concurrent_promotion(
    postgres_baseline, monkeypatch
) -> None:
    first = _promote(postgres_baseline, 0)
    environment, _baselines, project_id, lineage_id = postgres_baseline
    service = SourcePolicyService(environment.factory, environment.store, clock=lambda: _NOW)
    _during_delta(service, monkeypatch, lambda: _promote(postgres_baseline, 1))
    evaluation = service.evaluate(
        project_id=project_id, lineage_id=lineage_id, candidate_run_id=str(_RUN_ID)
    )
    assert evaluation.baseline_id == first.baseline_id
    assert evaluation.baseline_revision == 1
    with environment.factory() as session:
        assert (
            session.scalar(select(func.count()).select_from(SourceTrustedBaselinePromotionRow)) == 2
        )


@pytest.mark.parametrize("mutation", ("governance", "suppression"))
def test_policy_evaluation_pins_effective_governance_across_concurrent_mutation(
    postgres_baseline, monkeypatch, mutation
) -> None:
    _promote(postgres_baseline, 0)
    environment, _baselines, project_id, lineage_id = postgres_baseline
    service = SourcePolicyService(environment.factory, environment.store, clock=lambda: _NOW)
    definition = DEFAULT_POLICY.model_dump(mode="json")
    definition["required_authorities"] = ["gitleaks"]
    definition["present"] = {band: "FAIL" for band in definition["present"]}
    service.update_policy(
        project_id=project_id,
        lineage_id=lineage_id,
        expected_version=1,
        definition=definition,
    )
    with environment.factory() as session:
        facts = service._lifecycle.load_candidate_facts_in_session(
            session, project_id=project_id, lineage_id=lineage_id, run_id=str(_RUN_ID)
        )
    finding_id = facts[0].finding_id

    def mutate():
        if mutation == "governance":
            SourceFindingGovernanceService(environment.factory, clock=lambda: _NOW).mutate(
                project_id=project_id,
                lineage_id=lineage_id,
                finding_id=finding_id,
                disposition=AnalystDisposition.FALSE_POSITIVE,
                reason="concurrent trusted review",
                expires_at=None,
                expected_revision=0,
            )
        else:
            SourceFindingSuppressionService(environment.factory, clock=lambda: _NOW).suppress(
                project_id=project_id,
                lineage_id=lineage_id,
                finding_id=finding_id,
                reason="concurrent trusted suppression",
                expires_at=_NOW + timedelta(days=30),
                expected_revision=0,
            )

    _during_delta(service, monkeypatch, mutate)
    before = service.evaluate(
        project_id=project_id, lineage_id=lineage_id, candidate_run_id=str(_RUN_ID)
    )
    after = service.evaluate(
        project_id=project_id, lineage_id=lineage_id, candidate_run_id=str(_RUN_ID)
    )
    assert before.result is PolicyResult.FAIL
    assert after.result is PolicyResult.PASS
    assert any(item.kind is PolicyDecisionKind.EXCLUSION for item in after.decisions)


def test_simultaneous_trusted_policy_revisions_have_one_winner(postgres_baseline) -> None:
    environment, _baselines, project_id, lineage_id = postgres_baseline
    service = SourcePolicyService(environment.factory, environment.store, clock=lambda: _NOW)
    definition = DEFAULT_POLICY.model_dump(mode="json")
    definition["required_authorities"] = ["gitleaks"]
    barrier = Barrier(2)

    def update():
        barrier.wait(timeout=10)
        try:
            return service.update_policy(
                project_id=project_id,
                lineage_id=lineage_id,
                expected_version=1,
                definition=definition,
            )
        except PolicyConflictError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(lambda _index: update(), range(2)))
    assert sum(not isinstance(item, Exception) for item in results) == 1
    assert sum(isinstance(item, PolicyConflictError) for item in results) == 1
    assert service.get_policy(project_id=project_id, lineage_id=lineage_id).version == 2


def test_missing_baseline_is_persisted_error_without_promotion(postgres_baseline) -> None:
    environment, _baselines, project_id, lineage_id = postgres_baseline
    service = SourcePolicyService(environment.factory, environment.store, clock=lambda: _NOW)
    result = service.evaluate(
        project_id=project_id, lineage_id=lineage_id, candidate_run_id=str(_RUN_ID)
    )
    assert result.result is PolicyResult.ERROR
    assert result.baseline_id is None and result.baseline_revision is None
    assert result.decisions[0].reason_code == "BASELINE_UNAVAILABLE"
    with environment.factory() as session:
        assert (
            session.scalar(select(func.count()).select_from(SourceTrustedBaselinePromotionRow)) == 0
        )
    with pytest.raises(PolicyNotFoundError):
        service.get_policy(
            project_id="99999999-9999-4999-8999-999999999999",
            lineage_id=lineage_id,
        )
