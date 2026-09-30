from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from postgres_test_guard import validated_postgres_test_url

from securescan.persistence.database import (
    AnalysisRunRow,
    SourceScanSubmissionRow,
    SourceTrustedBaselinePromotionRow,
    TargetRow,
)
from securescan.product_core import (
    AnalystDisposition,
    EffectiveGovernanceService,
    SecurityDeltaState,
    SourceFindingGovernanceService,
    SourceFindingLifecycleService,
    SourceFindingSuppressionService,
    SourceScanSubmissionService,
    SourceSecurityDeltaService,
    SourceTrustedBaselineService,
    TrustedBaselineConflictError,
    TrustedBaselineIneligibleError,
)
from tests.test_postgres_source_product_core_pc1 import _reset
from tests.test_source_orchestration_s6b import _RUN_ID, _Environment
from tests.test_source_product_core_pc1 import _publish_environment

pytestmark = pytest.mark.postgres

_NOW = datetime(2026, 10, 3, tzinfo=UTC)


@pytest.fixture
def postgres_baseline(tmp_path: Path):
    database_url = validated_postgres_test_url()
    _reset(database_url)
    environment = _Environment(tmp_path, database_url=database_url)
    _publish_environment(environment)
    try:
        with environment.factory.begin() as session:
            run = session.get(AnalysisRunRow, str(_RUN_ID))
            assert run is not None
            target = session.get(TargetRow, run.target_id)
            assert target is not None
            target.source_path = environment.workspace.workspace_id
            project_id = target.project_id
        submissions = SourceScanSubmissionService(
            environment.factory,
            environment.store,
            environment.workspace_manager,
            clock=lambda: _NOW,
        )
        lineage = submissions.create_lineage(project_id=project_id)
        submissions.reserve(
            run_id=str(_RUN_ID),
            lineage_id=lineage.lineage_id,
            intake_ref=environment.workspace.workspace_id,
        )
        submissions.finalize(run_id=str(_RUN_ID))
        baselines = SourceTrustedBaselineService(
            environment.factory, environment.store, clock=lambda: _NOW
        )
        yield environment, baselines, project_id, lineage.lineage_id
    finally:
        environment.close()
        _reset(database_url)


def _promote(context, expected_revision: int):
    _environment, service, project_id, lineage_id = context
    return service.promote(
        project_id=project_id,
        lineage_id=lineage_id,
        run_id=str(_RUN_ID),
        expected_revision=expected_revision,
    )


def _race(barrier: threading.Barrier, operation):
    barrier.wait()
    try:
        return operation()
    except Exception as error:
        return error


def test_postgres_simultaneous_initial_and_later_promotions_have_one_winner(
    postgres_baseline,
) -> None:
    barrier = threading.Barrier(2)
    with ThreadPoolExecutor(max_workers=2) as pool:
        initial = tuple(
            pool.map(
                lambda _value: _race(barrier, lambda: _promote(postgres_baseline, 0)),
                range(2),
            )
        )
    assert sum(not isinstance(item, Exception) for item in initial) == 1
    assert sum(isinstance(item, TrustedBaselineConflictError) for item in initial) == 1

    barrier = threading.Barrier(2)
    with ThreadPoolExecutor(max_workers=2) as pool:
        later = tuple(
            pool.map(
                lambda _value: _race(barrier, lambda: _promote(postgres_baseline, 1)),
                range(2),
            )
        )
    assert sum(not isinstance(item, Exception) for item in later) == 1
    assert sum(isinstance(item, TrustedBaselineConflictError) for item in later) == 1
    environment, _service, _project_id, lineage_id = postgres_baseline
    with environment.factory() as session:
        rows = tuple(
            session.query(SourceTrustedBaselinePromotionRow)
            .filter(SourceTrustedBaselinePromotionRow.lineage_id == lineage_id)
            .order_by(SourceTrustedBaselinePromotionRow.revision)
        )
    assert [item.revision for item in rows] == [1, 2]
    assert rows[0].baseline_id != rows[1].baseline_id


def test_postgres_read_during_promotion_returns_one_exact_revision(
    postgres_baseline,
) -> None:
    first = _promote(postgres_baseline, 0)
    environment, service, project_id, lineage_id = postgres_baseline
    barrier = threading.Barrier(2)
    with ThreadPoolExecutor(max_workers=2) as pool:
        read_future = pool.submit(
            _race,
            barrier,
            lambda: service.get_current(project_id=project_id, lineage_id=lineage_id),
        )
        promote_future = pool.submit(_race, barrier, lambda: _promote(postgres_baseline, 1))
        observed = read_future.result()
        promoted = promote_future.result()
    assert not isinstance(observed, Exception)
    assert not isinstance(promoted, Exception)
    assert observed.revision in {1, 2}
    assert observed.baseline is not None
    expected_id = first.baseline_id if observed.revision == 1 else promoted.baseline_id
    assert observed.baseline.baseline_id == expected_id
    with environment.factory() as session:
        assert session.query(SourceTrustedBaselinePromotionRow).count() == 2


def test_postgres_delta_during_promotion_identifies_its_exact_baseline(
    postgres_baseline,
) -> None:
    first = _promote(postgres_baseline, 0)
    environment, _service, project_id, lineage_id = postgres_baseline
    delta = SourceSecurityDeltaService(environment.factory, environment.store)
    barrier = threading.Barrier(2)
    with ThreadPoolExecutor(max_workers=2) as pool:
        delta_future = pool.submit(
            _race,
            barrier,
            lambda: delta.evaluate(
                project_id=project_id,
                lineage_id=lineage_id,
                candidate_run_id=str(_RUN_ID),
            ),
        )
        promote_future = pool.submit(_race, barrier, lambda: _promote(postgres_baseline, 1))
        observed = delta_future.result()
        promoted = promote_future.result()
    assert not isinstance(observed, Exception)
    assert not isinstance(promoted, Exception)
    assert observed.baseline_revision in {1, 2}
    expected_id = first.baseline_id if observed.baseline_revision == 1 else promoted.baseline_id
    assert observed.baseline_id == expected_id
    assert {item.state for item in observed.findings} == {SecurityDeltaState.PRESENT}


def test_postgres_promotion_never_accepts_unfinalized_snapshot(
    postgres_baseline,
) -> None:
    _environment, _service, _project_id, _lineage_id = postgres_baseline
    _promote(postgres_baseline, 0)
    environment = postgres_baseline[0]
    with environment.factory.begin() as session:
        submission = session.get(SourceScanSubmissionRow, str(_RUN_ID))
        assert submission is not None
        submission.finalized_at = None
    barrier = threading.Barrier(2)

    def finalize():
        with environment.factory.begin() as session:
            submission = session.get(SourceScanSubmissionRow, str(_RUN_ID))
            assert submission is not None
            barrier.wait()
            submission.finalized_at = _NOW

    with ThreadPoolExecutor(max_workers=2) as pool:
        finalize_future = pool.submit(finalize)
        promote_future = pool.submit(_race, barrier, lambda: _promote(postgres_baseline, 1))
        finalize_future.result()
        result = promote_future.result()
    assert not isinstance(result, Exception) or isinstance(result, TrustedBaselineIneligibleError)
    current = postgres_baseline[1].get_current(
        project_id=postgres_baseline[2], lineage_id=postgres_baseline[3]
    )
    assert current.revision in {1, 2}
    with environment.factory() as session:
        submission = session.get(SourceScanSubmissionRow, str(_RUN_ID))
        assert submission is not None and submission.finalized_at is not None


def test_postgres_delta_self_read_is_stable_and_does_not_mutate_baseline(
    postgres_baseline,
) -> None:
    promoted = _promote(postgres_baseline, 0)
    environment, baselines, project_id, lineage_id = postgres_baseline
    delta = SourceSecurityDeltaService(environment.factory, environment.store)
    result = delta.evaluate(
        project_id=project_id,
        lineage_id=lineage_id,
        candidate_run_id=str(_RUN_ID),
    )
    assert result.baseline_id == promoted.baseline_id
    assert result.findings
    assert {item.state for item in result.findings} == {SecurityDeltaState.PRESENT}
    current = baselines.get_current(project_id=project_id, lineage_id=lineage_id)
    assert current.revision == 1 and current.baseline == promoted


@pytest.mark.parametrize("mutation", ("governance", "suppression"))
def test_postgres_shared_snapshot_excludes_concurrent_governance_changes(
    postgres_baseline, mutation: str
) -> None:
    promoted = _promote(postgres_baseline, 0)
    environment, _baselines, project_id, lineage_id = postgres_baseline
    delta_service = SourceSecurityDeltaService(environment.factory, environment.store)
    effective_service = EffectiveGovernanceService(environment.factory, clock=lambda: _NOW)
    with environment.factory() as session:
        session.connection(execution_options={"isolation_level": "REPEATABLE READ"})
        delta = delta_service.evaluate_in_session(
            session,
            project_id=project_id,
            lineage_id=lineage_id,
            candidate_run_id=str(_RUN_ID),
        )
        finding_id = delta.findings[0].finding_id

        def mutate() -> None:
            if mutation == "governance":
                SourceFindingGovernanceService(environment.factory, clock=lambda: _NOW).mutate(
                    project_id=project_id,
                    lineage_id=lineage_id,
                    finding_id=finding_id,
                    disposition=AnalystDisposition.FALSE_POSITIVE,
                    reason="snapshot race",
                    expires_at=None,
                    expected_revision=0,
                )
            else:
                SourceFindingSuppressionService(environment.factory, clock=lambda: _NOW).suppress(
                    project_id=project_id,
                    lineage_id=lineage_id,
                    finding_id=finding_id,
                    reason="snapshot race",
                    expires_at=_NOW + timedelta(days=30),
                    expected_revision=0,
                )

        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(mutate).result(timeout=30)
        snapshot = effective_service.get_many_in_session(
            session,
            project_id=project_id,
            lineage_id=lineage_id,
            finding_ids=(finding_id,),
            evaluated_at=_NOW,
        )[0]
        assert delta.baseline_id == promoted.baseline_id
        assert snapshot.false_positive_effective is False
        assert snapshot.suppression_effective is False

    current = effective_service.get(
        project_id=project_id, lineage_id=lineage_id, finding_id=finding_id
    )
    assert (
        current.false_positive_effective
        if mutation == "governance"
        else current.suppression_effective
    )


def test_postgres_shared_snapshot_pins_baseline_and_candidate_lifecycle(
    postgres_baseline,
) -> None:
    first = _promote(postgres_baseline, 0)
    environment, _baselines, project_id, lineage_id = postgres_baseline
    delta_service = SourceSecurityDeltaService(environment.factory, environment.store)
    lifecycle_service = SourceFindingLifecycleService(environment.factory, environment.store)
    with environment.factory() as session:
        session.connection(execution_options={"isolation_level": "REPEATABLE READ"})
        delta = delta_service.evaluate_in_session(
            session,
            project_id=project_id,
            lineage_id=lineage_id,
            candidate_run_id=str(_RUN_ID),
        )
        with ThreadPoolExecutor(max_workers=1) as pool:
            second = pool.submit(_promote, postgres_baseline, 1).result(timeout=30)
        facts = lifecycle_service.load_candidate_facts_in_session(
            session,
            project_id=project_id,
            lineage_id=lineage_id,
            run_id=str(_RUN_ID),
        )
        assert facts
        assert delta.baseline_id == first.baseline_id
        assert delta.baseline_revision == 1
        assert (
            delta_service.evaluate_in_session(
                session,
                project_id=project_id,
                lineage_id=lineage_id,
                candidate_run_id=str(_RUN_ID),
            ).baseline_id
            == first.baseline_id
        )
    assert (
        delta_service.evaluate(
            project_id=project_id, lineage_id=lineage_id, candidate_run_id=str(_RUN_ID)
        ).baseline_id
        == second.baseline_id
    )
