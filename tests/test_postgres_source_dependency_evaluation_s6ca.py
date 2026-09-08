from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from postgres_test_guard import validated_postgres_test_url
from sqlalchemy import create_engine, func, select, text
from test_source_dependency_evaluation_s6ca import _accept_syft, _nodes
from test_source_orchestration_s6a import _NOW, _RUN_ID
from test_source_orchestration_s6b import _Environment

from securescan.domain.enums import ExecutionOutcome
from securescan.orchestration.dependency_evaluation import (
    DependencyEvaluationDecision,
    SourceDependencyEvaluationError,
    SourceDependencyEvaluationService,
)
from securescan.orchestration.models import SourceAuthority
from securescan.persistence.database import (
    SourceOrchestrationDependencyEvaluationRow,
    SourceOrchestrationNodeRow,
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
def postgres_s6ca(tmp_path: Path):
    database_url = validated_postgres_test_url()
    _reset(database_url)
    environment = _Environment(tmp_path, database_url=database_url)
    try:
        yield environment
    finally:
        environment.close()
        _reset(database_url)


@pytest.mark.parametrize("with_packages", [False, True])
def test_concurrent_dependency_evaluation_has_one_durable_serial_result(
    postgres_s6ca: _Environment, with_packages: bool
) -> None:
    syft, osv = _nodes(postgres_s6ca)
    if with_packages:
        _node, job, _attempt = postgres_s6ca.start_attempt(syft.authority)
        from test_source_dependency_evaluation_s6ca import (
            _finish_existing_syft,
            _observation,
        )

        _finish_existing_syft(
            postgres_s6ca,
            syft,
            job,
            (_observation(job, syft, ("requirements.lock",)),),
        )
    else:
        _accept_syft(postgres_s6ca, ())
    barrier = threading.Barrier(2)

    def evaluate():
        service = SourceDependencyEvaluationService(
            postgres_s6ca.factory, postgres_s6ca.store, clock=lambda: _NOW
        )
        barrier.wait()
        return service.evaluate(run_id=str(_RUN_ID), osv_node_id=osv.node_id)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(lambda _value: evaluate(), range(2)))

    assert sorted(item.created for item in results) == [False, True]
    assert len({item.artifact_sha256 for item in results}) == 1
    expected = (
        DependencyEvaluationDecision.OSV_RUN_REQUIRED
        if with_packages
        else DependencyEvaluationDecision.NOT_APPLICABLE_NO_PACKAGES
    )
    assert {item.evaluation.decision for item in results} == {expected}
    with postgres_s6ca.factory() as session:
        assert (
            session.scalar(
                select(func.count()).select_from(SourceOrchestrationDependencyEvaluationRow)
            )
            == 1
        )
        node = session.get(SourceOrchestrationNodeRow, osv.node_id)
        assert node is not None
        assert node.lifecycle_state == ("READY" if with_packages else "TERMINAL")


def test_syft_acceptance_vs_evaluation_has_a_valid_serial_order(
    postgres_s6ca: _Environment,
) -> None:
    _syft, osv = _nodes(postgres_s6ca)
    node, job, _attempt = postgres_s6ca.start_attempt(SourceAuthority.SYFT)
    native = postgres_s6ca.native_result(node, job)
    barrier = threading.Barrier(2)

    def accept() -> None:
        barrier.wait()
        postgres_s6ca.attempts.accept_result(
            native,
            lease_token="33333333-3333-4333-8333-333333333333",
            execution_outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
            return_code=0,
            duration_ms=1,
        )

    def evaluate() -> bool:
        service = SourceDependencyEvaluationService(
            postgres_s6ca.factory, postgres_s6ca.store, clock=lambda: _NOW
        )
        barrier.wait()
        try:
            service.evaluate(run_id=str(_RUN_ID), osv_node_id=osv.node_id)
            return True
        except SourceDependencyEvaluationError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        accepted = pool.submit(accept)
        evaluated = pool.submit(evaluate)
        accepted.result()
        first_evaluation_succeeded = evaluated.result()

    service = SourceDependencyEvaluationService(
        postgres_s6ca.factory, postgres_s6ca.store, clock=lambda: _NOW
    )
    final = service.evaluate(run_id=str(_RUN_ID), osv_node_id=osv.node_id)
    assert final.evaluation.decision is DependencyEvaluationDecision.NOT_APPLICABLE_NO_PACKAGES
    assert final.created is (not first_evaluation_succeeded)
    with postgres_s6ca.factory() as session:
        assert (
            session.scalar(
                select(func.count()).select_from(SourceOrchestrationDependencyEvaluationRow)
            )
            == 1
        )


def test_conflicting_durable_evaluation_material_fails_closed(
    postgres_s6ca: _Environment,
) -> None:
    _syft, osv = _nodes(postgres_s6ca)
    _accept_syft(postgres_s6ca, ())
    service = SourceDependencyEvaluationService(
        postgres_s6ca.factory, postgres_s6ca.store, clock=lambda: _NOW
    )
    service.evaluate(run_id=str(_RUN_ID), osv_node_id=osv.node_id)
    with postgres_s6ca.factory.begin() as session:
        row = session.get(SourceOrchestrationDependencyEvaluationRow, (str(_RUN_ID), osv.node_id))
        assert row is not None
        row.scope_digest = "f" * 64
    with pytest.raises(SourceDependencyEvaluationError):
        service.evaluate(run_id=str(_RUN_ID), osv_node_id=osv.node_id)
