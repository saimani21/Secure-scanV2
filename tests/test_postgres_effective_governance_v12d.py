from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import pytest
from postgres_test_guard import validated_postgres_test_url
from sqlalchemy import select

from securescan.persistence.database import (
    AnalysisRunRow,
    ProjectRow,
    SourceFindingGovernanceEventRow,
    SourceFindingLifecycleRow,
    SourceFindingSuppressionEventRow,
    SourceLineageRunRow,
    SourceTargetLineageRow,
    TargetRow,
)
from securescan.product_core import (
    AnalystDisposition,
    EffectiveGovernanceService,
    FindingLifecycleState,
    SourceFindingGovernanceService,
    SourceFindingIndexService,
    SourceFindingLifecycleService,
    SourceFindingSuppressionService,
)
from tests.test_effective_governance_v12d import (
    _NOW,
    _Clock,
    _govern,
    _read,
    _resolve_and_reopen,
    _suppress,
)
from tests.test_postgres_source_product_core_pc1 import _reset
from tests.test_source_orchestration_s6b import _RUN_ID, _Environment
from tests.test_source_product_core_pc1 import _INDEXED_AT, _LINEAGE_IDS, _publish_environment
from tests.test_source_product_core_pc2 import _PC2_TIME, _RUN_IDS, _add_run

pytestmark = pytest.mark.postgres


@pytest.fixture
def postgres_effective(tmp_path: Path):
    database_url = validated_postgres_test_url()
    _reset(database_url)
    environment = _Environment(tmp_path, database_url=database_url)
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
    reports = {str(_RUN_ID): report}
    lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    finding_id = report.findings[0].finding_id
    clock = _Clock(_NOW)
    context = {
        "pc2": (environment, index, lifecycle, lineage, reports),
        "environment": environment,
        "lifecycle": lifecycle,
        "lineage_id": lineage.lineage_id,
        "finding_id": finding_id,
        "project_id": project_id,
        "clock": clock,
        "governance": SourceFindingGovernanceService(environment.factory, clock=clock),
        "suppression": SourceFindingSuppressionService(environment.factory, clock=clock),
        "effective": EffectiveGovernanceService(environment.factory, clock=clock),
    }
    try:
        yield context
    finally:
        environment.close()
        _reset(database_url)


def test_postgres_reopen_dormancy_and_reaffirmation_with_equal_timestamps(
    postgres_effective, monkeypatch
) -> None:
    postgres_effective["clock"].value = _INDEXED_AT + timedelta(days=2)
    _govern(
        postgres_effective,
        AnalystDisposition.FALSE_POSITIVE,
        reason="historical false positive",
    )
    old_suppression = _suppress(
        postgres_effective,
        reason="historical suppression",
        expiry=_NOW + timedelta(days=90),
    )
    _resolve_and_reopen(postgres_effective, monkeypatch)
    historical = _read(postgres_effective)
    assert historical.lifecycle_state is FindingLifecycleState.REOPENED
    assert historical.false_positive_effective is False
    assert historical.suppression_effective is False
    assert historical.review_required is True

    _govern(
        postgres_effective,
        AnalystDisposition.FALSE_POSITIVE,
        reason="same value reaffirmed",
        revision=1,
    )
    new_suppression = _suppress(
        postgres_effective,
        reason="new lifecycle episode",
        expiry=_NOW + timedelta(days=91),
        revision=1,
    )
    assert new_suppression.suppression_id != old_suppression.suppression_id
    current = _read(postgres_effective)
    assert current.false_positive_effective is True
    assert current.suppression_effective is True
    assert current.review_required is False
    assert current.governance_lifecycle_transition_version == 3
    assert current.suppression_lifecycle_transition_version == 3


def test_postgres_legacy_null_markers_are_dormant_after_reopen(
    postgres_effective, monkeypatch
) -> None:
    _govern(
        postgres_effective,
        AnalystDisposition.ACCEPTED_RISK,
        reason="legacy risk",
        expiry=_NOW + timedelta(days=60),
    )
    _suppress(postgres_effective, expiry=_NOW + timedelta(days=60))
    with postgres_effective["environment"].factory.begin() as session:
        governance_event = session.scalar(select(SourceFindingGovernanceEventRow))
        suppression_event = session.scalar(select(SourceFindingSuppressionEventRow))
        assert governance_event is not None and suppression_event is not None
        governance_event.lifecycle_transition_version = None
        suppression_event.lifecycle_transition_version = None
    assert _read(postgres_effective).accepted_risk_effective is True

    _resolve_and_reopen(postgres_effective, monkeypatch)
    state = _read(postgres_effective)
    assert state.accepted_risk_effective is False
    assert state.suppression_effective is False
    assert state.review_required is True


def _race(barrier: threading.Barrier, operation):
    barrier.wait()
    return operation()


def test_postgres_resolution_and_governance_mutation_serialize(
    postgres_effective, monkeypatch
) -> None:
    _add_run(
        postgres_effective["pc2"],
        monkeypatch,
        _RUN_IDS[0],
        present=False,
        ordinal=2,
    )
    barrier = threading.Barrier(2)
    with ThreadPoolExecutor(max_workers=2) as pool:
        lifecycle_future = pool.submit(
            _race,
            barrier,
            lambda: postgres_effective["lifecycle"].evaluate(
                lineage_id=postgres_effective["lineage_id"], run_id=_RUN_IDS[0]
            ),
        )
        governance_future = pool.submit(
            _race,
            barrier,
            lambda: _govern(
                postgres_effective,
                AnalystDisposition.FALSE_POSITIVE,
                reason="concurrent decision",
            ),
        )
        lifecycle_future.result()
        governance_future.result()
    state = _read(postgres_effective)
    assert state.lifecycle_state is FindingLifecycleState.RESOLVED
    assert state.false_positive_effective is False
    assert state.governance_lifecycle_transition_version in {1, 2}


def test_postgres_resolution_and_suppression_mutation_serialize(
    postgres_effective, monkeypatch
) -> None:
    _add_run(
        postgres_effective["pc2"],
        monkeypatch,
        _RUN_IDS[0],
        present=False,
        ordinal=2,
    )
    barrier = threading.Barrier(2)
    with ThreadPoolExecutor(max_workers=2) as pool:
        lifecycle_future = pool.submit(
            _race,
            barrier,
            lambda: postgres_effective["lifecycle"].evaluate(
                lineage_id=postgres_effective["lineage_id"], run_id=_RUN_IDS[0]
            ),
        )
        suppression_future = pool.submit(
            _race,
            barrier,
            lambda: _suppress(postgres_effective, reason="concurrent suppression"),
        )
        lifecycle_future.result()
        suppression_future.result()
    state = _read(postgres_effective)
    assert state.lifecycle_state is FindingLifecycleState.RESOLVED
    assert state.suppression_effective is False
    assert state.suppression_lifecycle_transition_version in {1, 2}


def test_postgres_reads_see_atomic_governance_suppression_and_revocation(
    postgres_effective,
) -> None:
    barrier = threading.Barrier(2)
    with ThreadPoolExecutor(max_workers=2) as pool:
        read_future = pool.submit(_race, barrier, lambda: _read(postgres_effective))
        write_future = pool.submit(
            _race,
            barrier,
            lambda: _govern(
                postgres_effective,
                AnalystDisposition.FALSE_POSITIVE,
                reason="concurrent governance",
            ),
        )
        observed = read_future.result()
        write_future.result()
    assert (observed.disposition_revision, observed.false_positive_effective) in {
        (0, False),
        (1, True),
    }

    barrier = threading.Barrier(2)
    with ThreadPoolExecutor(max_workers=2) as pool:
        read_future = pool.submit(_race, barrier, lambda: _read(postgres_effective))
        write_future = pool.submit(
            _race,
            barrier,
            lambda: _suppress(postgres_effective, reason="concurrent suppression"),
        )
        observed = read_future.result()
        created = write_future.result()
    assert (observed.suppression_revision, observed.suppression_effective) in {
        (0, False),
        (1, True),
    }

    barrier = threading.Barrier(2)
    with ThreadPoolExecutor(max_workers=2) as pool:
        read_future = pool.submit(_race, barrier, lambda: _read(postgres_effective))
        revoke_future = pool.submit(
            _race,
            barrier,
            lambda: postgres_effective["suppression"].revoke(
                project_id=postgres_effective["project_id"],
                lineage_id=postgres_effective["lineage_id"],
                finding_id=postgres_effective["finding_id"],
                expected_revision=created.revision,
            ),
        )
        observed = read_future.result()
        revoke_future.result()
    assert (observed.suppression_revision, observed.suppression_effective) in {
        (1, True),
        (2, False),
    }


def test_postgres_same_finding_id_isolated_by_lineage_and_project(
    postgres_effective,
) -> None:
    environment = postgres_effective["environment"]
    lineage_a = postgres_effective["lineage_id"]
    finding_id = postgres_effective["finding_id"]
    project_b = "77777777-7777-4777-8777-777777777771"
    target_b = "77777777-7777-4777-8777-777777777772"
    run_b = "77777777-7777-4777-8777-777777777773"
    lineage_b = "77777777-7777-4777-8777-777777777774"
    with environment.factory.begin() as session:
        original = session.get(SourceFindingLifecycleRow, (lineage_a, finding_id))
        assert original is not None
        session.add(ProjectRow(id=project_b, name="isolated-effective-project", created_at=_NOW))
        session.flush()
        session.add(
            TargetRow(
                id=target_b,
                project_id=project_b,
                target_type="source_repository",
                content_digest="5" * 64,
                source_path="securescan-effective-isolated",
                metadata_json={},
                created_at=_NOW,
            )
        )
        session.flush()
        session.add(
            AnalysisRunRow(
                id=run_b,
                target_id=target_b,
                status="completed",
                report_json={},
                created_at=_NOW,
            )
        )
        session.flush()
        session.add(
            SourceTargetLineageRow(lineage_id=lineage_b, project_id=project_b, created_at=_NOW)
        )
        session.flush()
        session.add(
            SourceLineageRunRow(
                run_id=run_b,
                lineage_id=lineage_b,
                sequence_number=1,
                predecessor_run_id=None,
                predecessor_sequence_number=None,
                report_artifact_sha256="5" * 64,
                report_artifact_size_bytes=1,
                report_schema_version="securescan-unified-evidence-s4-v1",
                indexing_state="INDEXED",
                indexed_at=_NOW,
                lifecycle_evaluated_at=_NOW,
                lifecycle_evaluation_sha256="4" * 64,
                lifecycle_event_count=1,
                created_at=_NOW,
            )
        )
        session.flush()
        session.add(
            SourceFindingLifecycleRow(
                lineage_id=lineage_b,
                finding_id=finding_id,
                authority=original.authority,
                category=original.category,
                native_identity_schema=original.native_identity_schema,
                current_state="NEW",
                first_seen_run_id=run_b,
                last_seen_run_id=run_b,
                resolved_run_id=None,
                first_seen_at=_NOW,
                last_seen_at=_NOW,
                resolved_at=None,
                transition_version=1,
            )
        )
    _govern(
        postgres_effective,
        AnalystDisposition.FALSE_POSITIVE,
        reason="project A only",
    )
    isolated = postgres_effective["effective"].get(
        project_id=project_b,
        lineage_id=lineage_b,
        finding_id=finding_id,
    )
    assert isolated.disposition is AnalystDisposition.UNREVIEWED
    assert isolated.false_positive_effective is False
    assert isolated.suppression_present is False
