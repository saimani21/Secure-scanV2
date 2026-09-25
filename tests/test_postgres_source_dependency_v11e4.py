from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from fastapi import HTTPException
from postgres_test_guard import validated_postgres_test_url
from sqlalchemy import create_engine, event, func, select, text

from securescan.advisories.osv import (
    OsvAdvisoryObservation,
    OsvAdvisoryReference,
    OsvCandidateMatch,
    OsvDependencyAnalysis,
    TrustedOsvClient,
    group_advisories,
)
from securescan.api.source_scan_routes import list_dependencies
from securescan.api.source_scan_schemas import DependencyPageResponse
from securescan.domain.enums import ExecutionOutcome, JobStatus
from securescan.orchestration.assembly import SourceResultAssemblyService
from securescan.orchestration.coordinator import SourceOrchestrationCoordinatorService
from securescan.orchestration.dependency_evaluation import (
    SourceDependencyEvaluationService,
)
from securescan.orchestration.execution import SourceScannerAttemptService
from securescan.orchestration.execution_models import (
    AttemptContainmentOutcome,
    SourceSandboxCleanupReceipt,
    source_sandbox_execution_identity,
)
from securescan.orchestration.models import (
    OrchestrationLifecycleState,
    SourceAuthority,
    frozen_source_v1_authority_roster,
    orchestration_request_digest,
)
from securescan.orchestration.osv_execution import (
    SafeSourceOsvResult,
    SourceOsvAttemptService,
    SourceOsvFailureCode,
    SourceOsvJobService,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    SourceFindingLifecycleEventRow,
    SourceFindingLifecycleRow,
    SourceFindingOccurrenceRow,
    SourceLineageRunRow,
    SourceOrchestrationDependencyEvaluationRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationRow,
    SourceOrchestrationScannerJobRow,
    SourceScanSubmissionRow,
    TargetRow,
)
from securescan.product_core import (
    SourceProductFinalizationRunner,
    SourceScanQueryPersistenceError,
    SourceScanQueryService,
    SourceScanSubmissionService,
)
from securescan.scanners.syft import PackageObservation
from securescan.source.enums import AnalysisCapability
from tests.test_source_dependency_evaluation_s6ca import (
    _finish_existing_syft,
    _nodes,
)
from tests.test_source_orchestration_s6a import _fixture_profile
from tests.test_source_orchestration_s6b import (
    _DEADLINE,
    _LEASE_TOKEN,
    _NOW,
    _RUN_ID,
    _Environment,
)
from tests.test_source_osv_execution_s6cb import (
    _LEASE,
    _clean,
    _start_osv_attempt,
)
from tests.test_source_product_core_pc1 import _INDEXED_AT

pytestmark = pytest.mark.postgres
_E4_DEADLINE = datetime(2099, 1, 1, tzinfo=UTC)


@dataclass(repr=False, slots=True)
class _PostgresDatabase:
    url: str

    def __repr__(self) -> str:
        return "_PostgresDatabase(<redacted>)"


@dataclass
class _Context:
    environment: _Environment
    queries: SourceScanQueryService
    run_id: str


def _reset(database_url: str) -> None:
    engine = create_engine(database_url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
    finally:
        engine.dispose()


@pytest.fixture
def postgres_database() -> _PostgresDatabase:
    database_url = validated_postgres_test_url()
    _reset(database_url)
    try:
        yield _PostgresDatabase(database_url)
    finally:
        _reset(database_url)


def _observations(environment: _Environment, count: int, *, outside: bool = False):
    syft, _osv = _nodes(environment)
    _node, job, _attempt = environment.start_attempt(SourceAuthority.SYFT)
    values = tuple(
        PackageObservation.create(
            package_name=f"e4-package-{ordinal:04d}",
            package_version="1.0.0",
            package_type="python",
            language="python",
            purl=f"pkg:pypi/e4-package-{ordinal:04d}@1.0.0",
            found_by="python-package-cataloger",
            locations=(("app.py",) if outside else ("requirements.lock",)),
            projection_id=job.projection_id,
            snapshot_digest=job.projection_digest,
            binding_digest=syft.contract_digest,
        )
        for ordinal in range(count)
    )
    return syft, job, values


def _accept_other_authorities(environment: _Environment) -> None:
    for authority in (
        SourceAuthority.GITLEAKS,
        SourceAuthority.CHECKOV,
        SourceAuthority.SEMGREP,
    ):
        if authority is SourceAuthority.SEMGREP:
            node, job = environment.create(authority)
            with environment.factory.begin() as session:
                durable = session.get(JobRow, job.job_id)
                assert durable is not None
                durable.status = JobStatus.RUNNING.value
                durable.attempt_count = 1
                durable.leased_by = "worker-e4"
                durable.lease_token = _LEASE_TOKEN
                durable.lease_expires_at = _DEADLINE
                durable.started_at = _NOW
            attempt = environment.attempts.register_attempt(
                job_id=job.job_id,
                worker_id="worker-e4",
                lease_token=_LEASE_TOKEN,
            )
            environment.attempts.record_sandbox_cleanup(
                SourceSandboxCleanupReceipt(
                    job_id=job.job_id,
                    attempt_number=attempt.attempt_number,
                    attempt_token=attempt.attempt_token,
                    execution_backend="docker-sandbox",
                    execution_id=job.job_id,
                    sandbox_identity=source_sandbox_execution_identity(
                        job.job_id, attempt.attempt_number, attempt.attempt_token
                    ),
                    cleanup_outcome=AttemptContainmentOutcome.CLEAN,
                    execution_removed=True,
                )
            )
        else:
            node, job, _attempt = environment.start_attempt(authority)
        environment.attempts.accept_result(
            environment.native_result(node, job),
            lease_token=_LEASE_TOKEN,
            execution_outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
            return_code=0,
            duration_ms=1,
        )


def _install_attempt_service(environment: _Environment) -> None:
    tokens = iter(
        UUID(f"bbbbbbbb-bbbb-4bbb-8bbb-{value:012d}") for value in range(1, 20)
    )
    environment.attempts = SourceScannerAttemptService(
        environment.factory,
        environment.store,
        environment.projections,
        clock=lambda: _NOW,
        token_factory=lambda: next(tokens),
    )


def _analysis(execution_input, advisory_count: int) -> OsvDependencyAnalysis:
    matches = []
    findings = []
    for position, candidate in enumerate(execution_input.candidates):
        advisories = ()
        references = ()
        if position == 0 and advisory_count:
            advisories = tuple(
                OsvAdvisoryObservation(
                    osv_record_id=f"OSV-E4-{ordinal}",
                    modified=f"2026-09-{ordinal:02d}T00:00:00Z",
                    published="2026-08-01T00:00:00Z",
                    aliases=(
                        f"CVE-2026-{10000 + ordinal}",
                        f"GHSA-2345-6789-{('cfgh' if ordinal == 1 else 'jmpq')}",
                    ),
                    cve_aliases=(f"CVE-2026-{10000 + ordinal}",),
                    ghsa_aliases=(
                        f"GHSA-2345-6789-{('cfgh' if ordinal == 1 else 'jmpq')}",
                    ),
                    summary=f"E4 advisory {ordinal}",
                    applicable_package_key=candidate.package_key,
                    fixed_versions=(f"1.0.{ordinal}",),
                    cvss=(),
                )
                for ordinal in range(1, advisory_count + 1)
            )
            references = tuple(
                OsvAdvisoryReference(item.osv_record_id, item.modified)
                for item in advisories
            )
            findings.extend(group_advisories(candidate, advisories))
        matches.append(OsvCandidateMatch(candidate, references, advisories))
    candidate_ids = tuple(item.candidate_id for item in execution_input.candidates)
    return OsvDependencyAnalysis(
        candidates=execution_input.candidates,
        gaps=(),
        candidate_matches=tuple(matches),
        findings=tuple(sorted(findings, key=lambda item: item.finding_id)),
        completed_candidate_ids=candidate_ids,
        zero_advisory_candidate_ids=tuple(
            item.candidate.candidate_id for item in matches if not item.references
        ),
    )


def _finalize(environment: _Environment) -> _Context:
    coordinator = SourceOrchestrationCoordinatorService(
        environment.factory,
        environment.store,
        frozen_source_v1_authority_roster(),
        environment.projections,
    )
    state = coordinator.advance(run_id=str(_RUN_ID), workspace=environment.workspace)
    assert state.lifecycle_state is OrchestrationLifecycleState.ASSEMBLY_READY
    SourceResultAssemblyService(
        environment.factory, environment.store, clock=lambda: _INDEXED_AT
    ).assemble_and_publish(str(_RUN_ID))
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
        clock=lambda: _INDEXED_AT,
    )
    lineage = submissions.create_lineage(project_id=project_id)
    submissions.reserve(
        run_id=str(_RUN_ID),
        lineage_id=lineage.lineage_id,
        intake_ref=environment.workspace.workspace_id,
    )
    result = SourceProductFinalizationRunner(
        environment.factory, submissions
    ).finalize_ready()
    assert result.finalized_count == 1
    return _Context(
        environment,
        SourceScanQueryService(environment.factory, environment.store),
        str(_RUN_ID),
    )


def _build(
    root: Path,
    database_url: str,
    *,
    count: int = 1,
    mode: str = "clean",
) -> _Context:
    environment = _Environment(root, database_url=database_url)
    with environment.factory.begin() as session:
        parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        assert parent is not None and run is not None
        parent.deadline_at = _E4_DEADLINE
        parent.creation_request_digest = orchestration_request_digest(
            target_id=run.target_id,
            idempotency_key=parent.idempotency_key,
            deadline_iso=_E4_DEADLINE.isoformat(),
            profile_digest=parent.profile_digest,
            plan_digest=parent.plan_digest,
            roster_digest=parent.roster_digest,
        )
    _install_attempt_service(environment)
    _accept_other_authorities(environment)
    syft, syft_job, observations = _observations(
        environment, count, outside=mode == "outside"
    )
    _finish_existing_syft(
        environment,
        syft,
        syft_job,
        observations,
        partial=mode == "partial",
    )
    _syft, osv = _nodes(environment)
    evaluations = SourceDependencyEvaluationService(
        environment.factory, environment.store, clock=lambda: _NOW
    )
    evaluations.evaluate(run_id=str(_RUN_ID), osv_node_id=osv.node_id)
    if mode not in {"outside"}:
        jobs = SourceOsvJobService(environment.factory, environment.store, evaluations)
        created = jobs.create_job(run_id=str(_RUN_ID), node_id=osv.node_id)
        attempt = _start_osv_attempt(environment, created)
        _clean(environment, attempt)
        if mode == "failed":
            with environment.factory.begin() as session:
                job = session.get(JobRow, created.job_id)
                assert job is not None
                job.max_attempts = 1
            SourceOsvAttemptService(environment.factory, environment.store, jobs).record_failure(
                job_id=created.job_id,
                attempt_number=attempt.attempt_number,
                attempt_token=str(attempt.attempt_token),
                lease_token=_LEASE,
                failure_code=SourceOsvFailureCode.NETWORK_FAILURE,
                duration_ms=1,
            )
        else:
            execution_input = jobs.load_input(job_id=created.job_id)
            result = SafeSourceOsvResult.from_analysis(
                execution_input,
                attempt_number=attempt.attempt_number,
                analysis=_analysis(
                    execution_input,
                    2 if mode == "vulnerable" else 1 if mode == "partial" else 0,
                ),
            )
            accepted = SourceOsvAttemptService(
                environment.factory, environment.store, jobs
            ).accept_result(result, lease_token=_LEASE, duration_ms=1)
            assert accepted is True
    return _finalize(environment)


def _build_omission(
    root: Path, database_url: str, monkeypatch: pytest.MonkeyPatch
) -> _Context:
    import tests.test_source_orchestration_s6b as s6b

    profile = _fixture_profile()
    profile = replace(
        profile,
        surfaces=tuple(
            item
            for item in profile.surfaces
            if item.capability is not AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING
        ),
    )
    with monkeypatch.context() as patch:
        patch.setattr(s6b, "_fixture_profile", lambda: profile)
        environment = _Environment(root, database_url=database_url)
    with environment.factory.begin() as session:
        parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        assert parent is not None and run is not None
        parent.deadline_at = _E4_DEADLINE
        parent.creation_request_digest = orchestration_request_digest(
            target_id=run.target_id,
            idempotency_key=parent.idempotency_key,
            deadline_iso=_E4_DEADLINE.isoformat(),
            profile_digest=parent.profile_digest,
            plan_digest=parent.plan_digest,
            roster_digest=parent.roster_digest,
        )
    _install_attempt_service(environment)
    _accept_other_authorities(environment)
    syft = next(
        item for item in environment.snapshot.nodes if item.authority is SourceAuthority.SYFT
    )
    _node, syft_job, _attempt = environment.start_attempt(SourceAuthority.SYFT)
    observation = PackageObservation.create(
        package_name="e4-fallback",
        package_version="1.0.0",
        package_type="python",
        language="python",
        purl="pkg:pypi/e4-fallback@1.0.0",
        found_by="python-package-cataloger",
        locations=("requirements.lock",),
        projection_id=syft_job.projection_id,
        snapshot_digest=syft_job.projection_digest,
        binding_digest=syft.contract_digest,
    )
    _finish_existing_syft(environment, syft, syft_job, (observation,))
    return _finalize(environment)


@pytest.mark.parametrize(
    ("mode", "evaluation", "count", "reason", "advisories"),
    [
        ("clean", "COMPLETE", 0, None, 0),
        ("vulnerable", "COMPLETE", 2, None, 2),
        ("partial", "PARTIAL", None, "SYFT_PREREQUISITE_PARTIAL", 1),
        ("failed", "FAILED", None, "NETWORK_FAILURE", 0),
        ("outside", "NOT_APPLICABLE", None, "OUTSIDE_SCOPE", 0),
    ],
)
def test_postgres_semantic_and_public_api_parity(
    tmp_path: Path,
    postgres_database: _PostgresDatabase,
    mode: str,
    evaluation: str,
    count: int | None,
    reason: str | None,
    advisories: int,
) -> None:
    context = _build(tmp_path, postgres_database.url, mode=mode)
    try:
        page = context.queries.list_dependencies(context.run_id)
        dependency = page.items[0]
        response = list_dependencies(UUID(context.run_id), context.queries)
        assert response == DependencyPageResponse.model_validate(page)
        assert dependency.vulnerability_evaluation == evaluation
        assert dependency.known_vulnerability_count == count
        assert dependency.vulnerability_evaluation_reason == reason
        assert len(dependency.advisories) == advisories
        assert dependency.advisory_aliases == tuple(
            sorted(alias for item in dependency.advisories for alias in item.aliases)
        )
        assert tuple(
            item.model_dump() for item in response.items[0].advisories
        ) == tuple(
            {
                "canonical_advisory_id": item.canonical_advisory_id,
                "finding_id": item.finding_id,
                "osv_record_ids": item.osv_record_ids,
                "aliases": item.aliases,
                "cve_aliases": item.cve_aliases,
                "ghsa_aliases": item.ghsa_aliases,
                "fixed_versions": item.fixed_versions,
                "priority_band": item.priority_band,
            }
            for item in dependency.advisories
        )
        if mode == "vulnerable":
            assert len({item.canonical_advisory_id for item in dependency.advisories}) == 2
    finally:
        context.environment.close()


@pytest.mark.parametrize("package_count", [1, 100, 500, 1000])
def test_postgres_dependency_reads_remain_bounded_at_scale(
    tmp_path: Path,
    postgres_database: _PostgresDatabase,
    monkeypatch: pytest.MonkeyPatch,
    package_count: int,
) -> None:
    context = _build(tmp_path, postgres_database.url, count=package_count)
    counters = {
        "sql": 0,
        "cas": 0,
        "report": 0,
        "priority": 0,
        "evaluation": 0,
        "input": 0,
        "result": 0,
        "planning": 0,
        "locations": 0,
    }

    def count_sql(*_args: object) -> None:
        counters["sql"] += 1

    def wrap(obj, name: str, key: str) -> None:
        original = getattr(obj, name)

        def counted(*args, **kwargs):
            counters[key] += 1
            return original(*args, **kwargs)

        monkeypatch.setattr(obj, name, counted)

    projection = context.queries._dependency_projection
    wrap(context.environment.store, "read_by_sha256", "cas")
    wrap(context.queries._index, "load_verified_published_report", "report")
    wrap(context.queries, "_priorities", "priority")
    wrap(projection._evaluations, "load", "evaluation")
    wrap(projection._osv_jobs, "load_input", "input")
    wrap(projection._osv_attempts, "load_accepted_result", "result")
    wrap(projection._orchestrations, "load", "planning")
    import securescan.product_core.dependencies as dependencies

    wrap(dependencies, "_repository_paths", "locations")
    monkeypatch.setattr(
        context.queries,
        "get_stages",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("dependency reads must not reconstruct stages")
        ),
    )
    event.listen(context.environment.engine, "before_cursor_execute", count_sql)
    started = time.perf_counter()
    try:
        page = context.queries.list_dependencies(
            context.run_id, limit=min(package_count, 200), offset=0
        )
    finally:
        elapsed = time.perf_counter() - started
        event.remove(context.environment.engine, "before_cursor_execute", count_sql)
    try:
        assert page.total == package_count
        assert counters == {
            "sql": 29,
            "cas": 16,
            "report": 1,
            "priority": 1,
            "evaluation": 1,
            "input": 1,
            "result": 1,
            "planning": 0,
            "locations": package_count,
        }
        print(
            "E4_SCALE "
            f"packages={package_count} sql={counters['sql']} cas={counters['cas']} "
            f"report={counters['report']} priority={counters['priority']} "
            f"evaluation={counters['evaluation']} input={counters['input']} "
            f"result={counters['result']} planning={counters['planning']} "
            f"locations={counters['locations']} seconds={elapsed:.6f}"
        )
    finally:
        context.environment.close()


def test_postgres_zero_outcome_fallback_loads_planning_once(
    tmp_path: Path,
    postgres_database: _PostgresDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_omission(tmp_path, postgres_database.url, monkeypatch)
    counters = {
        "report": 0,
        "evaluation": 0,
        "input": 0,
        "result": 0,
        "planning": 0,
    }

    def wrap(obj, name: str, key: str) -> None:
        original = getattr(obj, name)

        def counted(*args, **kwargs):
            counters[key] += 1
            return original(*args, **kwargs)

        monkeypatch.setattr(obj, name, counted)

    projection = context.queries._dependency_projection
    wrap(context.queries._index, "load_verified_published_report", "report")
    wrap(projection._evaluations, "load", "evaluation")
    wrap(projection._osv_jobs, "load_input", "input")
    wrap(projection._osv_attempts, "load_accepted_result", "result")
    wrap(projection._orchestrations, "load", "planning")
    monkeypatch.setattr(
        context.queries,
        "get_stages",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("fallback must not use get_stages")
        ),
    )
    try:
        page = context.queries.list_dependencies(context.run_id)
        assert page.items[0].vulnerability_evaluation == "NOT_APPLICABLE"
        assert page.items[0].known_vulnerability_count is None
        assert counters == {
            "report": 1,
            "evaluation": 0,
            "input": 0,
            "result": 0,
            "planning": 1,
        }
    finally:
        context.environment.close()


def _artifact_snapshot(root: Path) -> tuple[tuple[str, str], ...]:
    return tuple(
        (path.relative_to(root).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest())
        for path in sorted(root.rglob("*"))
        if path.is_file()
    )


def _database_snapshot(context: _Context) -> tuple[object, ...]:
    with context.environment.factory() as session:
        parent = session.get(SourceOrchestrationRow, context.run_id)
        submission = session.get(SourceScanSubmissionRow, context.run_id)
        assert parent is not None and submission is not None
        tables = (
            SourceLineageRunRow,
            SourceFindingOccurrenceRow,
            SourceFindingLifecycleRow,
            SourceFindingLifecycleEventRow,
            SourceOrchestrationNodeRow,
        )
        return (
            *(
                int(session.scalar(select(func.count()).select_from(table)) or 0)
                for table in tables
            ),
            parent.lifecycle_state,
            parent.state_version,
            parent.published_at,
            submission.finalized_at,
        )


def test_postgres_pagination_determinism_read_only_confidential_and_network_free(
    tmp_path: Path,
    postgres_database: _PostgresDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build(
        tmp_path, postgres_database.url, count=100, mode="vulnerable"
    )
    monkeypatch.setattr(
        TrustedOsvClient,
        "query",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("dependency read attempted network access")
        ),
    )
    before_database = _database_snapshot(context)
    before_artifacts = _artifact_snapshot(context.environment.store.root)
    try:
        full = context.queries.list_dependencies(context.run_id, limit=200)
        first = list_dependencies(UUID(context.run_id), context.queries, limit=40, offset=0)
        second = list_dependencies(UUID(context.run_id), context.queries, limit=40, offset=40)
        repeat = list_dependencies(UUID(context.run_id), context.queries, limit=40, offset=0)
        assert full.total == first.total == second.total == 100
        assert first.limit == second.limit == 40
        assert (first.offset, second.offset) == (0, 40)
        assert first.items + second.items == DependencyPageResponse.model_validate(
            replace(full, items=full.items[:80], limit=80)
        ).items
        assert first.model_dump_json() == repeat.model_dump_json()
        rendered = first.model_dump_json() + second.model_dump_json()
        for forbidden in (
            context.environment.workspace.root_directory.as_posix(),
            context.environment.store.root.as_posix(),
            "postgresql+psycopg",
            "securescan_e4",
            "artifact_sha256",
            "storage_path",
            "node_id",
            "job_id",
            "attempt_id",
            "lease_token",
            "stdout",
            "stderr",
            "advisory_group_key",
        ):
            assert forbidden not in rendered
        assert _database_snapshot(context) == before_database
        assert _artifact_snapshot(context.environment.store.root) == before_artifacts
    finally:
        context.environment.close()


@pytest.mark.parametrize(
    "corruption",
    ["missing_priority", "evaluation_digest", "accepted_relationship", "unknown_reason"],
)
def test_postgres_dependency_integrity_fails_closed(
    tmp_path: Path,
    postgres_database: _PostgresDatabase,
    corruption: str,
) -> None:
    mode = "failed" if corruption == "unknown_reason" else "vulnerable"
    context = _build(tmp_path, postgres_database.url, mode=mode)
    with context.environment.factory.begin() as session:
        if corruption == "missing_priority":
            occurrence = session.scalar(
                select(SourceFindingOccurrenceRow).where(
                    SourceFindingOccurrenceRow.authority == SourceAuthority.OSV.value
                )
            )
            assert occurrence is not None
            occurrence.priority_band = None
            occurrence.priority_reason_codes_json = None
        elif corruption == "evaluation_digest":
            evaluation = session.scalar(select(SourceOrchestrationDependencyEvaluationRow))
            assert evaluation is not None
            evaluation.scope_digest = "0" * 64
        elif corruption == "accepted_relationship":
            mapping = session.scalar(
                select(SourceOrchestrationScannerJobRow).where(
                    SourceOrchestrationScannerJobRow.authority == SourceAuthority.OSV.value
                )
            )
            assert mapping is not None
            mapping.selected_attempt_number = None
        else:
            node = session.scalar(
                select(SourceOrchestrationNodeRow).where(
                    SourceOrchestrationNodeRow.authority == SourceAuthority.OSV.value
                )
            )
            assert node is not None
            node.terminal_reason_code = "UNKNOWN_E4_REASON"
    try:
        with pytest.raises(SourceScanQueryPersistenceError):
            context.queries.list_dependencies(context.run_id)
        with pytest.raises(HTTPException) as raised:
            list_dependencies(UUID(context.run_id), context.queries)
        assert raised.value.status_code == 503
        assert raised.value.detail == {
            "code": "QUERY_UNAVAILABLE",
            "message": "Source scan query is unavailable",
        }
    finally:
        context.environment.close()
