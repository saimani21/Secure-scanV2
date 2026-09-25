from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import func, select
from test_source_orchestration_s6a import _NOW, _RUN_ID
from test_source_orchestration_s6b import _LEASE_TOKEN, _Environment

from securescan.advisories.osv import (
    OsvAdvisoryObservation,
    OsvAdvisoryReference,
    OsvCandidateMatch,
    build_osv_query_candidates,
    evaluate_syft_packages,
)
from securescan.benchmarks.syft_inventory import _execute, corpus_identity
from securescan.cli.source import SourceRepositoryProfilePlanner
from securescan.domain.enums import ExecutionOutcome
from securescan.evidence import adapt_osv_analysis, adapt_syft_result
from securescan.execution import CancellableProcessExecutor
from securescan.orchestration.dependency_evaluation import (
    DependencyEvaluationDecision,
    SourceDependencyEvaluationService,
)
from securescan.orchestration.execution_models import SafeSourceNativeResult
from securescan.orchestration.models import SourceAuthority, frozen_source_v1_authority_roster
from securescan.orchestration.osv_execution import (
    SafeSourceOsvResult,
    SourceOsvJobService,
)
from securescan.orchestration.service import orchestration_request_digest
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationRow,
    SourceOrchestrationScannerJobRow,
)
from securescan.product_core.dependencies import (
    DependencyProjectionMaterial,
    resolve_dependency_summaries,
)
from securescan.scanners.semgrep.source_execution import SourceProjectionExecutionReference
from securescan.scanners.syft import (
    TrustedSyftBinding,
    create_default_syft_binding,
    parse_syft_json,
)
from securescan.source import (
    EnryBatchResult,
    EnryClassification,
    EnryFileInput,
    SourcePlanAction,
    TrustedEnryHelper,
    TrustedSourceAnalyzer,
    TrustedSourceAnalyzerRegistry,
)
from securescan.source.execution_context import SourceExecutionContext
from securescan.workspaces import RepositoryWorkspaceManager

_ROOT = Path(__file__).resolve().parents[1]
_CORPUS = _ROOT / "tests/fixtures/syft/v11p"


def _binding() -> TrustedSyftBinding:
    executable = os.environ.get("SECURESCAN_SYFT_EXECUTABLE")
    if executable is None:
        pytest.skip("trusted Syft real-binary replay is opt-in")
    binding = create_default_syft_binding(Path(executable).resolve(strict=True))
    binding.verify_runtime()
    return binding


class _Enry:
    configuration = TrustedEnryHelper(
        helper_path=Path("/trusted/enry-helper"), expected_sha256="e" * 64
    )

    def classify(self, files: tuple[EnryFileInput, ...]) -> EnryBatchResult:
        return EnryBatchResult(
            classifications=tuple(
                EnryClassification(
                    relative_path=item.relative_path,
                    language=None,
                    candidate_languages=(),
                    is_binary=False,
                    is_vendor=False,
                    is_generated=False,
                    is_test=False,
                    is_configuration=False,
                    is_documentation=False,
                    is_dot_file=False,
                    is_image=False,
                )
                for item in files
            ),
            helper_sha256="e" * 64,
            helper_version="0.2.3",
            enry_version="v2.9.6",
            duration_ms=1,
        )


def _registry() -> TrustedSourceAnalyzerRegistry:
    return TrustedSourceAnalyzerRegistry(
        analyzers=tuple(
            sorted(
                (
                    TrustedSourceAnalyzer(
                        authority.analyzer_id,
                        (authority.capability,),
                        True,
                    )
                    for authority in frozen_source_v1_authority_roster().authorities
                ),
                key=lambda analyzer: analyzer.analyzer_id,
            )
        )
    )


def _production_profile_plan(tmp_path: Path, content: bytes):
    source = tmp_path / "planning-source"
    source.mkdir(parents=True)
    (source / "requirements.txt").write_bytes(content)
    manager = RepositoryWorkspaceManager(tmp_path / "planning-workspaces")
    workspace = manager.prepare_repository(source)
    try:
        return SourceRepositoryProfilePlanner(
            lambda: _Enry(),  # type: ignore[return-value]
            _registry,
        ).build(workspace)
    finally:
        manager.cleanup_workspace(workspace)


def _environment(tmp_path: Path, content: bytes) -> _Environment:
    profile, plan = _production_profile_plan(tmp_path, content)
    advisory = next(
        entry
        for entry in plan.entries
        if entry.capability.value == "dependency_advisory_matching"
    )
    assert advisory.action is SourcePlanAction.RUN
    assert advisory.selected_paths == ("requirements.txt",)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    environment = _Environment(
        runtime,
        profile=profile,
        plan=plan,
        source_files={"requirements.txt": content},
    )
    deadline = datetime(2099, 1, 1, tzinfo=UTC)
    with environment.factory.begin() as session:
        parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        assert parent is not None and run is not None
        parent.deadline_at = deadline
        parent.creation_request_digest = orchestration_request_digest(
            target_id=run.target_id,
            idempotency_key=parent.idempotency_key,
            deadline_iso=deadline.isoformat(),
            profile_digest=parent.profile_digest,
            plan_digest=parent.plan_digest,
            roster_digest=parent.roster_digest,
        )
    return environment


def _execute_bound_syft(environment: _Environment, binding: TrustedSyftBinding):
    syft = next(
        item for item in environment.snapshot.nodes if item.authority is SourceAuthority.SYFT
    )
    _node, job, _attempt = environment.start_attempt(SourceAuthority.SYFT)
    assert binding.binding_digest() == syft.contract_digest
    with environment.factory() as session:
        mapping = session.get(SourceOrchestrationScannerJobRow, job.job_id)
        assert mapping is not None
        context = SourceExecutionContext.from_json(
            environment.store.read_by_sha256(
                mapping.context_artifact_sha256,
                expected_size_bytes=mapping.context_artifact_size_bytes,
            )
        )
    projection = environment.projections.reopen_projection(
        job.projection_id,
        expected_context_digest=job.context_digest,
        expected_projection_digest=job.projection_digest,
    )
    handle = binding.start_directory_execution(
        projection.source_directory,
        CancellableProcessExecutor(),
    )
    with handle:
        process = handle.wait(timeout_seconds=305)
    assert process is not None
    assert process.return_code == 0
    assert process.stderr == b""
    assert process.timed_out is False
    assert process.output_limit_exceeded is False
    assert process.termination_requested is False
    assert process.force_killed is False
    parsed = parse_syft_json(
        process.stdout,
        expected_source_root=str(projection.source_directory),
        authorized_paths=frozenset(
            item.relative_path for item in projection.manifest.entries
        ),
        projection_id=job.projection_id,
        snapshot_digest=job.projection_digest,
        binding_digest=syft.contract_digest,
    )
    native = SafeSourceNativeResult.from_parse_result(
        result=parsed,
        node_id=syft.node_id,
        job_id=job.job_id,
        attempt_number=1,
        authority=SourceAuthority.SYFT.value,
        analyzer_id=syft.analyzer_id,
        context=context,
    )
    environment.attempts.accept_result(
        native,
        lease_token=_LEASE_TOKEN,
        execution_outcome=(
            ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS
            if parsed.observations
            else ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS
        ),
        return_code=0,
        duration_ms=1,
    )
    reference = SourceProjectionExecutionReference(
        projection_id=projection.projection_id,
        context_digest=projection.context_digest,
        projection_digest=projection.projection_digest,
    )
    return parsed, context, reference


class _FakeOsv:
    def __init__(self, *, vulnerable: bool) -> None:
        self._vulnerable = vulnerable

    def query(self, candidates):
        matches = []
        for candidate in candidates:
            if not self._vulnerable:
                matches.append(OsvCandidateMatch(candidate, (), ()))
                continue
            advisory = OsvAdvisoryObservation(
                osv_record_id="GHSA-8q59-q68h-6hv4",
                modified="2026-02-04T03:33:10Z",
                published="2021-03-25T21:26:26Z",
                aliases=("CVE-2020-14343",),
                cve_aliases=("CVE-2020-14343",),
                ghsa_aliases=("GHSA-8q59-q68h-6hv4",),
                summary="Controlled offline advisory",
                applicable_package_key=candidate.package_key,
                fixed_versions=("5.4",),
                cvss=(),
            )
            reference = OsvAdvisoryReference(advisory.osv_record_id, advisory.modified)
            matches.append(OsvCandidateMatch(candidate, (reference,), (advisory,)))
        return tuple(matches)


def _project_dependency_case(
    environment: _Environment,
    parsed,
    context: SourceExecutionContext,
    projection: SourceProjectionExecutionReference,
    *,
    vulnerable: bool,
):
    osv = next(
        item for item in environment.snapshot.nodes if item.authority is SourceAuthority.OSV
    )
    evaluations = SourceDependencyEvaluationService(
        environment.factory,
        environment.store,
        clock=lambda: _NOW,
    )
    record = evaluations.evaluate(run_id=str(_RUN_ID), osv_node_id=osv.node_id)
    assert record.evaluation.decision is DependencyEvaluationDecision.OSV_RUN_REQUIRED
    jobs = SourceOsvJobService(environment.factory, environment.store, evaluations)
    job = jobs.create_job(run_id=str(_RUN_ID), node_id=osv.node_id)
    execution_input = jobs.load_input(job_id=job.job_id)
    analysis = evaluate_syft_packages(parsed, _FakeOsv(vulnerable=vulnerable))
    accepted = SafeSourceOsvResult.from_analysis(
        execution_input,
        attempt_number=1,
        analysis=analysis,
    )
    syft_fragment = adapt_syft_result(parsed, context=context, projection=projection)
    osv_fragment = adapt_osv_analysis(analysis, scope=syft_fragment.scope)
    report = {
        "scope": syft_fragment.scope.canonical_data(),
        "components": [item.canonical_data() for item in syft_fragment.components],
        "evidence": [
            item.canonical_data()
            for item in (*syft_fragment.evidence, *osv_fragment.evidence)
        ],
        "findings": [item.canonical_data() for item in osv_fragment.findings],
        "coverage_outcomes": [
            item.canonical_data()
            for item in (
                *syft_fragment.coverage_outcomes,
                *osv_fragment.coverage_outcomes,
            )
        ],
    }
    priorities = {item.finding_id: "HIGH" for item in osv_fragment.findings}
    dependencies = resolve_dependency_summaries(
        report,
        priorities,
        DependencyProjectionMaterial(
            evaluation=record.evaluation,
            evaluation_sha256=record.artifact_sha256,
            execution_input=execution_input,
            accepted_result=accepted,
        ),
    )
    return record, execution_input, dependencies


def test_frozen_syft_exact_nonexact_and_mixed_requirements_are_deterministic() -> None:
    binding = _binding()
    expected = {
        "exact": {
            ("flask", "3.0.0", "pkg:pypi/flask@3.0.0"),
            ("pyyaml", "5.3.1", "pkg:pypi/pyyaml@5.3.1"),
            ("requests", "2.31.0", "pkg:pypi/requests@2.31.0"),
        },
        "nonexact": set(),
        "mixed": {("pyyaml", "5.3.1", "pkg:pypi/pyyaml@5.3.1")},
    }
    for name, coordinates in expected.items():
        root = _CORPUS / name
        digest, paths = corpus_identity(root)
        first = _execute(binding, root, snapshot_digest=digest, paths=paths)
        second = _execute(binding, root, snapshot_digest=digest, paths=paths)
        assert first.canonical_json() == second.canonical_json()
        assert {
            (item.package_name, item.package_version, item.purl)
            for item in first.observations
        } == coordinates
        candidates, gaps = build_osv_query_candidates(first.observations)
        assert len(candidates) == len(coordinates)
        assert gaps == ()


def test_mixed_requirements_only_projects_the_exact_vulnerable_pin(
    tmp_path: Path,
) -> None:
    content = b"PyYAML==5.3.1\nrequests>=2.31\nFlask\n"
    environment = _environment(tmp_path, content)
    try:
        parsed, context, projection = _execute_bound_syft(environment, _binding())
        assert [item.package_name for item in parsed.observations] == ["pyyaml"]
        record, execution_input, dependencies = _project_dependency_case(
            environment,
            parsed,
            context,
            projection,
            vulnerable=True,
        )
        assert len(record.evaluation.eligible_package_observation_ids) == 1
        assert len(execution_input.candidates) == 1
        assert execution_input.candidates[0].purl == "pkg:pypi/pyyaml@5.3.1"
        assert len(dependencies) == 1
        assert dependencies[0].vulnerability_evaluation == "COMPLETE"
        assert dependencies[0].known_vulnerability_count == 1
        assert len(dependencies[0].advisories) == 1
    finally:
        environment.close()


def test_exact_clean_requirement_projects_complete_zero(
    tmp_path: Path,
) -> None:
    content = b"securescan-syft-fixture==1.0.0\n"
    environment = _environment(tmp_path, content)
    try:
        parsed, context, projection = _execute_bound_syft(environment, _binding())
        assert len(parsed.observations) == 1
        assert parsed.observations[0].purl == "pkg:pypi/securescan-syft-fixture@1.0.0"
        _record, execution_input, dependencies = _project_dependency_case(
            environment,
            parsed,
            context,
            projection,
            vulnerable=False,
        )
        assert len(execution_input.candidates) == 1
        assert len(dependencies) == 1
        assert dependencies[0].vulnerability_evaluation == "COMPLETE"
        assert dependencies[0].known_vulnerability_count == 0
        assert dependencies[0].advisories == ()
    finally:
        environment.close()


def test_nonexact_requirements_follow_existing_no_packages_contract(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path, b"PyYAML>=5.3\nFlask\n")
    try:
        parsed, _context, _projection = _execute_bound_syft(environment, _binding())
        assert parsed.observations == ()
        osv = next(
            item
            for item in environment.snapshot.nodes
            if item.authority is SourceAuthority.OSV
        )
        record = SourceDependencyEvaluationService(
            environment.factory,
            environment.store,
            clock=lambda: _NOW,
        ).evaluate(run_id=str(_RUN_ID), osv_node_id=osv.node_id)
        assert record.evaluation.decision is (
            DependencyEvaluationDecision.NOT_APPLICABLE_NO_PACKAGES
        )
        with environment.factory() as session:
            node = session.get(SourceOrchestrationNodeRow, osv.node_id)
            assert node is not None
            assert node.terminal_disposition == "NOT_APPLICABLE"
            assert node.terminal_reason_code == "NO_PACKAGES_OBSERVED"
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(JobRow)
                    .where(JobRow.adapter_id == SourceAuthority.OSV.value)
                )
                == 0
            )
    finally:
        environment.close()
