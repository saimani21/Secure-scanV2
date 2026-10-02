from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from securescan.adapters.trusted_registry import (
    TrustedAdapterRegistry,
    TrustedAdapterResolver,
)
from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.config import Settings
from securescan.domain.enums import JobFailureCategory, JobStatus, TargetType
from securescan.execution import CancellableProcessResult
from securescan.jobs import (
    JobCancellationService,
    JobExecutionService,
    JobFailureCommitService,
    JobHeartbeatService,
    JobRepository,
    JobResultCommitService,
    JobSubmissionService,
)
from securescan.persistence.database import (
    JobRow,
    ProjectRow,
    TargetRow,
    create_session_factory,
    initialize_database,
)
from securescan.scanners.semgrep import (
    SOURCE_EXECUTION_PAYLOAD_KEY,
    InvalidSourceSemgrepExecutionRequestError,
    SourceExecutionEnvelope,
    SourceSemgrepSubmissionRequest,
    SourceSemgrepSubmissionService,
    TrustedSemgrepSourceBinding,
    create_semgrep_trusted_definition,
    create_source_aware_semgrep_trusted_definition,
    load_source_ruleset,
)
from securescan.source import (
    AnalysisCapability,
    AnalysisSurface,
    FileContentKind,
    RepositoryProfile,
    SourceFileFlag,
    SourceFileRecord,
    SourceFileRole,
    SourcePlanningPolicy,
    SourceProjectionManager,
    SourceSupportState,
    TrustedSourceAnalyzer,
    TrustedSourceAnalyzerRegistry,
    build_source_analysis_plan,
)
from securescan.worker import SingleJobWorkerCycle, WorkerCycleDisposition
from securescan.workspaces import RepositoryWorkspaceManager
from securescan.workspaces.models import repository_content_digest

IMAGE = f"registry.example/securescan/semgrep@sha256:{'7' * 64}"
NOW = datetime(2063, 3, 3, 3, 3, 3, tzinfo=UTC)
WORKER_ID = "source-semgrep-worker"
LEASE_TOKEN = str(UUID("00000000-0000-4000-8000-000000003c33"))
FIXTURE = Path(__file__).parent / "fixtures" / "semgrep" / "output" / "valid-findings.json"


def _process_result() -> CancellableProcessResult:
    return CancellableProcessResult(
        return_code=0,
        stdout=b"",
        stderr=b"",
        duration_ms=12,
        timed_out=False,
        output_limit_exceeded=False,
        termination_requested=False,
        force_killed=False,
    )


class _DockerHandle:
    def __init__(self) -> None:
        self.closed = False

    def poll(self):
        return _process_result()

    def terminate(self) -> None:
        raise AssertionError("completed fake execution must not be terminated")

    def kill(self) -> None:
        raise AssertionError("completed fake execution must not be killed")

    def close(self) -> None:
        self.closed = True


class _DockerExecutor:
    def __init__(self, raw: bytes | None = None) -> None:
        self.raw = raw if raw is not None else FIXTURE.read_bytes()
        self.requests = []
        self.visible_files: list[tuple[str, ...]] = []
        self.handles: list[_DockerHandle] = []

    def start(self, request):
        self.requests.append(request)
        self.visible_files.append(
            tuple(
                sorted(
                    path.relative_to(request.source_directory).as_posix()
                    for path in request.source_directory.rglob("*")
                    if path.is_file()
                )
            )
        )
        (request.output_directory / "semgrep-results.json").write_bytes(self.raw)
        handle = _DockerHandle()
        self.handles.append(handle)
        return handle

    def execute(self, request):
        self.requests.append(request)
        self.visible_files.append(
            tuple(
                sorted(
                    path.relative_to(request.source_directory).as_posix()
                    for path in request.source_directory.rglob("*")
                    if path.is_file()
                )
            )
        )
        (request.output_directory / "semgrep-results.json").write_bytes(self.raw)
        return _process_result()


class _LeasePublishedJob:
    def __init__(self, session_factory, job_id: str) -> None:
        self._session_factory = session_factory
        self._job_id = job_id

    def lease_next_job(self, *, worker_id: str, lease_seconds: int):
        assert (worker_id, lease_seconds) == (WORKER_ID, 30)
        with self._session_factory.begin() as session:
            row = session.get(JobRow, self._job_id)
            assert row is not None
            row.status = JobStatus.LEASED.value
            row.leased_by = WORKER_ID
            row.lease_token = LEASE_TOKEN
            row.lease_expires_at = NOW + timedelta(seconds=30)
            row.heartbeat_at = NOW
            row.attempt_count += 1
            row.updated_at = NOW
        return JobRepository(self._session_factory).get_job(self._job_id)


@dataclass
class _Environment:
    session_factory: object
    store: ContentAddressedArtifactStore
    source_repository: Path
    source_workspace_manager: RepositoryWorkspaceManager
    source_workspace: object
    projection_manager: SourceProjectionManager
    profile: RepositoryProfile
    plan: object
    entry: object
    binding: TrustedSemgrepSourceBinding
    submission: object
    job: object

    def definition(
        self,
        tmp_path: Path,
        executor: _DockerExecutor,
        *,
        ordinary_source_resolver=lambda _run_id: Path("/ordinary/not-used"),
        workspace_manager: RepositoryWorkspaceManager | None = None,
        binding: TrustedSemgrepSourceBinding | None = None,
    ):
        trusted_binding = binding or self.binding
        return create_source_aware_semgrep_trusted_definition(
            image_reference=IMAGE,
            tool_version=trusted_binding.declared_tool_version,
            docker_executor=executor,
            workspace_manager=workspace_manager
            or RepositoryWorkspaceManager(tmp_path / "attempt-workspaces"),
            ruleset=load_source_ruleset(),
            artifact_store=self.store,
            source_resolver=ordinary_source_resolver,
            projection_manager=SourceProjectionManager(self.projection_manager.base_directory),
            binding=trusted_binding,
            clock=lambda: NOW,
        )


def _profile(workspace, *, select_ignore: bool = False):
    selected_paths = (
        (".semgrepignore", "app.py", "pkg/auth.py") if select_ignore else ("app.py", "pkg/auth.py")
    )
    records = []
    for entry in workspace.manifest.entries:
        selected = entry.relative_path in selected_paths
        flag = (
            (SourceFileFlag.TEST,)
            if entry.relative_path.startswith("tests/")
            else (SourceFileFlag.VENDORED,)
            if entry.relative_path.startswith("vendor/")
            else ()
        )
        records.append(
            SourceFileRecord(
                entry=entry,
                content_kind=FileContentKind.TEXT,
                role=(
                    SourceFileRole.CONFIGURATION
                    if entry.relative_path in {".gitignore", ".semgrepignore"}
                    else SourceFileRole.SOURCE
                ),
                flags=flag,
                eligible_capabilities=(
                    (
                        AnalysisCapability.REPOSITORY_PROFILING,
                        AnalysisCapability.SOURCE_SAST,
                    )
                    if selected
                    else (AnalysisCapability.REPOSITORY_PROFILING,)
                ),
            )
        )
    records_tuple = tuple(records)
    return RepositoryProfile(
        repository_digest=repository_content_digest(
            tuple(record.entry for record in records_tuple)
        ),
        files=records_tuple,
        surfaces=tuple(
            sorted(
                (
                    AnalysisSurface(
                        capability=AnalysisCapability.REPOSITORY_PROFILING,
                        support_state=SourceSupportState.DETECTED,
                        eligible_paths=tuple(record.relative_path for record in records_tuple),
                    ),
                    AnalysisSurface(
                        capability=AnalysisCapability.SOURCE_SAST,
                        support_state=SourceSupportState.SCANNABLE,
                        eligible_paths=selected_paths,
                    ),
                ),
                key=lambda surface: surface.capability.value,
            )
        ),
    )


def _environment(tmp_path: Path, *, select_ignore: bool = False) -> _Environment:
    source = tmp_path / "mutable-source"
    (source / "pkg").mkdir(parents=True)
    (source / "tests").mkdir()
    (source / "vendor").mkdir()
    (source / "app.py").write_text("value = eval(user_input)\n", encoding="utf-8")
    (source / "pkg" / "auth.py").write_text("password = input()\n", encoding="utf-8")
    (source / "tests" / "test_app.py").write_text("assert True\n", encoding="utf-8")
    (source / "vendor" / "lib.py").write_text("vendored = True\n", encoding="utf-8")
    (source / ".semgrepignore").write_text("app.py\n", encoding="utf-8")
    (source / ".gitignore").write_text("pkg/\n", encoding="utf-8")

    source_workspace_manager = RepositoryWorkspaceManager(tmp_path / "source-workspaces")
    source_workspace = source_workspace_manager.prepare_repository(source)
    profile = _profile(source_workspace, select_ignore=select_ignore)
    analyzer_registry = TrustedSourceAnalyzerRegistry(
        analyzers=(
            TrustedSourceAnalyzer(
                analyzer_id="semgrep-source-v1",
                capabilities=(AnalysisCapability.SOURCE_SAST,),
                available=True,
            ),
        )
    )
    plan = build_source_analysis_plan(profile, analyzer_registry, SourcePlanningPolicy())
    entry = next(item for item in plan.entries if item.capability is AnalysisCapability.SOURCE_SAST)

    placeholder_executor = _DockerExecutor()
    base_definition = create_semgrep_trusted_definition(
        image_reference=IMAGE,
        tool_version="1.171.0",
        docker_executor=placeholder_executor,
        workspace_manager=RepositoryWorkspaceManager(tmp_path / "unused-workspaces"),
        ruleset=load_source_ruleset(),
        artifact_store=ContentAddressedArtifactStore(tmp_path / "artifacts"),
        source_resolver=lambda _run_id: source,
        clock=lambda: NOW,
    )
    binding = TrustedSemgrepSourceBinding(
        definition=base_definition,
        ruleset=load_source_ruleset(),
    )

    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'bridge.db'}",
        artifact_root=tmp_path / "artifacts",
    )
    initialize_database(settings)
    _engine, session_factory = create_session_factory(settings)
    with session_factory.begin() as session:
        project = ProjectRow(name="Source bridge")
        target = TargetRow(
            project=project,
            target_type=TargetType.SOURCE_REPOSITORY.value,
            content_digest=profile.repository_digest,
            source_path=str(source),
        )
        session.add(target)
        session.flush()
        target_id = target.id

    store = ContentAddressedArtifactStore(tmp_path / "artifacts")
    projection_manager = SourceProjectionManager.initialize_base_directory(tmp_path / "projections")
    submission = SourceSemgrepSubmissionService(
        JobSubmissionService(session_factory),
        store,
        projection_manager,
        run_id_factory=lambda: UUID("00000000-0000-4000-8000-000000003c31"),
        job_id_factory=lambda: UUID("00000000-0000-4000-8000-000000003c32"),
    ).submit(
        SourceSemgrepSubmissionRequest(
            target_id=target_id,
            idempotency_key="c" * 64,
            workspace=source_workspace,
            profile=profile,
            plan=plan,
            entry=entry,
            binding=binding,
        )
    )
    job = JobRepository(session_factory).get_job(submission.job_id)
    assert job is not None
    return _Environment(
        session_factory=session_factory,
        store=store,
        source_repository=source,
        source_workspace_manager=source_workspace_manager,
        source_workspace=source_workspace,
        projection_manager=projection_manager,
        profile=profile,
        plan=plan,
        entry=entry,
        binding=binding,
        submission=submission,
        job=job,
    )


def _run(adapter, job):
    handle = adapter.start(job)
    result = handle.poll()
    assert result is not None
    handle.close()
    return result


def test_durable_source_job_reopens_projection_through_existing_worker(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    executor = _DockerExecutor()
    definition = environment.definition(tmp_path, executor)
    registry = TrustedAdapterRegistry((definition,))

    environment.source_workspace_manager.cleanup_workspace(environment.source_workspace)
    shutil.rmtree(environment.source_repository)

    cycle = SingleJobWorkerCycle(
        _LeasePublishedJob(environment.session_factory, environment.submission.job_id),
        JobExecutionService(environment.session_factory, clock=lambda: NOW),
        JobResultCommitService(environment.session_factory, clock=lambda: NOW),
        JobFailureCommitService(environment.session_factory, clock=lambda: NOW),
        TrustedAdapterResolver(registry),
        JobRepository(environment.session_factory),
        JobCancellationService(environment.session_factory, clock=lambda: NOW),
        JobHeartbeatService(environment.session_factory, clock=lambda: NOW),
        worker_id=WORKER_ID,
        lease_seconds=30,
        execution_poll_interval_seconds=0.01,
    )

    result = cycle.run_one_job()
    committed = JobRepository(environment.session_factory).get_job(environment.submission.job_id)

    assert result.disposition is WorkerCycleDisposition.SUCCEEDED
    assert committed is not None and committed.status is JobStatus.SUCCEEDED
    assert executor.visible_files == [("app.py", "pkg/auth.py")]
    assert len(executor.requests) == 1
    request = executor.requests[0]
    assert request.source_directory.parent.name.startswith("securescan-workspace-")
    assert "--no-git-ignore" in request.arguments
    assert request.arguments.count("--config=/workspace/output/.securescan-semgrep-rules.yml") == 1
    assert "auto" not in " ".join(request.arguments)
    assert executor.handles[0].closed is True
    assert list((tmp_path / "attempt-workspaces").iterdir()) == []
    assert any(environment.projection_manager.base_directory.iterdir())


def test_source_envelope_without_source_aware_resolver_fails_closed(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    executor = _DockerExecutor()
    source_calls = []

    def generic_resolver(run_id: str) -> Path:
        source_calls.append(run_id)
        return environment.source_repository

    definition = create_semgrep_trusted_definition(
        image_reference=IMAGE,
        tool_version=environment.binding.declared_tool_version,
        docker_executor=executor,
        workspace_manager=RepositoryWorkspaceManager(tmp_path / "ordinary-attempts"),
        ruleset=load_source_ruleset(),
        artifact_store=environment.store,
        source_resolver=generic_resolver,
        clock=lambda: NOW,
    )

    result = _run(definition.factory(), environment.job)

    assert result.tool_execution.failure_category is JobFailureCategory.NON_RETRYABLE_POLICY
    assert result.tool_execution.retryable is False
    assert source_calls == []
    assert executor.requests == []


@pytest.mark.parametrize("resolver_fails", (False, True))
def test_source_aware_composition_preserves_ordinary_resolution_semantics(
    tmp_path: Path,
    resolver_fails: bool,
) -> None:
    environment = _environment(tmp_path)
    ordinary = tmp_path / "ordinary-comparison"
    ordinary.mkdir()
    (ordinary / "app.py").write_text("ordinary = True\n", encoding="utf-8")
    plain_calls = []
    aware_calls = []

    def resolver(calls):
        def resolve(run_id: str) -> Path:
            calls.append(run_id)
            if resolver_fails:
                raise RuntimeError("untrusted detail must be hidden")
            return ordinary

        return resolve

    plain_executor = _DockerExecutor(b'{"results": [], "errors": []}')
    aware_executor = _DockerExecutor(b'{"results": [], "errors": []}')
    plain_definition = create_semgrep_trusted_definition(
        image_reference=IMAGE,
        tool_version=environment.binding.declared_tool_version,
        docker_executor=plain_executor,
        workspace_manager=RepositoryWorkspaceManager(tmp_path / "plain-attempts"),
        ruleset=load_source_ruleset(),
        artifact_store=environment.store,
        source_resolver=resolver(plain_calls),
        clock=lambda: NOW,
    )
    aware_definition = environment.definition(
        tmp_path / "aware",
        aware_executor,
        ordinary_source_resolver=resolver(aware_calls),
    )
    ordinary_job = replace(environment.job, payload_json={"ordinary": True})

    plain = _run(plain_definition.factory(), ordinary_job)
    aware = _run(aware_definition.factory(), ordinary_job)

    assert plain_calls == aware_calls == [ordinary_job.run_id]
    assert type(plain) is type(aware)
    assert plain.tool_execution == aware.tool_execution
    if resolver_fails:
        assert plain_executor.requests == aware_executor.requests == []
        assert plain.tool_execution.failure_category is JobFailureCategory.RETRYABLE_INFRASTRUCTURE
    else:
        assert plain.final_status == aware.final_status == JobStatus.SUCCEEDED
        assert plain.report_json["observations"] == aware.report_json["observations"]
        assert plain_executor.visible_files == aware_executor.visible_files == [("app.py",)]


def test_source_envelope_wrong_adapter_is_policy_failure_but_ordinary_is_unchanged(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    executor = _DockerExecutor()
    adapter = environment.definition(tmp_path, executor).factory()

    source_result = _run(
        adapter,
        replace(environment.job, adapter_id="other-adapter"),
    )
    ordinary_result = _run(
        adapter,
        replace(
            environment.job,
            adapter_id="other-adapter",
            payload_json={"ordinary": True},
        ),
    )

    assert source_result.tool_execution.failure_category is JobFailureCategory.NON_RETRYABLE_POLICY
    assert source_result.tool_execution.retryable is False
    assert (
        ordinary_result.tool_execution.failure_category
        is JobFailureCategory.RETRYABLE_INFRASTRUCTURE
    )
    assert ordinary_result.tool_execution.retryable is True
    assert executor.requests == []


@pytest.mark.parametrize(
    "mutation",
    (
        "missing",
        "unknown",
        "schema",
        "projection_id",
        "context_digest",
        "projection_digest",
        "disagreement",
    ),
)
def test_projection_reference_and_envelope_are_strict(
    tmp_path: Path,
    mutation: str,
) -> None:
    environment = _environment(tmp_path)
    payload = json.loads(json.dumps(environment.job.payload_json))
    envelope = payload[SOURCE_EXECUTION_PAYLOAD_KEY]
    reference = envelope["projection_reference"]
    if mutation == "missing":
        reference.pop("projection_digest")
    elif mutation == "unknown":
        reference["unknown"] = True
    elif mutation == "schema":
        reference["schema_version"] = "0.3C2"
    elif mutation == "projection_id":
        reference["projection_id"] = "/host/path"
    elif mutation == "context_digest":
        reference["context_digest"] = "not-a-digest"
    elif mutation == "projection_digest":
        reference["projection_digest"] = "not-a-digest"
    else:
        reference["context_digest"] = "0" * 64

    with pytest.raises(InvalidSourceSemgrepExecutionRequestError):
        SourceExecutionEnvelope.from_payload_json(payload)

    with pytest.raises(InvalidSourceSemgrepExecutionRequestError):
        SourceExecutionEnvelope.from_payload_json({**environment.job.payload_json, "unknown": True})


@pytest.mark.parametrize(
    "field",
    ("projection_id", "projection_digest", "context_digest"),
)
def test_tampered_durable_projection_reference_blocks_before_docker(
    tmp_path: Path,
    field: str,
) -> None:
    environment = _environment(tmp_path)
    envelope = SourceExecutionEnvelope.from_payload_json(environment.job.payload_json)
    reference = envelope.projection_reference
    if field == "projection_id":
        reference = replace(
            reference,
            projection_id="securescan-source-projection-" + "0" * 32,
        )
    elif field == "projection_digest":
        reference = replace(reference, projection_digest="0" * 64)
    else:
        payload = envelope.payload_json()
        value = payload[SOURCE_EXECUTION_PAYLOAD_KEY]
        value["context_digest"] = "0" * 64
        value["projection_reference"]["context_digest"] = "0" * 64
    if field != "context_digest":
        envelope = replace(envelope, projection_reference=reference)
        payload = envelope.payload_json()
    job = replace(environment.job, payload_json=payload)
    executor = _DockerExecutor()
    adapter = environment.definition(tmp_path, executor).factory()

    result = _run(adapter, job)

    expected = (
        JobFailureCategory.RETRYABLE_INFRASTRUCTURE
        if field == "projection_id"
        else JobFailureCategory.NON_RETRYABLE_POLICY
    )
    assert result.tool_execution.failure_category is expected
    assert executor.requests == []


@pytest.mark.parametrize("mutation", ("marker", "modified", "extra", "symlink", "hardlink"))
def test_projection_tree_tampering_is_reinventoried_before_every_attempt(
    tmp_path: Path,
    mutation: str,
) -> None:
    environment = _environment(tmp_path)
    envelope = SourceExecutionEnvelope.from_payload_json(environment.job.payload_json)
    projection = environment.projection_manager.reopen_projection(
        envelope.projection_reference.projection_id,
        expected_context_digest=envelope.projection_reference.context_digest,
        expected_projection_digest=envelope.projection_reference.projection_digest,
    )
    source = projection.source_directory
    os.chmod(projection.root_directory, 0o700)
    os.chmod(source, 0o755)
    if mutation == "marker":
        marker = projection.root_directory / ".securescan-source-projection.json"
        os.chmod(marker, 0o600)
        marker.write_text("{}", encoding="utf-8")
    elif mutation == "modified":
        target = source / "app.py"
        os.chmod(target, 0o644)
        target.write_text("changed\n", encoding="utf-8")
    elif mutation == "extra":
        (source / "extra.py").write_text("extra = True\n", encoding="utf-8")
    elif mutation == "symlink":
        (source / "link.py").symlink_to("app.py")
    else:
        os.link(source / "app.py", source / "linked.py")
    executor = _DockerExecutor()

    result = _run(environment.definition(tmp_path, executor).factory(), environment.job)

    assert result.tool_execution.failure_category is JobFailureCategory.NON_RETRYABLE_POLICY
    assert executor.requests == []


def test_missing_projection_is_retryable_and_never_rebuilt_from_original(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    envelope = SourceExecutionEnvelope.from_payload_json(environment.job.payload_json)
    projection = environment.projection_manager.reopen_projection(
        envelope.projection_reference.projection_id,
        expected_context_digest=envelope.projection_reference.context_digest,
        expected_projection_digest=envelope.projection_reference.projection_digest,
    )
    environment.projection_manager.cleanup_projection(projection)
    executor = _DockerExecutor()

    result = _run(environment.definition(tmp_path, executor).factory(), environment.job)

    assert result.tool_execution.failure_category is JobFailureCategory.RETRYABLE_INFRASTRUCTURE
    assert result.tool_execution.retryable is True
    assert executor.requests == []


def test_binding_change_and_attempt_manifest_mismatch_block_before_docker(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    executor = _DockerExecutor()
    changed_definition = create_semgrep_trusted_definition(
        image_reference=IMAGE,
        tool_version="1.172.0",
        docker_executor=executor,
        workspace_manager=RepositoryWorkspaceManager(tmp_path / "changed-unused"),
        ruleset=load_source_ruleset(),
        artifact_store=environment.store,
        source_resolver=lambda _run_id: environment.source_repository,
    )
    changed_binding = TrustedSemgrepSourceBinding(
        definition=changed_definition,
        ruleset=load_source_ruleset(),
    )

    changed_result = _run(
        environment.definition(tmp_path, executor, binding=changed_binding).factory(),
        environment.job,
    )

    class _MismatchingWorkspaceManager(RepositoryWorkspaceManager):
        def prepare_repository(self, source_directory: Path):
            workspace = super().prepare_repository(source_directory)
            return replace(
                workspace,
                manifest=replace(
                    workspace.manifest,
                    entries=workspace.manifest.entries[:-1],
                    file_count=workspace.manifest.file_count - 1,
                    total_bytes=sum(entry.size_bytes for entry in workspace.manifest.entries[:-1]),
                    content_digest=repository_content_digest(workspace.manifest.entries[:-1]),
                ),
            )

    mismatch_executor = _DockerExecutor()
    mismatch_manager = _MismatchingWorkspaceManager(tmp_path / "mismatch-attempts")
    mismatch_result = _run(
        environment.definition(
            tmp_path,
            mismatch_executor,
            workspace_manager=mismatch_manager,
        ).factory(),
        environment.job,
    )

    assert changed_result.tool_execution.failure_category is JobFailureCategory.NON_RETRYABLE_POLICY
    assert (
        mismatch_result.tool_execution.failure_category is JobFailureCategory.NON_RETRYABLE_POLICY
    )
    assert executor.requests == []
    assert mismatch_executor.requests == []
    assert list(mismatch_manager.base_directory.iterdir()) == []


def test_source_selected_ignore_file_is_rejected_as_scanner_configuration(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path, select_ignore=True)
    executor = _DockerExecutor()

    result = _run(environment.definition(tmp_path, executor).factory(), environment.job)

    assert result.tool_execution.failure_category is JobFailureCategory.NON_RETRYABLE_POLICY
    assert executor.requests == []


def test_ordinary_job_uses_existing_resolver_and_is_not_treated_as_source(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    ordinary = tmp_path / "ordinary"
    ordinary.mkdir()
    (ordinary / "app.py").write_text("ordinary = True\n", encoding="utf-8")
    calls = []

    def resolve(run_id: str) -> Path:
        calls.append(run_id)
        return ordinary

    executor = _DockerExecutor(b'{"results": [], "errors": []}')
    ordinary_job = replace(environment.job, payload_json={"ordinary": True})

    result = _run(
        environment.definition(
            tmp_path,
            executor,
            ordinary_source_resolver=resolve,
        ).factory(),
        ordinary_job,
    )

    assert result.final_status is JobStatus.SUCCEEDED
    assert calls == [ordinary_job.run_id]
    assert executor.visible_files == [("app.py",)]


def test_finding_outside_selected_manifest_remains_parser_rejection(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["results"][0]["path"] = "/workspace/source/vendor/lib.py"
    executor = _DockerExecutor(json.dumps(payload, separators=(",", ":")).encode("utf-8"))

    result = _run(environment.definition(tmp_path, executor).factory(), environment.job)

    assert result.final_status is JobStatus.PARTIAL
    assert result.report_json["observations"] == []
    assert result.tool_execution.outcome == "partial_analysis"


def test_fresh_resolver_reopens_projection_on_retry_and_detects_later_mutation(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    first_executor = _DockerExecutor(b'{"results": [], "errors": []}')
    first = _run(
        environment.definition(tmp_path / "first", first_executor).factory(),
        environment.job,
    )
    envelope = SourceExecutionEnvelope.from_payload_json(environment.job.payload_json)
    projection = environment.projection_manager.reopen_projection(
        envelope.projection_reference.projection_id,
        expected_context_digest=envelope.projection_reference.context_digest,
        expected_projection_digest=envelope.projection_reference.projection_digest,
    )
    target = projection.source_directory / "app.py"
    os.chmod(projection.root_directory, 0o700)
    os.chmod(projection.source_directory, 0o755)
    os.chmod(target, 0o644)
    target.write_text("mutated after attempt\n", encoding="utf-8")
    second_executor = _DockerExecutor()
    second = _run(
        environment.definition(tmp_path / "second", second_executor).factory(),
        environment.job,
    )

    assert first.final_status is JobStatus.SUCCEEDED
    assert len(first_executor.requests) == 1
    assert second.tool_execution.failure_category is JobFailureCategory.NON_RETRYABLE_POLICY
    assert second_executor.requests == []
