from __future__ import annotations

import hashlib
import inspect
import subprocess
from dataclasses import FrozenInstanceError, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import ArtifactKind, JobStatus
from securescan.execution import CancellableProcessRequest, CancellableProcessResult
from securescan.jobs.models import JobRecord
from securescan.scanners.gitleaks import (
    GITLEAKS_SOURCE_ANALYZER_ID,
    GITLEAKS_V04A_BASELINE_COMMIT,
    GitleaksExecutionStatus,
    GitleaksFailureCode,
    GitleaksSourceExecutionBridge,
    GitleaksSourceExecutionContextResolver,
    GitleaksSourceExecutionError,
    GitleaksSourceExecutionResolver,
    TrustedGitleaksBinding,
    create_default_gitleaks_binding,
)
from securescan.scanners.semgrep import (
    SourceExecutionEnvelope,
    SourceProjectionExecutionReference,
    SourceProjectionLifecycleDisposition,
    SourceProjectionLifecycleService,
)
from securescan.source import (
    AnalysisCapability,
    SourceExecutionContext,
    SourceExecutionSelectedFile,
    SourceProjectionManager,
)
from securescan.worker import WorkerExecutionHandle
from securescan.workspaces import RepositoryWorkspaceManager

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2064, 4, 4, 4, 4, 4, tzinfo=UTC)
RUN_ID = str(UUID("00000000-0000-4000-8000-000000004b01"))
JOB_ID = str(UUID("00000000-0000-4000-8000-000000004b02"))
RAW_SECRET = b"ghp_abcdefghijklmnopqrstuvwxyz0123456789"
EXPECTED_BINDING_DIGEST = (
    "8d9f224e1c5ddabef508a26be2966f51dc2a9c2e5805ea3bffcf444b3cae9561"
)
EXPECTED_BINDING_ARTIFACT_SHA256 = (
    "8d0e06a802158827bbe685b7970ffa075ae07f6393debbb088c3b9bf29f1bd44"
)


def _write(path: Path, content: bytes, mode: int) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(mode)
    return hashlib.sha256(content).hexdigest()


def _binding(tmp_path: Path) -> TrustedGitleaksBinding:
    root = tmp_path / "trusted-gitleaks"
    executable = root / "gitleaks"
    config = root / "securescan-gitleaks-v1.toml"
    ignore = root / "securescan-gitleaks-v1.ignore"
    return TrustedGitleaksBinding(
        executable_path=executable,
        executable_sha256=_write(executable, b"trusted executable", 0o700),
        config_path=config,
        config_sha256=_write(config, b"[extend]\nuseDefault = true\n", 0o600),
        ignore_path=ignore,
        ignore_sha256=_write(ignore, b"# intentionally empty\n", 0o600),
    )


def _process_result(
    *,
    return_code: int = 0,
    stdout: bytes = b"[]\n",
    stderr: bytes = b"",
    timed_out: bool = False,
    output_limit_exceeded: bool = False,
    termination_requested: bool = False,
    force_killed: bool = False,
) -> CancellableProcessResult:
    return CancellableProcessResult(
        return_code=return_code,
        stdout=stdout,
        stderr=stderr,
        duration_ms=17,
        timed_out=timed_out,
        output_limit_exceeded=output_limit_exceeded,
        termination_requested=termination_requested,
        force_killed=force_killed,
    )


class _Handle:
    def __init__(
        self,
        result: CancellableProcessResult | None,
        *,
        poll_error: Exception | None = None,
    ) -> None:
        self.result = result
        self.poll_error = poll_error
        self.terminate_calls = 0
        self.kill_calls = 0
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    def poll(self):
        if self.poll_error is not None:
            raise self.poll_error
        return self.result

    def wait(self, timeout_seconds: float | None = None):
        return self.poll()

    def terminate(self) -> None:
        self.terminate_calls += 1
        if self.result is None:
            self.result = _process_result(
                return_code=-15,
                stdout=RAW_SECRET,
                termination_requested=True,
            )

    def kill(self) -> None:
        self.kill_calls += 1
        self.result = _process_result(
            return_code=-9,
            stdout=RAW_SECRET,
            termination_requested=True,
            force_killed=True,
        )

    def close(self) -> None:
        self.closed = True


class _Executor:
    def __init__(
        self,
        scan_result: CancellableProcessResult | None = None,
        *,
        version_result: CancellableProcessResult | None = None,
        scan_handle: _Handle | None = None,
        scan_error: Exception | None = None,
    ) -> None:
        self.version_result = version_result or _process_result(
            stdout=b"8.30.1\n"
        )
        self.scan_handle = scan_handle or _Handle(
            scan_result or _process_result()
        )
        self.scan_error = scan_error
        self.requests: list[CancellableProcessRequest] = []

    def start(self, request: CancellableProcessRequest):
        self.requests.append(request)
        if len(request.argv) >= 2 and request.argv[1] == "version":
            return _Handle(self.version_result)
        if self.scan_error is not None:
            raise self.scan_error
        return self.scan_handle


@dataclass
class _Environment:
    binding: TrustedGitleaksBinding
    store: ContentAddressedArtifactStore
    projection_manager: SourceProjectionManager
    projection: object
    context_resolver: GitleaksSourceExecutionContextResolver
    execution_resolver: GitleaksSourceExecutionResolver
    job: JobRecord

    def bridge(self, executor: _Executor) -> GitleaksSourceExecutionBridge:
        return GitleaksSourceExecutionBridge(
            self.execution_resolver,
            self.binding,
            executor,
        )


def _environment(tmp_path: Path) -> _Environment:
    source = tmp_path / "mutable-intake"
    source.mkdir()
    (source / "app.py").write_bytes(b"value = 'snapshot'\n")
    (source / "nested").mkdir()
    (source / "nested" / "settings.txt").write_bytes(b"setting=true\n")
    workspace = RepositoryWorkspaceManager(
        tmp_path / "workspaces"
    ).prepare_repository(source)
    binding = _binding(tmp_path)
    context = SourceExecutionContext(
        source_run_id=RUN_ID,
        job_id=JOB_ID,
        repository_digest=workspace.manifest.content_digest,
        profile_digest="a" * 64,
        plan_digest="b" * 64,
        source_analyzer_id=GITLEAKS_SOURCE_ANALYZER_ID,
        capability=AnalysisCapability.SECRET_DETECTION,
        component_id=None,
        selected_files=tuple(
            SourceExecutionSelectedFile(entry=replace(entry), component_id=None)
            for entry in workspace.manifest.entries
        ),
        binding_digest=binding.binding_digest(),
        core_adapter_id="gitleaks",
    )
    projection_manager = SourceProjectionManager(tmp_path / "projections")
    projection = projection_manager.build_projection(
        workspace,
        context,
        projection_suffix="4b" * 16,
    )
    store = ContentAddressedArtifactStore(tmp_path / "artifacts")
    artifact = store.put(
        context.canonical_json(),
        kind=ArtifactKind.SOURCE_EXECUTION_CONTEXT,
        media_type="application/json",
        sanitized=False,
    )
    envelope = SourceExecutionEnvelope(
        artifact_sha256=artifact.sha256,
        artifact_size_bytes=artifact.size_bytes,
        context_digest=context.context_digest(),
        projection_reference=SourceProjectionExecutionReference(
            projection_id=projection.projection_id,
            context_digest=projection.context_digest,
            projection_digest=projection.projection_digest,
        ),
    )
    job = JobRecord(
        id=JOB_ID,
        run_id=RUN_ID,
        adapter_id="gitleaks",
        status=JobStatus.RUNNING,
        priority=100,
        attempt_count=1,
        max_attempts=3,
        available_at=NOW,
        leased_by="worker",
        lease_expires_at=NOW,
        heartbeat_at=NOW,
        cancel_requested=False,
        idempotency_key="4" * 64,
        payload_json=envelope.payload_json(),
        last_error=None,
        created_at=NOW,
        updated_at=NOW,
        started_at=NOW,
        finished_at=None,
        lease_token=str(UUID("00000000-0000-4000-8000-000000004b03")),
    )
    context_resolver = GitleaksSourceExecutionContextResolver(store, binding)
    return _Environment(
        binding=binding,
        store=store,
        projection_manager=projection_manager,
        projection=projection,
        context_resolver=context_resolver,
        execution_resolver=GitleaksSourceExecutionResolver(
            context_resolver,
            projection_manager,
        ),
        job=job,
    )


def _scan_request(executor: _Executor) -> CancellableProcessRequest:
    assert len(executor.requests) == 2
    assert executor.requests[0].argv[1:] == ("version",)
    return executor.requests[1]


def test_bridge_uses_only_durable_trusted_projection_and_exact_frozen_argv(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    executor = _Executor()

    handle = environment.bridge(executor).start(environment.job)
    request = _scan_request(executor)

    assert request.argv == (
        str(environment.binding.executable_path),
        "dir",
        "--config",
        str(environment.binding.config_path),
        "--gitleaks-ignore-path",
        str(environment.binding.ignore_path),
        "--report-format",
        "json",
        "--report-path",
        "-",
        "--redact=100",
        "--ignore-gitleaks-allow",
        "--no-banner",
        "--no-color",
        "--log-level",
        "error",
        "--max-archive-depth",
        "0",
        "--max-decode-depth",
        "0",
        "--timeout",
        "295",
        "--exit-code",
        "1",
        str(environment.projection.source_directory),
    )
    assert request.cwd == environment.binding.config_path.parent
    assert dict(request.environment or {}) == {}
    assert request.stdin_data is None
    assert request.timeout_seconds == 300.0
    assert request.stdout_limit_bytes == 64 * 1024 * 1024
    assert request.stderr_limit_bytes == 64 * 1024
    assert "shell" not in inspect.signature(executor.start).parameters
    assert handle.poll() is not None


def test_bridge_has_no_arbitrary_path_or_scanner_flag_input(tmp_path: Path) -> None:
    environment = _environment(tmp_path)

    assert tuple(inspect.signature(environment.bridge(_Executor()).start).parameters) == (
        "job",
    )
    with pytest.raises(TypeError):
        environment.bridge(_Executor()).start(  # type: ignore[call-arg]
            environment.job,
            tmp_path / "hostile",
        )


@pytest.mark.parametrize(
    "job",
    (
        lambda current: replace(current, status=JobStatus.SUCCEEDED),
        lambda current: replace(current, cancel_requested=True),
    ),
)
def test_terminal_or_already_cancel_requested_job_cannot_launch(
    tmp_path: Path,
    job,
) -> None:
    environment = _environment(tmp_path)
    executor = _Executor()

    with pytest.raises(GitleaksSourceExecutionError) as raised:
        environment.bridge(executor).start(job(environment.job))

    assert raised.value.code is GitleaksFailureCode.CONTEXT_INVALID
    assert executor.requests == []


@pytest.mark.parametrize("kind", ("missing", "symlink", "digest_mismatch"))
def test_missing_symlinked_or_mismatched_projection_fails_before_launch(
    tmp_path: Path,
    kind: str,
) -> None:
    environment = _environment(tmp_path)
    root = environment.projection.root_directory
    if kind == "missing":
        environment.projection_manager.cleanup_projection(environment.projection)
    elif kind == "symlink":
        outside = tmp_path / "outside"
        root.rename(outside)
        root.symlink_to(outside, target_is_directory=True)
    else:
        (environment.projection.source_directory / "app.py").chmod(0o600)
    executor = _Executor()

    with pytest.raises(GitleaksSourceExecutionError) as raised:
        environment.bridge(executor).start(environment.job)

    assert raised.value.code is GitleaksFailureCode.PROJECTION_INVALID
    assert executor.requests == []


@pytest.mark.parametrize(
    ("result", "expected_status", "expected_failure"),
    (
        (
            _process_result(return_code=0),
            GitleaksExecutionStatus.COMPLETED_NO_FINDINGS,
            None,
        ),
        (
            _process_result(return_code=1, stdout=RAW_SECRET),
            GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS,
            None,
        ),
        (
            _process_result(return_code=2, stderr=RAW_SECRET),
            GitleaksExecutionStatus.FAILED,
            GitleaksFailureCode.INVALID_EXIT_CODE,
        ),
        (
            _process_result(return_code=99),
            GitleaksExecutionStatus.FAILED,
            GitleaksFailureCode.INVALID_EXIT_CODE,
        ),
        (
            _process_result(
                return_code=-15,
                timed_out=True,
                termination_requested=True,
            ),
            GitleaksExecutionStatus.TIMED_OUT,
            GitleaksFailureCode.TIMEOUT,
        ),
        (
            _process_result(
                return_code=-15,
                output_limit_exceeded=True,
                termination_requested=True,
            ),
            GitleaksExecutionStatus.OUTPUT_LIMIT_EXCEEDED,
            GitleaksFailureCode.OUTPUT_LIMIT,
        ),
        (
            _process_result(
                return_code=-15,
                stdout=b"",
                stderr=RAW_SECRET,
                output_limit_exceeded=True,
                termination_requested=True,
            ),
            GitleaksExecutionStatus.OUTPUT_LIMIT_EXCEEDED,
            GitleaksFailureCode.OUTPUT_LIMIT,
        ),
        (
            _process_result(
                return_code=-9,
                termination_requested=True,
                force_killed=True,
            ),
            GitleaksExecutionStatus.FAILED,
            GitleaksFailureCode.EXECUTION_FAILED,
        ),
    ),
)
def test_process_result_semantics_are_exact_and_do_not_parse_output(
    tmp_path: Path,
    result: CancellableProcessResult,
    expected_status: GitleaksExecutionStatus,
    expected_failure: GitleaksFailureCode | None,
) -> None:
    environment = _environment(tmp_path)

    envelope = environment.bridge(_Executor(result)).start(environment.job).poll()

    assert envelope is not None
    assert envelope.execution_status is expected_status
    assert envelope.failure_code is expected_failure
    assert envelope.stdout_bytes == result.stdout
    assert envelope.stderr_bytes == result.stderr


def test_exit_one_is_completed_success_with_opaque_findings(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    result = environment.bridge(
        _Executor(_process_result(return_code=1, stdout=b"not parsed as json"))
    ).start(environment.job).poll()

    assert result is not None
    assert result.execution_status is GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS
    assert result.failure_code is None
    assert result.stdout_bytes == b"not parsed as json"


def test_graceful_cancellation_reaches_process_and_cannot_be_clean(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    process = _Handle(None)
    handle = environment.bridge(_Executor(scan_handle=process)).start(environment.job)

    assert isinstance(handle, WorkerExecutionHandle)
    assert handle.poll() is None
    handle.terminate()
    result = handle.poll()

    assert process.terminate_calls == 1
    assert process.kill_calls == 0
    assert result is not None
    assert result.execution_status is GitleaksExecutionStatus.CANCELLED
    assert result.failure_code is GitleaksFailureCode.CANCELLED
    assert result.stdout_bytes == RAW_SECRET


def test_force_kill_is_available_and_remains_incomplete(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    process = _Handle(None)
    handle = environment.bridge(_Executor(scan_handle=process)).start(environment.job)

    handle.terminate()
    process.result = None
    handle.kill()
    result = handle.poll()

    assert process.terminate_calls == 1
    assert process.kill_calls == 1
    assert result is not None
    assert result.execution_status is GitleaksExecutionStatus.CANCELLED
    assert result.force_killed is True


@pytest.mark.parametrize(
    ("failure", "expected_code"),
    (
        ("version", GitleaksFailureCode.VERSION_INVALID),
        ("config", GitleaksFailureCode.CONFIG_INVALID),
        ("executable", GitleaksFailureCode.EXECUTABLE_INVALID),
        ("start", GitleaksFailureCode.EXECUTION_FAILED),
    ),
)
def test_runtime_and_start_failures_are_fixed_and_sanitized(
    tmp_path: Path,
    failure: str,
    expected_code: GitleaksFailureCode,
    caplog: pytest.LogCaptureFixture,
) -> None:
    environment = _environment(tmp_path)
    executor = _Executor()
    if failure == "version":
        executor.version_result = _process_result(
            stdout=b"8.30.0\n" + RAW_SECRET,
            stderr=RAW_SECRET,
        )
    elif failure == "config":
        environment.binding.config_path.write_bytes(RAW_SECRET)
    elif failure == "executable":
        environment.binding.executable_path.write_bytes(RAW_SECRET)
    else:
        executor.scan_error = RuntimeError(RAW_SECRET.decode("ascii"))

    with pytest.raises(GitleaksSourceExecutionError) as raised:
        environment.bridge(executor).start(environment.job)

    combined = f"{raised.value}\n{caplog.text}".encode()
    assert raised.value.code is expected_code
    assert RAW_SECRET not in combined
    assert str(tmp_path).encode() not in combined


def test_process_observation_error_does_not_expose_stream_material(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    environment = _environment(tmp_path)
    process = _Handle(
        None,
        poll_error=RuntimeError(RAW_SECRET.decode("ascii")),
    )
    handle = environment.bridge(_Executor(scan_handle=process)).start(environment.job)

    with pytest.raises(GitleaksSourceExecutionError) as raised:
        handle.poll()

    combined = f"{raised.value}\n{caplog.text}".encode()
    assert raised.value.code is GitleaksFailureCode.EXECUTION_FAILED
    assert RAW_SECRET not in combined


def test_command_has_no_git_history_url_or_repository_controlled_option(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    executor = _Executor()
    environment.bridge(executor).start(environment.job)
    request = _scan_request(executor)

    assert request.argv[1] == "dir"
    assert "git" not in request.argv
    assert not any("http://" in value or "https://" in value for value in request.argv)
    assert not any(
        value in request.argv
        for value in ("--log-opts", "--commit", "--branch", "--source")
    )
    assert request.argv.count("--config") == 1
    assert request.argv.count("--gitleaks-ignore-path") == 1


class _JobRepository:
    def __init__(self, job: JobRecord) -> None:
        self.job = job

    def get_job(self, job_id: str) -> JobRecord | None:
        return self.job if job_id == self.job.id else None


def _lifecycle(environment: _Environment, job: JobRecord):
    repository = _JobRepository(job)
    service = SourceProjectionLifecycleService(
        repository,
        environment.context_resolver,
        environment.projection_manager,
    )
    return repository, service


def test_active_execution_retains_projection_until_durable_terminal_state(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    process = _Handle(None)
    handle = environment.bridge(_Executor(scan_handle=process)).start(environment.job)
    _repository, lifecycle = _lifecycle(environment, environment.job)

    result = lifecycle.reconcile_job(environment.job.id)

    assert handle.poll() is None
    assert result.disposition is SourceProjectionLifecycleDisposition.RETAINED_NON_TERMINAL
    assert environment.projection.root_directory.is_dir()


@pytest.mark.parametrize(
    ("process_result", "terminal_status"),
    (
        (_process_result(return_code=0), JobStatus.SUCCEEDED),
        (_process_result(return_code=2), JobStatus.FAILED),
        (
            _process_result(return_code=-15, termination_requested=True),
            JobStatus.CANCELLED,
        ),
        (
            _process_result(
                return_code=-15,
                timed_out=True,
                termination_requested=True,
            ),
            JobStatus.FAILED,
        ),
    ),
)
def test_terminal_durable_truth_releases_projection_for_all_outcomes(
    tmp_path: Path,
    process_result: CancellableProcessResult,
    terminal_status: JobStatus,
) -> None:
    environment = _environment(tmp_path)
    environment.bridge(_Executor(process_result)).start(environment.job).poll()
    terminal_job = replace(
        environment.job,
        status=terminal_status,
        leased_by=None,
        lease_token=None,
        lease_expires_at=None,
        finished_at=NOW,
    )
    _repository, lifecycle = _lifecycle(environment, terminal_job)

    result = lifecycle.reconcile_job(environment.job.id)

    assert result.disposition is SourceProjectionLifecycleDisposition.CLEANED
    assert not environment.projection.root_directory.exists()


def test_terminal_exception_path_releases_projection(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    with pytest.raises(GitleaksSourceExecutionError):
        environment.bridge(
            _Executor(scan_error=RuntimeError(RAW_SECRET.decode("ascii")))
        ).start(environment.job)
    terminal_job = replace(
        environment.job,
        status=JobStatus.FAILED,
        leased_by=None,
        lease_token=None,
        lease_expires_at=None,
        finished_at=NOW,
    )
    _repository, lifecycle = _lifecycle(environment, terminal_job)

    result = lifecycle.reconcile_job(environment.job.id)

    assert result.disposition is SourceProjectionLifecycleDisposition.CLEANED


def test_result_envelope_is_immutable_deterministic_and_path_free(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    process_result = _process_result(return_code=1, stdout=RAW_SECRET)
    first = environment.bridge(_Executor(process_result)).start(environment.job).poll()
    second = environment.bridge(_Executor(process_result)).start(environment.job).poll()

    assert first == second
    assert first is not None
    assert not hasattr(first, "source_directory")
    assert str(tmp_path) not in repr(first)
    with pytest.raises(FrozenInstanceError):
        first.return_code = 0  # type: ignore[misc]


def test_sensitive_stdout_and_stderr_are_excluded_from_repr_and_str(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    process_result = _process_result(
        return_code=2,
        stdout=RAW_SECRET,
        stderr=RAW_SECRET,
    )
    envelope = environment.bridge(_Executor(process_result)).start(
        environment.job
    ).poll()

    assert envelope is not None
    assert RAW_SECRET.decode("ascii") not in repr(envelope)
    assert RAW_SECRET.decode("ascii") not in str(envelope)
    assert envelope.stdout_bytes == RAW_SECRET
    assert envelope.stderr_bytes == RAW_SECRET


def test_contradictory_result_envelope_is_rejected(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    result = environment.bridge(_Executor()).start(environment.job).poll()
    assert result is not None

    with pytest.raises(ValueError, match="result envelope is invalid"):
        replace(
            result,
            execution_status=GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS,
        )
    with pytest.raises(ValueError, match="result envelope is invalid"):
        replace(result, stderr_bytes=b"x" * (64 * 1024 + 1))


def test_v04b_bridge_has_no_parser_logger_or_raw_output_persistence() -> None:
    source = (
        ROOT / "src/securescan/scanners/gitleaks/source_execution.py"
    ).read_text(encoding="utf-8")

    assert "import json" not in source
    assert "json.loads" not in source
    assert "parse_" not in source
    assert "RuleID" not in source
    assert "finding_count" not in source
    assert ".put(" not in source
    assert "logging" not in source


def test_v04a_baseline_tag_and_frozen_files_are_exact() -> None:
    tag_commit = subprocess.run(
        ["git", "rev-parse", "source-v0.4A-gitleaks-binding^{commit}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    ancestry = subprocess.run(
        ["git", "merge-base", "--is-ancestor", tag_commit, "HEAD"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    frozen_paths = (
        "benchmarks/gitleaks/gitleaks-binding-v1.json",
        "src/securescan/scanners/gitleaks/binding.py",
        "src/securescan/scanners/gitleaks/config/securescan-gitleaks-v1.toml",
        "src/securescan/scanners/gitleaks/config/securescan-gitleaks-v1.ignore",
        "benchmarks/python_sast",
    )
    unchanged = subprocess.run(
        ["git", "diff", "--quiet", tag_commit, "--", *frozen_paths],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    binding = create_default_gitleaks_binding(Path("/opt/securescan/bin/gitleaks"))
    artifact = ROOT / "benchmarks/gitleaks/gitleaks-binding-v1.json"

    assert tag_commit == GITLEAKS_V04A_BASELINE_COMMIT
    assert ancestry.returncode == 0
    assert unchanged.returncode == 0
    assert binding.binding_digest() == EXPECTED_BINDING_DIGEST
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == (
        EXPECTED_BINDING_ARTIFACT_SHA256
    )
