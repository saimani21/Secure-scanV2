from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from securescan.adapters.trusted_registry import (
    TrustedAdapterRegistry,
    TrustedAdapterResolver,
)
from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import JobFailureCategory, JobStatus
from securescan.execution import CancellableProcessResult
from securescan.jobs import JobFailureCommitResult, JobRecord, JobResultCommitResult
from securescan.scanners.semgrep import (
    create_semgrep_trusted_definition,
    load_source_ruleset,
)
from securescan.worker import SingleJobWorkerCycle, WorkerCycleDisposition
from securescan.workspaces import RepositoryWorkspaceManager

IMAGE = f"registry.example/semgrep@sha256:{'2' * 64}"
NOW = datetime(2061, 1, 2, 3, 4, 5, tzinfo=UTC)
JOB_ID = str(UUID("00000000-0000-4000-8000-000000006101"))
RUN_ID = str(UUID("00000000-0000-4000-8000-000000006102"))
LEASE_TOKEN = str(UUID("00000000-0000-4000-8000-000000006103"))
WORKER_ID = "semgrep-worker"


def _job(status: JobStatus) -> JobRecord:
    return JobRecord(
        id=JOB_ID,
        run_id=RUN_ID,
        adapter_id="semgrep-ce",
        status=status,
        priority=100,
        attempt_count=1,
        max_attempts=3,
        available_at=NOW,
        leased_by=WORKER_ID,
        lease_expires_at=NOW + timedelta(seconds=30),
        heartbeat_at=NOW,
        cancel_requested=False,
        idempotency_key="b" * 64,
        payload_json={
            "image": "attacker/tool:latest",
            "rules": "p/remote",
            "arguments": ["--config=auto", "--network"],
            "environment": {"HOME": "/workspace/source"},
        },
        last_error=None,
        created_at=NOW,
        updated_at=NOW,
        started_at=NOW if status is JobStatus.RUNNING else None,
        finished_at=None,
        lease_token=LEASE_TOKEN,
    )


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
        raise AssertionError("Completed execution must not be terminated")

    def kill(self) -> None:
        raise AssertionError("Completed execution must not be killed")

    def close(self) -> None:
        self.closed = True


class _DockerExecutor:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.requests = []
        self.handles = []

    def start(self, request):
        self.requests.append(request)
        (request.output_directory / "semgrep-results.json").write_bytes(self.raw)
        handle = _DockerHandle()
        self.handles.append(handle)
        return handle

    def execute(self, request):
        raise AssertionError("Worker must use controllable execution")


class _Leasing:
    def lease_next_job(self, *, worker_id: str, lease_seconds: int) -> JobRecord:
        assert (worker_id, lease_seconds) == (WORKER_ID, 30)
        return _job(JobStatus.LEASED)


class _Execution:
    def start_job(self, *, job_id: str, worker_id: str, lease_token: str) -> JobRecord:
        assert (job_id, worker_id, lease_token) == (JOB_ID, WORKER_ID, LEASE_TOKEN)
        return _job(JobStatus.RUNNING)


class _Reader:
    def get_job(self, job_id: str) -> JobRecord:
        assert job_id == JOB_ID
        return _job(JobStatus.RUNNING)


class _ResultCommit:
    def __init__(self) -> None:
        self.requests = []

    def commit_result(self, request) -> JobResultCommitResult:
        self.requests.append(request)
        return JobResultCommitResult(
            job=replace(
                _job(JobStatus.RUNNING),
                status=request.final_status,
                leased_by=None,
                lease_token=None,
                lease_expires_at=None,
                finished_at=NOW,
            ),
            run_id=RUN_ID,
            tool_execution_id="semgrep-execution",
            attempt_number=1,
            report_json=request.report_json,
        )


class _FailureCommit:
    def __init__(self) -> None:
        self.requests = []

    def commit_failure(self, request) -> JobFailureCommitResult:
        self.requests.append(request)
        return JobFailureCommitResult(
            job=replace(_job(JobStatus.RUNNING), status=JobStatus.FAILED),
            run_id=RUN_ID,
            tool_execution_id="unexpected-failure",
            attempt_number=1,
            retry_scheduled=False,
            retry_delay_seconds=None,
            failure_category=JobFailureCategory.NON_RETRYABLE_PARSER,
        )


class _Cancellation:
    def acknowledge_cancellation(self, job_id: str, worker_id: str, lease_token: str):
        raise AssertionError("Cancellation must not be acknowledged")


class _Heartbeat:
    def renew_lease(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        lease_seconds: int = 30,
    ):
        raise AssertionError("Immediate execution must not heartbeat")


def _definition(tmp_path: Path, executor: _DockerExecutor, source: Path):
    manager = RepositoryWorkspaceManager(tmp_path / "workspaces")
    source_calls = []

    def resolve_source(run_id: str) -> Path:
        source_calls.append(run_id)
        return source

    definition = create_semgrep_trusted_definition(
        image_reference=IMAGE,
        tool_version="1.171.0",
        docker_executor=executor,
        workspace_manager=manager,
        ruleset=load_source_ruleset(),
        artifact_store=ContentAddressedArtifactStore(tmp_path / "artifacts"),
        source_resolver=resolve_source,
        clock=lambda: NOW,
    )
    return definition, manager, source_calls


def _repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "app.py").write_text("value = eval(user_input)\n", encoding="utf-8")
    return repository


def test_trusted_registry_creates_semgrep_adapter_without_executing_it(
    tmp_path: Path,
) -> None:
    executor = _DockerExecutor(b'{"results": [], "errors": []}')
    definition, manager, source_calls = _definition(
        tmp_path,
        executor,
        _repository(tmp_path),
    )
    registry = TrustedAdapterRegistry((definition,))

    adapter = registry.create_adapter("semgrep-ce")

    assert adapter.adapter_id == "semgrep-ce"
    assert executor.requests == []
    assert source_calls == []
    assert list(manager.base_directory.iterdir()) == []


def test_worker_semgrep_vertical_slice_commits_normalized_result_once(
    tmp_path: Path,
) -> None:
    raw = (
        Path(__file__).parent / "fixtures" / "semgrep" / "output" / "valid-findings.json"
    ).read_bytes()
    executor = _DockerExecutor(raw)
    definition, manager, source_calls = _definition(
        tmp_path,
        executor,
        _repository(tmp_path),
    )
    factory_calls = []
    original_factory = definition.factory

    def counted_factory():
        factory_calls.append(True)
        return original_factory()

    registry = TrustedAdapterRegistry((replace(definition, factory=counted_factory),))
    result_commit = _ResultCommit()
    failure_commit = _FailureCommit()
    cycle = SingleJobWorkerCycle(
        _Leasing(),
        _Execution(),
        result_commit,
        failure_commit,
        TrustedAdapterResolver(registry),
        _Reader(),
        _Cancellation(),
        _Heartbeat(),
        worker_id=WORKER_ID,
        lease_seconds=30,
        execution_poll_interval_seconds=0.01,
    )

    result = cycle.run_one_job()

    assert result.disposition is WorkerCycleDisposition.SUCCEEDED
    assert len(factory_calls) == 1
    assert source_calls == [RUN_ID]
    assert len(executor.requests) == 1
    assert len(result_commit.requests) == 1
    assert failure_commit.requests == []
    assert len(result_commit.requests[0].report_json["observations"]) == 1
    assert executor.requests[0].definition.image_reference == IMAGE
    assert "config=auto" not in " ".join(executor.requests[0].arguments)
    assert executor.requests[0].environment == (("HOME", "/tmp"),)
    assert executor.handles[0].closed is True
    assert list(manager.base_directory.iterdir()) == []
