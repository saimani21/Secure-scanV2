from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import JobStatus
from securescan.domain.models import ArtifactRecord
from securescan.execution import CancellableProcessResult
from securescan.jobs import JobRecord
from securescan.scanners.semgrep import (
    SEMGREP_ARGUMENTS,
    SemgrepAdapterError,
    SemgrepScanPlan,
    create_semgrep_trusted_definition,
    load_baseline_ruleset,
)
from securescan.workspaces import RepositoryWorkspaceManager

FIXTURES = Path(__file__).parent / "fixtures" / "semgrep" / "output"
IMAGE = f"registry.example/semgrep@sha256:{'1' * 64}"
NOW = datetime(2060, 1, 2, 3, 4, 5, tzinfo=UTC)
RUN_ID = str(UUID("00000000-0000-4000-8000-000000006001"))
JOB_ID = str(UUID("00000000-0000-4000-8000-000000006002"))


def _job(payload: dict | None = None) -> JobRecord:
    return JobRecord(
        id=JOB_ID,
        run_id=RUN_ID,
        adapter_id="semgrep-ce",
        status=JobStatus.RUNNING,
        priority=100,
        attempt_count=1,
        max_attempts=3,
        available_at=NOW,
        leased_by="worker",
        lease_expires_at=NOW,
        heartbeat_at=NOW,
        cancel_requested=False,
        idempotency_key="a" * 64,
        payload_json=payload or {},
        last_error=None,
        created_at=NOW,
        updated_at=NOW,
        started_at=NOW,
        finished_at=None,
        lease_token=str(UUID("00000000-0000-4000-8000-000000006003")),
    )


def _result(return_code: int = 0) -> CancellableProcessResult:
    return CancellableProcessResult(
        return_code=return_code,
        stdout=b"",
        stderr=b"private stderr",
        duration_ms=25,
        timed_out=False,
        output_limit_exceeded=False,
        termination_requested=False,
        force_killed=False,
    )


class _FakeDockerExecutor:
    def __init__(
        self,
        output: bytes | None,
        *,
        return_code: int = 0,
        error: Exception | None = None,
    ) -> None:
        self.output = output
        self.return_code = return_code
        self.error = error
        self.requests = []
        self.snapshot_files: tuple[str, ...] = ()

    def execute(self, request):
        self.requests.append(request)
        self.snapshot_files = tuple(
            sorted(
                path.relative_to(request.source_directory).as_posix()
                for path in request.source_directory.rglob("*")
                if path.is_file()
            )
        )
        if self.error is not None:
            raise self.error
        if self.output is not None:
            (request.output_directory / "semgrep-results.json").write_bytes(self.output)
        return _result(self.return_code)

    def start(self, request):
        raise AssertionError("Synchronous adapter test must use execute")


def _adapter(
    tmp_path: Path,
    executor: _FakeDockerExecutor,
    repository: Path,
    *,
    plan: SemgrepScanPlan | None = None,
):
    manager = RepositoryWorkspaceManager(tmp_path / "workspaces")
    store = ContentAddressedArtifactStore(tmp_path / "artifacts")
    definition = create_semgrep_trusted_definition(
        image_reference=IMAGE,
        tool_version="1.171.0",
        docker_executor=executor,
        workspace_manager=manager,
        ruleset=load_baseline_ruleset(),
        artifact_store=store,
        source_resolver=lambda _run_id: repository,
        plan=plan,
        clock=lambda: NOW,
    )
    return definition.factory(), manager, store, definition


def _repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "app.py").write_text("value = eval(user_input)\n", encoding="utf-8")
    return repository


def test_adapter_prepares_workspace_executes_parses_and_cleans(tmp_path: Path) -> None:
    executor = _FakeDockerExecutor((FIXTURES / "valid-findings.json").read_bytes())
    adapter, manager, _, _ = _adapter(tmp_path, executor, _repository(tmp_path))

    outcome = adapter.execute(_job())

    assert outcome.final_status is JobStatus.SUCCEEDED
    assert executor.snapshot_files == ("app.py",)
    assert len(executor.requests) == 1
    assert list(manager.base_directory.iterdir()) == []


def test_adapter_uses_offline_trusted_command_only(tmp_path: Path) -> None:
    executor = _FakeDockerExecutor((FIXTURES / "valid-findings.json").read_bytes())
    payload = {
        "image": "attacker/tool:latest",
        "rules": "p/remote",
        "arguments": ["--config=auto", "--token=secret"],
    }
    adapter, _, _, definition = _adapter(tmp_path, executor, _repository(tmp_path))

    adapter.execute(_job(payload))
    request = executor.requests[0]

    assert definition.command_prefix == ("semgrep",)
    assert request.arguments == SEMGREP_ARGUMENTS
    assert definition.policy.allowed_environment_names == ("HOME",)
    assert request.environment == (("HOME", "/tmp"),)
    assert request.arguments[-1] == "/workspace/source"
    assert "--metrics=off" in request.arguments
    assert "--no-rewrite-rule-ids" in request.arguments
    serialized = " ".join(request.arguments)
    assert all(value not in serialized for value in ("config=auto", "p/remote", "token"))


def test_adapter_returns_findings_raw_artifact_and_deterministic_digest(
    tmp_path: Path,
) -> None:
    raw = (FIXTURES / "valid-findings.json").read_bytes()
    executor = _FakeDockerExecutor(raw)
    adapter, _, store, _ = _adapter(tmp_path, executor, _repository(tmp_path))

    outcome = adapter.execute(_job())
    report = outcome.report_json
    artifact_data = report["executions"][0]["artifacts"][0]

    assert len(report["observations"]) == 1
    assert artifact_data["sha256"] == hashlib.sha256(raw).hexdigest()
    assert artifact_data["size_bytes"] == len(raw)
    assert artifact_data["media_type"] == "application/json"
    assert store.read(ArtifactRecord.model_validate(artifact_data)) == raw


def test_adapter_returns_partial_result_for_valid_output_with_errors(
    tmp_path: Path,
) -> None:
    raw = (FIXTURES / "findings-with-errors.json").read_bytes()
    adapter, _, _, _ = _adapter(
        tmp_path,
        _FakeDockerExecutor(raw),
        _repository(tmp_path),
    )

    outcome = adapter.execute(_job())

    assert outcome.final_status is JobStatus.PARTIAL
    assert len(outcome.report_json["observations"]) == 1
    assert outcome.report_json["analysis_gaps"][0]["code"] == "SEMGREP_PARSE_ERROR"


def test_adapter_rejects_nonzero_missing_malformed_and_oversized_output(
    tmp_path: Path,
) -> None:
    cases = (
        (_FakeDockerExecutor(b'{"results": [], "errors": []}', return_code=2), None),
        (_FakeDockerExecutor(None), None),
        (_FakeDockerExecutor(b"{broken"), None),
        (
            _FakeDockerExecutor(b"x" * (1024 * 1024 + 1)),
            SemgrepScanPlan(
                ruleset=load_baseline_ruleset(),
                maximum_result_bytes=1024 * 1024,
            ),
        ),
    )
    for index, (executor, plan) in enumerate(cases):
        root = tmp_path / f"case-{index}"
        root.mkdir()
        adapter, manager, _, _ = _adapter(
            root,
            executor,
            _repository(root),
            plan=plan,
        )
        with pytest.raises(SemgrepAdapterError):
            adapter.execute(_job())
        assert list(manager.base_directory.iterdir()) == []


def test_adapter_cleans_workspace_after_execution_and_parser_failures(
    tmp_path: Path,
) -> None:
    cases = (
        _FakeDockerExecutor(None, error=RuntimeError("private executor failure")),
        _FakeDockerExecutor(b'{"results": "invalid", "errors": []}'),
    )
    for index, executor in enumerate(cases):
        root = tmp_path / f"failure-{index}"
        root.mkdir()
        adapter, manager, _, _ = _adapter(root, executor, _repository(root))
        with pytest.raises(SemgrepAdapterError):
            adapter.execute(_job())
        assert list(manager.base_directory.iterdir()) == []
