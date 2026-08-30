from __future__ import annotations

from pathlib import Path

import pytest

from securescan.adapters.sandbox_policy import (
    SandboxExecutionBackend,
    SandboxExecutionPolicy,
    SandboxResourceLimits,
)
from securescan.adapters.trusted_registry import TrustedAdapterDefinition
from securescan.execution import CancellableProcessResult
from securescan.execution.docker_sandbox import (
    DockerContainerCreationError,
    DockerControlCommandResult,
    DockerSandboxExecutionRequest,
    DockerSandboxExecutor,
    DockerSandboxTimeoutError,
)

IMAGE = "private.invalid/token-scanner@sha256:" + "d" * 64
NAME = "securescan-deadbeefdeadbeef"


def _request(
    tmp_path: Path,
    *,
    timeout_seconds: int = 300,
) -> DockerSandboxExecutionRequest:
    source = tmp_path / "source-sensitive"
    output = tmp_path / "output-sensitive"
    source.mkdir()
    output.mkdir()
    definition = TrustedAdapterDefinition(
        adapter_id="docker-scanner",
        display_name="Docker scanner",
        tool_name="docker-scanner",
        tool_version="1",
        backend=SandboxExecutionBackend.DOCKER_SANDBOX,
        policy=SandboxExecutionPolicy(
            resources=SandboxResourceLimits(timeout_seconds=timeout_seconds),
        ),
        factory=lambda: object(),
        image_reference=IMAGE,
        command_prefix=("/trusted/scanner",),
    )
    return DockerSandboxExecutionRequest(
        definition,
        source,
        output,
        arguments=("token=secret-value",),
    )


def _process_result(
    *,
    return_code: int = 0,
    timed_out: bool = False,
) -> CancellableProcessResult:
    return CancellableProcessResult(
        return_code=return_code,
        stdout=b"scanner-output",
        stderr=b"scanner-warning",
        duration_ms=20,
        timed_out=timed_out,
        output_limit_exceeded=False,
        termination_requested=False,
        force_killed=False,
    )


class _Attached:
    def __init__(
        self,
        events: list[str],
        poll_result: CancellableProcessResult | None,
    ) -> None:
        self.events = events
        self.poll_result = poll_result
        self.terminate_calls = 0
        self.kill_calls = 0
        self.close_calls = 0

    def poll(self) -> CancellableProcessResult | None:
        self.events.append("attached-poll")
        return self.poll_result

    def wait(self, timeout_seconds=None) -> CancellableProcessResult | None:
        self.events.append("attached-wait")
        return self.poll_result

    def terminate(self) -> None:
        self.events.append("attached-terminate")
        self.terminate_calls += 1

    def kill(self) -> None:
        self.events.append("attached-kill")
        self.kill_calls += 1

    def close(self) -> None:
        self.events.append("attached-close")
        self.close_calls += 1


class _Runner:
    def __init__(
        self,
        attached: _Attached,
        *,
        create_return_code: int = 0,
        create_stderr: bytes = b"",
        running_values: tuple[bool, ...] = (False,),
        remove_missing: bool = False,
        exit_code: int = 0,
    ) -> None:
        self.attached = attached
        self.events = attached.events
        self.create_return_code = create_return_code
        self.create_stderr = create_stderr
        self.running_values = list(running_values)
        self.remove_missing = remove_missing
        self.exit_code = exit_code
        self.commands: list[tuple[str, ...]] = []
        self.start_calls = 0

    def run_control_command(
        self,
        argv: tuple[str, ...],
        timeout_seconds: float,
    ) -> DockerControlCommandResult:
        self.commands.append(argv)
        operation = argv[1]
        self.events.append(operation)
        if operation == "create":
            return DockerControlCommandResult(
                self.create_return_code,
                b"",
                self.create_stderr,
            )
        if operation == "inspect" and "{{.State.Running}}|{{.State.ExitCode}}" in argv:
            return DockerControlCommandResult(
                0,
                f"false|{self.exit_code}\n".encode(),
                b"",
            )
        if operation == "inspect" and "{{.State.Running}}" in argv:
            running = self.running_values.pop(0) if self.running_values else False
            return DockerControlCommandResult(
                0,
                b"true\n" if running else b"false\n",
                b"",
            )
        if operation == "rm" and self.remove_missing:
            return DockerControlCommandResult(1, b"", b"No such container")
        if operation == "inspect":
            return DockerControlCommandResult(1, b"", b"No such container")
        return DockerControlCommandResult(0, b"ok\n", b"")

    def start_attached(
        self,
        argv: tuple[str, ...],
        stdout_limit: int,
        stderr_limit: int,
        timeout_seconds: float,
    ) -> _Attached:
        self.commands.append(argv)
        self.events.append("start")
        self.start_calls += 1
        return self.attached


class _Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


def _executor(runner: _Runner, clock: _Clock | None = None) -> DockerSandboxExecutor:
    fake_clock = clock or _Clock()
    return DockerSandboxExecutor(
        runner=runner,
        name_generator=lambda: NAME,
        monotonic_clock=fake_clock,
        sleeper=fake_clock.sleep,
    )


def test_executor_creates_starts_inspects_and_removes_container(tmp_path: Path) -> None:
    events: list[str] = []
    attached = _Attached(events, _process_result())
    runner = _Runner(attached, exit_code=7)

    result = _executor(runner).execute(_request(tmp_path))

    assert result.return_code == 7
    assert result.stdout == b"scanner-output"
    assert [command[1] for command in runner.commands] == [
        "version",
        "image",
        "create",
        "start",
        "inspect",
        "rm",
        "inspect",
    ]
    prerequisite_operations = [
        command[1]
        for command in runner.commands
        if command[1] in {"version", "image"}
    ]
    assert prerequisite_operations == ["version", "image"]
    assert attached.close_calls == 1


def test_executor_create_failure_does_not_start_container(tmp_path: Path) -> None:
    events: list[str] = []
    attached = _Attached(events, _process_result())
    runner = _Runner(attached, create_return_code=1)

    with pytest.raises(DockerContainerCreationError):
        _executor(runner).execute(_request(tmp_path))

    assert runner.start_calls == 0
    assert [command[1] for command in runner.commands] == [
        "version",
        "image",
        "create",
        "rm",
        "image",
    ]


def test_executor_timeout_stops_kills_and_removes_container(tmp_path: Path) -> None:
    events: list[str] = []
    attached = _Attached(events, None)
    runner = _Runner(attached, running_values=(True,))
    clock = _Clock()
    executor = _executor(runner, clock)
    handle = executor.start(_request(tmp_path, timeout_seconds=1))
    clock.value = 2

    with pytest.raises(DockerSandboxTimeoutError):
        handle.poll()
    handle.close()

    operations = [command[1] for command in runner.commands]
    assert operations.index("stop") < operations.index("kill") < operations.index("rm")
    assert attached.terminate_calls == 1
    assert attached.kill_calls == 1


def test_executor_cancellation_stops_container_before_reporting_completion(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    attached = _Attached(events, _process_result(return_code=-15))
    runner = _Runner(attached, running_values=(False,))
    handle = _executor(runner).start(_request(tmp_path))

    handle.terminate()
    result = handle.poll()

    assert result is not None
    assert result.termination_requested is True
    assert events.index("stop") < events.index("attached-terminate")
    assert events.index("attached-terminate") < events.index("rm")


def test_executor_cleanup_is_idempotent_when_container_is_missing(tmp_path: Path) -> None:
    events: list[str] = []
    attached = _Attached(events, _process_result(return_code=-15))
    runner = _Runner(
        attached,
        running_values=(False,),
        remove_missing=True,
    )
    handle = _executor(runner).start(_request(tmp_path))

    handle.close()
    command_count = len(runner.commands)
    handle.close()

    assert len(runner.commands) == command_count
    assert [command[1] for command in runner.commands].count("rm") == 1
    assert attached.close_calls == 1


def test_executor_errors_hide_docker_output_paths_image_and_container_name(
    tmp_path: Path,
) -> None:
    sensitive_stderr = (
        b"docker error /source-sensitive "
        + IMAGE.encode()
        + b" container="
        + NAME.encode()
        + b" token=secret-value postgresql://user:password@host/database"
    )
    events: list[str] = []
    attached = _Attached(events, _process_result())
    runner = _Runner(
        attached,
        create_return_code=1,
        create_stderr=sensitive_stderr,
    )

    with pytest.raises(DockerContainerCreationError) as error:
        _executor(runner).execute(_request(tmp_path))

    message = str(error.value)
    assert message == "Docker sandbox container could not be created"
    for sensitive in (
        "source-sensitive",
        IMAGE,
        NAME,
        "secret-value",
        "postgresql",
        "password",
        "docker error",
    ):
        assert sensitive not in message
