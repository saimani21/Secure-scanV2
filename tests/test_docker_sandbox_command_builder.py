from __future__ import annotations

from pathlib import Path

from securescan.adapters.sandbox_policy import (
    SandboxExecutionBackend,
    SandboxExecutionPolicy,
)
from securescan.adapters.trusted_registry import TrustedAdapterDefinition
from securescan.execution.docker_sandbox import (
    DockerControlCommandResult,
    DockerSandboxCommandBuilder,
    DockerSandboxExecutionRequest,
    DockerSandboxExecutor,
)

IMAGE = "registry.invalid/securescan/scanner@sha256:" + "b" * 64
NAME = "securescan-0123456789abcdef"


def _definition(
    *,
    allowed_environment_names: tuple[str, ...] = (),
) -> TrustedAdapterDefinition:
    return TrustedAdapterDefinition(
        adapter_id="docker-scanner",
        display_name="Docker scanner",
        tool_name="docker-scanner",
        tool_version="1",
        backend=SandboxExecutionBackend.DOCKER_SANDBOX,
        policy=SandboxExecutionPolicy(
            allowed_environment_names=allowed_environment_names,
        ),
        factory=lambda: object(),
        image_reference=IMAGE,
        command_prefix=("/trusted/scanner", "--json"),
    )


def _request(
    tmp_path: Path,
    *,
    arguments: tuple[str, ...] = (),
    environment: dict[str, str] | None = None,
    allowed_environment_names: tuple[str, ...] = (),
) -> DockerSandboxExecutionRequest:
    source = tmp_path / "source"
    output = tmp_path / "output"
    source.mkdir()
    output.mkdir()
    return DockerSandboxExecutionRequest(
        definition=_definition(
            allowed_environment_names=allowed_environment_names,
        ),
        source_directory=source,
        output_directory=output,
        arguments=arguments,
        environment=environment or {},
        execution_id="execution-9",
    )


def _command(request: DockerSandboxExecutionRequest, name: str = NAME) -> tuple[str, ...]:
    return DockerSandboxCommandBuilder().build_create_command(request, name)


def _option_value(command: tuple[str, ...], option: str) -> str:
    return command[command.index(option) + 1]


def test_builder_emits_locked_down_create_command(tmp_path: Path) -> None:
    request = _request(tmp_path)
    command = _command(request)
    resources = request.definition.policy.resources

    assert command[:2] == ("docker", "create")
    assert _option_value(command, "--pull") == "never"
    assert _option_value(command, "--network") == "none"
    assert "--read-only" in command
    assert _option_value(command, "--user") == "65532:65532"
    assert _option_value(command, "--cap-drop") == "ALL"
    assert _option_value(command, "--security-opt") == "no-new-privileges=true"
    assert _option_value(command, "--pids-limit") == str(resources.pids_limit)
    assert _option_value(command, "--memory") == str(resources.memory_bytes)
    assert _option_value(command, "--memory-swap") == str(resources.memory_bytes)
    assert _option_value(command, "--cpus") == "1"
    assert _option_value(command, "--tmpfs").endswith(f"size={resources.tmpfs_bytes}")
    mounts = [command[index + 1] for index, value in enumerate(command) if value == "--mount"]
    assert mounts[0].endswith("dst=/workspace/source,readonly")
    assert mounts[1].endswith("dst=/workspace/output")
    assert _option_value(command, "--workdir") == "/workspace/source"
    assert IMAGE in command


def test_builder_uses_only_trusted_image_and_command_prefix(tmp_path: Path) -> None:
    hostile = (
        "attacker/image@sha256:" + "c" * 64 + ";docker run privileged",
        "../../var/run/docker.sock",
        "postgresql://user:password@host/database",
    )
    request = _request(tmp_path, arguments=hostile)
    command = _command(request)
    image_index = command.index(IMAGE)

    assert command[image_index + 1 : image_index + 3] == (
        "/trusted/scanner",
        "--json",
    )
    assert command[image_index + 3 :] == hostile
    assert command.count(IMAGE) == 1
    assert "attacker/image@sha256:" + "c" * 64 not in command


def test_builder_keeps_arguments_as_separate_argv_elements(tmp_path: Path) -> None:
    arguments = ("$(command)", "`command`", "value;docker run bad", "two words")
    command = _command(_request(tmp_path, arguments=arguments))

    assert command[-4:] == arguments
    assert "sh" not in command
    assert "-c" not in command


def test_builder_emits_only_allowlisted_environment(tmp_path: Path) -> None:
    request = _request(
        tmp_path,
        environment={"TZ": "UTC", "LANG": "C.UTF-8"},
        allowed_environment_names=("TZ", "LANG"),
    )
    command = _command(request)
    environment_values = [
        command[index + 1] for index, value in enumerate(command) if value == "--env"
    ]

    assert environment_values == ["LANG=C.UTF-8", "TZ=UTC"]
    assert "PATH" not in " ".join(environment_values)
    assert "HOME" not in " ".join(environment_values)


def test_builder_does_not_emit_privileged_host_or_socket_options(tmp_path: Path) -> None:
    command = _command(_request(tmp_path, arguments=("/var/run/docker.sock",)))
    joined_options = "\n".join(command[: command.index(IMAGE)])

    assert "--privileged" not in command
    assert "host" not in command
    assert "--pid" not in command
    assert "--ipc" not in command
    assert "--device" not in command
    assert "docker.sock" not in joined_options
    source_mount = _option_value(command, "--mount")
    assert source_mount.endswith(",readonly")


class _Attached:
    def poll(self):
        return None

    def wait(self, timeout_seconds=None):
        return None

    def terminate(self) -> None:
        pass

    def kill(self) -> None:
        pass

    def close(self) -> None:
        pass


class _RecordingRunner:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []

    def run_control_command(
        self,
        argv: tuple[str, ...],
        timeout_seconds: float,
    ) -> DockerControlCommandResult:
        self.commands.append(argv)
        if argv[1:4] == ("inspect", "--format", "{{.State.Running}}"):
            return DockerControlCommandResult(0, b"false\n", b"")
        if argv[1] == "inspect":
            return DockerControlCommandResult(1, b"", b"")
        return DockerControlCommandResult(0, b"ok\n", b"")

    def start_attached(
        self,
        argv: tuple[str, ...],
        stdout_limit: int,
        stderr_limit: int,
        timeout_seconds: float,
    ) -> _Attached:
        self.commands.append(argv)
        return _Attached()


def test_builder_generates_safe_non_user_controlled_container_name(tmp_path: Path) -> None:
    runner = _RecordingRunner()
    executor = DockerSandboxExecutor(
        runner=runner,
        name_generator=lambda: NAME,
    )
    request = _request(tmp_path, arguments=("repository-name-controlled",))

    handle = executor.start(request)
    handle.close()

    create = next(command for command in runner.commands if command[1] == "create")
    assert _option_value(create, "--name") == NAME
    assert "repository-name-controlled" not in _option_value(create, "--name")
    assert NAME.startswith("securescan-")
    assert NAME.isascii() and NAME.lower() == NAME


def test_builder_output_is_deterministic_except_for_injected_container_name(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path, arguments=("--stable",))
    first = _command(request, "securescan-1111111111111111")
    second = _command(request, "securescan-2222222222222222")

    assert _command(request, NAME) == _command(request, NAME)
    differing_indexes = {
        index
        for index, values in enumerate(zip(first, second, strict=True))
        if values[0] != values[1]
    }
    assert differing_indexes == {5}
