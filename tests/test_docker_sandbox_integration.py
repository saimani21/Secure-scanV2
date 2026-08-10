from __future__ import annotations

import json
import secrets
import subprocess
from pathlib import Path

import pytest
from docker_test_guard import validated_docker_test_image

from securescan.adapters.sandbox_policy import (
    SandboxExecutionBackend,
    SandboxExecutionPolicy,
    SandboxResourceLimits,
)
from securescan.adapters.trusted_registry import TrustedAdapterDefinition
from securescan.execution.docker_sandbox import (
    DockerSandboxExecutionRequest,
    DockerSandboxExecutor,
    DockerSandboxTimeoutError,
)

pytestmark = pytest.mark.docker


@pytest.fixture
def docker_image() -> str:
    return validated_docker_test_image()


def _directories(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "source"
    output = tmp_path / "output"
    source.mkdir(mode=0o755)
    output.mkdir(mode=0o777)
    output.chmod(0o777)
    return source, output


def _definition(
    image: str,
    command_prefix: tuple[str, ...],
    *,
    timeout_seconds: int = 10,
) -> TrustedAdapterDefinition:
    return TrustedAdapterDefinition(
        adapter_id="docker-integration",
        display_name="Docker integration",
        tool_name="docker-integration",
        tool_version="1",
        backend=SandboxExecutionBackend.DOCKER_SANDBOX,
        policy=SandboxExecutionPolicy(
            resources=SandboxResourceLimits(
                timeout_seconds=timeout_seconds,
                termination_grace_seconds=1,
            )
        ),
        factory=lambda: object(),
        image_reference=image,
        command_prefix=command_prefix,
    )


def _request(
    tmp_path: Path,
    image: str,
    command_prefix: tuple[str, ...],
    arguments: tuple[str, ...],
    execution_id: str,
    *,
    timeout_seconds: int = 10,
) -> DockerSandboxExecutionRequest:
    source, output = _directories(tmp_path)
    return DockerSandboxExecutionRequest(
        definition=_definition(
            image,
            command_prefix,
            timeout_seconds=timeout_seconds,
        ),
        source_directory=source,
        output_directory=output,
        arguments=arguments,
        execution_id=execution_id,
    )


def _docker_check(argv: tuple[str, ...]) -> bytes:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed integration-only Docker checks
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            shell=False,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pytest.fail("Docker integration state check failed")
    if completed.returncode != 0:
        pytest.fail("Docker integration state check failed")
    return completed.stdout


def _managed_container_exists(execution_id: str) -> bool:
    output = _docker_check(
        (
            "docker",
            "ps",
            "-a",
            "-q",
            "--filter",
            f"label=securescan.execution={execution_id}",
        )
    )
    return bool(output.strip())


def _inspect_value(container_name: str, template: str) -> str:
    return _docker_check(
        ("docker", "inspect", "--format", template, container_name)
    ).decode("utf-8", errors="strict").strip()


def test_docker_executor_runs_command_and_removes_container(
    tmp_path: Path,
    docker_image: str,
) -> None:
    execution_id = f"integration-{secrets.token_hex(8)}"
    request = _request(
        tmp_path,
        docker_image,
        ("/bin/echo",),
        ("secure-docker-output",),
        execution_id,
    )

    result = DockerSandboxExecutor().execute(request)

    assert result.return_code == 0
    assert result.stdout.strip() == b"secure-docker-output"
    assert not _managed_container_exists(execution_id)


def test_docker_container_security_configuration_is_enforced(
    tmp_path: Path,
    docker_image: str,
) -> None:
    execution_id = f"integration-{secrets.token_hex(8)}"
    container_name = f"securescan-{secrets.token_hex(16)}"
    request = _request(
        tmp_path,
        docker_image,
        ("/bin/sleep",),
        ("30",),
        execution_id,
    )
    executor = DockerSandboxExecutor(name_generator=lambda: container_name)
    handle = executor.start(request)
    try:
        policy = request.definition.policy
        assert _inspect_value(container_name, "{{.HostConfig.NetworkMode}}") == "none"
        assert _inspect_value(container_name, "{{.HostConfig.ReadonlyRootfs}}") == "true"
        assert _inspect_value(container_name, "{{.Config.User}}") == "65532:65532"
        cap_drop = json.loads(_inspect_value(container_name, "{{json .HostConfig.CapDrop}}"))
        security_options = json.loads(
            _inspect_value(container_name, "{{json .HostConfig.SecurityOpt}}")
        )
        assert "ALL" in cap_drop
        assert "no-new-privileges=true" in security_options
        assert int(_inspect_value(container_name, "{{.HostConfig.PidsLimit}}")) == (
            policy.resources.pids_limit
        )
        assert int(_inspect_value(container_name, "{{.HostConfig.Memory}}")) == (
            policy.resources.memory_bytes
        )
        assert int(_inspect_value(container_name, "{{.HostConfig.NanoCpus}}")) == 1_000_000_000
        mounts = json.loads(_inspect_value(container_name, "{{json .Mounts}}"))
        source_mount = next(
            mount for mount in mounts if mount["Destination"] == "/workspace/source"
        )
        output_mount = next(
            mount for mount in mounts if mount["Destination"] == "/workspace/output"
        )
        assert source_mount["RW"] is False
        assert output_mount["RW"] is True
        assert all(mount["Destination"] != "/var/run/docker.sock" for mount in mounts)
        assert _inspect_value(container_name, "{{.HostConfig.PidMode}}") == ""
        assert _inspect_value(container_name, "{{.HostConfig.IpcMode}}") != "host"
    finally:
        handle.close()
    assert not _managed_container_exists(execution_id)


def test_docker_source_is_read_only_and_output_is_writable(
    tmp_path: Path,
    docker_image: str,
) -> None:
    denied_id = f"integration-{secrets.token_hex(8)}"
    denied_root = tmp_path / "denied"
    denied_root.mkdir()
    denied = _request(
        denied_root,
        docker_image,
        ("/bin/touch",),
        ("/workspace/source/denied",),
        denied_id,
    )
    denied_result = DockerSandboxExecutor().execute(denied)
    assert denied_result.return_code != 0
    assert not (denied.source_directory / "denied").exists()
    assert not _managed_container_exists(denied_id)

    allowed_id = f"integration-{secrets.token_hex(8)}"
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    allowed = _request(
        allowed_root,
        docker_image,
        ("/bin/touch",),
        ("/workspace/output/created",),
        allowed_id,
    )
    allowed_result = DockerSandboxExecutor().execute(allowed)
    assert allowed_result.return_code == 0
    assert (allowed.output_directory / "created").is_file()
    assert not _managed_container_exists(allowed_id)


def test_docker_timeout_terminates_and_removes_container(
    tmp_path: Path,
    docker_image: str,
) -> None:
    execution_id = f"integration-{secrets.token_hex(8)}"
    request = _request(
        tmp_path,
        docker_image,
        ("/bin/sleep",),
        ("30",),
        execution_id,
        timeout_seconds=1,
    )

    with pytest.raises(DockerSandboxTimeoutError):
        DockerSandboxExecutor().execute(request)

    assert not _managed_container_exists(execution_id)
