from __future__ import annotations

import os
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from securescan.adapters.sandbox_policy import (
    SandboxExecutionBackend,
    SandboxExecutionPolicy,
)
from securescan.adapters.trusted_registry import TrustedAdapterDefinition
from securescan.execution.docker_sandbox import (
    DockerSandboxExecutionRequest,
    InvalidDockerSandboxRequestError,
)

IMAGE = "registry.invalid/securescan/test@sha256:" + "a" * 64


def _definition(
    *,
    allowed_environment_names: tuple[str, ...] = (),
) -> TrustedAdapterDefinition:
    return TrustedAdapterDefinition(
        adapter_id="docker-test",
        display_name="Docker test",
        tool_name="docker-test",
        tool_version="1",
        backend=SandboxExecutionBackend.DOCKER_SANDBOX,
        policy=SandboxExecutionPolicy(
            allowed_environment_names=allowed_environment_names,
        ),
        factory=lambda: object(),
        image_reference=IMAGE,
        command_prefix=("/scanner",),
    )


def _directories(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "source"
    output = tmp_path / "output"
    source.mkdir()
    output.mkdir()
    return source, output


def test_docker_request_accepts_trusted_locked_down_definition(tmp_path: Path) -> None:
    source, output = _directories(tmp_path)
    definition = _definition(allowed_environment_names=("LANG",))

    request = DockerSandboxExecutionRequest(
        definition=definition,
        source_directory=source,
        output_directory=output,
        arguments=("--json", "$(command)", "`command`"),
        environment={"LANG": "C.UTF-8"},
        execution_id="execution-1",
    )

    assert request.definition is definition
    assert request.source_directory == source.resolve()
    assert request.output_directory == output.resolve()
    assert request.arguments == ("--json", "$(command)", "`command`")
    assert request.environment == (("LANG", "C.UTF-8"),)


def test_docker_request_rejects_test_backend_and_mutable_definition(tmp_path: Path) -> None:
    source, output = _directories(tmp_path)
    test_definition = TrustedAdapterDefinition(
        adapter_id="test-only",
        display_name="Test only",
        tool_name="test-only",
        tool_version="1",
        backend=SandboxExecutionBackend.TEST_ONLY,
        policy=SandboxExecutionPolicy(backend=SandboxExecutionBackend.TEST_ONLY),
        factory=lambda: object(),
        test_only=True,
    )
    with pytest.raises(InvalidDockerSandboxRequestError):
        DockerSandboxExecutionRequest(test_definition, source, output)

    corrupted_definition = _definition()
    object.__setattr__(corrupted_definition, "image_reference", "scanner:latest")
    with pytest.raises(InvalidDockerSandboxRequestError):
        DockerSandboxExecutionRequest(corrupted_definition, source, output)


def test_docker_request_rejects_unsafe_or_overlapping_paths(tmp_path: Path) -> None:
    source, output = _directories(tmp_path)
    source_child = source / "child"
    source_child.mkdir()
    output_child = output / "child"
    output_child.mkdir()
    source_link = tmp_path / "source-link"
    output_link = tmp_path / "output-link"
    source_link.symlink_to(source, target_is_directory=True)
    output_link.symlink_to(output, target_is_directory=True)
    relative = Path("relative")
    unsafe_pairs = (
        (relative, output),
        (source, relative),
        (source_link, output),
        (source, output_link),
        (source, source),
        (source, source_child),
        (output_child, output),
        (Path("/etc"), output),
    )

    for unsafe_source, unsafe_output in unsafe_pairs:
        with pytest.raises(InvalidDockerSandboxRequestError):
            DockerSandboxExecutionRequest(
                _definition(),
                unsafe_source,
                unsafe_output,
            )


def test_docker_request_rejects_invalid_arguments_and_environment(tmp_path: Path) -> None:
    source, output = _directories(tmp_path)
    definition = _definition(allowed_environment_names=("LANG",))
    invalid_values = (
        {"arguments": ("value\0hidden",)},
        {"arguments": ("value\nhidden",)},
        {"arguments": ("value\rhidden",)},
        {"environment": {"TOKEN": "secret-value"}},
        {"environment": {"LANG": "value\0hidden"}},
        {"environment": {"LANG": "value\nhidden"}},
        {"environment": {"LANG": 123}},
    )

    for changes in invalid_values:
        with pytest.raises(InvalidDockerSandboxRequestError):
            DockerSandboxExecutionRequest(
                definition,
                source,
                output,
                **changes,
            )


def test_docker_request_is_immutable_and_does_not_inherit_host_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, output = _directories(tmp_path)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-be-forwarded")
    monkeypatch.setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    request = DockerSandboxExecutionRequest(_definition(), source, output)

    assert request.environment == ()
    assert "AWS_SECRET_ACCESS_KEY" not in dict(request.environment)
    assert "DOCKER_HOST" not in dict(request.environment)
    assert os.environ["AWS_SECRET_ACCESS_KEY"] == "must-not-be-forwarded"
    with pytest.raises(FrozenInstanceError):
        request.arguments = ("changed",)  # type: ignore[misc]
