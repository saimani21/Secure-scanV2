from __future__ import annotations

from pathlib import Path

from securescan.adapters.sandbox_policy import (
    SandboxExecutionBackend,
    SandboxExecutionPolicy,
)
from securescan.adapters.trusted_registry import TrustedAdapterDefinition
from securescan.execution.docker_sandbox import (
    DockerSandboxCommandBuilder,
    DockerSandboxExecutionRequest,
)
from securescan.workspaces import RepositoryWorkspaceManager

IMAGE = "registry.invalid/securescan/scanner@sha256:" + "e" * 64


def _definition() -> TrustedAdapterDefinition:
    return TrustedAdapterDefinition(
        adapter_id="repository-scanner",
        display_name="Repository scanner",
        tool_name="repository-scanner",
        tool_version="1",
        backend=SandboxExecutionBackend.DOCKER_SANDBOX,
        policy=SandboxExecutionPolicy(),
        factory=lambda: object(),
        image_reference=IMAGE,
        command_prefix=("/trusted/scanner", "--json"),
    )


def _workspace(tmp_path: Path):
    source = tmp_path / "repository"
    source.mkdir()
    (source / "app.py").write_bytes(b"print('safe')\n")
    manager = RepositoryWorkspaceManager(
        tmp_path / "managed",
        workspace_id_factory=lambda: "f" * 32,
    )
    return manager, manager.prepare_repository(source)


def test_prepared_workspace_is_accepted_by_docker_request(tmp_path: Path) -> None:
    manager, workspace = _workspace(tmp_path)
    try:
        request = DockerSandboxExecutionRequest(
            definition=_definition(),
            source_directory=workspace.source_directory,
            output_directory=workspace.output_directory,
            arguments=("--scan",),
        )

        assert request.source_directory == workspace.source_directory
        assert request.output_directory == workspace.output_directory
        assert request.definition.image_reference == IMAGE
    finally:
        manager.cleanup_workspace(workspace)


def test_workspace_paths_cannot_override_trusted_image_command_or_policy(
    tmp_path: Path,
) -> None:
    source = tmp_path / ("image@sha256:" + "a" * 64)
    source.mkdir()
    (source / "--privileged").write_bytes(b"inert")
    manager = RepositoryWorkspaceManager(
        tmp_path / "managed",
        workspace_id_factory=lambda: "1" * 32,
    )
    workspace = manager.prepare_repository(source)
    definition = _definition()
    try:
        request = DockerSandboxExecutionRequest(
            definition,
            workspace.source_directory,
            workspace.output_directory,
            arguments=("$(command)",),
        )
        command = DockerSandboxCommandBuilder().build_create_command(
            request,
            "securescan-1111111111111111",
        )

        assert command[command.index(IMAGE) + 1 : command.index(IMAGE) + 3] == (
            "/trusted/scanner",
            "--json",
        )
        assert request.definition.policy.network_mode.value == "disabled"
        assert request.definition.policy.run_as_uid == 65532
        assert request.definition.policy.run_as_gid == 65532
        assert request.definition.policy.resources.timeout_seconds == 300
        assert workspace.root_directory.name not in IMAGE
    finally:
        manager.cleanup_workspace(workspace)
