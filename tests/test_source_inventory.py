from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from securescan.source import (
    AnalysisCapability,
    FileContentKind,
    SourceFileFlag,
    SourceFileRole,
    SourceInventoryPolicy,
    SourceSnapshotIntegrityError,
    build_repository_inventory,
)
from securescan.workspaces import RepositoryWorkspaceManager


class _Suffixes:
    def __init__(self) -> None:
        self._values: Iterator[int] = iter(
            range(1, 100)
        )

    def __call__(self) -> str:
        return f"{next(self._values):032x}"


def _manager(
    tmp_path: Path,
) -> RepositoryWorkspaceManager:
    return RepositoryWorkspaceManager(
        tmp_path / "managed",
        workspace_id_factory=_Suffixes(),
    )


def _repository(
    tmp_path: Path,
) -> Path:
    source = tmp_path / "repository"
    (source / "src").mkdir(parents=True)
    (source / "assets").mkdir()

    (source / "src" / "app.py").write_text(
        "print('hello')\n",
        encoding="utf-8",
    )
    (source / "pyproject.toml").write_text(
        "[project]\nname = 'demo'\n",
        encoding="utf-8",
    )
    (source / "poetry.lock").write_text(
        "package = []\n",
        encoding="utf-8",
    )
    (source / "main.tf").write_text(
        'resource "null_resource" "demo" {}\n',
        encoding="utf-8",
    )
    (source / "Dockerfile").write_text(
        "FROM scratch\n",
        encoding="utf-8",
    )
    (source / "README.md").write_text(
        "# Demo\n",
        encoding="utf-8",
    )
    (source / "config.yaml").write_text(
        "enabled: true\n",
        encoding="utf-8",
    )
    (source / "assets" / "logo.bin").write_bytes(
        b"\x00\x01\x02\x03"
    )
    (source / "legacy.data").write_bytes(
        b"text-\xff-value"
    )

    return source


def test_inventory_classifies_repository_files(
    tmp_path: Path,
) -> None:
    source = _repository(tmp_path)
    manager = _manager(tmp_path)
    workspace = manager.prepare_repository(source)

    try:
        inventory = build_repository_inventory(
            workspace
        )
        files = {
            file.relative_path: file
            for file in inventory.files
        }

        assert inventory.file_count == 9
        assert inventory.repository_digest == (
            workspace.manifest.content_digest
        )
        assert len(inventory.inventory_digest()) == 64

        assert (
            files["src/app.py"].role
            is SourceFileRole.SOURCE
        )
        assert (
            files["src/app.py"].content_kind
            is FileContentKind.TEXT
        )
        assert (
            AnalysisCapability.SECRET_DETECTION
            in files["src/app.py"].eligible_capabilities
        )

        assert (
            files["pyproject.toml"].role
            is SourceFileRole.MANIFEST
        )
        assert (
            AnalysisCapability.PACKAGE_INVENTORY
            in files[
                "pyproject.toml"
            ].eligible_capabilities
        )

        assert (
            files["poetry.lock"].role
            is SourceFileRole.LOCKFILE
        )
        assert (
            AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING
            in files[
                "poetry.lock"
            ].eligible_capabilities
        )

        assert (
            files["main.tf"].role
            is SourceFileRole.TERRAFORM
        )
        assert (
            AnalysisCapability.TERRAFORM_SOURCE_POLICY
            in files[
                "main.tf"
            ].eligible_capabilities
        )

        assert (
            files["Dockerfile"].role
            is SourceFileRole.DOCKERFILE
        )
        assert (
            AnalysisCapability.DOCKERFILE_POLICY
            in files[
                "Dockerfile"
            ].eligible_capabilities
        )

        assert (
            files["README.md"].role
            is SourceFileRole.DOCUMENTATION
        )
        assert (
            files["config.yaml"].role
            is SourceFileRole.CONFIGURATION
        )

        binary = files["assets/logo.bin"]
        assert (
            binary.content_kind
            is FileContentKind.BINARY
        )
        assert (
            binary.role
            is SourceFileRole.BINARY
        )
        assert binary.flags == (
            SourceFileFlag.BINARY,
        )
        assert binary.eligible_capabilities == (
            AnalysisCapability.REPOSITORY_PROFILING,
        )

        unknown = files["legacy.data"]
        assert (
            unknown.content_kind
            is FileContentKind.UNKNOWN
        )
        assert unknown.flags == (
            SourceFileFlag.UNSUPPORTED,
        )
    finally:
        manager.cleanup_workspace(workspace)


def test_inventory_is_deterministic_across_locations(
    tmp_path: Path,
) -> None:
    first_source = _repository(
        tmp_path / "first"
    )
    second_source = _repository(
        tmp_path / "second"
    )
    manager = _manager(tmp_path)

    first = manager.prepare_repository(first_source)
    second = manager.prepare_repository(second_source)

    try:
        first_inventory = build_repository_inventory(
            first
        )
        second_inventory = build_repository_inventory(
            second
        )

        assert (
            first_inventory.canonical_data()
            == second_inventory.canonical_data()
        )
        assert (
            first_inventory.inventory_digest()
            == second_inventory.inventory_digest()
        )
    finally:
        manager.cleanup_workspace(first)
        manager.cleanup_workspace(second)


def test_inventory_contains_no_absolute_host_paths(
    tmp_path: Path,
) -> None:
    source = _repository(tmp_path)
    manager = _manager(tmp_path)
    workspace = manager.prepare_repository(source)

    try:
        inventory = build_repository_inventory(
            workspace
        )
        serialized = str(
            inventory.canonical_data()
        )

        assert str(tmp_path) not in serialized
        assert str(
            workspace.source_directory
        ) not in serialized
    finally:
        manager.cleanup_workspace(workspace)


def test_inventory_detects_modified_snapshot_file(
    tmp_path: Path,
) -> None:
    source = _repository(tmp_path)
    manager = _manager(tmp_path)
    workspace = manager.prepare_repository(source)

    try:
        file_path = (
            workspace.source_directory
            / "src"
            / "app.py"
        )
        os.chmod(file_path, 0o644)
        file_path.write_text(
            "print('changed')\n",
            encoding="utf-8",
        )

        with pytest.raises(
            SourceSnapshotIntegrityError,
            match=(
                "Source snapshot integrity "
                "verification failed"
            ),
        ):
            build_repository_inventory(workspace)
    finally:
        manager.cleanup_workspace(workspace)


def test_inventory_detects_added_snapshot_file(
    tmp_path: Path,
) -> None:
    source = _repository(tmp_path)
    manager = _manager(tmp_path)
    workspace = manager.prepare_repository(source)

    try:
        os.chmod(
            workspace.source_directory,
            0o755,
        )
        (
            workspace.source_directory
            / "unexpected.txt"
        ).write_text(
            "unexpected",
            encoding="utf-8",
        )

        with pytest.raises(
            SourceSnapshotIntegrityError
        ):
            build_repository_inventory(workspace)
    finally:
        manager.cleanup_workspace(workspace)


def test_inventory_detects_removed_snapshot_file(
    tmp_path: Path,
) -> None:
    source = _repository(tmp_path)
    manager = _manager(tmp_path)
    workspace = manager.prepare_repository(source)

    try:
        file_path = (
            workspace.source_directory
            / "README.md"
        )
        os.chmod(
            workspace.source_directory,
            0o755,
        )
        file_path.unlink()

        with pytest.raises(
            SourceSnapshotIntegrityError
        ):
            build_repository_inventory(workspace)
    finally:
        manager.cleanup_workspace(workspace)


def test_inventory_and_policy_are_immutable(
    tmp_path: Path,
) -> None:
    source = _repository(tmp_path)
    manager = _manager(tmp_path)
    workspace = manager.prepare_repository(source)

    try:
        policy = SourceInventoryPolicy()
        inventory = build_repository_inventory(
            workspace,
            policy=policy,
        )

        with pytest.raises(FrozenInstanceError):
            policy.sample_bytes = 1  # type: ignore[misc]

        with pytest.raises(FrozenInstanceError):
            inventory.repository_digest = (  # type: ignore[misc]
                "a" * 64
            )
    finally:
        manager.cleanup_workspace(workspace)


def test_inventory_policy_rejects_unsafe_values() -> None:
    for value in (
        0,
        1023,
        True,
        1024 * 1024 + 1,
    ):
        with pytest.raises(
            ValueError,
            match="Source inventory policy is invalid",
        ):
            SourceInventoryPolicy(
                sample_bytes=value,
            )
