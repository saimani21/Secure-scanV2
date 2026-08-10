from __future__ import annotations

import hashlib
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest

import securescan.workspaces.intake as intake_module
from securescan.workspaces import (
    RepositoryChangedDuringIntakeError,
    RepositoryWorkspaceManager,
)


class _Suffixes:
    def __init__(self) -> None:
        self._values: Iterator[int] = iter(range(1, 100))

    def __call__(self) -> str:
        return f"{next(self._values):032x}"


def _manager(tmp_path: Path) -> RepositoryWorkspaceManager:
    return RepositoryWorkspaceManager(
        tmp_path / "managed",
        workspace_id_factory=_Suffixes(),
    )


def test_workspace_prepares_regular_repository_and_manifest(tmp_path: Path) -> None:
    source = tmp_path / "repository"
    (source / "nested").mkdir(parents=True)
    (source / ".git").mkdir()
    (source / "nested" / ".hg").mkdir()
    (source / ".git" / "ignored").write_text("ignored")
    (source / "nested" / ".hg" / "ignored").write_text("ignored")
    (source / "z.txt").write_bytes(b"z")
    (source / "nested" / "a.txt").write_bytes(b"alpha")
    (source / "--privileged").write_bytes(b"inert")
    (source / "$(command)").write_bytes(b"inert-too")
    manager = _manager(tmp_path)

    workspace = manager.prepare_repository(source)
    try:
        paths = tuple(entry.relative_path for entry in workspace.manifest.entries)
        assert paths == tuple(sorted(paths))
        assert paths == ("$(command)", "--privileged", "nested/a.txt", "z.txt")
        assert workspace.manifest.file_count == 4
        assert workspace.manifest.total_bytes == sum(
            len(value) for value in (b"inert-too", b"inert", b"alpha", b"z")
        )
        hashes = {entry.relative_path: entry.sha256 for entry in workspace.manifest.entries}
        assert hashes["nested/a.txt"] == hashlib.sha256(b"alpha").hexdigest()
        assert not (workspace.source_directory / ".git").exists()
        assert not (workspace.source_directory / "nested" / ".hg").exists()
        assert list(workspace.output_directory.iterdir()) == []
        assert (workspace.root_directory / ".securescan-workspace").is_file()
    finally:
        manager.cleanup_workspace(workspace)


def test_repository_digest_is_deterministic_across_source_locations(tmp_path: Path) -> None:
    first_source = tmp_path / "first"
    second_source = tmp_path / "$(command)"
    for source in (first_source, second_source):
        (source / "src").mkdir(parents=True)
        (source / "src" / "app.py").write_bytes(b"print('same')\n")
        (source / ".git").mkdir()
        (source / ".git" / "different").write_text(str(source))
    manager = _manager(tmp_path)

    first = manager.prepare_repository(first_source)
    second = manager.prepare_repository(second_source)
    try:
        assert first.manifest == second.manifest
        assert first.manifest.content_digest == second.manifest.content_digest
    finally:
        manager.cleanup_workspace(first)
        manager.cleanup_workspace(second)


def test_repository_digest_changes_for_content_path_addition_and_removal(
    tmp_path: Path,
) -> None:
    source = tmp_path / "repository"
    source.mkdir()
    file_path = source / "file.txt"
    file_path.write_bytes(b"first")
    manager = _manager(tmp_path)
    workspaces = [manager.prepare_repository(source)]
    file_path.write_bytes(b"second")
    workspaces.append(manager.prepare_repository(source))
    file_path.rename(source / "renamed.txt")
    workspaces.append(manager.prepare_repository(source))
    added = source / "added.txt"
    added.write_bytes(b"added")
    workspaces.append(manager.prepare_repository(source))
    added.unlink()
    workspaces.append(manager.prepare_repository(source))

    try:
        digests = [workspace.manifest.content_digest for workspace in workspaces]
        assert digests[0] != digests[1]
        assert digests[1] != digests[2]
        assert digests[2] != digests[3]
        assert digests[3] != digests[4]
    finally:
        for workspace in workspaces:
            manager.cleanup_workspace(workspace)


def test_empty_repository_is_supported(tmp_path: Path) -> None:
    source = tmp_path / "empty"
    source.mkdir()
    manager = _manager(tmp_path)

    workspace = manager.prepare_repository(source)
    try:
        assert workspace.manifest.entries == ()
        assert workspace.manifest.file_count == 0
        assert workspace.manifest.total_bytes == 0
        assert len(workspace.manifest.content_digest) == 64
    finally:
        manager.cleanup_workspace(workspace)


def test_workspace_source_is_read_only_and_output_is_container_writable(
    tmp_path: Path,
) -> None:
    source = tmp_path / "repository"
    (source / "nested").mkdir(parents=True)
    (source / "nested" / "file").write_bytes(b"content")
    manager = _manager(tmp_path)

    workspace = manager.prepare_repository(source)
    try:
        assert stat.S_IMODE(workspace.root_directory.stat().st_mode) == 0o700
        assert stat.S_IMODE(workspace.source_directory.stat().st_mode) == 0o555
        assert stat.S_IMODE((workspace.source_directory / "nested").stat().st_mode) == 0o555
        assert stat.S_IMODE(
            (workspace.source_directory / "nested" / "file").stat().st_mode
        ) == 0o444
        assert stat.S_IMODE(workspace.output_directory.stat().st_mode) == 0o777
    finally:
        manager.cleanup_workspace(workspace)


def test_cleanup_is_idempotent(tmp_path: Path) -> None:
    source = tmp_path / "repository"
    source.mkdir()
    manager = _manager(tmp_path)
    workspace = manager.prepare_repository(source)

    manager.cleanup_workspace(workspace)
    manager.cleanup_workspace(workspace)

    assert not workspace.root_directory.exists()
    assert manager.base_directory.exists()
    assert source.exists()


def test_failed_intake_removes_partial_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "repository"
    source.mkdir()
    (source / "token=secret-value").write_bytes(b"sensitive")
    manager = _manager(tmp_path)

    def failed_read(_descriptor: int, _size: int) -> bytes:
        raise OSError("postgresql://user:password@host/database")

    monkeypatch.setattr(intake_module.os, "read", failed_read)
    with pytest.raises(RepositoryChangedDuringIntakeError):
        manager.prepare_repository(source)

    assert list(manager.base_directory.iterdir()) == []
