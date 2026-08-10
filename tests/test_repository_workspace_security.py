from __future__ import annotations

import os
import socket
from pathlib import Path

import pytest

from securescan.workspaces import (
    ForeignWorkspaceError,
    InvalidRepositorySourceError,
    RepositoryIntakeLimitError,
    RepositoryIntakeLimits,
    RepositoryWorkspaceError,
    RepositoryWorkspaceManager,
    UnsupportedRepositoryEntryError,
)


def _manager(
    tmp_path: Path,
    *,
    name: str = "managed",
    limits: RepositoryIntakeLimits | None = None,
) -> RepositoryWorkspaceManager:
    if limits is None:
        return RepositoryWorkspaceManager(
            tmp_path / name,
            workspace_id_factory=lambda: "a" * 32,
        )
    return RepositoryWorkspaceManager(
        tmp_path / name,
        limits=limits,
        workspace_id_factory=lambda: "a" * 32,
    )


def test_source_validation_rejects_relative_missing_symlink_and_protected_paths(
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    source = tmp_path / "source"
    source.mkdir()
    source_link = tmp_path / "source-link"
    source_link.symlink_to(source, target_is_directory=True)
    vcs_source = tmp_path / ".git"
    vcs_source.mkdir()

    for invalid in (
        Path("relative"),
        tmp_path / "missing",
        source_link,
        vcs_source,
        Path("/etc"),
        manager.base_directory,
    ):
        with pytest.raises(InvalidRepositorySourceError):
            manager.prepare_repository(invalid)


def test_intake_rejects_symlink_files_and_directories(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    source = tmp_path / "source"
    source.mkdir()
    file_link = source / "file-link"
    file_link.symlink_to("/etc/passwd")
    with pytest.raises(UnsupportedRepositoryEntryError):
        manager.prepare_repository(source)
    file_link.unlink()

    directory_link = source / "directory-link"
    directory_link.symlink_to("/etc", target_is_directory=True)
    with pytest.raises(UnsupportedRepositoryEntryError):
        manager.prepare_repository(source)
    directory_link.unlink()

    socket_link = source / "docker.sock"
    socket_link.symlink_to("/var/run/docker.sock")
    with pytest.raises(UnsupportedRepositoryEntryError):
        manager.prepare_repository(source)


def test_intake_rejects_hardlinks_and_duplicate_inodes(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    source = tmp_path / "source"
    source.mkdir()
    os.link(outside, source / "external-hardlink")
    with pytest.raises(UnsupportedRepositoryEntryError):
        manager.prepare_repository(source)

    (source / "external-hardlink").unlink()
    first = source / "first"
    first.write_bytes(b"same inode")
    os.link(first, source / "second")
    with pytest.raises(UnsupportedRepositoryEntryError):
        manager.prepare_repository(source)


@pytest.mark.skipif(os.name != "posix", reason="POSIX special entries are required")
def test_intake_rejects_fifo_socket_and_other_special_entries(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    source = tmp_path / "source"
    source.mkdir()
    fifo = source / "repository-credential"
    os.mkfifo(fifo)
    with pytest.raises(UnsupportedRepositoryEntryError):
        manager.prepare_repository(source)
    fifo.unlink()

    socket_path = source / "scanner.sock"
    server = socket.socket(socket.AF_UNIX)
    try:
        try:
            server.bind(str(socket_path))
        except PermissionError:
            return
        with pytest.raises(UnsupportedRepositoryEntryError):
            manager.prepare_repository(source)
    finally:
        server.close()
        socket_path.unlink(missing_ok=True)


def test_intake_enforces_file_count_single_file_and_total_limits(tmp_path: Path) -> None:
    count_source = tmp_path / "count-source"
    count_source.mkdir()
    (count_source / "one").write_bytes(b"a")
    (count_source / "two").write_bytes(b"b")
    count_manager = _manager(
        tmp_path,
        name="count-managed",
        limits=RepositoryIntakeLimits(
            max_file_count=1,
            max_single_file_bytes=1024,
            max_total_bytes=1024,
        ),
    )
    with pytest.raises(RepositoryIntakeLimitError):
        count_manager.prepare_repository(count_source)

    single_source = tmp_path / "single-source"
    single_source.mkdir()
    (single_source / "large").write_bytes(b"x" * 1025)
    single_manager = _manager(
        tmp_path,
        name="single-managed",
        limits=RepositoryIntakeLimits(
            max_single_file_bytes=1024,
            max_total_bytes=2048,
        ),
    )
    with pytest.raises(RepositoryIntakeLimitError):
        single_manager.prepare_repository(single_source)

    total_source = tmp_path / "total-source"
    total_source.mkdir()
    (total_source / "one").write_bytes(b"x" * 600)
    (total_source / "two").write_bytes(b"x" * 600)
    total_manager = _manager(
        tmp_path,
        name="total-managed",
        limits=RepositoryIntakeLimits(
            max_single_file_bytes=1024,
            max_total_bytes=1024,
        ),
    )
    with pytest.raises(RepositoryIntakeLimitError):
        total_manager.prepare_repository(total_source)


def test_intake_enforces_depth_and_relative_path_limits(tmp_path: Path) -> None:
    depth_source = tmp_path / "depth-source"
    (depth_source / "one" / "two").mkdir(parents=True)
    (depth_source / "one" / "two" / "file").write_bytes(b"x")
    depth_manager = _manager(
        tmp_path,
        name="depth-managed",
        limits=RepositoryIntakeLimits(max_directory_depth=1),
    )
    with pytest.raises(RepositoryIntakeLimitError):
        depth_manager.prepare_repository(depth_source)

    path_source = tmp_path / "path-source"
    path_source.mkdir()
    (path_source / ("x" * 65)).write_bytes(b"x")
    path_manager = _manager(
        tmp_path,
        name="path-managed",
        limits=RepositoryIntakeLimits(max_relative_path_bytes=64),
    )
    with pytest.raises(RepositoryIntakeLimitError):
        path_manager.prepare_repository(path_source)


def test_cleanup_refuses_foreign_markerless_and_symlinked_workspaces(
    tmp_path: Path,
) -> None:
    first_manager = _manager(tmp_path, name="first-managed")
    second_manager = _manager(tmp_path, name="second-managed")
    source = tmp_path / "source"
    source.mkdir()
    workspace = first_manager.prepare_repository(source)

    with pytest.raises(ForeignWorkspaceError):
        second_manager.cleanup_workspace(workspace)

    marker = workspace.root_directory / ".securescan-workspace"
    marker_content = marker.read_bytes()
    marker.unlink()
    with pytest.raises(ForeignWorkspaceError):
        first_manager.cleanup_workspace(workspace)
    marker.write_bytes(marker_content)
    marker.chmod(0o600)

    saved_root = workspace.root_directory.with_name("saved-workspace")
    workspace.root_directory.rename(saved_root)
    workspace.root_directory.symlink_to(saved_root, target_is_directory=True)
    with pytest.raises(ForeignWorkspaceError):
        first_manager.cleanup_workspace(workspace)
    workspace.root_directory.unlink()
    saved_root.rename(workspace.root_directory)
    first_manager.cleanup_workspace(workspace)


def test_public_errors_hide_paths_filenames_and_sensitive_content(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    source = tmp_path / "--privileged"
    source.mkdir()
    newline_name = "token=secret-value\nrepository-credential"
    newline_entry = source / newline_name
    newline_entry.write_bytes(
        b"postgresql://user:password@host/database ../../etc/passwd"
    )

    with pytest.raises(RepositoryWorkspaceError) as error:
        manager.prepare_repository(source)
    newline_entry.unlink()
    carriage_name = "token=secret-value\rrepository-credential"
    (source / carriage_name).write_bytes(b"sensitive")
    with pytest.raises(RepositoryWorkspaceError) as carriage_error:
        manager.prepare_repository(source)

    messages = (str(error.value), str(carriage_error.value))
    for sensitive in (
        str(source),
        newline_name,
        carriage_name,
        "secret-value",
        "repository-credential",
        "postgresql",
        "password",
        "../../etc/passwd",
    ):
        assert all(sensitive not in message for message in messages)
    with pytest.raises(InvalidRepositorySourceError) as missing_error:
        manager.prepare_repository(Path("/home/private/project"))
    assert "/home/private/project" not in str(missing_error.value)
