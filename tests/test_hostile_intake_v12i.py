"""V1.2I-A hostile intake checks over disposable repository fixtures only."""

from __future__ import annotations

from pathlib import Path

import pytest

from securescan.workspaces import (
    RepositoryChangedDuringIntakeError,
    RepositoryIntakeLimitError,
    RepositoryIntakeLimits,
    RepositoryWorkspaceManager,
    UnsupportedRepositoryEntryError,
)


def _manager(
    tmp_path: Path, *, limits: RepositoryIntakeLimits | None = None
) -> RepositoryWorkspaceManager:
    options = {} if limits is None else {"limits": limits}
    return RepositoryWorkspaceManager(
        tmp_path / "managed",
        workspace_id_factory=lambda: "a" * 32,
        **options,
    )


@pytest.mark.parametrize("link_kind", ("broken", "loop"))
def test_broken_and_looping_links_reject_without_publishing_workspace(
    tmp_path: Path, link_kind: str
) -> None:
    source = tmp_path / "repository"
    source.mkdir()
    if link_kind == "broken":
        (source / "broken.py").symlink_to("missing.py")
    else:
        (source / "loop-a.py").symlink_to("loop-b.py")
        (source / "loop-b.py").symlink_to("loop-a.py")
    manager = _manager(tmp_path)

    with pytest.raises(UnsupportedRepositoryEntryError):
        manager.prepare_repository(source)

    assert list(manager.base_directory.iterdir()) == []


@pytest.mark.parametrize("mutation", ("delete", "replace_with_external_link"))
def test_file_changed_after_stat_fails_closed_and_cleans_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    source = tmp_path / "repository"
    source.mkdir()
    file_path = source / "app.py"
    file_path.write_bytes(b"print('safe')\n")
    outside = tmp_path / "outside-secret"
    outside.write_bytes(b"never-copy-this-sentinel")
    manager = _manager(tmp_path)
    original_copy = manager._copy_file

    def change_before_open(*args, **kwargs) -> None:
        file_path.unlink()
        if mutation == "replace_with_external_link":
            file_path.symlink_to(outside)
        original_copy(*args, **kwargs)

    monkeypatch.setattr(manager, "_copy_file", change_before_open)
    with pytest.raises(RepositoryChangedDuringIntakeError) as raised:
        manager.prepare_repository(source)

    assert str(outside) not in str(raised.value)
    assert outside.read_bytes() == b"never-copy-this-sentinel"
    assert list(manager.base_directory.iterdir()) == []


def test_directory_replaced_with_external_link_after_stat_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "repository"
    nested = source / "nested"
    nested.mkdir(parents=True)
    (nested / "app.py").write_bytes(b"print('safe')\n")
    outside = tmp_path / "outside-directory"
    outside.mkdir()
    (outside / "sentinel").write_bytes(b"never-copy-this-sentinel")
    parked = tmp_path / "parked-original"
    manager = _manager(tmp_path)
    original_open = manager._open_source_directory

    def change_before_open(name, parent_descriptor, expected):
        nested.rename(parked)
        nested.symlink_to(outside, target_is_directory=True)
        return original_open(name, parent_descriptor, expected)

    monkeypatch.setattr(manager, "_open_source_directory", change_before_open)
    with pytest.raises(RepositoryChangedDuringIntakeError) as raised:
        manager.prepare_repository(source)

    assert str(outside) not in str(raised.value)
    assert (outside / "sentinel").read_bytes() == b"never-copy-this-sentinel"
    assert list(manager.base_directory.iterdir()) == []


def test_sparse_file_exceeds_limit_before_any_workspace_is_published(
    tmp_path: Path,
) -> None:
    source = tmp_path / "repository"
    source.mkdir()
    sparse = source / "sparse.bin"
    with sparse.open("wb") as stream:
        stream.seek(2_000_000)
        stream.write(b"x")
    manager = _manager(
        tmp_path,
        limits=RepositoryIntakeLimits(
            max_single_file_bytes=1_024,
            max_total_bytes=2_048,
        ),
    )

    with pytest.raises(RepositoryIntakeLimitError):
        manager.prepare_repository(source)

    assert sparse.stat().st_size == 2_000_001
    assert list(manager.base_directory.iterdir()) == []


def test_distinct_unicode_spellings_keep_exact_manifest_paths(tmp_path: Path) -> None:
    source = tmp_path / "repository"
    source.mkdir()
    names = ("caf\u00e9.py", "cafe\u0301.py")
    for index, name in enumerate(names):
        (source / name).write_bytes(f"print({index})\n".encode())
    manager = _manager(tmp_path)

    workspace = manager.prepare_repository(source)
    try:
        actual = tuple(entry.relative_path for entry in workspace.manifest.entries)
        assert actual == tuple(sorted(names))
        assert workspace.manifest.file_count == 2
        assert len({entry.sha256 for entry in workspace.manifest.entries}) == 2
    finally:
        manager.cleanup_workspace(workspace)
