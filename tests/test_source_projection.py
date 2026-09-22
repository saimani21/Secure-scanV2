from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
from collections.abc import Iterator
from dataclasses import FrozenInstanceError, dataclass, replace
from pathlib import Path
from uuid import UUID

import pytest

import securescan.source.projection as projection_module
from securescan.execution.docker_sandbox import DockerSandboxExecutor
from securescan.scanners.semgrep import SemgrepScannerAdapter
from securescan.source import (
    AnalysisCapability,
    InvalidSourceProjectionRequestError,
    PreparedSourceProjection,
    SourceExecutionContext,
    SourceExecutionSelectedFile,
    SourceProjectionCleanupError,
    SourceProjectionCorruptError,
    SourceProjectionLimitError,
    SourceProjectionManager,
    SourceProjectionMissingError,
    SourceProjectionOwnershipError,
    SourceProjectionPublicationError,
    SourceProjectionSelectedFileMismatchError,
    SourceProjectionSourceMutationError,
    SourceProjectionWorkspaceContextMismatchError,
)
from securescan.workspaces import (
    PreparedRepositoryWorkspace,
    RepositoryIntakeLimits,
    RepositoryManifestEntry,
    RepositoryWorkspaceManager,
)
from securescan.workspaces.models import repository_content_digest

RUN_ID = str(UUID("00000000-0000-4000-8000-000000003c21"))
JOB_ID = str(UUID("00000000-0000-4000-8000-000000003c22"))
ROOT_MARKER_NAME = ".securescan-source-projection-root"
ROOT_MARKER_CONTENT = b"securescan_source_projection_root_version=1\n"


class _Suffixes:
    def __init__(self) -> None:
        self._values: Iterator[int] = iter(range(1, 100))

    def __call__(self) -> str:
        return f"{next(self._values):032x}"


@dataclass(slots=True)
class _Environment:
    workspace_manager: RepositoryWorkspaceManager
    workspace: PreparedRepositoryWorkspace
    context: SourceExecutionContext
    projection_manager: SourceProjectionManager


def _prepare_environment(
    tmp_path: Path,
    *,
    selected: dict[str, bytes] | None = None,
    excluded: dict[str, bytes] | None = None,
) -> _Environment:
    selected_content = selected or {
        "app.py": b"print('approved')\n",
        "pkg/auth.py": b"def authenticate():\n    return True\n",
    }
    excluded_content = excluded if excluded is not None else {
        ".gitignore": b"*.secret\n",
        ".semgrepignore": b"vendor/\n",
        "README.md": b"excluded documentation\n",
        "secret.txt": b"credential=excluded\n",
        "tests/test_app.py": b"assert False\n",
        "vendor/lib.py": b"dangerous_vendor_code()\n",
    }
    source = tmp_path / "original-repository"
    source.mkdir()
    for relative_path, content in {**selected_content, **excluded_content}.items():
        path = source / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    (source / ".git").mkdir(exist_ok=True)
    (source / ".git" / "config").write_bytes(b"target-controlled\n")

    workspace_manager = RepositoryWorkspaceManager(
        tmp_path / "repository-workspaces",
        workspace_id_factory=lambda: "a" * 32,
    )
    workspace = workspace_manager.prepare_repository(source)
    entries = {
        entry.relative_path: entry for entry in workspace.manifest.entries
    }
    selected_entries = tuple(
        entries[path] for path in sorted(selected_content)
    )
    context = SourceExecutionContext(
        source_run_id=RUN_ID,
        job_id=JOB_ID,
        repository_digest=workspace.manifest.content_digest,
        profile_digest="1" * 64,
        plan_digest="2" * 64,
        source_analyzer_id="python-semgrep-v1",
        capability=AnalysisCapability.PYTHON_SAST,
        component_id=None,
        selected_files=tuple(
            SourceExecutionSelectedFile(entry=entry, component_id=None)
            for entry in selected_entries
        ),
        binding_digest="3" * 64,
        core_adapter_id="semgrep-ce",
    )
    return _Environment(
        workspace_manager=workspace_manager,
        workspace=workspace,
        context=context,
        projection_manager=SourceProjectionManager.initialize_base_directory(
            tmp_path / "source-projections",
            projection_id_factory=_Suffixes(),
        ),
    )


@pytest.fixture
def projection_environment(tmp_path: Path) -> Iterator[_Environment]:
    environment = _prepare_environment(tmp_path)
    try:
        yield environment
    finally:
        environment.workspace_manager.cleanup_workspace(environment.workspace)


def _visible_files(source_directory: Path) -> tuple[str, ...]:
    return tuple(
        sorted(
            path.relative_to(source_directory).as_posix()
            for path in source_directory.rglob("*")
            if path.is_file() and not path.is_symlink()
        )
    )


def _assert_no_symlinks_or_special_files(source_directory: Path) -> None:
    for current, directories, files in os.walk(source_directory, followlinks=False):
        current_path = Path(current)
        for name in (*directories, *files):
            metadata = (current_path / name).lstat()
            assert not stat.S_ISLNK(metadata.st_mode)
            assert stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)


def _projection_root_payloads(manager: SourceProjectionManager) -> tuple[str, ...]:
    marker = manager.base_directory / ROOT_MARKER_NAME
    assert marker.read_bytes() == ROOT_MARKER_CONTENT
    return tuple(
        sorted(
            entry.name
            for entry in manager.base_directory.iterdir()
            if entry.name != ROOT_MARKER_NAME
        )
    )


def _make_parent_writable(path: Path) -> None:
    os.chmod(path.parent, 0o755, follow_symlinks=False)


def _restore_parent_read_only(path: Path) -> None:
    os.chmod(path.parent, 0o555, follow_symlinks=False)


def test_projection_materializes_exact_selected_scope_and_independent_inodes(
    projection_environment: _Environment,
) -> None:
    environment = projection_environment
    projection = environment.projection_manager.build_projection(
        environment.workspace,
        environment.context,
    )
    try:
        expected_entries = tuple(
            selected.entry for selected in environment.context.selected_files
        )
        expected_paths = tuple(entry.relative_path for entry in expected_entries)

        assert isinstance(projection, PreparedSourceProjection)
        assert _visible_files(projection.source_directory) == expected_paths
        assert projection.manifest.entries == expected_entries
        assert projection.manifest.file_count == 2
        assert projection.projection_digest == repository_content_digest(
            expected_entries
        )
        assert projection.projection_digest != environment.context.repository_digest
        assert projection.context_digest == environment.context.context_digest()
        assert not (projection.source_directory / ".git").exists()
        for excluded in (
            ".gitignore",
            ".semgrepignore",
            "README.md",
            "secret.txt",
            "tests/test_app.py",
            "vendor/lib.py",
        ):
            assert not (projection.source_directory / excluded).exists()
        _assert_no_symlinks_or_special_files(projection.source_directory)
        for entry in expected_entries:
            source_metadata = (
                environment.workspace.source_directory / entry.relative_path
            ).stat()
            projected_metadata = (
                projection.source_directory / entry.relative_path
            ).stat()
            assert (source_metadata.st_dev, source_metadata.st_ino) != (
                projected_metadata.st_dev,
                projected_metadata.st_ino,
            )
            assert projected_metadata.st_nlink == 1
            assert stat.S_IMODE(projected_metadata.st_mode) == 0o444
        assert stat.S_IMODE(projection.source_directory.stat().st_mode) == 0o555
        marker = projection.root_directory / ".securescan-source-projection.json"
        marker_document = json.loads(marker.read_bytes())
        assert marker.parent == projection.root_directory
        assert marker_document["context_digest"] == projection.context_digest
        assert marker_document["projection_digest"] == projection.projection_digest
        assert "source_directory" not in marker_document
        with pytest.raises(FrozenInstanceError):
            projection.projection_digest = "f" * 64  # type: ignore[misc]
    finally:
        environment.projection_manager.cleanup_projection(projection)


def test_projection_manifest_and_digest_are_deterministic(
    projection_environment: _Environment,
) -> None:
    environment = projection_environment
    first = environment.projection_manager.build_projection(
        environment.workspace,
        environment.context,
    )
    second = environment.projection_manager.build_projection(
        environment.workspace,
        environment.context,
    )
    try:
        assert first.projection_id != second.projection_id
        assert first.manifest == second.manifest
        assert first.projection_digest == second.projection_digest
        assert first.context_digest == second.context_digest
        first_marker = json.loads(
            (first.root_directory / ".securescan-source-projection.json").read_bytes()
        )
        second_marker = json.loads(
            (second.root_directory / ".securescan-source-projection.json").read_bytes()
        )
        first_marker.pop("projection_id")
        second_marker.pop("projection_id")
        assert first_marker == second_marker
    finally:
        environment.projection_manager.cleanup_projection(first)
        environment.projection_manager.cleanup_projection(second)


def test_fresh_manager_reopens_projection_after_restart(
    projection_environment: _Environment,
) -> None:
    environment = projection_environment
    projection = environment.projection_manager.build_projection(
        environment.workspace,
        environment.context,
    )
    base_directory = environment.projection_manager.base_directory
    root_marker = base_directory / ROOT_MARKER_NAME
    assert root_marker.read_bytes() == ROOT_MARKER_CONTENT
    del environment.projection_manager
    fresh_manager = SourceProjectionManager(base_directory)
    reopened = fresh_manager.reopen_projection(
        projection.projection_id,
        expected_context_digest=projection.context_digest,
        expected_projection_digest=projection.projection_digest,
    )

    assert reopened == projection
    assert reopened.manifest.entries == tuple(
        selected.entry for selected in environment.context.selected_files
    )
    fresh_manager.cleanup_projection(reopened)


@pytest.mark.parametrize(
    ("tamper", "error"),
    (
        ("repository", SourceProjectionWorkspaceContextMismatchError),
        ("missing", SourceProjectionSelectedFileMismatchError),
        ("size", SourceProjectionSelectedFileMismatchError),
        ("sha", SourceProjectionSelectedFileMismatchError),
    ),
)
def test_workspace_context_and_selected_identity_mismatches_are_rejected(
    projection_environment: _Environment,
    tamper: str,
    error: type[Exception],
) -> None:
    environment = projection_environment
    context = environment.context
    if tamper == "repository":
        context = replace(context, repository_digest="f" * 64)
    else:
        selected = list(context.selected_files)
        if tamper == "missing":
            selected[0] = SourceExecutionSelectedFile(
                entry=RepositoryManifestEntry(
                    relative_path="absent.py",
                    size_bytes=1,
                    sha256=hashlib.sha256(b"x").hexdigest(),
                ),
                component_id=None,
            )
        elif tamper == "size":
            selected[0] = replace(
                selected[0],
                entry=replace(selected[0].entry, size_bytes=999),
            )
        else:
            selected[0] = replace(
                selected[0],
                entry=replace(selected[0].entry, sha256="f" * 64),
            )
        context = replace(
            context,
            selected_files=tuple(
                sorted(selected, key=lambda item: item.relative_path)
            ),
        )

    with pytest.raises(error):
        environment.projection_manager.build_projection(
            environment.workspace,
            context,
        )
    assert _projection_root_payloads(environment.projection_manager) == ()


@pytest.mark.parametrize("tamper", ("empty", "duplicate", "noncanonical"))
def test_invalid_context_selection_is_rejected_defensively(
    projection_environment: _Environment,
    tamper: str,
) -> None:
    environment = projection_environment
    context = replace(environment.context)
    if tamper == "empty":
        object.__setattr__(context, "selected_files", ())
    elif tamper == "duplicate":
        object.__setattr__(
            context,
            "selected_files",
            (context.selected_files[0], context.selected_files[0]),
        )
    else:
        object.__setattr__(
            context.selected_files[0].entry,
            "relative_path",
            "../app.py",
        )

    with pytest.raises(InvalidSourceProjectionRequestError):
        environment.projection_manager.build_projection(
            environment.workspace,
            context,
        )


@pytest.mark.parametrize("tamper", ("content", "symlink", "hardlink", "fifo"))
def test_source_changes_before_copy_are_rejected(
    projection_environment: _Environment,
    tamper: str,
) -> None:
    if tamper == "fifo" and os.name != "posix":
        pytest.skip("POSIX special files are required")
    environment = projection_environment
    app = environment.workspace.source_directory / "app.py"
    _make_parent_writable(app)
    if tamper == "content":
        os.chmod(app, 0o644, follow_symlinks=False)
        app.write_bytes(b"print('modified')\n")
        os.chmod(app, 0o444, follow_symlinks=False)
    elif tamper == "symlink":
        app.unlink()
        app.symlink_to("README.md")
    elif tamper == "hardlink":
        app.unlink()
        os.link(environment.workspace.source_directory / "README.md", app)
    else:
        app.unlink()
        os.mkfifo(app)
    _restore_parent_read_only(app)

    with pytest.raises(SourceProjectionSourceMutationError):
        environment.projection_manager.build_projection(
            environment.workspace,
            environment.context,
        )
    assert _projection_root_payloads(environment.projection_manager) == ()


def test_source_mutation_during_copy_is_rejected(
    projection_environment: _Environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = projection_environment
    app = environment.workspace.source_directory / "app.py"
    original_inventory = projection_module._inventory_tree
    original_read = projection_module.os.read
    armed = False
    changed = False

    def inventory_then_arm(*args: object, **kwargs: object):
        nonlocal armed
        result = original_inventory(*args, **kwargs)
        root = args[0]
        if root == environment.workspace.source_directory:
            armed = True
        return result

    def mutate_after_read(descriptor: int, size: int) -> bytes:
        nonlocal changed
        content = original_read(descriptor, size)
        if armed and not changed and content:
            changed = True
            os.chmod(app, 0o644, follow_symlinks=False)
            app.write_bytes(b"print('modified')\n")
            os.chmod(app, 0o444, follow_symlinks=False)
        return content

    monkeypatch.setattr(projection_module, "_inventory_tree", inventory_then_arm)
    monkeypatch.setattr(projection_module.os, "read", mutate_after_read)

    with pytest.raises(SourceProjectionSourceMutationError):
        environment.projection_manager.build_projection(
            environment.workspace,
            environment.context,
        )
    assert changed is True
    assert _projection_root_payloads(environment.projection_manager) == ()


def test_destination_preexisting_file_attack_prevents_publication(
    projection_environment: _Environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = projection_environment
    original_open = projection_module.os.open
    injected = False

    def attacking_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal injected
        if path == "app.py" and flags & os.O_CREAT and not injected:
            injected = True
            descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
            os.close(descriptor)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(projection_module.os, "open", attacking_open)
    with pytest.raises(SourceProjectionPublicationError):
        environment.projection_manager.build_projection(
            environment.workspace,
            environment.context,
        )
    assert injected is True
    assert _projection_root_payloads(environment.projection_manager) == ()


def test_destination_parent_symlink_attack_prevents_publication(
    projection_environment: _Environment,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    environment = projection_environment
    outside = tmp_path / "outside"
    outside.mkdir()
    original_mkdir = projection_module.os.mkdir
    injected = False

    def attacking_mkdir(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal injected
        if path == "pkg" and dir_fd is not None and not injected:
            injected = True
            os.symlink(outside, path, target_is_directory=True, dir_fd=dir_fd)
        original_mkdir(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr(projection_module.os, "mkdir", attacking_mkdir)
    with pytest.raises(SourceProjectionPublicationError):
        environment.projection_manager.build_projection(
            environment.workspace,
            environment.context,
        )
    assert injected is True
    assert outside.exists()
    assert _projection_root_payloads(environment.projection_manager) == ()


def test_extra_file_injected_before_publication_is_rejected(
    projection_environment: _Environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = projection_environment
    original = SourceProjectionManager._make_source_read_only

    def inject_extra(source_directory: Path) -> None:
        original(source_directory)
        os.chmod(source_directory, 0o755, follow_symlinks=False)
        extra = source_directory / ".semgrepignore"
        extra.write_bytes(b"ignore everything\n")
        os.chmod(extra, 0o444, follow_symlinks=False)
        os.chmod(source_directory, 0o555, follow_symlinks=False)

    monkeypatch.setattr(
        SourceProjectionManager,
        "_make_source_read_only",
        staticmethod(inject_extra),
    )
    with pytest.raises(SourceProjectionPublicationError):
        environment.projection_manager.build_projection(
            environment.workspace,
            environment.context,
        )
    assert _projection_root_payloads(environment.projection_manager) == ()


@pytest.mark.parametrize(
    ("tamper", "error"),
    (
        ("modified", SourceProjectionCorruptError),
        ("deleted", SourceProjectionCorruptError),
        ("symlink", SourceProjectionCorruptError),
        ("hardlink", SourceProjectionCorruptError),
        ("special", SourceProjectionCorruptError),
        ("extra", SourceProjectionCorruptError),
        ("marker_modified", SourceProjectionOwnershipError),
        ("marker_missing", SourceProjectionOwnershipError),
        ("marker_projection_digest", SourceProjectionCorruptError),
        ("marker_context_digest", SourceProjectionCorruptError),
        ("projection_digest", SourceProjectionCorruptError),
        ("context_digest", SourceProjectionCorruptError),
        ("root_symlink", SourceProjectionOwnershipError),
    ),
)
def test_reopen_rejects_projection_and_marker_tampering(
    projection_environment: _Environment,
    tamper: str,
    error: type[Exception],
    tmp_path: Path,
) -> None:
    environment = projection_environment
    projection = environment.projection_manager.build_projection(
        environment.workspace,
        environment.context,
    )
    app = projection.source_directory / "app.py"
    marker = projection.root_directory / ".securescan-source-projection.json"
    context_digest = projection.context_digest
    projection_digest = projection.projection_digest
    if tamper == "modified":
        os.chmod(app, 0o644, follow_symlinks=False)
        app.write_bytes(b"print('modified')\n")
        os.chmod(app, 0o444, follow_symlinks=False)
    elif tamper == "deleted":
        os.chmod(projection.source_directory, 0o755, follow_symlinks=False)
        app.unlink()
        os.chmod(projection.source_directory, 0o555, follow_symlinks=False)
    elif tamper == "symlink":
        outside = tmp_path / "outside-file"
        outside.write_bytes(b"outside")
        os.chmod(projection.source_directory, 0o755, follow_symlinks=False)
        app.unlink()
        app.symlink_to(outside)
        os.chmod(projection.source_directory, 0o555, follow_symlinks=False)
    elif tamper == "hardlink":
        os.link(app, tmp_path / "external-hardlink")
    elif tamper == "special":
        if os.name != "posix":
            pytest.skip("POSIX special files are required")
        os.chmod(projection.source_directory, 0o755, follow_symlinks=False)
        os.mkfifo(projection.source_directory / "scanner.pipe")
        os.chmod(projection.source_directory, 0o555, follow_symlinks=False)
    elif tamper == "extra":
        os.chmod(projection.source_directory, 0o755, follow_symlinks=False)
        extra = projection.source_directory / ".semgrepignore"
        extra.write_bytes(b"app.py\n")
        os.chmod(extra, 0o444, follow_symlinks=False)
        os.chmod(projection.source_directory, 0o555, follow_symlinks=False)
    elif tamper == "marker_modified":
        os.chmod(marker, 0o600, follow_symlinks=False)
        marker.write_bytes(b"{}")
        os.chmod(marker, 0o400, follow_symlinks=False)
    elif tamper == "marker_missing":
        marker.unlink()
    elif tamper in {"marker_projection_digest", "marker_context_digest"}:
        marker_document = json.loads(marker.read_bytes())
        field = tamper.removeprefix("marker_")
        marker_document[field] = "f" * 64
        canonical_marker = json.dumps(
            marker_document,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        os.chmod(marker, 0o600, follow_symlinks=False)
        marker.write_bytes(canonical_marker)
        os.chmod(marker, 0o400, follow_symlinks=False)
    elif tamper == "projection_digest":
        projection_digest = "f" * 64
    else:
        if tamper == "context_digest":
            context_digest = "e" * 64
        else:
            saved_root = projection.root_directory.with_name("saved-projection")
            projection.root_directory.rename(saved_root)
            projection.root_directory.symlink_to(
                saved_root,
                target_is_directory=True,
            )

    with pytest.raises(error):
        SourceProjectionManager(
            environment.projection_manager.base_directory
        ).reopen_projection(
            projection.projection_id,
            expected_context_digest=context_digest,
            expected_projection_digest=projection_digest,
        )


@pytest.mark.parametrize(
    "projection_id",
    (
        "../../escape",
        "/absolute/path",
        "securescan-source-projection-xyz",
        "securescan-source-projection-" + "a" * 15 + "/x",
    ),
)
def test_reopen_rejects_untrusted_projection_ids(
    projection_environment: _Environment,
    projection_id: str,
) -> None:
    with pytest.raises(InvalidSourceProjectionRequestError):
        projection_environment.projection_manager.reopen_projection(
            projection_id,
            expected_context_digest="1" * 64,
            expected_projection_digest="2" * 64,
        )


def test_reopen_distinguishes_missing_projection(
    projection_environment: _Environment,
) -> None:
    with pytest.raises(SourceProjectionMissingError):
        projection_environment.projection_manager.reopen_projection(
            "securescan-source-projection-" + "f" * 32,
            expected_context_digest="1" * 64,
            expected_projection_digest="2" * 64,
        )


@pytest.mark.parametrize("tamper", ("duplicate", "unknown", "noncanonical"))
def test_marker_parser_rejects_non_strict_json(
    projection_environment: _Environment,
    tamper: str,
) -> None:
    environment = projection_environment
    projection = environment.projection_manager.build_projection(
        environment.workspace,
        environment.context,
    )
    marker = projection.root_directory / ".securescan-source-projection.json"
    content = marker.read_bytes()
    if tamper == "duplicate":
        content = content.replace(
            b'{"context_digest":',
            b'{"context_digest":"0","context_digest":',
        )
    elif tamper == "unknown":
        document = json.loads(content)
        document["unknown"] = True
        content = json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    else:
        content = b" " + content
    os.chmod(marker, 0o600, follow_symlinks=False)
    marker.write_bytes(content)
    os.chmod(marker, 0o400, follow_symlinks=False)

    with pytest.raises(SourceProjectionOwnershipError):
        SourceProjectionManager(
            environment.projection_manager.base_directory
        ).reopen_projection(
            projection.projection_id,
            expected_context_digest=projection.context_digest,
            expected_projection_digest=projection.projection_digest,
        )


def test_projection_enforces_file_count_limit(
    projection_environment: _Environment,
    tmp_path: Path,
) -> None:
    manager = SourceProjectionManager.initialize_base_directory(
        tmp_path / "count-limited-projections",
        limits=RepositoryIntakeLimits(max_file_count=1),
    )
    with pytest.raises(SourceProjectionLimitError):
        manager.build_projection(
            projection_environment.workspace,
            projection_environment.context,
        )


@pytest.mark.parametrize("limit", ("single", "total"))
def test_projection_enforces_byte_limits(tmp_path: Path, limit: str) -> None:
    selected = (
        {"large.py": b"x" * 1025}
        if limit == "single"
        else {"first.py": b"x" * 600, "second.py": b"y" * 600}
    )
    environment = _prepare_environment(
        tmp_path,
        selected=selected,
        excluded={},
    )
    limits = (
        RepositoryIntakeLimits(
            max_single_file_bytes=1024,
            max_total_bytes=2048,
        )
        if limit == "single"
        else RepositoryIntakeLimits(
            max_single_file_bytes=1024,
            max_total_bytes=1024,
        )
    )
    manager = SourceProjectionManager.initialize_base_directory(
        tmp_path / "byte-limited-projections",
        limits=limits,
    )
    try:
        with pytest.raises(SourceProjectionLimitError):
            manager.build_projection(environment.workspace, environment.context)
    finally:
        environment.workspace_manager.cleanup_workspace(environment.workspace)


@pytest.mark.parametrize(
    ("selected_path", "limits"),
    (
        (
            "one/two/app.py",
            RepositoryIntakeLimits(max_directory_depth=1),
        ),
        (
            "x" * 65,
            RepositoryIntakeLimits(max_relative_path_bytes=64),
        ),
    ),
)
def test_projection_enforces_depth_and_path_limits(
    tmp_path: Path,
    selected_path: str,
    limits: RepositoryIntakeLimits,
) -> None:
    environment = _prepare_environment(
        tmp_path,
        selected={selected_path: b"x"},
        excluded={},
    )
    manager = SourceProjectionManager.initialize_base_directory(
        tmp_path / "path-limited-projections",
        limits=limits,
    )
    try:
        with pytest.raises(SourceProjectionLimitError):
            manager.build_projection(environment.workspace, environment.context)
    finally:
        environment.workspace_manager.cleanup_workspace(environment.workspace)


def test_cleanup_is_marker_gated_safe_and_distinguishes_missing(
    projection_environment: _Environment,
    tmp_path: Path,
) -> None:
    environment = projection_environment
    projection = environment.projection_manager.build_projection(
        environment.workspace,
        environment.context,
    )
    outside = tmp_path / "cleanup-outside"
    outside.write_bytes(b"must survive")
    os.chmod(projection.source_directory, 0o755, follow_symlinks=False)
    (projection.source_directory / "hostile-link").symlink_to(outside)
    os.chmod(projection.source_directory, 0o555, follow_symlinks=False)

    environment.projection_manager.cleanup_projection(projection)

    assert not projection.root_directory.exists()
    assert outside.read_bytes() == b"must survive"
    with pytest.raises(SourceProjectionMissingError):
        environment.projection_manager.cleanup_projection(projection)


def test_cleanup_rejects_invalid_reference_and_modified_marker(
    projection_environment: _Environment,
    tmp_path: Path,
) -> None:
    environment = projection_environment
    projection = environment.projection_manager.build_projection(
        environment.workspace,
        environment.context,
    )
    foreign_root = tmp_path / "foreign" / projection.projection_id
    invalid = replace(
        projection,
        root_directory=foreign_root,
        source_directory=foreign_root / "source",
    )
    with pytest.raises(InvalidSourceProjectionRequestError):
        environment.projection_manager.cleanup_projection(invalid)

    marker = projection.root_directory / ".securescan-source-projection.json"
    os.chmod(marker, 0o600, follow_symlinks=False)
    marker.write_bytes(b"{}")
    os.chmod(marker, 0o400, follow_symlinks=False)
    with pytest.raises(SourceProjectionOwnershipError):
        environment.projection_manager.cleanup_projection(projection)
    assert projection.root_directory.exists()


def test_cleanup_filesystem_failure_is_sanitized(
    projection_environment: _Environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = projection_environment
    projection = environment.projection_manager.build_projection(
        environment.workspace,
        environment.context,
    )
    original_unlink = projection_module.os.unlink

    def fail_unlink(*_args: object, **_kwargs: object) -> None:
        raise OSError("/private/token=secret")

    monkeypatch.setattr(projection_module.os, "unlink", fail_unlink)
    with pytest.raises(SourceProjectionCleanupError) as raised:
        environment.projection_manager.cleanup_projection(projection)
    assert "/private" not in str(raised.value)
    assert "secret" not in str(raised.value)
    monkeypatch.setattr(projection_module.os, "unlink", original_unlink)
    environment.projection_manager.cleanup_projection(projection)


def test_preexisting_final_projection_is_not_overwritten(tmp_path: Path) -> None:
    environment = _prepare_environment(tmp_path)
    manager = SourceProjectionManager.initialize_base_directory(
        tmp_path / "fixed-projections",
        projection_id_factory=lambda: "f" * 32,
    )
    final = manager.base_directory / (
        "securescan-source-projection-" + "f" * 32
    )
    final.mkdir()
    try:
        with pytest.raises(SourceProjectionPublicationError):
            manager.build_projection(environment.workspace, environment.context)
        assert final.is_dir()
        assert list(final.iterdir()) == []
    finally:
        environment.workspace_manager.cleanup_workspace(environment.workspace)


def test_projection_root_first_initialization_is_owned_and_private(
    tmp_path: Path,
) -> None:
    root = tmp_path / "new-parent" / "source-projections"
    manager = SourceProjectionManager.initialize_base_directory(root)
    marker = manager.base_directory / ROOT_MARKER_NAME
    root_metadata = manager.base_directory.stat(follow_symlinks=False)
    marker_metadata = marker.stat(follow_symlinks=False)

    assert manager.base_directory == root.resolve(strict=True)
    assert marker.read_bytes() == ROOT_MARKER_CONTENT
    assert stat.S_ISDIR(root_metadata.st_mode)
    assert stat.S_ISREG(marker_metadata.st_mode)
    assert marker_metadata.st_nlink == 1
    assert _projection_root_payloads(manager) == ()
    if os.name == "posix":
        assert stat.S_IMODE(root_metadata.st_mode) == 0o700
        assert stat.S_IMODE(marker_metadata.st_mode) == 0o400
    if hasattr(os, "geteuid"):
        assert root_metadata.st_uid == os.geteuid()
        assert marker_metadata.st_uid == os.geteuid()


def test_ordinary_constructor_initializes_genuinely_absent_root(
    tmp_path: Path,
) -> None:
    root = tmp_path / "missing-parent" / "source-projections"

    manager = SourceProjectionManager(root)

    assert manager.base_directory == root
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert (root / ROOT_MARKER_NAME).read_bytes() == ROOT_MARKER_CONTENT


@pytest.mark.parametrize("foreign_entry", (False, True))
def test_projection_root_rejects_unmarked_existing_directory_without_repair(
    tmp_path: Path,
    foreign_entry: bool,
) -> None:
    root = tmp_path / "unmarked"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700, follow_symlinks=False)
    if foreign_entry:
        (root / "unrelated-host-data").write_bytes(b"must survive")
    mode_before = stat.S_IMODE(root.stat(follow_symlinks=False).st_mode)

    with pytest.raises(SourceProjectionOwnershipError):
        SourceProjectionManager(root)

    assert stat.S_IMODE(root.stat(follow_symlinks=False).st_mode) == mode_before
    assert not (root / ROOT_MARKER_NAME).exists()
    if foreign_entry:
        assert (root / "unrelated-host-data").read_bytes() == b"must survive"


@pytest.mark.parametrize("tamper", ("content", "permissions"))
def test_projection_root_rejects_corrupt_marker(
    tmp_path: Path,
    tamper: str,
) -> None:
    root = tmp_path / "corrupt-root-marker"
    manager = SourceProjectionManager.initialize_base_directory(root)
    marker = manager.base_directory / ROOT_MARKER_NAME
    if tamper == "content":
        os.chmod(marker, 0o600, follow_symlinks=False)
        marker.write_bytes(b"securescan_source_projection_root_version=2\n")
        os.chmod(marker, 0o400, follow_symlinks=False)
    else:
        os.chmod(marker, 0o600, follow_symlinks=False)

    with pytest.raises(SourceProjectionOwnershipError):
        SourceProjectionManager(root)


def test_projection_root_rejects_marker_symlink(tmp_path: Path) -> None:
    root = tmp_path / "symlinked-root-marker"
    manager = SourceProjectionManager.initialize_base_directory(root)
    marker = manager.base_directory / ROOT_MARKER_NAME
    outside = tmp_path / "outside-root-marker"
    outside.write_bytes(ROOT_MARKER_CONTENT)
    marker.unlink()
    marker.symlink_to(outside)

    with pytest.raises(SourceProjectionOwnershipError):
        SourceProjectionManager(root)


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard links are required")
def test_projection_root_rejects_marker_hardlink(tmp_path: Path) -> None:
    root = tmp_path / "hardlinked-root-marker"
    manager = SourceProjectionManager.initialize_base_directory(root)
    marker = manager.base_directory / ROOT_MARKER_NAME
    os.link(marker, tmp_path / "external-root-marker-link")

    with pytest.raises(SourceProjectionOwnershipError):
        SourceProjectionManager(root)


def test_projection_root_rejects_wrong_permissions_without_repair(
    tmp_path: Path,
) -> None:
    if os.name != "posix":
        pytest.skip("POSIX permission semantics are required")
    root = tmp_path / "wrong-root-permissions"
    manager = SourceProjectionManager.initialize_base_directory(root)
    os.chmod(manager.base_directory, 0o755, follow_symlinks=False)

    with pytest.raises(SourceProjectionOwnershipError):
        SourceProjectionManager(root)

    assert stat.S_IMODE(root.stat(follow_symlinks=False).st_mode) == 0o755


def test_projection_root_checks_effective_user_ownership(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not hasattr(os, "geteuid"):
        pytest.skip("effective-user ownership is unavailable")
    root = tmp_path / "foreign-owner"
    SourceProjectionManager.initialize_base_directory(root)
    current_effective_user = os.geteuid()
    monkeypatch.setattr(
        projection_module.os,
        "geteuid",
        lambda: current_effective_user + 1,
    )

    with pytest.raises(SourceProjectionOwnershipError):
        SourceProjectionManager(root)


def test_projection_root_rejects_broad_temporary_root_without_modifying_it() -> None:
    if not Path("/tmp").is_dir():
        pytest.skip("the broad temporary root is unavailable")
    mode_before = stat.S_IMODE(Path("/tmp").stat(follow_symlinks=False).st_mode)
    marker_existed_before = os.path.lexists(Path("/tmp") / ROOT_MARKER_NAME)

    with pytest.raises(SourceProjectionPublicationError):
        SourceProjectionManager(Path("/tmp"))

    assert stat.S_IMODE(Path("/tmp").stat(follow_symlinks=False).st_mode) == mode_before
    assert (
        os.path.lexists(Path("/tmp") / ROOT_MARKER_NAME)
        is marker_existed_before
    )


def test_projection_root_rejects_relative_symlink_and_git_locations(
    tmp_path: Path,
) -> None:
    real_root = tmp_path / "real-root"
    real_root.mkdir()
    symlink_root = tmp_path / "symlink-root"
    symlink_root.symlink_to(real_root, target_is_directory=True)
    git_root = tmp_path / ".git" / "projections"

    for invalid in (Path("relative"), symlink_root, git_root):
        with pytest.raises(SourceProjectionPublicationError):
            SourceProjectionManager(invalid)


def test_projection_boundary_never_executes_tools(
    projection_environment: _Environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("v0.3C2 attempted discovery or execution")

    monkeypatch.setattr(shutil, "which", fail)
    monkeypatch.setattr(subprocess, "run", fail)
    monkeypatch.setattr(subprocess, "Popen", fail)
    monkeypatch.setattr(os, "system", fail)
    monkeypatch.setattr(DockerSandboxExecutor, "execute", fail)
    monkeypatch.setattr(DockerSandboxExecutor, "start", fail)
    monkeypatch.setattr(SemgrepScannerAdapter, "execute", fail)

    environment = projection_environment
    projection = environment.projection_manager.build_projection(
        environment.workspace,
        environment.context,
    )
    reopened = SourceProjectionManager(
        environment.projection_manager.base_directory
    ).reopen_projection(
        projection.projection_id,
        expected_context_digest=projection.context_digest,
        expected_projection_digest=projection.projection_digest,
    )
    assert reopened == projection
    environment.projection_manager.cleanup_projection(projection)
