from __future__ import annotations

import hashlib
import os
import secrets
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from securescan.workspaces.models import (
    PreparedRepositoryWorkspace,
    RepositoryIntakeLimits,
    RepositoryManifest,
    RepositoryManifestEntry,
    repository_content_digest,
)

_WORKSPACE_PREFIX = "securescan-workspace-"
_STAGING_PREFIX = ".securescan-staging-"
_MARKER_NAME = ".securescan-workspace"
_MARKER_VERSION = "1"
_COPY_CHUNK_BYTES = 1024 * 1024
_EXCLUDED_DIRECTORIES = frozenset({".git", ".hg", ".svn"})
_PROTECTED_DIRECTORIES = (
    Path("/"),
    Path("/dev"),
    Path("/etc"),
    Path("/proc"),
    Path("/root"),
    Path("/run"),
    Path("/sys"),
    Path("/var/run"),
)
_DIRECTORY_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FILE_READ_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FILE_CREATE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_DEFAULT_INTAKE_LIMITS = RepositoryIntakeLimits()


class RepositoryWorkspaceError(RuntimeError):
    """Base class for sanitized repository workspace failures."""


class InvalidRepositorySourceError(RepositoryWorkspaceError, ValueError):
    def __init__(self) -> None:
        super().__init__("Repository source is invalid")


class UnsupportedRepositoryEntryError(RepositoryWorkspaceError):
    def __init__(self) -> None:
        super().__init__("Repository contains an unsupported entry")


class RepositoryIntakeLimitError(RepositoryWorkspaceError):
    def __init__(self) -> None:
        super().__init__("Repository intake limit was exceeded")


class RepositoryChangedDuringIntakeError(RepositoryWorkspaceError):
    def __init__(self) -> None:
        super().__init__("Repository changed during intake")


class RepositoryWorkspaceCreationError(RepositoryWorkspaceError):
    def __init__(self) -> None:
        super().__init__("Repository workspace could not be created")


class RepositoryWorkspaceCleanupError(RepositoryWorkspaceError):
    def __init__(self) -> None:
        super().__init__("Repository workspace could not be removed")


class ForeignWorkspaceError(RepositoryWorkspaceError):
    def __init__(self) -> None:
        super().__init__("Repository workspace ownership could not be verified")


def _new_workspace_suffix() -> str:
    return secrets.token_hex(16)


def _contains_control_characters(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _is_protected_directory(path: Path) -> bool:
    return any(
        path == protected
        or (protected != Path("/") and path.is_relative_to(protected))
        for protected in _PROTECTED_DIRECTORIES
    )


def _same_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def _marker_content(workspace_id: str) -> bytes:
    return (
        f"securescan_workspace_version={_MARKER_VERSION}\n"
        f"workspace_id={workspace_id}\n"
    ).encode("ascii")


@dataclass(slots=True)
class _IntakeState:
    limits: RepositoryIntakeLimits
    entries: list[RepositoryManifestEntry] = field(default_factory=list)
    total_bytes: int = 0
    seen_identities: set[tuple[int, int]] = field(default_factory=set)


class RepositoryWorkspaceManager:
    def __init__(
        self,
        base_directory: Path,
        limits: RepositoryIntakeLimits = _DEFAULT_INTAKE_LIMITS,
        workspace_id_factory: Callable[[], str] = _new_workspace_suffix,
    ) -> None:
        self._limits = limits
        if not isinstance(self._limits, RepositoryIntakeLimits):
            raise RepositoryWorkspaceCreationError
        if not callable(workspace_id_factory):
            raise RepositoryWorkspaceCreationError
        self._workspace_id_factory = workspace_id_factory
        self._base_directory = self._prepare_base_directory(base_directory)
        base_metadata = self._base_directory.stat(follow_symlinks=False)
        self._base_identity = (base_metadata.st_dev, base_metadata.st_ino)

    @property
    def base_directory(self) -> Path:
        return self._base_directory

    @staticmethod
    def _prepare_base_directory(base_directory: object) -> Path:
        if (
            not isinstance(base_directory, Path)
            or not base_directory.is_absolute()
            or base_directory.is_symlink()
        ):
            raise RepositoryWorkspaceCreationError
        try:
            base_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            if base_directory.is_symlink():
                raise RepositoryWorkspaceCreationError
            resolved = base_directory.resolve(strict=True)
            if not resolved.is_dir() or _is_protected_directory(resolved):
                raise RepositoryWorkspaceCreationError
            os.chmod(resolved, 0o700, follow_symlinks=False)
        except RepositoryWorkspaceError:
            raise
        except (OSError, RuntimeError) as exc:
            raise RepositoryWorkspaceCreationError from exc
        return resolved

    def _validate_source(self, source_directory: object) -> Path:
        if (
            not isinstance(source_directory, Path)
            or not source_directory.is_absolute()
            or source_directory.is_symlink()
        ):
            raise InvalidRepositorySourceError
        try:
            source = source_directory.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise InvalidRepositorySourceError from exc
        if (
            not source.is_dir()
            or _is_protected_directory(source)
            or source.name == "docker.sock"
            or source.name in _EXCLUDED_DIRECTORIES
            or source == self._base_directory
            or source.is_relative_to(self._base_directory)
            or self._base_directory.is_relative_to(source)
        ):
            raise InvalidRepositorySourceError
        for parent in (source, *source.parents):
            marker = parent / _MARKER_NAME
            try:
                if marker.is_file() and not marker.is_symlink():
                    raise InvalidRepositorySourceError
            except OSError as exc:
                raise InvalidRepositorySourceError from exc
        return source

    def _workspace_names(self) -> tuple[str, str]:
        try:
            suffix = self._workspace_id_factory()
        except Exception as exc:
            raise RepositoryWorkspaceCreationError from exc
        if (
            not isinstance(suffix, str)
            or not 16 <= len(suffix) <= 48
            or any(character not in "0123456789abcdef" for character in suffix)
        ):
            raise RepositoryWorkspaceCreationError
        return f"{_WORKSPACE_PREFIX}{suffix}", f"{_STAGING_PREFIX}{suffix}"

    @staticmethod
    def _write_marker(staging: Path, workspace_id: str) -> None:
        marker = staging / _MARKER_NAME
        try:
            descriptor = os.open(marker, _FILE_CREATE_FLAGS, 0o600)
            try:
                content = _marker_content(workspace_id)
                written = 0
                while written < len(content):
                    written += os.write(descriptor, content[written:])
                os.fchmod(descriptor, 0o600)
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise RepositoryWorkspaceCreationError from exc

    def _validate_relative_path(
        self,
        relative_parts: tuple[str, ...],
    ) -> str:
        if (
            not relative_parts
            or any(
                not component
                or component in {".", ".."}
                or "\\" in component
                or _contains_control_characters(component)
                for component in relative_parts
            )
        ):
            raise UnsupportedRepositoryEntryError
        relative_path = PurePosixPath(*relative_parts).as_posix()
        try:
            path_bytes = relative_path.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise UnsupportedRepositoryEntryError from exc
        if len(path_bytes) > self._limits.max_relative_path_bytes:
            raise RepositoryIntakeLimitError
        return relative_path

    @staticmethod
    def _open_source_directory(
        name: str,
        parent_descriptor: int,
        expected: os.stat_result,
    ) -> int:
        descriptor: int | None = None
        try:
            descriptor = os.open(
                name,
                _DIRECTORY_OPEN_FLAGS,
                dir_fd=parent_descriptor,
            )
            actual = os.fstat(descriptor)
        except OSError as exc:
            if descriptor is not None:
                os.close(descriptor)
            raise RepositoryChangedDuringIntakeError from exc
        assert descriptor is not None
        if not stat.S_ISDIR(actual.st_mode) or not _same_identity(expected, actual):
            os.close(descriptor)
            raise RepositoryChangedDuringIntakeError
        return descriptor

    def _copy_file(
        self,
        source_descriptor: int,
        destination_directory: Path,
        name: str,
        relative_path: str,
        initial: os.stat_result,
        state: _IntakeState,
    ) -> None:
        if initial.st_nlink > 1:
            raise UnsupportedRepositoryEntryError
        if initial.st_size > self._limits.max_single_file_bytes:
            raise RepositoryIntakeLimitError
        try:
            source_file = os.open(
                name,
                _FILE_READ_FLAGS,
                dir_fd=source_descriptor,
            )
        except OSError as exc:
            raise RepositoryChangedDuringIntakeError from exc
        destination_file: int | None = None
        try:
            try:
                opened = os.fstat(source_file)
            except OSError as exc:
                raise RepositoryChangedDuringIntakeError from exc
            if (
                not stat.S_ISREG(opened.st_mode)
                or not _same_identity(initial, opened)
                or opened.st_nlink != 1
            ):
                raise RepositoryChangedDuringIntakeError
            try:
                destination_file = os.open(
                    destination_directory / name,
                    _FILE_CREATE_FLAGS,
                    0o600,
                )
            except OSError as exc:
                raise RepositoryWorkspaceCreationError from exc

            digest = hashlib.sha256()
            copied_bytes = 0
            while True:
                try:
                    chunk = os.read(source_file, _COPY_CHUNK_BYTES)
                except OSError as exc:
                    raise RepositoryChangedDuringIntakeError from exc
                if not chunk:
                    break
                copied_bytes += len(chunk)
                if copied_bytes > initial.st_size:
                    raise RepositoryChangedDuringIntakeError
                if copied_bytes > self._limits.max_single_file_bytes:
                    raise RepositoryIntakeLimitError
                if state.total_bytes + copied_bytes > self._limits.max_total_bytes:
                    raise RepositoryIntakeLimitError
                digest.update(chunk)
                remaining = memoryview(chunk)
                while remaining:
                    try:
                        written = os.write(destination_file, remaining)
                    except OSError as exc:
                        raise RepositoryWorkspaceCreationError from exc
                    if written <= 0:
                        raise RepositoryWorkspaceCreationError
                    remaining = remaining[written:]

            try:
                finished = os.fstat(source_file)
            except OSError as exc:
                raise RepositoryChangedDuringIntakeError from exc
            if (
                copied_bytes != initial.st_size
                or not _same_identity(initial, finished)
                or finished.st_size != initial.st_size
                or finished.st_nlink != 1
                or finished.st_mtime_ns != initial.st_mtime_ns
                or finished.st_ctime_ns != initial.st_ctime_ns
            ):
                raise RepositoryChangedDuringIntakeError
            os.fchmod(destination_file, 0o444)
            state.total_bytes += copied_bytes
            state.entries.append(
                RepositoryManifestEntry(
                    relative_path=relative_path,
                    size_bytes=copied_bytes,
                    sha256=digest.hexdigest(),
                )
            )
        finally:
            if destination_file is not None:
                os.close(destination_file)
            os.close(source_file)

    def _copy_directory(
        self,
        source_descriptor: int,
        destination_directory: Path,
        relative_parts: tuple[str, ...],
        depth: int,
        state: _IntakeState,
    ) -> None:
        try:
            initial_directory = os.fstat(source_descriptor)
            with os.scandir(source_descriptor) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError as exc:
            raise RepositoryChangedDuringIntakeError from exc

        for entry in entries:
            name = entry.name
            child_parts = (*relative_parts, name)
            relative_path = self._validate_relative_path(child_parts)
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise RepositoryChangedDuringIntakeError from exc
            identity = (metadata.st_dev, metadata.st_ino)
            if identity in state.seen_identities:
                raise UnsupportedRepositoryEntryError
            state.seen_identities.add(identity)

            if stat.S_ISLNK(metadata.st_mode):
                raise UnsupportedRepositoryEntryError
            if stat.S_ISDIR(metadata.st_mode):
                if name in _EXCLUDED_DIRECTORIES:
                    continue
                child_depth = depth + 1
                if child_depth > self._limits.max_directory_depth:
                    raise RepositoryIntakeLimitError
                try:
                    destination_child = destination_directory / name
                    destination_child.mkdir(mode=0o700)
                except OSError as exc:
                    raise RepositoryWorkspaceCreationError from exc
                child_descriptor = self._open_source_directory(
                    name,
                    source_descriptor,
                    metadata,
                )
                try:
                    self._copy_directory(
                        child_descriptor,
                        destination_child,
                        child_parts,
                        child_depth,
                        state,
                    )
                finally:
                    os.close(child_descriptor)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise UnsupportedRepositoryEntryError
            if len(state.entries) >= self._limits.max_file_count:
                raise RepositoryIntakeLimitError
            self._copy_file(
                source_descriptor,
                destination_directory,
                name,
                relative_path,
                metadata,
                state,
            )
        try:
            finished_directory = os.fstat(source_descriptor)
        except OSError as exc:
            raise RepositoryChangedDuringIntakeError from exc
        if (
            not _same_identity(initial_directory, finished_directory)
            or initial_directory.st_mtime_ns != finished_directory.st_mtime_ns
            or initial_directory.st_ctime_ns != finished_directory.st_ctime_ns
        ):
            raise RepositoryChangedDuringIntakeError

    @staticmethod
    def _make_source_read_only(source_directory: Path) -> None:
        try:
            for current, directories, files in os.walk(
                source_directory,
                topdown=False,
                followlinks=False,
            ):
                current_path = Path(current)
                for file_name in files:
                    os.chmod(
                        current_path / file_name,
                        0o444,
                        follow_symlinks=False,
                    )
                for directory_name in directories:
                    os.chmod(
                        current_path / directory_name,
                        0o555,
                        follow_symlinks=False,
                    )
                os.chmod(current_path, 0o555, follow_symlinks=False)
        except OSError as exc:
            raise RepositoryWorkspaceCreationError from exc

    @staticmethod
    def _clear_directory(descriptor: int) -> None:
        os.fchmod(descriptor, 0o700)
        with os.scandir(descriptor) as iterator:
            entries = list(iterator)
        for entry in entries:
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                child = os.open(
                    entry.name,
                    _DIRECTORY_OPEN_FLAGS,
                    dir_fd=descriptor,
                )
                try:
                    actual = os.fstat(child)
                    if not _same_identity(metadata, actual):
                        raise RepositoryWorkspaceCleanupError
                    RepositoryWorkspaceManager._clear_directory(child)
                finally:
                    os.close(child)
                os.rmdir(entry.name, dir_fd=descriptor)
            else:
                os.unlink(entry.name, dir_fd=descriptor)

    def _remove_direct_child(
        self,
        child_name: str,
        expected_identity: tuple[int, int] | None = None,
    ) -> None:
        base_descriptor: int | None = None
        child_descriptor: int | None = None
        try:
            base_descriptor = os.open(self._base_directory, _DIRECTORY_OPEN_FLAGS)
            opened_base = os.fstat(base_descriptor)
            if (opened_base.st_dev, opened_base.st_ino) != self._base_identity:
                raise RepositoryWorkspaceCleanupError
            try:
                initial = os.stat(
                    child_name,
                    dir_fd=base_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                return
            if not stat.S_ISDIR(initial.st_mode) or stat.S_ISLNK(initial.st_mode):
                raise RepositoryWorkspaceCleanupError
            if expected_identity is not None and (
                initial.st_dev,
                initial.st_ino,
            ) != expected_identity:
                raise RepositoryWorkspaceCleanupError
            child_descriptor = os.open(
                child_name,
                _DIRECTORY_OPEN_FLAGS,
                dir_fd=base_descriptor,
            )
            actual = os.fstat(child_descriptor)
            if not _same_identity(initial, actual):
                raise RepositoryWorkspaceCleanupError
            self._clear_directory(child_descriptor)
            final = os.stat(
                child_name,
                dir_fd=base_descriptor,
                follow_symlinks=False,
            )
            if not _same_identity(initial, final):
                raise RepositoryWorkspaceCleanupError
            os.rmdir(child_name, dir_fd=base_descriptor)
        except RepositoryWorkspaceError:
            raise
        except OSError as exc:
            raise RepositoryWorkspaceCleanupError from exc
        finally:
            if child_descriptor is not None:
                os.close(child_descriptor)
            if base_descriptor is not None:
                os.close(base_descriptor)

    def _snapshot_repository(
        self,
        source: Path,
        snapshot: Path,
    ) -> RepositoryManifest:
        source_descriptor: int | None = None
        try:
            root_metadata = source.stat(follow_symlinks=False)
            source_descriptor = os.open(source, _DIRECTORY_OPEN_FLAGS)
            opened_root = os.fstat(source_descriptor)
        except OSError as exc:
            if source_descriptor is not None:
                os.close(source_descriptor)
            raise RepositoryChangedDuringIntakeError from exc
        assert source_descriptor is not None
        if not _same_identity(root_metadata, opened_root):
            os.close(source_descriptor)
            raise RepositoryChangedDuringIntakeError
        state = _IntakeState(
            limits=self._limits,
            seen_identities={(opened_root.st_dev, opened_root.st_ino)},
        )
        try:
            self._copy_directory(
                source_descriptor,
                snapshot,
                (),
                0,
                state,
            )
        finally:
            os.close(source_descriptor)
        entries = tuple(sorted(state.entries, key=lambda entry: entry.relative_path))
        return RepositoryManifest(
            entries=entries,
            file_count=len(entries),
            total_bytes=state.total_bytes,
            content_digest=repository_content_digest(entries),
        )

    def prepare_repository(
        self,
        source_directory: Path,
    ) -> PreparedRepositoryWorkspace:
        source = self._validate_source(source_directory)
        workspace_id, staging_name = self._workspace_names()
        staging = self._base_directory / staging_name
        final = self._base_directory / workspace_id
        active_name: str | None = None
        try:
            if os.path.lexists(final):
                raise RepositoryWorkspaceCreationError
            staging.mkdir(mode=0o700)
            active_name = staging_name
            os.chmod(staging, 0o700, follow_symlinks=False)
            self._write_marker(staging, workspace_id)
            snapshot = staging / "source"
            output = staging / "output"
            snapshot.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            manifest = self._snapshot_repository(source, snapshot)
            self._make_source_read_only(snapshot)
            # Docker UID 65532 needs write access to this bind mount. Its private
            # 0700 workspace parent prevents unrelated host users from traversing it.
            os.chmod(output, 0o777, follow_symlinks=False)
            os.chmod(staging, 0o700, follow_symlinks=False)
            staging.rename(final)
            active_name = workspace_id
            return PreparedRepositoryWorkspace(
                workspace_id=workspace_id,
                root_directory=final,
                source_directory=final / "source",
                output_directory=final / "output",
                manifest=manifest,
            )
        except RepositoryWorkspaceError as exc:
            if active_name is not None:
                try:
                    self._remove_direct_child(active_name)
                except RepositoryWorkspaceError as cleanup_error:
                    raise cleanup_error from exc
            raise
        except Exception as exc:
            if active_name is not None:
                try:
                    self._remove_direct_child(active_name)
                except RepositoryWorkspaceError as cleanup_error:
                    raise cleanup_error from exc
            raise RepositoryWorkspaceCreationError from exc

    def resolve_workspace(
        self,
        workspace_id: str,
        manifest: RepositoryManifest,
    ) -> PreparedRepositoryWorkspace:
        """Resolve an opaque owned workspace without accepting a caller path."""

        try:
            base_metadata = self._base_directory.stat(follow_symlinks=False)
            if (
                self._base_directory.is_symlink()
                or not stat.S_ISDIR(base_metadata.st_mode)
                or (base_metadata.st_dev, base_metadata.st_ino) != self._base_identity
            ):
                raise ForeignWorkspaceError
            workspace = PreparedRepositoryWorkspace(
                workspace_id=workspace_id,
                root_directory=self._base_directory / workspace_id,
                source_directory=self._base_directory / workspace_id / "source",
                output_directory=self._base_directory / workspace_id / "output",
                manifest=manifest,
            )
            if self._validate_cleanup_ownership(workspace) is None:
                raise ForeignWorkspaceError
            return workspace
        except RepositoryWorkspaceError:
            raise
        except (OSError, TypeError, ValueError):
            raise ForeignWorkspaceError from None

    def _validate_cleanup_ownership(
        self,
        workspace: object,
    ) -> tuple[str, tuple[int, int]] | None:
        if not isinstance(workspace, PreparedRepositoryWorkspace):
            raise ForeignWorkspaceError
        expected_root = self._base_directory / workspace.workspace_id
        if (
            workspace.root_directory != expected_root
            or workspace.source_directory != expected_root / "source"
            or workspace.output_directory != expected_root / "output"
            or not workspace.workspace_id.startswith(_WORKSPACE_PREFIX)
        ):
            raise ForeignWorkspaceError
        if not os.path.lexists(expected_root):
            return None
        if expected_root.is_symlink():
            raise ForeignWorkspaceError
        try:
            root_metadata = expected_root.stat(follow_symlinks=False)
            marker = expected_root / _MARKER_NAME
            marker_metadata = marker.stat(follow_symlinks=False)
            if (
                not stat.S_ISDIR(root_metadata.st_mode)
                or not stat.S_ISREG(marker_metadata.st_mode)
                or marker_metadata.st_nlink != 1
                or marker.is_symlink()
            ):
                raise ForeignWorkspaceError
            descriptor = os.open(marker, _FILE_READ_FLAGS)
            try:
                opened_marker = os.fstat(descriptor)
                if (
                    not _same_identity(marker_metadata, opened_marker)
                    or not stat.S_ISREG(opened_marker.st_mode)
                    or opened_marker.st_nlink != 1
                ):
                    raise ForeignWorkspaceError
                content = os.read(descriptor, 4096)
                if os.read(descriptor, 1):
                    raise ForeignWorkspaceError
            finally:
                os.close(descriptor)
            if content != _marker_content(workspace.workspace_id):
                raise ForeignWorkspaceError
            for expected in (workspace.source_directory, workspace.output_directory):
                if os.path.lexists(expected) and (
                    expected.is_symlink() or not expected.is_dir()
                ):
                    raise ForeignWorkspaceError
        except RepositoryWorkspaceError:
            raise
        except OSError as exc:
            raise ForeignWorkspaceError from exc
        return workspace.workspace_id, (root_metadata.st_dev, root_metadata.st_ino)

    def cleanup_workspace(
        self,
        workspace: PreparedRepositoryWorkspace,
    ) -> None:
        ownership = self._validate_cleanup_ownership(workspace)
        if ownership is None:
            return
        child_name, expected_identity = ownership
        try:
            self._remove_direct_child(child_name, expected_identity)
        except RepositoryWorkspaceCleanupError:
            raise
        except RepositoryWorkspaceError as exc:
            raise RepositoryWorkspaceCleanupError from exc
