from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Any

from securescan.source.execution_context import SourceExecutionContext
from securescan.workspaces.models import (
    PreparedRepositoryWorkspace,
    RepositoryIntakeLimits,
    RepositoryManifest,
    RepositoryManifestEntry,
    repository_content_digest,
)

_PROJECTION_PREFIX = "securescan-source-projection-"
_STAGING_PREFIX = ".securescan-source-projection-staging-"
_PROJECTION_ID_PATTERN = re.compile(
    rf"{_PROJECTION_PREFIX}[0-9a-f]{{16,48}}\Z",
    re.ASCII,
)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MARKER_NAME = ".securescan-source-projection.json"
_ROOT_MARKER_NAME = ".securescan-source-projection-root"
_WORKSPACE_MARKER_NAME = ".securescan-workspace"
_SCHEMA_VERSION = "0.3C2"
_ROOT_SCHEMA_VERSION = "1"
_ROOT_MARKER_CONTENT = (
    f"securescan_source_projection_root_version={_ROOT_SCHEMA_VERSION}\n"
).encode("ascii")
_COPY_CHUNK_BYTES = 1024 * 1024
_MAX_MARKER_BYTES = 16 * 1024
_PROTECTED_EXACT_DIRECTORIES = (
    Path("/"),
    Path("/tmp"),
    Path("/var/tmp"),
)
_PROTECTED_DIRECTORY_TREES = (
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
_DEFAULT_LIMITS = RepositoryIntakeLimits()
_VERIFICATION_LIMITS = RepositoryIntakeLimits(
    max_file_count=1_000_000,
    max_single_file_bytes=256 * 1024 * 1024,
    max_total_bytes=16 * 1024 * 1024 * 1024,
    max_directory_depth=256,
    max_relative_path_bytes=16_384,
)
_MARKER_FIELDS = frozenset(
    {
        "context_digest",
        "file_count",
        "projection_digest",
        "projection_id",
        "schema_version",
        "total_bytes",
    }
)


class SourceProjectionError(RuntimeError):
    """Base class for sanitized Source projection failures."""


class InvalidSourceProjectionRequestError(SourceProjectionError, ValueError):
    def __init__(self) -> None:
        RuntimeError.__init__(self, "Source projection request is invalid")


class SourceProjectionWorkspaceContextMismatchError(SourceProjectionError):
    def __init__(self) -> None:
        super().__init__("Source workspace and execution context do not match")


class SourceProjectionSelectedFileMismatchError(SourceProjectionError):
    def __init__(self) -> None:
        super().__init__("Selected Source file identity does not match")


class SourceProjectionSourceMutationError(SourceProjectionError):
    def __init__(self) -> None:
        super().__init__("Source workspace changed during projection")


class SourceProjectionLimitError(SourceProjectionError):
    def __init__(self) -> None:
        super().__init__("Source projection limit was exceeded")


class SourceProjectionPublicationError(SourceProjectionError):
    def __init__(self) -> None:
        super().__init__("Source projection could not be published")


class SourceProjectionMissingError(SourceProjectionError):
    def __init__(self) -> None:
        super().__init__("Source projection does not exist")


class SourceProjectionCorruptError(SourceProjectionError):
    def __init__(self) -> None:
        super().__init__("Source projection integrity verification failed")


class SourceProjectionOwnershipError(SourceProjectionError):
    def __init__(self) -> None:
        super().__init__("Source projection ownership could not be verified")


class SourceProjectionCleanupError(SourceProjectionError):
    def __init__(self) -> None:
        super().__init__("Source projection could not be removed")


class _TreeIntegrityFailure(RuntimeError):
    pass


def _new_projection_suffix() -> str:
    return secrets.token_hex(16)


def _same_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def _same_stable_file_metadata(
    first: os.stat_result,
    second: os.stat_result,
) -> bool:
    return (
        _same_identity(first, second)
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
        and first.st_ctime_ns == second.st_ctime_ns
    )


def _is_protected_directory(path: Path) -> bool:
    return path in _PROTECTED_EXACT_DIRECTORIES or any(
        path == protected or path.is_relative_to(protected)
        for protected in _PROTECTED_DIRECTORY_TREES
    )


def _owned_by_effective_user(metadata: os.stat_result) -> bool:
    get_effective_user = getattr(os, "geteuid", None)
    owner = getattr(metadata, "st_uid", None)
    if get_effective_user is None or owner is None:
        return True
    return owner == get_effective_user()


def _has_secure_mode(metadata: os.stat_result, expected: int) -> bool:
    if os.name != "posix":
        return True
    return stat.S_IMODE(metadata.st_mode) == expected


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and _SHA256_PATTERN.fullmatch(value) is not None


def _valid_projection_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and _PROJECTION_ID_PATTERN.fullmatch(value) is not None
    )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_non_finite(_value: str) -> None:
    raise ValueError


@dataclass(frozen=True, slots=True, kw_only=True)
class PreparedSourceProjection:
    projection_id: str
    root_directory: Path
    source_directory: Path
    manifest: RepositoryManifest
    context_digest: str
    projection_digest: str

    def __post_init__(self) -> None:
        if (
            not _valid_projection_id(self.projection_id)
            or not isinstance(self.root_directory, Path)
            or not self.root_directory.is_absolute()
            or self.root_directory.name != self.projection_id
            or self.source_directory != self.root_directory / "source"
            or not isinstance(self.manifest, RepositoryManifest)
            or not self.manifest.entries
            or not _valid_digest(self.context_digest)
            or not _valid_digest(self.projection_digest)
            or self.projection_digest != self.manifest.content_digest
        ):
            raise InvalidSourceProjectionRequestError


@dataclass(frozen=True, slots=True, kw_only=True)
class _ProjectionMarker:
    projection_id: str
    context_digest: str
    projection_digest: str
    file_count: int
    total_bytes: int
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != _SCHEMA_VERSION
            or not _valid_projection_id(self.projection_id)
            or not _valid_digest(self.context_digest)
            or not _valid_digest(self.projection_digest)
            or type(self.file_count) is not int
            or not 1 <= self.file_count <= 1_000_000
            or type(self.total_bytes) is not int
            or not 0 <= self.total_bytes <= 16 * 1024 * 1024 * 1024
        ):
            raise ValueError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "context_digest": self.context_digest,
            "file_count": self.file_count,
            "projection_digest": self.projection_digest,
            "projection_id": self.projection_id,
            "schema_version": self.schema_version,
            "total_bytes": self.total_bytes,
        }

    def canonical_json(self) -> bytes:
        return json.dumps(
            self.canonical_data(),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @classmethod
    def from_json(cls, payload: bytes) -> _ProjectionMarker:
        try:
            document = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_non_finite,
            )
            if not isinstance(document, dict) or set(document) != _MARKER_FIELDS:
                raise ValueError
            marker = cls(
                projection_id=document["projection_id"],
                context_digest=document["context_digest"],
                projection_digest=document["projection_digest"],
                file_count=document["file_count"],
                total_bytes=document["total_bytes"],
                schema_version=document["schema_version"],
            )
        except (
            KeyError,
            OverflowError,
            RecursionError,
            TypeError,
            UnicodeDecodeError,
            ValueError,
        ) as exc:
            raise SourceProjectionOwnershipError from exc
        if marker.canonical_json() != payload:
            raise SourceProjectionOwnershipError
        return marker


@dataclass(slots=True)
class _InventoryState:
    limits: RepositoryIntakeLimits
    entries: list[RepositoryManifestEntry] = field(default_factory=list)
    directories: list[str] = field(default_factory=list)
    total_bytes: int = 0
    seen_identities: set[tuple[int, int]] = field(default_factory=set)


@dataclass(frozen=True, slots=True)
class _TreeInventory:
    manifest: RepositoryManifest
    directories: tuple[str, ...]


def _validated_relative_path(
    parts: tuple[str, ...],
    limits: RepositoryIntakeLimits,
) -> str:
    try:
        relative_path = PurePosixPath(*parts).as_posix()
        RepositoryManifestEntry(
            relative_path=relative_path,
            size_bytes=0,
            sha256="0" * 64,
        )
        encoded = relative_path.encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise _TreeIntegrityFailure from exc
    if (
        len(parts) > limits.max_directory_depth + 1
        or len(encoded) > limits.max_relative_path_bytes
    ):
        raise SourceProjectionLimitError
    return relative_path


def _read_inventory_file(
    parent_descriptor: int,
    name: str,
    relative_path: str,
    initial: os.stat_result,
    state: _InventoryState,
    *,
    require_read_only: bool,
) -> None:
    descriptor: int | None = None
    try:
        if (
            not stat.S_ISREG(initial.st_mode)
            or initial.st_nlink != 1
            or initial.st_size > state.limits.max_single_file_bytes
        ):
            if initial.st_size > state.limits.max_single_file_bytes:
                raise SourceProjectionLimitError
            raise _TreeIntegrityFailure
        descriptor = os.open(name, _FILE_READ_FLAGS, dir_fd=parent_descriptor)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or not _same_identity(initial, opened)
            or (require_read_only and stat.S_IMODE(opened.st_mode) != 0o444)
        ):
            raise _TreeIntegrityFailure
        digest = hashlib.sha256()
        copied = 0
        while True:
            chunk = os.read(descriptor, _COPY_CHUNK_BYTES)
            if not chunk:
                break
            copied += len(chunk)
            if copied > state.limits.max_single_file_bytes:
                raise SourceProjectionLimitError
            if state.total_bytes + copied > state.limits.max_total_bytes:
                raise SourceProjectionLimitError
            digest.update(chunk)
        finished = os.fstat(descriptor)
        if (
            copied != opened.st_size
            or not _same_stable_file_metadata(opened, finished)
            or finished.st_nlink != 1
        ):
            raise _TreeIntegrityFailure
        state.total_bytes += copied
        state.entries.append(
            RepositoryManifestEntry(
                relative_path=relative_path,
                size_bytes=copied,
                sha256=digest.hexdigest(),
            )
        )
    except (SourceProjectionLimitError, _TreeIntegrityFailure):
        raise
    except OSError as exc:
        raise _TreeIntegrityFailure from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _walk_inventory(
    descriptor: int,
    relative_parts: tuple[str, ...],
    depth: int,
    state: _InventoryState,
    *,
    require_read_only: bool,
) -> None:
    try:
        initial_directory = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(initial_directory.st_mode)
            or (
                require_read_only
                and stat.S_IMODE(initial_directory.st_mode) != 0o555
            )
        ):
            raise _TreeIntegrityFailure
        with os.scandir(descriptor) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name)
    except _TreeIntegrityFailure:
        raise
    except OSError as exc:
        raise _TreeIntegrityFailure from exc

    for entry in entries:
        child_parts = (*relative_parts, entry.name)
        relative_path = _validated_relative_path(child_parts, state.limits)
        if ".git" in child_parts:
            raise _TreeIntegrityFailure
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError as exc:
            raise _TreeIntegrityFailure from exc
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in state.seen_identities:
            raise _TreeIntegrityFailure
        state.seen_identities.add(identity)
        if stat.S_ISLNK(metadata.st_mode):
            raise _TreeIntegrityFailure
        if stat.S_ISDIR(metadata.st_mode):
            child_depth = depth + 1
            if child_depth > state.limits.max_directory_depth:
                raise SourceProjectionLimitError
            child_descriptor: int | None = None
            try:
                child_descriptor = os.open(
                    entry.name,
                    _DIRECTORY_OPEN_FLAGS,
                    dir_fd=descriptor,
                )
                opened = os.fstat(child_descriptor)
                if not _same_identity(metadata, opened):
                    raise _TreeIntegrityFailure
                state.directories.append(relative_path)
                _walk_inventory(
                    child_descriptor,
                    child_parts,
                    child_depth,
                    state,
                    require_read_only=require_read_only,
                )
            except (SourceProjectionLimitError, _TreeIntegrityFailure):
                raise
            except OSError as exc:
                raise _TreeIntegrityFailure from exc
            finally:
                if child_descriptor is not None:
                    os.close(child_descriptor)
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise _TreeIntegrityFailure
        if len(state.entries) >= state.limits.max_file_count:
            raise SourceProjectionLimitError
        _read_inventory_file(
            descriptor,
            entry.name,
            relative_path,
            metadata,
            state,
            require_read_only=require_read_only,
        )

    try:
        finished_directory = os.fstat(descriptor)
    except OSError as exc:
        raise _TreeIntegrityFailure from exc
    if not _same_stable_file_metadata(initial_directory, finished_directory):
        raise _TreeIntegrityFailure


def _inventory_tree(
    root: Path,
    limits: RepositoryIntakeLimits,
    *,
    require_read_only: bool,
) -> _TreeInventory:
    descriptor: int | None = None
    try:
        initial = root.stat(follow_symlinks=False)
        if root.is_symlink() or not stat.S_ISDIR(initial.st_mode):
            raise _TreeIntegrityFailure
        descriptor = os.open(root, _DIRECTORY_OPEN_FLAGS)
        opened = os.fstat(descriptor)
        if not _same_identity(initial, opened):
            raise _TreeIntegrityFailure
        state = _InventoryState(
            limits=limits,
            seen_identities={(opened.st_dev, opened.st_ino)},
        )
        _walk_inventory(
            descriptor,
            (),
            0,
            state,
            require_read_only=require_read_only,
        )
        entries = tuple(
            sorted(state.entries, key=lambda entry: entry.relative_path)
        )
        manifest = RepositoryManifest(
            entries=entries,
            file_count=len(entries),
            total_bytes=state.total_bytes,
            content_digest=repository_content_digest(entries),
        )
        return _TreeInventory(
            manifest=manifest,
            directories=tuple(sorted(state.directories)),
        )
    except (SourceProjectionLimitError, _TreeIntegrityFailure):
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise _TreeIntegrityFailure from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _expected_directories(entries: tuple[RepositoryManifestEntry, ...]) -> tuple[str, ...]:
    directories: set[str] = set()
    for entry in entries:
        parent = PurePosixPath(entry.relative_path).parent
        while parent != PurePosixPath("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    return tuple(sorted(directories))


class SourceProjectionManager:
    def __init__(
        self,
        base_directory: Path,
        limits: RepositoryIntakeLimits = _DEFAULT_LIMITS,
        projection_id_factory: Callable[[], str] = _new_projection_suffix,
    ) -> None:
        if not isinstance(limits, RepositoryIntakeLimits):
            raise SourceProjectionPublicationError
        if not callable(projection_id_factory):
            raise SourceProjectionPublicationError
        self._limits = limits
        self._projection_id_factory = projection_id_factory
        (
            self._base_directory,
            self._base_identity,
        ) = self._prepare_base_directory(base_directory)

    @property
    def base_directory(self) -> Path:
        return self._base_directory

    @classmethod
    def _prepare_base_directory(
        cls,
        value: object,
    ) -> tuple[Path, tuple[int, int]]:
        if (
            not isinstance(value, Path)
            or not value.is_absolute()
            or value.is_symlink()
            or ".git" in value.parts
        ):
            raise SourceProjectionPublicationError
        try:
            exists = os.path.lexists(value)
            resolved = value.resolve(strict=exists)
            if (
                _is_protected_directory(resolved)
                or ".git" in resolved.parts
            ):
                raise SourceProjectionPublicationError
            if not exists:
                resolved.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                os.mkdir(resolved, mode=0o700)
                root_descriptor = os.open(resolved, _DIRECTORY_OPEN_FLAGS)
                try:
                    os.fchmod(root_descriptor, 0o700)
                    cls._validate_base_metadata(os.fstat(root_descriptor))
                    cls._write_root_marker(root_descriptor)
                    os.fsync(root_descriptor)
                    cls._validate_base_descriptor(root_descriptor)
                    metadata = os.fstat(root_descriptor)
                finally:
                    os.close(root_descriptor)
            else:
                root_descriptor = os.open(resolved, _DIRECTORY_OPEN_FLAGS)
                try:
                    cls._validate_base_descriptor(root_descriptor)
                    metadata = os.fstat(root_descriptor)
                finally:
                    os.close(root_descriptor)
        except SourceProjectionError:
            raise
        except (OSError, RuntimeError) as exc:
            raise SourceProjectionPublicationError from exc
        return resolved, (metadata.st_dev, metadata.st_ino)

    @staticmethod
    def _validate_base_metadata(metadata: os.stat_result) -> None:
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or not _has_secure_mode(metadata, 0o700)
            or not _owned_by_effective_user(metadata)
        ):
            raise SourceProjectionOwnershipError

    @staticmethod
    def _write_root_marker(root_descriptor: int) -> None:
        descriptor: int | None = None
        try:
            descriptor = os.open(
                _ROOT_MARKER_NAME,
                _FILE_CREATE_FLAGS,
                0o400,
                dir_fd=root_descriptor,
            )
            remaining = memoryview(_ROOT_MARKER_CONTENT)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise SourceProjectionPublicationError
                remaining = remaining[written:]
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o400)
        except SourceProjectionError:
            raise
        except OSError as exc:
            raise SourceProjectionPublicationError from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @classmethod
    def _validate_base_descriptor(cls, root_descriptor: int) -> None:
        try:
            cls._validate_base_metadata(os.fstat(root_descriptor))
            marker_metadata = os.stat(
                _ROOT_MARKER_NAME,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(marker_metadata.st_mode)
                or stat.S_ISLNK(marker_metadata.st_mode)
                or marker_metadata.st_nlink != 1
                or not _has_secure_mode(marker_metadata, 0o400)
                or not _owned_by_effective_user(marker_metadata)
            ):
                raise SourceProjectionOwnershipError
            if (
                cls._read_small_regular_at(root_descriptor, _ROOT_MARKER_NAME)
                != _ROOT_MARKER_CONTENT
            ):
                raise SourceProjectionOwnershipError
        except SourceProjectionError:
            raise
        except OSError as exc:
            raise SourceProjectionOwnershipError from exc

    def _open_base(self) -> int:
        descriptor: int | None = None
        try:
            descriptor = os.open(self._base_directory, _DIRECTORY_OPEN_FLAGS)
            metadata = os.fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) != self._base_identity:
                raise SourceProjectionOwnershipError
            self._validate_base_descriptor(descriptor)
            return descriptor
        except SourceProjectionError:
            if descriptor is not None:
                os.close(descriptor)
            raise
        except OSError as exc:
            if descriptor is not None:
                os.close(descriptor)
            raise SourceProjectionOwnershipError from exc

    def _projection_names(
        self,
        projection_suffix: str | None = None,
    ) -> tuple[str, str]:
        try:
            suffix = (
                self._projection_id_factory()
                if projection_suffix is None
                else projection_suffix
            )
        except Exception as exc:
            raise SourceProjectionPublicationError from exc
        if (
            not isinstance(suffix, str)
            or not 16 <= len(suffix) <= 48
            or any(character not in "0123456789abcdef" for character in suffix)
        ):
            raise SourceProjectionPublicationError
        return f"{_PROJECTION_PREFIX}{suffix}", f"{_STAGING_PREFIX}{suffix}"

    def _validate_workspace(
        self,
        workspace: object,
    ) -> PreparedRepositoryWorkspace:
        try:
            if not isinstance(workspace, PreparedRepositoryWorkspace):
                raise TypeError
            validated = replace(
                workspace,
                manifest=replace(
                    workspace.manifest,
                    entries=tuple(replace(entry) for entry in workspace.manifest.entries),
                ),
            )
            if validated != workspace:
                raise ValueError
            root = validated.root_directory
            if (
                root.resolve(strict=True) != root
                or root.is_symlink()
                or validated.source_directory.is_symlink()
                or not validated.source_directory.is_dir()
                or root == self._base_directory
                or root.is_relative_to(self._base_directory)
                or self._base_directory.is_relative_to(root)
            ):
                raise ValueError
            root_descriptor = os.open(root, _DIRECTORY_OPEN_FLAGS)
            try:
                marker = self._read_small_regular_at(
                    root_descriptor,
                    _WORKSPACE_MARKER_NAME,
                )
            finally:
                os.close(root_descriptor)
            expected_marker = (
                "securescan_workspace_version=1\n"
                f"workspace_id={validated.workspace_id}\n"
            ).encode("ascii")
            if marker != expected_marker:
                raise ValueError
            return validated
        except SourceProjectionError:
            raise
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise InvalidSourceProjectionRequestError from exc

    @staticmethod
    def _validated_context(context: object) -> SourceExecutionContext:
        try:
            if not isinstance(context, SourceExecutionContext):
                raise TypeError
            validated = SourceExecutionContext.from_json(context.canonical_json())
        except Exception as exc:
            raise InvalidSourceProjectionRequestError from exc
        if validated != context:
            raise InvalidSourceProjectionRequestError
        return validated

    def _selected_manifest(
        self,
        workspace: PreparedRepositoryWorkspace,
        context: SourceExecutionContext,
    ) -> RepositoryManifest:
        if workspace.manifest.content_digest != context.repository_digest:
            raise SourceProjectionWorkspaceContextMismatchError
        if not context.selected_files:
            raise InvalidSourceProjectionRequestError
        if len(context.selected_files) > self._limits.max_file_count:
            raise SourceProjectionLimitError
        workspace_entries = {
            entry.relative_path: entry for entry in workspace.manifest.entries
        }
        selected_entries: list[RepositoryManifestEntry] = []
        total_bytes = 0
        for selected in context.selected_files:
            entry = replace(selected.entry)
            parts = PurePosixPath(entry.relative_path).parts
            _validated_relative_path(parts, self._limits)
            if (
                entry.size_bytes > self._limits.max_single_file_bytes
                or total_bytes + entry.size_bytes > self._limits.max_total_bytes
            ):
                raise SourceProjectionLimitError
            actual = workspace_entries.get(entry.relative_path)
            if actual != entry:
                raise SourceProjectionSelectedFileMismatchError
            selected_entries.append(entry)
            total_bytes += entry.size_bytes
        entries = tuple(selected_entries)
        return RepositoryManifest(
            entries=entries,
            file_count=len(entries),
            total_bytes=total_bytes,
            content_digest=repository_content_digest(entries),
        )

    @staticmethod
    def _read_small_regular_at(parent_descriptor: int, name: str) -> bytes:
        descriptor: int | None = None
        try:
            initial = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            if (
                not stat.S_ISREG(initial.st_mode)
                or initial.st_nlink != 1
                or initial.st_size > _MAX_MARKER_BYTES
            ):
                raise SourceProjectionOwnershipError
            descriptor = os.open(name, _FILE_READ_FLAGS, dir_fd=parent_descriptor)
            opened = os.fstat(descriptor)
            if not _same_identity(initial, opened) or opened.st_nlink != 1:
                raise SourceProjectionOwnershipError
            content = bytearray()
            while len(content) <= _MAX_MARKER_BYTES:
                chunk = os.read(descriptor, _MAX_MARKER_BYTES + 1 - len(content))
                if not chunk:
                    break
                content.extend(chunk)
            finished = os.fstat(descriptor)
            if (
                len(content) > _MAX_MARKER_BYTES
                or not _same_stable_file_metadata(opened, finished)
                or finished.st_nlink != 1
            ):
                raise SourceProjectionOwnershipError
            return bytes(content)
        except SourceProjectionError:
            raise
        except OSError as exc:
            raise SourceProjectionOwnershipError from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def _open_existing_parent(
        root_descriptor: int,
        parts: tuple[str, ...],
    ) -> int:
        current = os.dup(root_descriptor)
        try:
            for name in parts:
                initial = os.stat(name, dir_fd=current, follow_symlinks=False)
                if not stat.S_ISDIR(initial.st_mode) or stat.S_ISLNK(initial.st_mode):
                    raise SourceProjectionSourceMutationError
                child = os.open(name, _DIRECTORY_OPEN_FLAGS, dir_fd=current)
                actual = os.fstat(child)
                if not _same_identity(initial, actual):
                    os.close(child)
                    raise SourceProjectionSourceMutationError
                os.close(current)
                current = child
            return current
        except SourceProjectionError:
            os.close(current)
            raise
        except OSError as exc:
            os.close(current)
            raise SourceProjectionSourceMutationError from exc

    @staticmethod
    def _open_destination_parent(
        root_descriptor: int,
        parts: tuple[str, ...],
    ) -> int:
        current = os.dup(root_descriptor)
        try:
            for name in parts:
                with suppress(FileExistsError):
                    os.mkdir(name, mode=0o700, dir_fd=current)
                initial = os.stat(name, dir_fd=current, follow_symlinks=False)
                if not stat.S_ISDIR(initial.st_mode) or stat.S_ISLNK(initial.st_mode):
                    raise SourceProjectionPublicationError
                child = os.open(name, _DIRECTORY_OPEN_FLAGS, dir_fd=current)
                actual = os.fstat(child)
                if not _same_identity(initial, actual):
                    os.close(child)
                    raise SourceProjectionPublicationError
                os.close(current)
                current = child
            return current
        except SourceProjectionError:
            os.close(current)
            raise
        except OSError as exc:
            os.close(current)
            raise SourceProjectionPublicationError from exc

    def _copy_selected_file(
        self,
        source_root_descriptor: int,
        destination_root_descriptor: int,
        entry: RepositoryManifestEntry,
        projected_before: int,
    ) -> int:
        parts = PurePosixPath(entry.relative_path).parts
        source_parent = self._open_existing_parent(
            source_root_descriptor,
            parts[:-1],
        )
        destination_parent: int | None = None
        source_file: int | None = None
        destination_file: int | None = None
        try:
            try:
                initial = os.stat(
                    parts[-1],
                    dir_fd=source_parent,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISREG(initial.st_mode)
                    or initial.st_nlink != 1
                    or initial.st_size != entry.size_bytes
                ):
                    raise SourceProjectionSourceMutationError
                source_file = os.open(
                    parts[-1],
                    _FILE_READ_FLAGS,
                    dir_fd=source_parent,
                )
                opened = os.fstat(source_file)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                    or not _same_identity(initial, opened)
                ):
                    raise SourceProjectionSourceMutationError
            except SourceProjectionError:
                raise
            except OSError as exc:
                raise SourceProjectionSourceMutationError from exc

            destination_parent = self._open_destination_parent(
                destination_root_descriptor,
                parts[:-1],
            )
            try:
                destination_file = os.open(
                    parts[-1],
                    _FILE_CREATE_FLAGS,
                    0o600,
                    dir_fd=destination_parent,
                )
                destination_opened = os.fstat(destination_file)
            except OSError as exc:
                raise SourceProjectionPublicationError from exc
            if (
                not stat.S_ISREG(destination_opened.st_mode)
                or destination_opened.st_nlink != 1
                or _same_identity(opened, destination_opened)
            ):
                raise SourceProjectionPublicationError

            digest = hashlib.sha256()
            copied = 0
            while True:
                try:
                    chunk = os.read(source_file, _COPY_CHUNK_BYTES)
                except OSError as exc:
                    raise SourceProjectionSourceMutationError from exc
                if not chunk:
                    break
                copied += len(chunk)
                if (
                    copied > entry.size_bytes
                    or copied > self._limits.max_single_file_bytes
                    or projected_before + copied > self._limits.max_total_bytes
                ):
                    raise SourceProjectionLimitError
                digest.update(chunk)
                remaining = memoryview(chunk)
                while remaining:
                    try:
                        written = os.write(destination_file, remaining)
                    except OSError as exc:
                        raise SourceProjectionPublicationError from exc
                    if written <= 0:
                        raise SourceProjectionPublicationError
                    remaining = remaining[written:]
            try:
                finished = os.fstat(source_file)
            except OSError as exc:
                raise SourceProjectionSourceMutationError from exc
            if (
                copied != entry.size_bytes
                or digest.hexdigest() != entry.sha256
                or not _same_stable_file_metadata(opened, finished)
                or finished.st_nlink != 1
            ):
                raise SourceProjectionSourceMutationError
            try:
                os.fsync(destination_file)
                os.fchmod(destination_file, 0o444)
                destination_finished = os.fstat(destination_file)
            except OSError as exc:
                raise SourceProjectionPublicationError from exc
            if (
                destination_finished.st_size != entry.size_bytes
                or destination_finished.st_nlink != 1
                or not stat.S_ISREG(destination_finished.st_mode)
                or stat.S_IMODE(destination_finished.st_mode) != 0o444
            ):
                raise SourceProjectionPublicationError
            return copied
        finally:
            if destination_file is not None:
                os.close(destination_file)
            if source_file is not None:
                os.close(source_file)
            if destination_parent is not None:
                os.close(destination_parent)
            os.close(source_parent)

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
                    os.chmod(current_path / file_name, 0o444, follow_symlinks=False)
                for directory_name in directories:
                    os.chmod(
                        current_path / directory_name,
                        0o555,
                        follow_symlinks=False,
                    )
                os.chmod(current_path, 0o555, follow_symlinks=False)
        except OSError as exc:
            raise SourceProjectionPublicationError from exc

    @staticmethod
    def _write_marker(root_descriptor: int, marker: _ProjectionMarker) -> None:
        descriptor: int | None = None
        try:
            descriptor = os.open(
                _MARKER_NAME,
                _FILE_CREATE_FLAGS,
                0o400,
                dir_fd=root_descriptor,
            )
            content = marker.canonical_json()
            remaining = memoryview(content)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise SourceProjectionPublicationError
                remaining = remaining[written:]
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o400)
        except SourceProjectionError:
            raise
        except OSError as exc:
            raise SourceProjectionPublicationError from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def _validate_projection_root_entries(root_descriptor: int) -> None:
        try:
            with os.scandir(root_descriptor) as iterator:
                entries = {entry.name: entry for entry in iterator}
            if _MARKER_NAME not in entries:
                raise SourceProjectionOwnershipError
            if set(entries) != {_MARKER_NAME, "source"}:
                raise SourceProjectionCorruptError
            marker = entries[_MARKER_NAME].stat(follow_symlinks=False)
            source = entries["source"].stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(marker.st_mode)
                or marker.st_nlink != 1
                or stat.S_ISLNK(marker.st_mode)
            ):
                raise SourceProjectionOwnershipError
            if not stat.S_ISDIR(source.st_mode) or stat.S_ISLNK(source.st_mode):
                raise SourceProjectionCorruptError
        except SourceProjectionError:
            raise
        except OSError as exc:
            raise SourceProjectionCorruptError from exc

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
                        raise SourceProjectionCleanupError
                    SourceProjectionManager._clear_directory(child)
                finally:
                    os.close(child)
                os.rmdir(entry.name, dir_fd=descriptor)
            else:
                os.unlink(entry.name, dir_fd=descriptor)

    def _remove_direct_child(
        self,
        child_name: str,
        expected_identity: tuple[int, int],
    ) -> None:
        base_descriptor: int | None = None
        child_descriptor: int | None = None
        try:
            base_descriptor = self._open_base()
            initial = os.stat(
                child_name,
                dir_fd=base_descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISDIR(initial.st_mode)
                or stat.S_ISLNK(initial.st_mode)
                or (initial.st_dev, initial.st_ino) != expected_identity
            ):
                raise SourceProjectionOwnershipError
            child_descriptor = os.open(
                child_name,
                _DIRECTORY_OPEN_FLAGS,
                dir_fd=base_descriptor,
            )
            actual = os.fstat(child_descriptor)
            if not _same_identity(initial, actual):
                raise SourceProjectionOwnershipError
            self._clear_directory(child_descriptor)
            final = os.stat(
                child_name,
                dir_fd=base_descriptor,
                follow_symlinks=False,
            )
            if not _same_identity(initial, final):
                raise SourceProjectionOwnershipError
            os.rmdir(child_name, dir_fd=base_descriptor)
        except SourceProjectionError:
            raise
        except OSError as exc:
            raise SourceProjectionCleanupError from exc
        finally:
            if child_descriptor is not None:
                os.close(child_descriptor)
            if base_descriptor is not None:
                os.close(base_descriptor)

    def build_projection(
        self,
        workspace: PreparedRepositoryWorkspace,
        context: SourceExecutionContext,
        *,
        projection_suffix: str | None = None,
    ) -> PreparedSourceProjection:
        trusted_workspace = self._validate_workspace(workspace)
        trusted_context = self._validated_context(context)
        selected_manifest = self._selected_manifest(
            trusted_workspace,
            trusted_context,
        )
        try:
            source_inventory = _inventory_tree(
                trusted_workspace.source_directory,
                _VERIFICATION_LIMITS,
                require_read_only=True,
            )
        except SourceProjectionLimitError as exc:
            raise SourceProjectionSourceMutationError from exc
        except _TreeIntegrityFailure as exc:
            raise SourceProjectionSourceMutationError from exc
        if source_inventory.manifest != trusted_workspace.manifest:
            raise SourceProjectionSourceMutationError

        projection_id, staging_name = self._projection_names(projection_suffix)
        base_descriptor: int | None = None
        staging_descriptor: int | None = None
        source_descriptor: int | None = None
        destination_descriptor: int | None = None
        active_name: str | None = None
        active_identity: tuple[int, int] | None = None
        staging = self._base_directory / staging_name
        final = self._base_directory / projection_id
        try:
            base_descriptor = self._open_base()
            try:
                os.stat(projection_id, dir_fd=base_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise SourceProjectionPublicationError
            os.mkdir(staging_name, mode=0o700, dir_fd=base_descriptor)
            active_name = staging_name
            staging_metadata = os.stat(
                staging_name,
                dir_fd=base_descriptor,
                follow_symlinks=False,
            )
            active_identity = (staging_metadata.st_dev, staging_metadata.st_ino)
            staging_descriptor = os.open(
                staging_name,
                _DIRECTORY_OPEN_FLAGS,
                dir_fd=base_descriptor,
            )
            if not _same_identity(staging_metadata, os.fstat(staging_descriptor)):
                raise SourceProjectionPublicationError
            os.mkdir("source", mode=0o700, dir_fd=staging_descriptor)
            destination_descriptor = os.open(
                "source",
                _DIRECTORY_OPEN_FLAGS,
                dir_fd=staging_descriptor,
            )
            source_descriptor = os.open(
                trusted_workspace.source_directory,
                _DIRECTORY_OPEN_FLAGS,
            )
            source_initial = os.fstat(source_descriptor)
            copied_total = 0
            for entry in selected_manifest.entries:
                copied_total += self._copy_selected_file(
                    source_descriptor,
                    destination_descriptor,
                    entry,
                    copied_total,
                )
            source_finished = os.fstat(source_descriptor)
            if not _same_stable_file_metadata(source_initial, source_finished):
                raise SourceProjectionSourceMutationError

            expected_directories = _expected_directories(selected_manifest.entries)
            try:
                first_inventory = _inventory_tree(
                    staging / "source",
                    self._limits,
                    require_read_only=False,
                )
            except _TreeIntegrityFailure as exc:
                raise SourceProjectionPublicationError from exc
            if (
                first_inventory.manifest != selected_manifest
                or first_inventory.directories != expected_directories
            ):
                raise SourceProjectionPublicationError

            context_digest = trusted_context.context_digest()
            marker = _ProjectionMarker(
                projection_id=projection_id,
                context_digest=context_digest,
                projection_digest=selected_manifest.content_digest,
                file_count=selected_manifest.file_count,
                total_bytes=selected_manifest.total_bytes,
            )
            self._write_marker(staging_descriptor, marker)
            self._make_source_read_only(staging / "source")
            try:
                second_inventory = _inventory_tree(
                    staging / "source",
                    self._limits,
                    require_read_only=True,
                )
            except _TreeIntegrityFailure as exc:
                raise SourceProjectionPublicationError from exc
            if second_inventory != first_inventory:
                raise SourceProjectionPublicationError
            self._validate_projection_root_entries(staging_descriptor)
            os.fchmod(staging_descriptor, 0o700)
            try:
                os.stat(projection_id, dir_fd=base_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise SourceProjectionPublicationError
            os.rename(
                staging_name,
                projection_id,
                src_dir_fd=base_descriptor,
                dst_dir_fd=base_descriptor,
            )
            active_name = projection_id
            final_metadata = os.stat(
                projection_id,
                dir_fd=base_descriptor,
                follow_symlinks=False,
            )
            if (
                active_identity is None
                or (final_metadata.st_dev, final_metadata.st_ino) != active_identity
            ):
                raise SourceProjectionPublicationError
            return PreparedSourceProjection(
                projection_id=projection_id,
                root_directory=final,
                source_directory=final / "source",
                manifest=selected_manifest,
                context_digest=context_digest,
                projection_digest=selected_manifest.content_digest,
            )
        except SourceProjectionError:
            if active_name is not None and active_identity is not None:
                try:
                    self._remove_direct_child(active_name, active_identity)
                except SourceProjectionError as cleanup_error:
                    raise SourceProjectionCleanupError from cleanup_error
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            if active_name is not None and active_identity is not None:
                try:
                    self._remove_direct_child(active_name, active_identity)
                except SourceProjectionError as cleanup_error:
                    raise SourceProjectionCleanupError from cleanup_error
            raise SourceProjectionPublicationError from exc
        finally:
            if destination_descriptor is not None:
                os.close(destination_descriptor)
            if source_descriptor is not None:
                os.close(source_descriptor)
            if staging_descriptor is not None:
                os.close(staging_descriptor)
            if base_descriptor is not None:
                os.close(base_descriptor)

    def reopen_projection(
        self,
        projection_id: str,
        *,
        expected_context_digest: str,
        expected_projection_digest: str,
    ) -> PreparedSourceProjection:
        if (
            not _valid_projection_id(projection_id)
            or not _valid_digest(expected_context_digest)
            or not _valid_digest(expected_projection_digest)
        ):
            raise InvalidSourceProjectionRequestError
        root = self._base_directory / projection_id
        if not os.path.lexists(root):
            raise SourceProjectionMissingError
        base_descriptor: int | None = None
        root_descriptor: int | None = None
        try:
            base_descriptor = self._open_base()
            initial = os.stat(
                projection_id,
                dir_fd=base_descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISDIR(initial.st_mode)
                or stat.S_ISLNK(initial.st_mode)
                or stat.S_IMODE(initial.st_mode) != 0o700
            ):
                raise SourceProjectionOwnershipError
            root_descriptor = os.open(
                projection_id,
                _DIRECTORY_OPEN_FLAGS,
                dir_fd=base_descriptor,
            )
            if not _same_identity(initial, os.fstat(root_descriptor)):
                raise SourceProjectionOwnershipError
            self._validate_projection_root_entries(root_descriptor)
            marker = _ProjectionMarker.from_json(
                self._read_small_regular_at(root_descriptor, _MARKER_NAME)
            )
            marker_metadata = os.stat(
                _MARKER_NAME,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
            if stat.S_IMODE(marker_metadata.st_mode) != 0o400:
                raise SourceProjectionOwnershipError
            if (
                marker.projection_id != projection_id
                or marker.context_digest != expected_context_digest
                or marker.projection_digest != expected_projection_digest
            ):
                raise SourceProjectionCorruptError
            try:
                inventory = _inventory_tree(
                    root / "source",
                    self._limits,
                    require_read_only=True,
                )
            except (SourceProjectionLimitError, _TreeIntegrityFailure) as exc:
                raise SourceProjectionCorruptError from exc
            if (
                inventory.manifest.content_digest != marker.projection_digest
                or inventory.manifest.file_count != marker.file_count
                or inventory.manifest.total_bytes != marker.total_bytes
                or inventory.directories
                != _expected_directories(inventory.manifest.entries)
            ):
                raise SourceProjectionCorruptError
            finished = os.stat(
                projection_id,
                dir_fd=base_descriptor,
                follow_symlinks=False,
            )
            if not _same_identity(initial, finished):
                raise SourceProjectionOwnershipError
            return PreparedSourceProjection(
                projection_id=projection_id,
                root_directory=root,
                source_directory=root / "source",
                manifest=inventory.manifest,
                context_digest=marker.context_digest,
                projection_digest=marker.projection_digest,
            )
        except SourceProjectionError:
            raise
        except OSError as exc:
            raise SourceProjectionCorruptError from exc
        finally:
            if root_descriptor is not None:
                os.close(root_descriptor)
            if base_descriptor is not None:
                os.close(base_descriptor)

    def cleanup_projection(self, projection: PreparedSourceProjection) -> None:
        try:
            if not isinstance(projection, PreparedSourceProjection):
                raise TypeError
            validated = replace(
                projection,
                manifest=replace(
                    projection.manifest,
                    entries=tuple(replace(entry) for entry in projection.manifest.entries),
                ),
            )
            expected_root = self._base_directory / validated.projection_id
            if (
                validated != projection
                or validated.root_directory != expected_root
                or validated.source_directory != expected_root / "source"
            ):
                raise ValueError
        except (TypeError, ValueError) as exc:
            raise InvalidSourceProjectionRequestError from exc
        if not os.path.lexists(expected_root):
            raise SourceProjectionMissingError

        base_descriptor: int | None = None
        root_descriptor: int | None = None
        try:
            base_descriptor = self._open_base()
            initial = os.stat(
                validated.projection_id,
                dir_fd=base_descriptor,
                follow_symlinks=False,
            )
            if not stat.S_ISDIR(initial.st_mode) or stat.S_ISLNK(initial.st_mode):
                raise SourceProjectionOwnershipError
            root_descriptor = os.open(
                validated.projection_id,
                _DIRECTORY_OPEN_FLAGS,
                dir_fd=base_descriptor,
            )
            if not _same_identity(initial, os.fstat(root_descriptor)):
                raise SourceProjectionOwnershipError
            marker = _ProjectionMarker.from_json(
                self._read_small_regular_at(root_descriptor, _MARKER_NAME)
            )
            if (
                marker.projection_id != validated.projection_id
                or marker.context_digest != validated.context_digest
                or marker.projection_digest != validated.projection_digest
                or marker.file_count != validated.manifest.file_count
                or marker.total_bytes != validated.manifest.total_bytes
            ):
                raise SourceProjectionOwnershipError
            expected_identity = (initial.st_dev, initial.st_ino)
        except SourceProjectionError:
            raise
        except OSError as exc:
            raise SourceProjectionOwnershipError from exc
        finally:
            if root_descriptor is not None:
                os.close(root_descriptor)
            if base_descriptor is not None:
                os.close(base_descriptor)
        self._remove_direct_child(validated.projection_id, expected_identity)


SOURCE_PROJECTION_SCHEMA_VERSION = _SCHEMA_VERSION
