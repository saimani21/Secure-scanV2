from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from securescan.source.enums import (
    AnalysisCapability,
    FileContentKind,
    SourceFileFlag,
    SourceFileRole,
)
from securescan.source.models import SourceFileRecord
from securescan.workspaces.models import (
    PreparedRepositoryWorkspace,
    RepositoryManifestEntry,
    repository_content_digest,
)

_INVENTORY_STREAM_VERSION = b"securescan-source-inventory-v0.2.2\0"
_READ_CHUNK_BYTES = 1024 * 1024
_DEFAULT_SAMPLE_BYTES = 32 * 1024
_MAX_SAMPLE_BYTES = 1024 * 1024
_MAX_RELATIVE_PATH_BYTES = 16_384
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)

_FILE_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)

_LOCKFILE_NAMES = frozenset(
    {
        "package-lock.json",
        "pipfile.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "uv.lock",
        "yarn.lock",
    }
)

_MANIFEST_NAMES = frozenset(
    {
        "package.json",
        "pipfile",
        "pyproject.toml",
        "setup.cfg",
        "setup.py",
    }
)

_DOCUMENTATION_NAMES = frozenset(
    {
        "authors",
        "changelog",
        "code_of_conduct",
        "contributing",
        "copying",
        "license",
        "notice",
        "readme",
        "security",
    }
)

_DOCUMENTATION_SUFFIXES = frozenset(
    {
        ".adoc",
        ".markdown",
        ".md",
        ".rst",
        ".txt",
    }
)

_CONFIGURATION_SUFFIXES = frozenset(
    {
        ".cfg",
        ".conf",
        ".ini",
        ".json",
        ".properties",
        ".toml",
        ".xml",
        ".yaml",
        ".yml",
    }
)

_SOURCE_CANDIDATE_SUFFIXES = frozenset(
    {
        ".bash",
        ".c",
        ".cc",
        ".cpp",
        ".cs",
        ".cxx",
        ".go",
        ".h",
        ".hpp",
        ".java",
        ".js",
        ".jsx",
        ".kt",
        ".kts",
        ".php",
        ".ps1",
        ".py",
        ".rb",
        ".rs",
        ".scala",
        ".sh",
        ".sql",
        ".swift",
        ".ts",
        ".tsx",
        ".zsh",
    }
)


class SourceInventoryError(RuntimeError):
    """Base class for sanitized repository-inventory failures."""


class InvalidSourceWorkspaceError(SourceInventoryError, ValueError):
    def __init__(self) -> None:
        super().__init__("Source workspace is invalid")


class SourceSnapshotIntegrityError(SourceInventoryError):
    def __init__(self) -> None:
        super().__init__("Source snapshot integrity verification failed")


def _valid_repository_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    if len(encoded) > _MAX_RELATIVE_PATH_BYTES:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and str(path) == value
        and all(component not in {"", ".", ".."} for component in path.parts)
    )


@dataclass(frozen=True, slots=True)
class VerifiedRepositoryFileSample:
    relative_path: str
    sample: bytes
    size_bytes: int
    sha256: str
    content_complete: bool

    def __post_init__(self) -> None:
        if (
            not _valid_repository_path(self.relative_path)
            or not isinstance(self.sample, bytes)
            or type(self.size_bytes) is not int
            or self.size_bytes < 0
            or not isinstance(self.sha256, str)
            or _SHA256_PATTERN.fullmatch(self.sha256) is None
            or type(self.content_complete) is not bool
            or len(self.sample) > self.size_bytes
            or (self.content_complete and len(self.sample) != self.size_bytes)
            or (not self.content_complete and len(self.sample) >= self.size_bytes)
        ):
            raise ValueError("Verified repository file sample is invalid")


@dataclass(frozen=True, slots=True)
class SourceInventoryPolicy:
    sample_bytes: int = _DEFAULT_SAMPLE_BYTES

    def __post_init__(self) -> None:
        if (
            not isinstance(self.sample_bytes, int)
            or isinstance(self.sample_bytes, bool)
            or not 1024 <= self.sample_bytes <= 1024 * 1024
        ):
            raise ValueError("Source inventory policy is invalid")


_DEFAULT_INVENTORY_POLICY = SourceInventoryPolicy()


@dataclass(frozen=True, slots=True, kw_only=True)
class RepositoryInventory:
    repository_digest: str
    files: tuple[SourceFileRecord, ...]
    schema_version: str = "0.2.2"

    def __post_init__(self) -> None:
        if (
            self.schema_version != "0.2.2"
            or not isinstance(self.repository_digest, str)
            or len(self.repository_digest) != 64
            or not isinstance(self.files, tuple)
            or any(
                not isinstance(file, SourceFileRecord)
                for file in self.files
            )
            or self.files
            != tuple(
                sorted(
                    self.files,
                    key=lambda file: file.relative_path,
                )
            )
            or len(
                {
                    file.relative_path
                    for file in self.files
                }
            )
            != len(self.files)
        ):
            raise ValueError("Repository inventory is invalid")

        expected_digest = repository_content_digest(
            tuple(file.entry for file in self.files)
        )
        if self.repository_digest != expected_digest:
            raise ValueError(
                "Repository inventory digest does not match its files"
            )

    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def total_bytes(self) -> int:
        return sum(
            file.entry.size_bytes
            for file in self.files
        )

    def canonical_data(self) -> dict[str, Any]:
        return {
            "file_count": self.file_count,
            "files": [
                file.canonical_data()
                for file in self.files
            ],
            "repository_digest": self.repository_digest,
            "schema_version": self.schema_version,
            "total_bytes": self.total_bytes,
        }

    def inventory_digest(self) -> str:
        payload = json.dumps(
            self.canonical_data(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

        digest = hashlib.sha256()
        digest.update(_INVENTORY_STREAM_VERSION)
        digest.update(payload)
        return digest.hexdigest()


def _snapshot_file_paths(
    source_directory: Path,
) -> tuple[str, ...]:
    discovered: list[str] = []

    try:
        for current, directories, files in os.walk(
            source_directory,
            followlinks=False,
        ):
            current_path = Path(current)

            for directory_name in directories:
                directory_path = current_path / directory_name
                metadata = directory_path.lstat()

                if (
                    stat.S_ISLNK(metadata.st_mode)
                    or not stat.S_ISDIR(metadata.st_mode)
                ):
                    raise SourceSnapshotIntegrityError

            for file_name in files:
                file_path = current_path / file_name
                metadata = file_path.lstat()

                if (
                    stat.S_ISLNK(metadata.st_mode)
                    or not stat.S_ISREG(metadata.st_mode)
                ):
                    raise SourceSnapshotIntegrityError

                discovered.append(
                    file_path.relative_to(
                        source_directory
                    ).as_posix()
                )
    except SourceInventoryError:
        raise
    except (OSError, RuntimeError, ValueError):
        raise SourceSnapshotIntegrityError from None

    return tuple(sorted(discovered))


def _read_and_verify_file(
    file_path: Path,
    *,
    relative_path: str,
    expected_size: int,
    expected_sha256: str,
    sample_bytes: int,
) -> VerifiedRepositoryFileSample:
    descriptor: int | None = None

    try:
        descriptor = os.open(
            file_path,
            _FILE_OPEN_FLAGS,
        )
        initial = os.fstat(descriptor)

        if (
            not stat.S_ISREG(initial.st_mode)
            or initial.st_size != expected_size
        ):
            raise SourceSnapshotIntegrityError

        digest = hashlib.sha256()
        sample = bytearray()
        total_bytes = 0

        while True:
            chunk = os.read(
                descriptor,
                _READ_CHUNK_BYTES,
            )
            if not chunk:
                break

            total_bytes += len(chunk)
            digest.update(chunk)

            if len(sample) < sample_bytes:
                remaining = sample_bytes - len(sample)
                sample.extend(chunk[:remaining])

        finished = os.fstat(descriptor)

        if (
            initial.st_dev != finished.st_dev
            or initial.st_ino != finished.st_ino
            or initial.st_size != finished.st_size
            or initial.st_mtime_ns != finished.st_mtime_ns
            or initial.st_ctime_ns != finished.st_ctime_ns
            or total_bytes != expected_size
            or digest.hexdigest() != expected_sha256
        ):
            raise SourceSnapshotIntegrityError

        sample_bytes_value = bytes(sample)
        return VerifiedRepositoryFileSample(
            relative_path=relative_path,
            sample=sample_bytes_value,
            size_bytes=total_bytes,
            sha256=digest.hexdigest(),
            content_complete=len(sample_bytes_value) == total_bytes,
        )

    except SourceInventoryError:
        raise
    except OSError:
        raise SourceSnapshotIntegrityError from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _manifest_contains_exact_entry(
    entries: tuple[RepositoryManifestEntry, ...],
    expected: RepositoryManifestEntry,
) -> bool:
    lower = 0
    upper = len(entries)
    while lower < upper:
        middle = (lower + upper) // 2
        entry = entries[middle]
        if entry.relative_path < expected.relative_path:
            lower = middle + 1
        else:
            upper = middle
    return lower < len(entries) and entries[lower] == expected


def read_verified_repository_file_sample(
    workspace: PreparedRepositoryWorkspace,
    entry: RepositoryManifestEntry,
    *,
    sample_bytes: int,
) -> VerifiedRepositoryFileSample:
    if (
        not isinstance(workspace, PreparedRepositoryWorkspace)
        or not isinstance(entry, RepositoryManifestEntry)
        or type(sample_bytes) is not int
        or not 1 <= sample_bytes <= _MAX_SAMPLE_BYTES
    ):
        raise InvalidSourceWorkspaceError
    if not _manifest_contains_exact_entry(workspace.manifest.entries, entry):
        raise SourceSnapshotIntegrityError

    return _read_and_verify_file(
        workspace.source_directory / Path(entry.relative_path),
        relative_path=entry.relative_path,
        expected_size=entry.size_bytes,
        expected_sha256=entry.sha256,
        sample_bytes=sample_bytes,
    )


def verify_repository_snapshot(
    workspace: PreparedRepositoryWorkspace,
) -> None:
    if not isinstance(workspace, PreparedRepositoryWorkspace):
        raise InvalidSourceWorkspaceError
    expected_paths = tuple(
        entry.relative_path
        for entry in workspace.manifest.entries
    )
    if _snapshot_file_paths(workspace.source_directory) != expected_paths:
        raise SourceSnapshotIntegrityError


def _classify_content(
    sample: bytes,
) -> FileContentKind:
    if not sample:
        return FileContentKind.TEXT

    if sample.startswith(
        (
            b"\xef\xbb\xbf",
            b"\xff\xfe",
            b"\xfe\xff",
            b"\xff\xfe\x00\x00",
            b"\x00\x00\xfe\xff",
        )
    ):
        return FileContentKind.TEXT

    if b"\x00" in sample:
        return FileContentKind.BINARY

    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        control_count = sum(
            byte < 9
            or 13 < byte < 32
            or byte == 127
            for byte in sample
        )

        if control_count / len(sample) >= 0.20:
            return FileContentKind.BINARY

        return FileContentKind.UNKNOWN

    return FileContentKind.TEXT


def _base_documentation_name(
    name: str,
) -> str:
    return name.split(".", maxsplit=1)[0].casefold()


def _is_manifest(
    name: str,
) -> bool:
    lower_name = name.casefold()

    return (
        lower_name in _MANIFEST_NAMES
        or (
            lower_name.startswith("requirements")
            and lower_name.endswith(".txt")
        )
    )


def _classify_role(
    relative_path: str,
    content_kind: FileContentKind,
) -> SourceFileRole:
    if content_kind is FileContentKind.BINARY:
        return SourceFileRole.BINARY

    path = Path(relative_path)
    name = path.name
    lower_name = name.casefold()
    lower_suffix = path.suffix.casefold()

    if lower_name in _LOCKFILE_NAMES:
        return SourceFileRole.LOCKFILE

    if _is_manifest(name):
        return SourceFileRole.MANIFEST

    if (
        lower_name.endswith(".tf")
        or lower_name.endswith(".tf.json")
    ):
        return SourceFileRole.TERRAFORM

    if (
        lower_name == "dockerfile"
        or lower_name.startswith("dockerfile.")
    ):
        return SourceFileRole.DOCKERFILE

    if (
        _base_documentation_name(name)
        in _DOCUMENTATION_NAMES
        or lower_suffix in _DOCUMENTATION_SUFFIXES
    ):
        return SourceFileRole.DOCUMENTATION

    if lower_suffix in _CONFIGURATION_SUFFIXES:
        return SourceFileRole.CONFIGURATION

    if lower_suffix in _SOURCE_CANDIDATE_SUFFIXES:
        return SourceFileRole.SOURCE

    return SourceFileRole.OTHER


def _file_flags(
    content_kind: FileContentKind,
) -> tuple[SourceFileFlag, ...]:
    flags: set[SourceFileFlag] = set()

    if content_kind is FileContentKind.BINARY:
        flags.add(SourceFileFlag.BINARY)

    if content_kind is FileContentKind.UNKNOWN:
        flags.add(SourceFileFlag.UNSUPPORTED)

    return tuple(
        sorted(
            flags,
            key=lambda flag: flag.value,
        )
    )


def _eligible_capabilities(
    content_kind: FileContentKind,
    role: SourceFileRole,
) -> tuple[AnalysisCapability, ...]:
    capabilities = {
        AnalysisCapability.REPOSITORY_PROFILING,
    }

    if content_kind is FileContentKind.TEXT:
        capabilities.add(
            AnalysisCapability.SECRET_DETECTION
        )

    if role is SourceFileRole.LOCKFILE:
        capabilities.update(
            {
                AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING,
                AnalysisCapability.PACKAGE_INVENTORY,
            }
        )

    if role is SourceFileRole.MANIFEST:
        capabilities.add(
            AnalysisCapability.PACKAGE_INVENTORY
        )

    if role is SourceFileRole.TERRAFORM:
        capabilities.add(
            AnalysisCapability.TERRAFORM_SOURCE_POLICY
        )

    if role is SourceFileRole.DOCKERFILE:
        capabilities.add(
            AnalysisCapability.DOCKERFILE_POLICY
        )

    if content_kind is FileContentKind.TEXT and role in {
        SourceFileRole.CONFIGURATION,
        SourceFileRole.DOCKERFILE,
        SourceFileRole.TERRAFORM,
    }:
        capabilities.add(AnalysisCapability.CONFIGURATION_SECURITY)

    return tuple(
        sorted(
            capabilities,
            key=lambda capability: capability.value,
        )
    )


def build_repository_inventory(
    workspace: PreparedRepositoryWorkspace,
    *,
    policy: SourceInventoryPolicy = _DEFAULT_INVENTORY_POLICY,
) -> RepositoryInventory:
    if (
        not isinstance(
            workspace,
            PreparedRepositoryWorkspace,
        )
        or not isinstance(
            policy,
            SourceInventoryPolicy,
        )
    ):
        raise InvalidSourceWorkspaceError

    verify_repository_snapshot(workspace)

    records: list[SourceFileRecord] = []

    for entry in workspace.manifest.entries:
        verified = read_verified_repository_file_sample(
            workspace,
            entry,
            sample_bytes=policy.sample_bytes,
        )

        content_kind = _classify_content(verified.sample)
        role = _classify_role(
            entry.relative_path,
            content_kind,
        )

        records.append(
            SourceFileRecord(
                entry=entry,
                content_kind=content_kind,
                role=role,
                flags=_file_flags(content_kind),
                eligible_capabilities=_eligible_capabilities(
                    content_kind,
                    role,
                ),
            )
        )

    verify_repository_snapshot(workspace)

    return RepositoryInventory(
        repository_digest=workspace.manifest.content_digest,
        files=tuple(records),
    )
