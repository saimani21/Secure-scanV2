from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_WORKSPACE_ID_PATTERN = re.compile(
    r"securescan-workspace-[0-9a-f]{16,48}\Z",
    re.ASCII,
)
_MANIFEST_STREAM_VERSION = b"securescan-repository-manifest-v1\0"
_MEBIBYTE = 1024 * 1024
_GIBIBYTE = 1024 * _MEBIBYTE


def _bounded_integer(value: object, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


@dataclass(frozen=True, slots=True)
class RepositoryIntakeLimits:
    max_file_count: int = 50_000
    max_single_file_bytes: int = 33_554_432
    max_total_bytes: int = 1_073_741_824
    max_directory_depth: int = 64
    max_relative_path_bytes: int = 4_096

    def __post_init__(self) -> None:
        if (
            not _bounded_integer(self.max_file_count, 1, 1_000_000)
            or not _bounded_integer(
                self.max_single_file_bytes,
                1024,
                256 * _MEBIBYTE,
            )
            or not _bounded_integer(
                self.max_total_bytes,
                self.max_single_file_bytes,
                16 * _GIBIBYTE,
            )
            or not _bounded_integer(self.max_directory_depth, 1, 256)
            or not _bounded_integer(self.max_relative_path_bytes, 64, 16_384)
        ):
            raise ValueError("Repository intake limits are invalid")


def _valid_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and str(path) == value
        and all(component not in {"", ".", ".."} for component in path.parts)
    )


@dataclass(frozen=True, slots=True)
class RepositoryManifestEntry:
    relative_path: str
    size_bytes: int
    sha256: str

    def __post_init__(self) -> None:
        if (
            not _valid_relative_path(self.relative_path)
            or not _bounded_integer(self.size_bytes, 0, 16 * _GIBIBYTE)
            or not isinstance(self.sha256, str)
            or _SHA256_PATTERN.fullmatch(self.sha256) is None
        ):
            raise ValueError("Repository manifest entry is invalid")


def repository_content_digest(
    entries: tuple[RepositoryManifestEntry, ...],
) -> str:
    digest = hashlib.sha256()
    digest.update(_MANIFEST_STREAM_VERSION)
    for entry in entries:
        path_bytes = entry.relative_path.encode("utf-8")
        digest.update(len(path_bytes).to_bytes(8, byteorder="big"))
        digest.update(path_bytes)
        digest.update(entry.size_bytes.to_bytes(16, byteorder="big"))
        digest.update(bytes.fromhex(entry.sha256))
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class RepositoryManifest:
    entries: tuple[RepositoryManifestEntry, ...]
    file_count: int
    total_bytes: int
    content_digest: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.entries, tuple)
            or any(not isinstance(entry, RepositoryManifestEntry) for entry in self.entries)
            or tuple(sorted(self.entries, key=lambda entry: entry.relative_path)) != self.entries
            or len({entry.relative_path for entry in self.entries}) != len(self.entries)
            or not _bounded_integer(self.file_count, 0, 1_000_000)
            or not _bounded_integer(self.total_bytes, 0, 16 * _GIBIBYTE)
            or self.file_count != len(self.entries)
            or self.total_bytes != sum(entry.size_bytes for entry in self.entries)
            or not isinstance(self.content_digest, str)
            or _SHA256_PATTERN.fullmatch(self.content_digest) is None
            or self.content_digest != repository_content_digest(self.entries)
        ):
            raise ValueError("Repository manifest is invalid")

    def canonical_data(self) -> dict[str, Any]:
        return {
            "content_digest": self.content_digest,
            "entries": [
                {
                    "relative_path": entry.relative_path,
                    "sha256": entry.sha256,
                    "size_bytes": entry.size_bytes,
                }
                for entry in self.entries
            ],
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
        }


@dataclass(frozen=True, slots=True)
class PreparedRepositoryWorkspace:
    workspace_id: str
    root_directory: Path
    source_directory: Path
    output_directory: Path
    manifest: RepositoryManifest

    def __post_init__(self) -> None:
        if (
            not isinstance(self.workspace_id, str)
            or _WORKSPACE_ID_PATTERN.fullmatch(self.workspace_id) is None
            or not isinstance(self.root_directory, Path)
            or not self.root_directory.is_absolute()
            or self.root_directory.name != self.workspace_id
            or self.source_directory != self.root_directory / "source"
            or self.output_directory != self.root_directory / "output"
            or self.source_directory == self.output_directory
            or not isinstance(self.manifest, RepositoryManifest)
        ):
            raise ValueError("Prepared repository workspace is invalid")
