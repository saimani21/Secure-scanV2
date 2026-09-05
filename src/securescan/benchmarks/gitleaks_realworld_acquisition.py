from __future__ import annotations

import hashlib
import json
import os
import posixpath
import shutil
import stat
import subprocess
import tarfile
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Final, Protocol
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from securescan.benchmarks.gitleaks_realworld_acquisition_contract import (
    GITLEAKS_ARCHIVE_MAX_DOWNLOADED_BYTES,
    GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_PATH,
    GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SCHEMA_PATH,
    GITLEAKS_REALWORLD_ACQUISITION_POLICY_PATH,
    GitleaksRealworldAcquisitionContractError,
    GitleaksRealworldAcquisitionManifestEntry,
    GitleaksRealworldAcquisitionManifestModel,
    GitleaksRealworldAcquisitionManifestState,
    canonical_gitleaks_realworld_acquisition,
    gitleaks_realworld_acquisition_manifest_schema_document,
    load_gitleaks_realworld_acquisition_manifest_schema,
    load_gitleaks_realworld_acquisition_policy,
)
from securescan.benchmarks.gitleaks_realworld_contract import (
    GITLEAKS_MATURITY,
    GITLEAKS_REALWORLD_RESULT_PATH,
    GitleaksRealworldContractError,
    verify_gitleaks_realworld_contract,
)
from securescan.benchmarks.gitleaks_realworld_selection import (
    GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SHA256,
    GitleaksRealworldSelectionError,
    gitleaks_realworld_selected_model,
    load_gitleaks_realworld_selection,
    verify_gitleaks_realworld_selection,
)
from securescan.workspaces import (
    PreparedRepositoryWorkspace,
    RepositoryManifest,
    RepositoryWorkspaceError,
    RepositoryWorkspaceManager,
)
from securescan.workspaces.models import RepositoryIntakeLimits

GITLEAKS_F5B2R2_COMMIT: Final = "9d04a6d41c89c3725e64cbb45b3bbb657b85f386"
GITLEAKS_F5B2R2_TAG: Final = (
    "source-v0.4F5B2R2-gitleaks-repository-selection-correction"
)
GITLEAKS_F5B2R2_SELECTED_MANIFEST_SHA256: Final = (
    "c4843b6558fbccff370d66cd621a42927ec9c1fb1bc26cb2f036c6656b24673b"
)
GITLEAKS_REALWORLD_ACQUIRED_MANIFEST_SHA256: Final = (
    "3a7f55e43210427974985c4e4009a1027fc4db12f3d94e119b490df8f0fc3b52"
)

_LIMITS = RepositoryIntakeLimits()
_MAX_ARCHIVE_MEMBERS = 50_000
_MAX_TOTAL_EXPANDED_BYTES = 1_073_741_824
_MAX_SINGLE_MEMBER_BYTES = 33_554_432
_MAX_NORMALIZED_PATH_BYTES = 4_096
_MAX_PATH_DEPTH = 64
_DOWNLOAD_CHUNK_BYTES = 1024 * 1024
_EXTRACT_CHUNK_BYTES = 1024 * 1024
_CONTROLLED_GIT_PATH = "/usr/bin:/bin"
_MAX_MANIFEST_BYTES = 1024 * 1024


class GitleaksRealworldAcquisitionError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Gitleaks real-world acquisition is invalid")


class _HTTPResponse(Protocol):
    headers: object

    def __enter__(self) -> _HTTPResponse: ...

    def __exit__(self, *args: object) -> object: ...

    def geturl(self) -> str: ...

    def read(self, size: int = -1) -> bytes: ...


@dataclass(frozen=True, slots=True)
class GitleaksDownloadedArchive:
    sha256: str
    byte_count: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.sha256, str)
            or len(self.sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.sha256)
            or type(self.byte_count) is not int
            or not 1 <= self.byte_count <= GITLEAKS_ARCHIVE_MAX_DOWNLOADED_BYTES
        ):
            raise GitleaksRealworldAcquisitionError


@dataclass(frozen=True, slots=True)
class GitleaksRepositoryAcquisition:
    repository_id: str
    archive_sha256: str
    archive_byte_count: int
    snapshot_digest: str
    file_count: int
    byte_count: int

    def __post_init__(self) -> None:
        try:
            GitleaksDownloadedArchive(self.archive_sha256, self.archive_byte_count)
        except GitleaksRealworldAcquisitionError:
            raise GitleaksRealworldAcquisitionError from None
        if (
            not isinstance(self.repository_id, str)
            or not self.repository_id
            or not isinstance(self.snapshot_digest, str)
            or len(self.snapshot_digest) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.snapshot_digest
            )
            or type(self.file_count) is not int
            or not 0 <= self.file_count <= _LIMITS.max_file_count
            or type(self.byte_count) is not int
            or not 0 <= self.byte_count <= _LIMITS.max_total_bytes
        ):
            raise GitleaksRealworldAcquisitionError


@dataclass(frozen=True, slots=True)
class _ValidatedTarMember:
    archive_name: str
    output_path: str
    kind: str
    size: int


def _git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "LC_ALL": "C",
        "PATH": _CONTROLLED_GIT_PATH,
    }


def _git(repository_root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *arguments],
            cwd=repository_root,
            env=_git_environment(),
            check=False,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        raise GitleaksRealworldAcquisitionError from None


def _verify_f5b2r2_git_boundary(repository_root: Path) -> None:
    branch = _git(repository_root, "branch", "--show-current")
    resolved = _git(
        repository_root,
        "rev-parse",
        f"{GITLEAKS_F5B2R2_TAG}^{{commit}}",
    )
    ancestry = _git(
        repository_root,
        "merge-base",
        "--is-ancestor",
        GITLEAKS_F5B2R2_COMMIT,
        "HEAD",
    )
    if (
        branch.returncode != 0
        or branch.stdout.strip() != "source/v0.3-semgrep"
        or resolved.returncode != 0
        or resolved.stdout.strip() != GITLEAKS_F5B2R2_COMMIT
        or ancestry.returncode != 0
        or GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SHA256
        != GITLEAKS_F5B2R2_SELECTED_MANIFEST_SHA256
    ):
        raise GitleaksRealworldAcquisitionError


def _valid_https_transport_url(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and bool(hostname)
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
    )


def _redirect_is_contained(original_url: str, final_url: str) -> bool:
    if not (
        _valid_https_transport_url(original_url)
        and _valid_https_transport_url(final_url)
    ):
        return False
    original_hostname = urlsplit(original_url).hostname
    final_hostname = urlsplit(final_url).hostname
    assert original_hostname is not None
    assert final_hostname is not None
    original_hostname = original_hostname.lower()
    final_hostname = final_hostname.lower()
    return final_hostname == original_hostname or final_hostname.endswith(
        f".{original_hostname}"
    )


def _open_https(url: str) -> _HTTPResponse:
    request = Request(
        url,
        headers={"User-Agent": "SecureScan-v0.4F5B3-controlled-acquisition"},
        method="GET",
    )
    return urlopen(request, timeout=120)  # type: ignore[return-value]


def _content_length(response: _HTTPResponse) -> int | None:
    try:
        raw = response.headers.get("Content-Length")  # type: ignore[attr-defined]
    except (AttributeError, TypeError, ValueError):
        raise GitleaksRealworldAcquisitionError from None
    if raw is None:
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise GitleaksRealworldAcquisitionError from None
    if value < 0:
        raise GitleaksRealworldAcquisitionError
    return value


def download_frozen_archive(
    archive_url: str,
    destination: Path,
    *,
    allowed_archive_urls: frozenset[str],
    opener: Callable[[str], _HTTPResponse] = _open_https,
) -> GitleaksDownloadedArchive:
    if (
        archive_url not in allowed_archive_urls
        or not _valid_https_transport_url(archive_url)
        or not archive_url.endswith(".tar.gz")
        or not isinstance(destination, Path)
        or not destination.is_absolute()
        or destination.suffixes[-2:] != [".tar", ".gz"]
    ):
        raise GitleaksRealworldAcquisitionError
    descriptor = -1
    completed = False
    try:
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        digest = hashlib.sha256()
        byte_count = 0
        with opener(archive_url) as response:
            if not _redirect_is_contained(archive_url, response.geturl()):
                raise GitleaksRealworldAcquisitionError
            declared_size = _content_length(response)
            if (
                declared_size is not None
                and declared_size > GITLEAKS_ARCHIVE_MAX_DOWNLOADED_BYTES
            ):
                raise GitleaksRealworldAcquisitionError
            while True:
                chunk = response.read(_DOWNLOAD_CHUNK_BYTES)
                if not isinstance(chunk, bytes):
                    raise GitleaksRealworldAcquisitionError
                if not chunk:
                    break
                byte_count += len(chunk)
                if byte_count > GITLEAKS_ARCHIVE_MAX_DOWNLOADED_BYTES:
                    raise GitleaksRealworldAcquisitionError
                digest.update(chunk)
                remaining = memoryview(chunk)
                while remaining:
                    written = os.write(descriptor, remaining)
                    if written <= 0:
                        raise OSError
                    remaining = remaining[written:]
        if byte_count == 0 or (
            declared_size is not None and byte_count != declared_size
        ):
            raise GitleaksRealworldAcquisitionError
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        completed = True
        return GitleaksDownloadedArchive(digest.hexdigest(), byte_count)
    except (GitleaksRealworldAcquisitionError, OSError, ValueError):
        raise GitleaksRealworldAcquisitionError from None
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        if not completed:
            with suppress(OSError):
                destination.unlink()


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


@contextmanager
def _open_stable_tar(archive_path: Path) -> Iterator[tarfile.TarFile]:
    descriptor = -1
    file_object: BinaryIO | None = None
    try:
        before = archive_path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_nlink != 1
            or not 1 <= before.st_size <= GITLEAKS_ARCHIVE_MAX_DOWNLOADED_BYTES
        ):
            raise OSError
        descriptor = os.open(
            archive_path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _stat_identity(opened) != _stat_identity(
            before
        ):
            raise OSError
        file_object = os.fdopen(descriptor, "rb", closefd=True)
        descriptor = -1
        with tarfile.open(fileobj=file_object, mode="r:gz") as archive:
            yield archive
        finished = os.fstat(file_object.fileno())
        after = archive_path.lstat()
        if (
            _stat_identity(finished) != _stat_identity(before)
            or _stat_identity(after) != _stat_identity(before)
        ):
            raise OSError
    except (OSError, EOFError, tarfile.TarError):
        raise GitleaksRealworldAcquisitionError from None
    finally:
        if file_object is not None:
            with suppress(OSError):
                file_object.close()
        elif descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)


def _normalized_member_parts(name: str) -> tuple[str, ...]:
    if (
        not isinstance(name, str)
        or not name
        or name.startswith("/")
        or "\\" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise GitleaksRealworldAcquisitionError
    raw_parts = name.rstrip("/").split("/")
    if not raw_parts or any(part == ".." for part in raw_parts):
        raise GitleaksRealworldAcquisitionError
    normalized = posixpath.normpath(name)
    if normalized in {"", ".", ".."} or normalized.startswith("../"):
        raise GitleaksRealworldAcquisitionError
    path = PurePosixPath(normalized)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise GitleaksRealworldAcquisitionError
    return path.parts


def _validate_tar_members(archive: tarfile.TarFile) -> tuple[_ValidatedTarMember, ...]:
    validated: list[_ValidatedTarMember] = []
    output_kinds: dict[str, str] = {}
    top_levels: set[str] = set()
    root_markers: set[str] = set()
    total_expanded = 0
    member_count = 0
    for member in archive:
        member_count += 1
        if member_count > _MAX_ARCHIVE_MEMBERS:
            raise GitleaksRealworldAcquisitionError
        parts = _normalized_member_parts(member.name)
        top_levels.add(parts[0])
        if len(top_levels) != 1:
            raise GitleaksRealworldAcquisitionError
        if member.type == tarfile.DIRTYPE:
            kind = "DIRECTORY"
            if member.size != 0:
                raise GitleaksRealworldAcquisitionError
        elif member.type in {tarfile.REGTYPE, tarfile.AREGTYPE}:
            kind = "REGULAR_FILE"
            if not 0 <= member.size <= _MAX_SINGLE_MEMBER_BYTES:
                raise GitleaksRealworldAcquisitionError
            total_expanded += member.size
            if total_expanded > _MAX_TOTAL_EXPANDED_BYTES:
                raise GitleaksRealworldAcquisitionError
        else:
            raise GitleaksRealworldAcquisitionError
        if len(parts) == 1:
            if kind != "DIRECTORY" or parts[0] in root_markers:
                raise GitleaksRealworldAcquisitionError
            root_markers.add(parts[0])
            continue
        output_parts = parts[1:]
        output_path = PurePosixPath(*output_parts).as_posix()
        try:
            path_bytes = output_path.encode("utf-8")
        except UnicodeEncodeError:
            raise GitleaksRealworldAcquisitionError from None
        if (
            not output_path
            or len(path_bytes) > _MAX_NORMALIZED_PATH_BYTES
            or len(output_parts) > _MAX_PATH_DEPTH
            or output_path in output_kinds
        ):
            raise GitleaksRealworldAcquisitionError
        output_kinds[output_path] = kind
        validated.append(
            _ValidatedTarMember(member.name, output_path, kind, member.size)
        )
    if len(top_levels) != 1 or root_markers != top_levels or not validated:
        raise GitleaksRealworldAcquisitionError
    for output_path in output_kinds:
        parent = PurePosixPath(output_path).parent
        while parent != PurePosixPath("."):
            if output_kinds.get(parent.as_posix()) == "REGULAR_FILE":
                raise GitleaksRealworldAcquisitionError
            parent = parent.parent
    return tuple(validated)


def _write_regular_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    destination: Path,
    expected_size: int,
) -> None:
    source = archive.extractfile(member)
    if source is None:
        raise GitleaksRealworldAcquisitionError
    descriptor = -1
    copied = 0
    try:
        descriptor = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        while True:
            chunk = source.read(_EXTRACT_CHUNK_BYTES)
            if not isinstance(chunk, bytes):
                raise GitleaksRealworldAcquisitionError
            if not chunk:
                break
            copied += len(chunk)
            if copied > expected_size or copied > _MAX_SINGLE_MEMBER_BYTES:
                raise GitleaksRealworldAcquisitionError
            remaining = memoryview(chunk)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError
                remaining = remaining[written:]
        if copied != expected_size:
            raise GitleaksRealworldAcquisitionError
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
    except (GitleaksRealworldAcquisitionError, OSError):
        raise GitleaksRealworldAcquisitionError from None
    finally:
        source.close()
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)


def validate_and_extract_tar_gz(archive_path: Path, destination: Path) -> None:
    if (
        not isinstance(archive_path, Path)
        or not archive_path.is_absolute()
        or archive_path.suffixes[-2:] != [".tar", ".gz"]
        or not isinstance(destination, Path)
        or not destination.is_absolute()
        or os.path.lexists(destination)
    ):
        raise GitleaksRealworldAcquisitionError
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}-staging-", dir=destination.parent)
    )
    completed = False
    try:
        with _open_stable_tar(archive_path) as archive:
            expected = _validate_tar_members(archive)
        with _open_stable_tar(archive_path) as archive:
            actual = _validate_tar_members(archive)
            if actual != expected:
                raise GitleaksRealworldAcquisitionError
            by_name = {member.name: member for member in archive.getmembers()}
            if len(by_name) != len(archive.getmembers()):
                raise GitleaksRealworldAcquisitionError
            ordered = sorted(
                actual,
                key=lambda item: (
                    item.kind != "DIRECTORY",
                    len(PurePosixPath(item.output_path).parts),
                    item.output_path,
                ),
            )
            for validated in ordered:
                member = by_name.get(validated.archive_name)
                if member is None:
                    raise GitleaksRealworldAcquisitionError
                target = staging.joinpath(*PurePosixPath(validated.output_path).parts)
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                if validated.kind == "DIRECTORY":
                    target.mkdir(mode=0o700, exist_ok=False)
                else:
                    _write_regular_member(archive, member, target, validated.size)
        staging.rename(destination)
        completed = True
    except (GitleaksRealworldAcquisitionError, OSError, tarfile.TarError):
        raise GitleaksRealworldAcquisitionError from None
    finally:
        if not completed:
            with suppress(OSError):
                shutil.rmtree(staging)


def repository_acquisition_from_manifest(
    repository_id: str,
    archive: GitleaksDownloadedArchive,
    manifest: RepositoryManifest,
) -> GitleaksRepositoryAcquisition:
    if not isinstance(manifest, RepositoryManifest):
        raise GitleaksRealworldAcquisitionError
    return GitleaksRepositoryAcquisition(
        repository_id=repository_id,
        archive_sha256=archive.sha256,
        archive_byte_count=archive.byte_count,
        snapshot_digest=manifest.content_digest,
        file_count=manifest.file_count,
        byte_count=manifest.total_bytes,
    )


def build_acquired_manifest_document(
    acquisitions: tuple[GitleaksRepositoryAcquisition, ...],
) -> dict[str, object]:
    selected = gitleaks_realworld_selected_model()
    by_repository = {item.repository_id: item for item in acquisitions}
    if len(acquisitions) != 6 or len(by_repository) != 6:
        raise GitleaksRealworldAcquisitionError
    entries: list[GitleaksRealworldAcquisitionManifestEntry] = []
    for entry in selected.entries:
        if entry.repository_id is None or entry.repository_id not in by_repository:
            raise GitleaksRealworldAcquisitionError
        result = by_repository[entry.repository_id]
        entries.append(
            replace(
                entry,
                archive_sha256=result.archive_sha256,
                archive_byte_count=result.archive_byte_count,
                snapshot_digest=result.snapshot_digest,
                file_count=result.file_count,
                byte_count=result.byte_count,
            )
        )
    try:
        acquired = GitleaksRealworldAcquisitionManifestModel(
            state=GitleaksRealworldAcquisitionManifestState.ACQUIRED,
            entries=tuple(entries),
        )
    except GitleaksRealworldAcquisitionContractError:
        raise GitleaksRealworldAcquisitionError from None
    document = gitleaks_realworld_acquisition_manifest_schema_document()
    document["acquisition_state"] = acquired.state.value
    document["repository_slots"] = [entry.canonical_data() for entry in acquired.entries]
    return document


def _atomic_record_manifest(
    manifest_path: Path,
    acquired_document: dict[str, object],
) -> None:
    load_gitleaks_realworld_selection(manifest_path)
    payload = canonical_gitleaks_realworld_acquisition(acquired_document)
    descriptor = -1
    temporary_path: Path | None = None
    try:
        descriptor, raw_path = tempfile.mkstemp(
            prefix=".acquisition-manifest-v1-",
            suffix=".tmp",
            dir=manifest_path.parent,
        )
        temporary_path = Path(raw_path)
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise OSError
            written += count
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o644)
        os.close(descriptor)
        descriptor = -1
        load_gitleaks_realworld_selection(manifest_path)
        os.replace(temporary_path, manifest_path)
        temporary_path = None
        directory = os.open(
            manifest_path.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except (GitleaksRealworldAcquisitionError, GitleaksRealworldSelectionError, OSError):
        raise GitleaksRealworldAcquisitionError from None
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        if temporary_path is not None:
            with suppress(OSError):
                temporary_path.unlink()


def _prepare_cache_directory(repository_root: Path, cache_directory: Path) -> Path:
    if not isinstance(cache_directory, Path) or not cache_directory.is_absolute():
        raise GitleaksRealworldAcquisitionError
    try:
        resolved_repository = repository_root.resolve(strict=True)
        resolved_parent = cache_directory.parent.resolve(strict=True)
    except (OSError, RuntimeError):
        raise GitleaksRealworldAcquisitionError from None
    resolved_candidate = resolved_parent / cache_directory.name
    if (
        resolved_candidate == resolved_repository
        or resolved_candidate.is_relative_to(resolved_repository)
        or resolved_repository.is_relative_to(resolved_candidate)
        or cache_directory.is_symlink()
    ):
        raise GitleaksRealworldAcquisitionError
    try:
        cache_directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        resolved = cache_directory.resolve(strict=True)
        if (
            resolved == resolved_repository
            or resolved.is_relative_to(resolved_repository)
            or resolved_repository.is_relative_to(resolved)
        ):
            with suppress(OSError):
                resolved.rmdir()
            raise GitleaksRealworldAcquisitionError
        os.chmod(resolved, 0o700, follow_symlinks=False)
    except OSError:
        raise GitleaksRealworldAcquisitionError from None
    return resolved


def acquire_gitleaks_realworld_repositories(
    repository_root: Path,
    cache_directory: Path,
    *,
    downloader: Callable[..., GitleaksDownloadedArchive] = download_frozen_archive,
) -> dict[str, object]:
    if not isinstance(repository_root, Path) or not repository_root.is_absolute():
        raise GitleaksRealworldAcquisitionError
    try:
        verify_gitleaks_realworld_selection(repository_root)
    except GitleaksRealworldSelectionError:
        raise GitleaksRealworldAcquisitionError from None
    _verify_f5b2r2_git_boundary(repository_root)
    selected = gitleaks_realworld_selected_model()
    allowed_urls = frozenset(
        entry.archive_url for entry in selected.entries if entry.archive_url is not None
    )
    cache = _prepare_cache_directory(repository_root, cache_directory)
    archives = cache / "archives"
    extractions = cache / "extractions"
    workspaces = cache / "workspaces"
    for directory in (archives, extractions):
        directory.mkdir(mode=0o700)
    workspace_manager = RepositoryWorkspaceManager(workspaces)
    prepared: list[PreparedRepositoryWorkspace] = []
    acquisitions: list[GitleaksRepositoryAcquisition] = []
    try:
        for entry in selected.entries:
            assert entry.repository_id is not None
            assert entry.archive_url is not None
            assert entry.exact_commit_sha is not None
            archive_path = archives / (
                f"{entry.repository_id}-{entry.exact_commit_sha}.tar.gz"
            )
            downloaded = downloader(
                entry.archive_url,
                archive_path,
                allowed_archive_urls=allowed_urls,
            )
            with tempfile.TemporaryDirectory(
                prefix=f"{entry.slot_id.lower()}-",
                dir=extractions,
            ) as temporary:
                source = Path(temporary) / "source"
                validate_and_extract_tar_gz(archive_path, source)
                workspace = workspace_manager.prepare_repository(source)
                prepared.append(workspace)
                acquisitions.append(
                    repository_acquisition_from_manifest(
                        entry.repository_id,
                        downloaded,
                        workspace.manifest,
                    )
                )
        acquired_document = build_acquired_manifest_document(tuple(acquisitions))
        _atomic_record_manifest(
            repository_root / GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_PATH,
            acquired_document,
        )
        return acquired_document
    except (
        GitleaksRealworldAcquisitionError,
        GitleaksRealworldSelectionError,
        RepositoryWorkspaceError,
        OSError,
    ):
        for workspace in reversed(prepared):
            with suppress(RepositoryWorkspaceError):
                workspace_manager.cleanup_workspace(workspace)
        raise GitleaksRealworldAcquisitionError from None


def load_gitleaks_realworld_acquired_manifest(path: Path) -> dict[str, object]:
    descriptor = -1
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_nlink != 1
            or not 1 <= before.st_size <= _MAX_MANIFEST_BYTES
        ):
            raise OSError
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _stat_identity(opened) != _stat_identity(
            before
        ):
            raise OSError
        payload = bytearray()
        while len(payload) <= _MAX_MANIFEST_BYTES:
            chunk = os.read(
                descriptor,
                min(65536, _MAX_MANIFEST_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        finished = os.fstat(descriptor)
        after = path.lstat()
        if (
            len(payload) > _MAX_MANIFEST_BYTES
            or len(payload) != before.st_size
            or _stat_identity(finished) != _stat_identity(before)
            or _stat_identity(after) != _stat_identity(before)
        ):
            raise OSError
        document = json.loads(
            bytes(payload).decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json,
        )
    except (OSError, UnicodeDecodeError, ValueError):
        raise GitleaksRealworldAcquisitionError from None
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
    try:
        slots = document["repository_slots"]
        if not isinstance(slots, list):
            raise TypeError
        expected = build_acquired_manifest_document(
            tuple(
                GitleaksRepositoryAcquisition(
                    repository_id=slot["repository_id"],
                    archive_sha256=slot["archive_sha256"],
                    archive_byte_count=slot["archive_byte_count"],
                    snapshot_digest=slot["snapshot_digest"],
                    file_count=slot["file_count"],
                    byte_count=slot["byte_count"],
                )
                for slot in slots
            )
        )
    except (KeyError, TypeError, GitleaksRealworldAcquisitionError):
        raise GitleaksRealworldAcquisitionError from None
    if (
        canonical_gitleaks_realworld_acquisition(document) != bytes(payload)
        or document != expected
        or hashlib.sha256(payload).hexdigest()
        != GITLEAKS_REALWORLD_ACQUIRED_MANIFEST_SHA256
    ):
        raise GitleaksRealworldAcquisitionError
    return document


def _reject_duplicate_json_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_nonfinite_json(_value: str) -> None:
    raise ValueError


def verify_gitleaks_realworld_acquisition(repository_root: Path) -> dict[str, object]:
    if not isinstance(repository_root, Path) or not repository_root.is_absolute():
        raise GitleaksRealworldAcquisitionError
    try:
        verify_gitleaks_realworld_contract(repository_root)
        load_gitleaks_realworld_acquisition_policy(
            repository_root / GITLEAKS_REALWORLD_ACQUISITION_POLICY_PATH
        )
        load_gitleaks_realworld_acquisition_manifest_schema(
            repository_root / GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SCHEMA_PATH
        )
    except (
        GitleaksRealworldAcquisitionContractError,
        GitleaksRealworldContractError,
    ):
        raise GitleaksRealworldAcquisitionError from None
    _verify_f5b2r2_git_boundary(repository_root)
    document = load_gitleaks_realworld_acquired_manifest(
        repository_root / GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_PATH
    )
    if document.get("maturity") != GITLEAKS_MATURITY:
        raise GitleaksRealworldAcquisitionError
    try:
        (repository_root / GITLEAKS_REALWORLD_RESULT_PATH).lstat()
    except FileNotFoundError:
        return document
    except OSError:
        raise GitleaksRealworldAcquisitionError from None
    raise GitleaksRealworldAcquisitionError
