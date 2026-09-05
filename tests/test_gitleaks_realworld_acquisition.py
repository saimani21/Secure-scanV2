from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import subprocess
import tarfile
from pathlib import Path

import pytest

import securescan.benchmarks.gitleaks_realworld_acquisition as acquisition_module
from securescan.benchmarks.gitleaks_realworld_acquisition import (
    GITLEAKS_F5B2R2_COMMIT,
    GITLEAKS_F5B2R2_SELECTED_MANIFEST_SHA256,
    GITLEAKS_F5B2R2_TAG,
    GITLEAKS_REALWORLD_ACQUIRED_MANIFEST_SHA256,
    GitleaksDownloadedArchive,
    GitleaksRealworldAcquisitionError,
    GitleaksRepositoryAcquisition,
    _atomic_record_manifest,
    _prepare_cache_directory,
    acquire_gitleaks_realworld_repositories,
    build_acquired_manifest_document,
    download_frozen_archive,
    load_gitleaks_realworld_acquired_manifest,
    repository_acquisition_from_manifest,
    validate_and_extract_tar_gz,
    verify_gitleaks_realworld_acquisition,
)
from securescan.benchmarks.gitleaks_realworld_acquisition_contract import (
    GITLEAKS_ARCHIVE_MAX_DOWNLOADED_BYTES,
    GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_PATH,
    GitleaksRealworldAcquisitionManifestState,
    canonical_gitleaks_realworld_acquisition,
)
from securescan.benchmarks.gitleaks_realworld_selection import (
    GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SHA256,
    gitleaks_realworld_selection_document,
)
from securescan.workspaces.models import (
    RepositoryManifest,
    RepositoryManifestEntry,
    repository_content_digest,
)

ROOT = Path(__file__).resolve().parents[1]


class _FakeResponse:
    def __init__(
        self,
        payload: bytes,
        *,
        url: str,
        content_length: str | None = None,
    ) -> None:
        self._stream = io.BytesIO(payload)
        self._url = url
        self.headers = (
            {} if content_length is None else {"Content-Length": content_length}
        )

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        self._stream.close()

    def geturl(self) -> str:
        return self._url

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)


def _tar_info(
    name: str,
    *,
    kind: bytes = tarfile.REGTYPE,
    content: bytes = b"",
    linkname: str = "",
) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = linkname
    info.mode = 0o644
    info.size = len(content) if kind in {tarfile.REGTYPE, tarfile.AREGTYPE} else 0
    return info, content


def _write_tar(
    path: Path,
    members: list[tuple[tarfile.TarInfo, bytes]],
) -> None:
    with tarfile.open(path, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        for info, content in members:
            source = io.BytesIO(content) if info.isreg() else None
            archive.addfile(info, source)


def _ordinary_tar(path: Path, marker: bytes = b"content") -> None:
    _write_tar(
        path,
        [
            _tar_info("repository/", kind=tarfile.DIRTYPE),
            _tar_info("repository/src/", kind=tarfile.DIRTYPE),
            _tar_info("repository/src/file.txt", content=marker),
        ],
    )


def _rejects_archive(
    tmp_path: Path,
    members: list[tuple[tarfile.TarInfo, bytes]],
    *,
    archive_name: str = "hostile.tar.gz",
) -> None:
    archive = (tmp_path / archive_name).resolve()
    _write_tar(archive, members)
    with pytest.raises(
        GitleaksRealworldAcquisitionError,
        match="^Gitleaks real-world acquisition is invalid$",
    ):
        validate_and_extract_tar_gz(archive, (tmp_path / "output").resolve())
    assert not os.path.lexists(tmp_path / "output")


def _acquisitions(*, duplicate_snapshot: bool = False) -> tuple[
    GitleaksRepositoryAcquisition, ...
]:
    repositories = (
        "charmbracelet-gum",
        "pallets-click",
        "pallets-flask",
        "quad4-software-reticulum-go",
        "golang-go",
        "sslmate-go-pkcs12",
    )
    return tuple(
        GitleaksRepositoryAcquisition(
            repository_id=repository_id,
            archive_sha256=f"{position + 6:x}" * 64,
            archive_byte_count=position * 100,
            snapshot_digest=("1" if duplicate_snapshot else f"{position:x}") * 64,
            file_count=position,
            byte_count=position * 10,
        )
        for position, repository_id in enumerate(repositories, start=1)
    )


def _selected_checkpoint(tmp_path: Path) -> Path:
    root = (tmp_path / "repository").resolve()
    manifest = root / GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_PATH
    manifest.parent.mkdir(parents=True)
    payload = subprocess.run(
        [
            "git",
            "show",
            f"{GITLEAKS_F5B2R2_TAG}:{GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_PATH}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    manifest.write_bytes(payload)
    return root


def test_f5b2r2_boundary_and_selected_manifest_identity_are_exact() -> None:
    assert GITLEAKS_F5B2R2_COMMIT == "9d04a6d41c89c3725e64cbb45b3bbb657b85f386"
    assert GITLEAKS_F5B2R2_TAG == (
        "source-v0.4F5B2R2-gitleaks-repository-selection-correction"
    )
    assert GITLEAKS_F5B2R2_SELECTED_MANIFEST_SHA256 == (
        "c4843b6558fbccff370d66cd621a42927ec9c1fb1bc26cb2f036c6656b24673b"
    )
    assert GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SHA256 == (
        GITLEAKS_F5B2R2_SELECTED_MANIFEST_SHA256
    )


def test_f5b2r2_tag_resolves_exactly_and_is_current_head_ancestor() -> None:
    resolved = subprocess.run(
        ["git", "rev-parse", f"{GITLEAKS_F5B2R2_TAG}^{{commit}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    ancestry = subprocess.run(
        ["git", "merge-base", "--is-ancestor", GITLEAKS_F5B2R2_COMMIT, "HEAD"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert resolved == GITLEAKS_F5B2R2_COMMIT
    assert ancestry.returncode == 0


def test_acquired_manifest_is_canonical_digest_bound_and_verified() -> None:
    path = ROOT / GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_PATH
    payload = path.read_bytes()
    document = json.loads(payload)

    assert GITLEAKS_REALWORLD_ACQUIRED_MANIFEST_SHA256 == (
        "3a7f55e43210427974985c4e4009a1027fc4db12f3d94e119b490df8f0fc3b52"
    )
    assert hashlib.sha256(payload).hexdigest() == (
        GITLEAKS_REALWORLD_ACQUIRED_MANIFEST_SHA256
    )
    assert payload == canonical_gitleaks_realworld_acquisition(document)
    assert load_gitleaks_realworld_acquired_manifest(path) == document
    assert verify_gitleaks_realworld_acquisition(ROOT.resolve()) == document
    assert document["acquisition_state"] == "ACQUIRED"

    slots = document["repository_slots"]
    assert len(slots) == 6
    assert len({slot["snapshot_digest"] for slot in slots}) == 6
    assert all(slot["archive_sha256"] is not None for slot in slots)
    assert all(slot["archive_byte_count"] is not None for slot in slots)


def test_bounded_download_records_complete_sha_and_byte_count(tmp_path: Path) -> None:
    payload = b"synthetic archive bytes"
    url = "https://example.invalid/frozen.tar.gz"
    destination = (tmp_path / "frozen.tar.gz").resolve()

    result = download_frozen_archive(
        url,
        destination,
        allowed_archive_urls=frozenset({url}),
        opener=lambda requested: _FakeResponse(
            payload,
            url=requested,
            content_length=str(len(payload)),
        ),
    )

    assert result == GitleaksDownloadedArchive(
        hashlib.sha256(payload).hexdigest(), len(payload)
    )
    assert destination.read_bytes() == payload
    assert stat_mode(destination) == 0o400


@pytest.mark.parametrize(
    "final_url",
    (
        "https://github.com/archive/frozen.tar.gz",
        "https://codeload.github.com/archive/frozen.tar.gz",
    ),
)
def test_same_host_and_subdomain_redirects_are_accepted(
    tmp_path: Path,
    final_url: str,
) -> None:
    payload = b"synthetic archive bytes"
    original_url = "https://github.com/project/archive/frozen.tar.gz"

    result = download_frozen_archive(
        original_url,
        (tmp_path / "frozen.tar.gz").resolve(),
        allowed_archive_urls=frozenset({original_url}),
        opener=lambda _requested: _FakeResponse(payload, url=final_url),
    )

    assert result.byte_count == len(payload)


@pytest.mark.parametrize(
    "final_url",
    (
        "https://unrelated.example/archive/frozen.tar.gz",
        "http://github.com/archive/frozen.tar.gz",
    ),
)
def test_unrelated_and_http_redirects_are_rejected(
    tmp_path: Path,
    final_url: str,
) -> None:
    original_url = "https://github.com/project/archive/frozen.tar.gz"
    destination = (tmp_path / "frozen.tar.gz").resolve()

    with pytest.raises(GitleaksRealworldAcquisitionError):
        download_frozen_archive(
            original_url,
            destination,
            allowed_archive_urls=frozenset({original_url}),
            opener=lambda _requested: _FakeResponse(b"payload", url=final_url),
        )

    assert not os.path.lexists(destination)


def stat_mode(path: Path) -> int:
    return path.stat(follow_symlinks=False).st_mode & 0o777


@pytest.mark.parametrize("declared", (None, "5"))
def test_download_byte_overflow_is_rejected_and_partial_file_removed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    declared: str | None,
) -> None:
    monkeypatch.setattr(acquisition_module, "GITLEAKS_ARCHIVE_MAX_DOWNLOADED_BYTES", 4)
    url = "https://example.invalid/frozen.tar.gz"
    destination = (tmp_path / "frozen.tar.gz").resolve()

    with pytest.raises(GitleaksRealworldAcquisitionError):
        download_frozen_archive(
            url,
            destination,
            allowed_archive_urls=frozenset({url}),
            opener=lambda requested: _FakeResponse(
                b"12345", url=requested, content_length=declared
            ),
        )

    assert not os.path.lexists(destination)


@pytest.mark.parametrize(
    ("url", "allowed"),
    (
        ("http://example.invalid/frozen.tar.gz", True),
        ("https://example.invalid/frozen.zip", True),
        ("https://example.invalid/frozen.tar.gz", False),
    ),
)
def test_download_rejects_non_https_wrong_format_and_unfrozen_url(
    tmp_path: Path,
    url: str,
    allowed: bool,
) -> None:
    with pytest.raises(GitleaksRealworldAcquisitionError):
        download_frozen_archive(
            url,
            (tmp_path / "archive.tar.gz").resolve(),
            allowed_archive_urls=frozenset({url}) if allowed else frozenset(),
            opener=lambda requested: _FakeResponse(b"x", url=requested),
        )


def test_valid_tar_is_materialized_without_provider_top_level(tmp_path: Path) -> None:
    archive = (tmp_path / "ordinary.tar.gz").resolve()
    destination = (tmp_path / "output").resolve()
    _ordinary_tar(archive)

    validate_and_extract_tar_gz(archive, destination)

    assert sorted(
        path.relative_to(destination).as_posix()
        for path in destination.rglob("*")
    ) == ["src", "src/file.txt"]
    assert (destination / "src/file.txt").read_bytes() == b"content"
    assert not (destination / "repository").exists()


@pytest.mark.parametrize(
    ("case", "members"),
    (
        (
            "absolute",
            [
                _tar_info("repository/", kind=tarfile.DIRTYPE),
                _tar_info("/repository/file", content=b"x"),
            ],
        ),
        (
            "dotdot",
            [
                _tar_info("repository/", kind=tarfile.DIRTYPE),
                _tar_info("repository/../escape", content=b"x"),
            ],
        ),
        (
            "normalized-escape",
            [
                _tar_info("repository/", kind=tarfile.DIRTYPE),
                _tar_info("repository/a/../../escape", content=b"x"),
            ],
        ),
        (
            "symlink",
            [
                _tar_info("repository/", kind=tarfile.DIRTYPE),
                _tar_info(
                    "repository/link", kind=tarfile.SYMTYPE, linkname="target"
                ),
            ],
        ),
        (
            "hardlink",
            [
                _tar_info("repository/", kind=tarfile.DIRTYPE),
                _tar_info(
                    "repository/link", kind=tarfile.LNKTYPE, linkname="target"
                ),
            ],
        ),
        (
            "character-device",
            [
                _tar_info("repository/", kind=tarfile.DIRTYPE),
                _tar_info("repository/device", kind=tarfile.CHRTYPE),
            ],
        ),
        (
            "block-device",
            [
                _tar_info("repository/", kind=tarfile.DIRTYPE),
                _tar_info("repository/device", kind=tarfile.BLKTYPE),
            ],
        ),
        (
            "fifo",
            [
                _tar_info("repository/", kind=tarfile.DIRTYPE),
                _tar_info("repository/fifo", kind=tarfile.FIFOTYPE),
            ],
        ),
        (
            "socket",
            [
                _tar_info("repository/", kind=tarfile.DIRTYPE),
                _tar_info("repository/socket", kind=b"s"),
            ],
        ),
        (
            "special",
            [
                _tar_info("repository/", kind=tarfile.DIRTYPE),
                _tar_info("repository/sparse", kind=tarfile.GNUTYPE_SPARSE),
            ],
        ),
        (
            "duplicate",
            [
                _tar_info("repository/", kind=tarfile.DIRTYPE),
                _tar_info("repository/file", content=b"a"),
                _tar_info("repository/file", content=b"b"),
            ],
        ),
        (
            "normalized-collision",
            [
                _tar_info("repository/", kind=tarfile.DIRTYPE),
                _tar_info("repository/a//file", content=b"a"),
                _tar_info("repository/a/file", content=b"b"),
            ],
        ),
        (
            "missing-common-top-level-directory",
            [_tar_info("file", content=b"x")],
        ),
        (
            "multiple-top-level-directories",
            [
                _tar_info("first/", kind=tarfile.DIRTYPE),
                _tar_info("first/file", content=b"a"),
                _tar_info("second/", kind=tarfile.DIRTYPE),
            ],
        ),
        (
            "empty-after-stripping",
            [_tar_info("repository/", kind=tarfile.DIRTYPE)],
        ),
    ),
)
def test_hostile_tar_member_is_rejected(
    tmp_path: Path,
    case: str,
    members: list[tuple[tarfile.TarInfo, bytes]],
) -> None:
    assert case
    _rejects_archive(tmp_path, members)


def test_member_count_overflow_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(acquisition_module, "_MAX_ARCHIVE_MEMBERS", 2)
    _rejects_archive(
        tmp_path,
        [
            _tar_info("repository/", kind=tarfile.DIRTYPE),
            _tar_info("repository/a", content=b"a"),
            _tar_info("repository/b", content=b"b"),
        ],
    )


def test_total_expanded_overflow_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(acquisition_module, "_MAX_TOTAL_EXPANDED_BYTES", 4)
    _rejects_archive(
        tmp_path,
        [
            _tar_info("repository/", kind=tarfile.DIRTYPE),
            _tar_info("repository/a", content=b"aaa"),
            _tar_info("repository/b", content=b"bbb"),
        ],
    )


def test_single_member_overflow_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(acquisition_module, "_MAX_SINGLE_MEMBER_BYTES", 2)
    _rejects_archive(
        tmp_path,
        [
            _tar_info("repository/", kind=tarfile.DIRTYPE),
            _tar_info("repository/file", content=b"123"),
        ],
    )


def test_path_length_overflow_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(acquisition_module, "_MAX_NORMALIZED_PATH_BYTES", 4)
    _rejects_archive(
        tmp_path,
        [
            _tar_info("repository/", kind=tarfile.DIRTYPE),
            _tar_info("repository/abcde", content=b"x"),
        ],
    )


def test_directory_depth_overflow_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(acquisition_module, "_MAX_PATH_DEPTH", 2)
    _rejects_archive(
        tmp_path,
        [
            _tar_info("repository/", kind=tarfile.DIRTYPE),
            _tar_info("repository/a/b/c", content=b"x"),
        ],
    )


@pytest.mark.parametrize(
    ("name", "payload"),
    (
        ("malformed-gzip.tar.gz", b"not gzip"),
        ("malformed-tar.tar.gz", gzip.compress(b"not a tar stream")),
    ),
)
def test_malformed_archive_is_rejected(
    tmp_path: Path, name: str, payload: bytes
) -> None:
    archive = (tmp_path / name).resolve()
    archive.write_bytes(payload)
    with pytest.raises(GitleaksRealworldAcquisitionError):
        validate_and_extract_tar_gz(archive, (tmp_path / "output").resolve())
    assert not os.path.lexists(tmp_path / "output")


def test_incorrect_archive_file_extension_is_rejected(tmp_path: Path) -> None:
    archive = (tmp_path / "archive.zip").resolve()
    _ordinary_tar(archive)
    with pytest.raises(GitleaksRealworldAcquisitionError):
        validate_and_extract_tar_gz(archive, (tmp_path / "output").resolve())


def test_partial_materialization_is_cleaned_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = (tmp_path / "ordinary.tar.gz").resolve()
    destination = (tmp_path / "output").resolve()
    _ordinary_tar(archive)

    def fail_write(*_args: object) -> None:
        raise GitleaksRealworldAcquisitionError

    monkeypatch.setattr(acquisition_module, "_write_regular_member", fail_write)
    with pytest.raises(GitleaksRealworldAcquisitionError):
        validate_and_extract_tar_gz(archive, destination)

    assert not os.path.lexists(destination)
    assert not list(tmp_path.glob(".output-staging-*"))


def test_repository_manifest_identity_is_mapped_exactly() -> None:
    entry = RepositoryManifestEntry("file.txt", 3, hashlib.sha256(b"abc").hexdigest())
    entries = (entry,)
    manifest = RepositoryManifest(entries, 1, 3, repository_content_digest(entries))
    archive = GitleaksDownloadedArchive("a" * 64, 123)

    result = repository_acquisition_from_manifest("repository", archive, manifest)

    assert result == GitleaksRepositoryAcquisition(
        repository_id="repository",
        archive_sha256="a" * 64,
        archive_byte_count=123,
        snapshot_digest=manifest.content_digest,
        file_count=manifest.file_count,
        byte_count=manifest.total_bytes,
    )


@pytest.mark.parametrize(
    ("sha256", "byte_count"),
    (
        ("A" * 64, 1),
        ("a" * 63, 1),
        ("g" * 64, 1),
        ("a" * 64, 0),
        ("a" * 64, GITLEAKS_ARCHIVE_MAX_DOWNLOADED_BYTES + 1),
    ),
)
def test_archive_identity_format_and_bounds_are_strict(
    sha256: str, byte_count: int
) -> None:
    with pytest.raises(GitleaksRealworldAcquisitionError):
        GitleaksDownloadedArchive(sha256, byte_count)


def test_acquired_manifest_changes_only_acquisition_fields() -> None:
    selected = gitleaks_realworld_selection_document()
    acquired = build_acquired_manifest_document(_acquisitions())

    assert acquired["acquisition_state"] == (
        GitleaksRealworldAcquisitionManifestState.ACQUIRED.value
    )
    assert set(acquired) == set(selected)
    for before, after in zip(
        selected["repository_slots"], acquired["repository_slots"], strict=True
    ):
        for field in before:
            if field in {
                "archive_sha256",
                "archive_byte_count",
                "snapshot_digest",
                "file_count",
                "byte_count",
            }:
                assert before[field] is None
                assert after[field] is not None
            else:
                assert after[field] == before[field]


def test_snapshot_digest_collision_fails_closed() -> None:
    with pytest.raises(GitleaksRealworldAcquisitionError):
        build_acquired_manifest_document(_acquisitions(duplicate_snapshot=True))


def test_partial_acquisition_cannot_build_acquired_manifest() -> None:
    with pytest.raises(GitleaksRealworldAcquisitionError):
        build_acquired_manifest_document(_acquisitions()[:-1])


def test_atomic_manifest_recording_replaces_selected_bytes(tmp_path: Path) -> None:
    root = _selected_checkpoint(tmp_path)
    path = root / GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_PATH
    acquired = build_acquired_manifest_document(_acquisitions())

    _atomic_record_manifest(path, acquired)

    assert path.read_bytes() == canonical_gitleaks_realworld_acquisition(acquired)
    assert not list(path.parent.glob(".acquisition-manifest-v1-*.tmp"))


def test_atomic_manifest_failure_preserves_selected_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _selected_checkpoint(tmp_path)
    path = root / GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_PATH
    before = path.read_bytes()

    def fail_replace(_source: object, _destination: object) -> None:
        raise OSError

    monkeypatch.setattr(acquisition_module.os, "replace", fail_replace)
    with pytest.raises(GitleaksRealworldAcquisitionError):
        _atomic_record_manifest(path, build_acquired_manifest_document(_acquisitions()))

    assert path.read_bytes() == before
    assert not list(path.parent.glob(".acquisition-manifest-v1-*.tmp"))


def test_offline_six_repository_acquisition_transitions_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _selected_checkpoint(tmp_path)
    cache = (tmp_path / "cache").resolve()
    monkeypatch.setattr(
        acquisition_module,
        "verify_gitleaks_realworld_selection",
        lambda _root: gitleaks_realworld_selection_document(),
    )
    monkeypatch.setattr(
        acquisition_module, "_verify_f5b2r2_git_boundary", lambda _root: None
    )

    def downloader(
        url: str,
        destination: Path,
        *,
        allowed_archive_urls: frozenset[str],
    ) -> GitleaksDownloadedArchive:
        assert url in allowed_archive_urls
        _ordinary_tar(destination, marker=url.encode())
        payload = destination.read_bytes()
        return GitleaksDownloadedArchive(hashlib.sha256(payload).hexdigest(), len(payload))

    document = acquire_gitleaks_realworld_repositories(
        root,
        cache,
        downloader=downloader,
    )

    assert document["acquisition_state"] == "ACQUIRED"
    assert json.loads(
        (root / GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_PATH).read_bytes()
    ) == document
    slots = document["repository_slots"]
    assert len({slot["snapshot_digest"] for slot in slots}) == 6
    assert len(list((cache / "workspaces").glob("securescan-workspace-*"))) == 6


def test_partial_pipeline_failure_does_not_record_acquired_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _selected_checkpoint(tmp_path)
    cache = (tmp_path / "cache").resolve()
    selected_bytes = (
        root / GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_PATH
    ).read_bytes()
    monkeypatch.setattr(
        acquisition_module,
        "verify_gitleaks_realworld_selection",
        lambda _root: gitleaks_realworld_selection_document(),
    )
    monkeypatch.setattr(
        acquisition_module, "_verify_f5b2r2_git_boundary", lambda _root: None
    )
    calls = 0

    def downloader(
        url: str,
        destination: Path,
        *,
        allowed_archive_urls: frozenset[str],
    ) -> GitleaksDownloadedArchive:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise GitleaksRealworldAcquisitionError
        assert url in allowed_archive_urls
        _ordinary_tar(destination, marker=url.encode())
        payload = destination.read_bytes()
        return GitleaksDownloadedArchive(hashlib.sha256(payload).hexdigest(), len(payload))

    with pytest.raises(GitleaksRealworldAcquisitionError):
        acquire_gitleaks_realworld_repositories(root, cache, downloader=downloader)

    assert (
        root / GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_PATH
    ).read_bytes() == selected_bytes
    assert not list((cache / "workspaces").glob("securescan-workspace-*"))


def test_resolved_cache_parent_symlink_into_repository_is_rejected(
    tmp_path: Path,
) -> None:
    repository = (tmp_path / "repository").resolve()
    repository.mkdir()
    concealed_parent = repository / "concealed-cache-parent"
    concealed_parent.mkdir()
    external_alias = tmp_path / "apparently-external"
    external_alias.symlink_to(concealed_parent, target_is_directory=True)
    cache = external_alias / "cache"

    with pytest.raises(GitleaksRealworldAcquisitionError):
        _prepare_cache_directory(repository, cache.absolute())

    assert not os.path.lexists(concealed_parent / "cache")


def test_canonical_artifact_contains_no_paths_results_findings_or_secrets() -> None:
    document = build_acquired_manifest_document(_acquisitions())
    payload = canonical_gitleaks_realworld_acquisition(document)

    for forbidden in (
        b"/tmp/",
        b"realworld-result-v1.json",
    ):
        assert forbidden not in payload
    forbidden_fields = set(document["confidentiality"]["forbidden_fields"])
    assert all(
        not (set(slot) & forbidden_fields) for slot in document["repository_slots"]
    )
    assert document["contains_result_or_finding_data"] is False


def test_module_exposes_no_scanner_or_repository_execution_surface() -> None:
    source = (
        ROOT / "src/securescan/benchmarks/gitleaks_realworld_acquisition.py"
    ).read_text()

    for forbidden in (
        "extractall(",
        "git clone",
        "git checkout",
        "git submodule",
        "pip install",
        "npm install",
        "go mod download",
        "shell=True",
        "securescan.scanners.gitleaks",
    ):
        assert forbidden not in source
