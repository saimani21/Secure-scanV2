from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace

import pytest

from securescan.source import (
    ENRY_MAX_CONTENT_BYTES,
    EnryBatchResult,
    EnryClassification,
    EnryClient,
    EnryFileInput,
    EnryHelperTimeoutError,
    EnryProtocolError,
    FileContentKind,
    InvalidSourceLanguageProfilingRequestError,
    RepositoryInventory,
    SourceLanguageCorrelationError,
    SourceLanguageEvidence,
    SourceLanguageProfile,
    SourceLanguageProfilingPolicy,
    SourceSnapshotIntegrityError,
    TrustedEnryHelper,
    VerifiedRepositoryFileSample,
    build_repository_inventory,
    encode_enry_requests,
    partition_enry_requests,
    profile_repository_languages,
    read_verified_repository_file_sample,
    verify_repository_snapshot,
)
from securescan.workspaces import (
    RepositoryManifestEntry,
    RepositoryWorkspaceManager,
)

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_LOCAL_HELPER = _PROJECT_ROOT / "tools/enry-helper/bin/securescan-enry-helper"
_HELPER_DIGEST = "a" * 64


def _prepared_repository(
    tmp_path: Path,
    files: dict[str, bytes],
) -> tuple[RepositoryWorkspaceManager, object, RepositoryInventory]:
    source = tmp_path / "repository"
    source.mkdir(parents=True)
    for relative_path, content in files.items():
        path = source / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    manager = RepositoryWorkspaceManager(tmp_path / "managed")
    workspace = manager.prepare_repository(source)
    inventory = build_repository_inventory(workspace)
    return manager, workspace, inventory


def _classification(
    relative_path: str,
    *,
    language: str | None = "Python",
    candidate_languages: tuple[str, ...] = ("Python",),
    is_binary: bool = False,
    is_vendor: bool = False,
    is_generated: bool = False,
    is_test: bool = False,
    is_configuration: bool = False,
    is_documentation: bool = False,
    is_dot_file: bool = False,
    is_image: bool = False,
) -> EnryClassification:
    return EnryClassification(
        relative_path=relative_path,
        language=language,
        candidate_languages=candidate_languages,
        is_binary=is_binary,
        is_vendor=is_vendor,
        is_generated=is_generated,
        is_test=is_test,
        is_configuration=is_configuration,
        is_documentation=is_documentation,
        is_dot_file=is_dot_file,
        is_image=is_image,
    )


def _evidence(
    relative_path: str = "src/app.py",
    *,
    language: str | None = "Python",
    candidate_languages: tuple[str, ...] = ("Python",),
    is_binary: bool = False,
) -> SourceLanguageEvidence:
    return SourceLanguageEvidence(
        relative_path=relative_path,
        language=language,
        candidate_languages=candidate_languages,
        is_binary=is_binary,
        is_vendor=False,
        is_generated=False,
        is_test=False,
        is_configuration=False,
        is_documentation=False,
        is_dot_file=False,
        is_image=False,
        analyzed_bytes=10,
        content_complete=True,
    )


def _profile(**overrides: object) -> SourceLanguageProfile:
    values: dict[str, object] = {
        "repository_digest": "b" * 64,
        "evidence": (_evidence(),),
        "skipped_binary_paths": (),
        "helper_sha256": _HELPER_DIGEST,
        "helper_version": "0.2.3",
        "enry_version": "v2.9.6",
        "batch_count": 1,
        "duration_ms": 5,
    }
    values.update(overrides)
    return SourceLanguageProfile(**values)  # type: ignore[arg-type]


class _FakeClient:
    def __init__(
        self,
        *,
        maximum_files: int = 256,
        results: list[object] | None = None,
        failure_index: int | None = None,
    ) -> None:
        self._configuration = TrustedEnryHelper(
            helper_path=Path("/trusted/enry-helper"),
            expected_sha256=_HELPER_DIGEST,
            maximum_files_per_batch=maximum_files,
        )
        self.results = results
        self.failure_index = failure_index
        self.calls: list[tuple[EnryFileInput, ...]] = []

    @property
    def configuration(self) -> TrustedEnryHelper:
        return self._configuration

    def classify(self, files: tuple[EnryFileInput, ...]) -> object:
        call_index = len(self.calls)
        self.calls.append(files)
        if self.failure_index == call_index:
            raise EnryHelperTimeoutError
        if self.results is not None:
            return self.results[call_index]
        classifications = tuple(
            _classification(
                file.relative_path,
                language=(None if file.relative_path.endswith(".data") else "Python"),
                candidate_languages=(
                    () if file.relative_path.endswith(".data") else ("Python",)
                ),
            )
            for file in files
        )
        return EnryBatchResult(
            classifications=classifications,
            helper_sha256=_HELPER_DIGEST,
            helper_version="0.2.3",
            enry_version="v2.9.6",
            duration_ms=7,
        )


def _raw_result(
    classifications: tuple[EnryClassification, ...],
    *,
    helper_sha256: str = _HELPER_DIGEST,
    helper_version: str = "0.2.3",
    enry_version: str = "v2.9.6",
    duration_ms: int = 7,
) -> SimpleNamespace:
    return SimpleNamespace(
        classifications=classifications,
        helper_sha256=helper_sha256,
        helper_version=helper_version,
        enry_version=enry_version,
        duration_ms=duration_ms,
    )


@pytest.mark.parametrize(
    ("content", "sample_bytes", "expected_sample", "complete"),
    [
        (b"small", 16, b"small", True),
        (b"", 16, b"", True),
        (b"1234", 4, b"1234", True),
        (b"12345", 4, b"1234", False),
    ],
)
def test_verified_reader_returns_bounded_complete_samples(
    tmp_path: Path,
    content: bytes,
    sample_bytes: int,
    expected_sample: bytes,
    complete: bool,
) -> None:
    manager, workspace, _ = _prepared_repository(tmp_path, {"file.txt": content})
    try:
        sample = read_verified_repository_file_sample(
            workspace,
            workspace.manifest.entries[0],
            sample_bytes=sample_bytes,
        )
        assert sample == VerifiedRepositoryFileSample(
            relative_path="file.txt",
            sample=expected_sample,
            size_bytes=len(content),
            sha256=hashlib.sha256(content).hexdigest(),
            content_complete=complete,
        )
    finally:
        manager.cleanup_workspace(workspace)


def test_verified_reader_hashes_entire_file_beyond_sample(tmp_path: Path) -> None:
    content = b"prefix" + b"tail" * 100_000
    manager, workspace, _ = _prepared_repository(tmp_path, {"large.py": content})
    try:
        sample = read_verified_repository_file_sample(
            workspace,
            workspace.manifest.entries[0],
            sample_bytes=6,
        )
        assert sample.sample == b"prefix"
        assert sample.sha256 == hashlib.sha256(content).hexdigest()
        assert sample.size_bytes == len(content)
        assert sample.content_complete is False
    finally:
        manager.cleanup_workspace(workspace)


@pytest.mark.parametrize("mutation", ["truncate", "grow", "same_size", "symlink"])
def test_verified_reader_rejects_snapshot_file_changes(
    tmp_path: Path,
    mutation: str,
) -> None:
    content = b"original-content"
    manager, workspace, _ = _prepared_repository(tmp_path, {"file.py": content})
    path = workspace.source_directory / "file.py"
    try:
        path.chmod(0o600)
        if mutation == "truncate":
            path.write_bytes(content[:-1])
        elif mutation == "grow":
            path.write_bytes(content + b"x")
        elif mutation == "same_size":
            path.write_bytes(b"x" * len(content))
        else:
            workspace.source_directory.chmod(0o700)
            path.unlink()
            path.symlink_to(tmp_path / "repository/file.py")
        with pytest.raises(SourceSnapshotIntegrityError):
            read_verified_repository_file_sample(
                workspace,
                workspace.manifest.entries[0],
                sample_bytes=8,
            )
    finally:
        manager.cleanup_workspace(workspace)


@pytest.mark.parametrize("field", ["size", "digest"])
def test_verified_reader_rejects_manifest_entry_mismatch(
    tmp_path: Path,
    field: str,
) -> None:
    manager, workspace, _ = _prepared_repository(tmp_path, {"file.py": b"content"})
    original = workspace.manifest.entries[0]
    supplied = RepositoryManifestEntry(
        relative_path=original.relative_path,
        size_bytes=(original.size_bytes + 1 if field == "size" else original.size_bytes),
        sha256=("0" * 64 if field == "digest" else original.sha256),
    )
    try:
        with pytest.raises(SourceSnapshotIntegrityError):
            read_verified_repository_file_sample(
                workspace,
                supplied,
                sample_bytes=8,
            )
    finally:
        manager.cleanup_workspace(workspace)


@pytest.mark.parametrize("mutation", ["add", "delete"])
def test_complete_snapshot_verification_rejects_file_set_changes(
    tmp_path: Path,
    mutation: str,
) -> None:
    manager, workspace, _ = _prepared_repository(tmp_path, {"file.py": b"content"})
    try:
        workspace.source_directory.chmod(0o700)
        if mutation == "add":
            (workspace.source_directory / "extra.py").write_bytes(b"extra")
        else:
            (workspace.source_directory / "file.py").unlink()
        with pytest.raises(SourceSnapshotIntegrityError):
            verify_repository_snapshot(workspace)
    finally:
        manager.cleanup_workspace(workspace)


def test_verified_reader_errors_hide_content_and_paths(tmp_path: Path) -> None:
    sensitive = b"sensitive-source-content"
    manager, workspace, _ = _prepared_repository(tmp_path, {"secret.py": sensitive})
    try:
        path = workspace.source_directory / "secret.py"
        path.chmod(0o600)
        path.write_bytes(b"x" * len(sensitive))
        with pytest.raises(SourceSnapshotIntegrityError) as raised:
            read_verified_repository_file_sample(
                workspace,
                workspace.manifest.entries[0],
                sample_bytes=8,
            )
        message = str(raised.value)
        assert sensitive.decode("ascii") not in message
        assert str(workspace.source_directory) not in message
        assert str(path) not in message
    finally:
        manager.cleanup_workspace(workspace)


def test_partition_empty_and_single_file() -> None:
    file = EnryFileInput("a.py", b"content")
    assert partition_enry_requests((), maximum_files=1, maximum_payload_bytes=1) == ()
    assert partition_enry_requests(
        (file,),
        maximum_files=1,
        maximum_payload_bytes=1024,
    ) == ((file,),)


def test_partition_file_count_boundary_preserves_every_file() -> None:
    files = tuple(EnryFileInput(f"{index}.py", b"x") for index in range(5))
    batches = partition_enry_requests(
        files,
        maximum_files=2,
        maximum_payload_bytes=4096,
    )
    assert tuple(len(batch) for batch in batches) == (2, 2, 1)
    assert tuple(file for batch in batches for file in batch) == files


def test_partition_exact_payload_boundary_and_unfit_request() -> None:
    file = EnryFileInput("a.py", b"content")
    payload, _ = encode_enry_requests(
        (file,),
        maximum_files=1,
        maximum_payload_bytes=4096,
    )
    assert partition_enry_requests(
        (file,),
        maximum_files=1,
        maximum_payload_bytes=len(payload),
    ) == ((file,),)
    with pytest.raises(EnryProtocolError):
        partition_enry_requests(
            (file,),
            maximum_files=1,
            maximum_payload_bytes=len(payload) - 1,
        )


def test_partition_is_deterministic_ordered_and_wire_compatible() -> None:
    files = tuple(
        EnryFileInput(f"src/{index}.py", bytes([index]) * 20)
        for index in range(4)
    )
    first = partition_enry_requests(
        files,
        maximum_files=2,
        maximum_payload_bytes=4096,
    )
    second = partition_enry_requests(
        files,
        maximum_files=2,
        maximum_payload_bytes=4096,
    )
    assert first == second
    assert tuple(file for batch in first for file in batch) == files
    for batch in first:
        payload, correlations = encode_enry_requests(
            batch,
            maximum_files=2,
            maximum_payload_bytes=4096,
        )
        assert payload.endswith(b"\n")
        assert len(correlations) == len(batch)


def test_partition_rejects_unsorted_duplicate_and_invalid_limits() -> None:
    first = EnryFileInput("a.py", b"a")
    second = EnryFileInput("b.py", b"b")
    for files in ((second, first), (first, first)):
        with pytest.raises(EnryProtocolError):
            partition_enry_requests(
                files,
                maximum_files=2,
                maximum_payload_bytes=4096,
            )
    for maximum_files, maximum_payload_bytes in ((0, 4096), (1, 0), (True, 4096)):
        with pytest.raises(EnryProtocolError):
            partition_enry_requests(
                (first,),
                maximum_files=maximum_files,
                maximum_payload_bytes=maximum_payload_bytes,
            )


def test_existing_request_wire_format_is_unchanged() -> None:
    payload, correlations = encode_enry_requests(
        (EnryFileInput("a.py", b"x"),),
        maximum_files=1,
        maximum_payload_bytes=4096,
    )
    assert payload == (
        b'{"content_base64":"eA==","relative_path":"a.py",'
        b'"request_id":"file-00000000","schema_version":"1.0.0"}\n'
    )
    assert correlations == (("file-00000000", "a.py"),)


def test_language_policy_and_evidence_are_immutable() -> None:
    policy = SourceLanguageProfilingPolicy()
    evidence = _evidence()
    with pytest.raises(FrozenInstanceError):
        policy.sample_bytes = 1  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        evidence.language = "Go"  # type: ignore[misc]


@pytest.mark.parametrize("sample_bytes", [0, True, ENRY_MAX_CONTENT_BYTES + 1])
def test_language_policy_rejects_invalid_sample_limits(sample_bytes: int) -> None:
    with pytest.raises(InvalidSourceLanguageProfilingRequestError):
        SourceLanguageProfilingPolicy(sample_bytes=sample_bytes)


@pytest.mark.parametrize(
    "overrides",
    [
        {"is_binary": True},
        {"candidate_languages": ("Go",)},
        {"candidate_languages": ("Python", "Go")},
        {"relative_path": "src/control\u0085name.py"},
    ],
)
def test_language_evidence_rejects_invalid_semantics(
    overrides: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "relative_path": "src/app.py",
        "language": "Python",
        "candidate_languages": ("Python",),
        "is_binary": False,
        "is_vendor": False,
        "is_generated": False,
        "is_test": False,
        "is_configuration": False,
        "is_documentation": False,
        "is_dot_file": False,
        "is_image": False,
        "analyzed_bytes": 10,
        "content_complete": True,
    }
    values.update(overrides)
    with pytest.raises(InvalidSourceLanguageProfilingRequestError):
        SourceLanguageEvidence(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "overrides",
    [
        {"repository_digest": "A" * 64},
        {"evidence": (_evidence("z.py"), _evidence("a.py"))},
        {"evidence": (_evidence(), _evidence())},
        {"skipped_binary_paths": ("b.bin", "b.bin")},
        {"skipped_binary_paths": ("src/app.py",)},
        {"helper_sha256": None},
        {"batch_count": 0},
        {
            "batch_count": 0,
            "duration_ms": 0,
            "helper_sha256": _HELPER_DIGEST,
            "helper_version": "0.2.3",
            "enry_version": "v2.9.6",
        },
        {
            "batch_count": 1,
            "helper_sha256": None,
            "helper_version": None,
            "enry_version": None,
        },
    ],
)
def test_language_profile_rejects_invalid_canonical_structure(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(InvalidSourceLanguageProfilingRequestError):
        _profile(**overrides)


def test_zero_batch_profile_is_valid_and_retains_no_bytes() -> None:
    profile = SourceLanguageProfile(
        repository_digest="b" * 64,
        evidence=(),
        skipped_binary_paths=(),
        helper_sha256=None,
        helper_version=None,
        enry_version=None,
        batch_count=0,
        duration_ms=0,
    )
    assert profile.schema_version == "0.2.3"
    assert not any(isinstance(value, bytes) for value in vars(SimpleNamespace(p=profile)).values())
    assert "source-content" not in repr(profile)


def test_workspace_digest_mismatch_is_rejected_before_enry(tmp_path: Path) -> None:
    first_manager, first_workspace, _ = _prepared_repository(
        tmp_path / "first",
        {"a.py": b"a"},
    )
    second_manager, second_workspace, second_inventory = _prepared_repository(
        tmp_path / "second",
        {"a.py": b"different"},
    )
    client = _FakeClient()
    try:
        with pytest.raises(SourceLanguageCorrelationError):
            profile_repository_languages(first_workspace, second_inventory, client)
        assert client.calls == []
    finally:
        first_manager.cleanup_workspace(first_workspace)
        second_manager.cleanup_workspace(second_workspace)


def test_manifest_inventory_entry_mismatch_is_rejected(tmp_path: Path) -> None:
    manager, workspace, inventory = _prepared_repository(tmp_path, {"a.py": b"a"})
    invalid = object.__new__(RepositoryInventory)
    object.__setattr__(invalid, "repository_digest", inventory.repository_digest)
    object.__setattr__(invalid, "files", ())
    object.__setattr__(invalid, "schema_version", "0.2.2")
    client = _FakeClient()
    try:
        with pytest.raises(SourceLanguageCorrelationError):
            profile_repository_languages(workspace, invalid, client)
        assert client.calls == []
    finally:
        manager.cleanup_workspace(workspace)


@pytest.mark.parametrize(
    ("files", "expected_skipped"),
    [
        ({}, ()),
        ({"asset.bin": b"\x00\x01"}, ("asset.bin",)),
    ],
)
def test_zero_eligible_files_never_invoke_client(
    tmp_path: Path,
    files: dict[str, bytes],
    expected_skipped: tuple[str, ...],
) -> None:
    manager, workspace, inventory = _prepared_repository(tmp_path, files)
    client = _FakeClient()
    try:
        profile = profile_repository_languages(workspace, inventory, client)
        assert client.calls == []
        assert profile.evidence == ()
        assert profile.skipped_binary_paths == expected_skipped
        assert profile.batch_count == 0
        assert profile.duration_ms == 0
        assert profile.helper_sha256 is None
    finally:
        manager.cleanup_workspace(workspace)


def test_text_unknown_and_empty_files_are_sent_in_path_order(tmp_path: Path) -> None:
    manager, workspace, inventory = _prepared_repository(
        tmp_path,
        {
            "z.py": b"print('z')\n",
            "a.data": b"text-\xff-value",
            "empty.py": b"",
        },
    )
    client = _FakeClient()
    original = inventory.canonical_data()
    try:
        profile = profile_repository_languages(workspace, inventory, client)
        assert tuple(file.relative_path for file in client.calls[0]) == (
            "a.data",
            "empty.py",
            "z.py",
        )
        assert inventory.files[0].content_kind is FileContentKind.UNKNOWN
        assert profile.evidence[0].language is None
        assert profile.evidence[1].analyzed_bytes == 0
        assert profile.evidence[1].content_complete is True
        assert inventory.canonical_data() == original
        assert all(file.language is None for file in inventory.files)
    finally:
        manager.cleanup_workspace(workspace)


def test_multiple_batches_are_deterministic_and_sum_duration(tmp_path: Path) -> None:
    files = {f"{index}.py": b"print('x')\n" for index in range(5)}
    manager, workspace, inventory = _prepared_repository(tmp_path, files)
    client = _FakeClient(maximum_files=2)
    try:
        first = profile_repository_languages(workspace, inventory, client)
        first_calls = tuple(tuple(file.relative_path for file in batch) for batch in client.calls)
        client.calls.clear()
        second = profile_repository_languages(workspace, inventory, client)
        second_calls = tuple(tuple(file.relative_path for file in batch) for batch in client.calls)
        assert first.batch_count == 3
        assert first.duration_ms == 21
        assert first_calls == second_calls
        assert first.evidence == second.evidence
    finally:
        manager.cleanup_workspace(workspace)


@pytest.mark.parametrize("failure", ["missing", "extra", "reordered"])
def test_classification_correlation_failures_are_rejected(
    tmp_path: Path,
    failure: str,
) -> None:
    manager, workspace, inventory = _prepared_repository(
        tmp_path,
        {"a.py": b"a", "b.py": b"b"},
    )
    if failure == "missing":
        classifications = (_classification("a.py"),)
    elif failure == "extra":
        classifications = (
            _classification("a.py"),
            _classification("b.py"),
            _classification("c.py"),
        )
    else:
        classifications = (_classification("b.py"), _classification("a.py"))
    client = _FakeClient(results=[_raw_result(classifications)])
    try:
        with pytest.raises(SourceLanguageCorrelationError):
            profile_repository_languages(workspace, inventory, client)
    finally:
        manager.cleanup_workspace(workspace)


@pytest.mark.parametrize("field", ["digest", "helper_version", "enry_version"])
def test_cross_batch_provenance_mismatch_is_rejected(
    tmp_path: Path,
    field: str,
) -> None:
    manager, workspace, inventory = _prepared_repository(
        tmp_path,
        {"a.py": b"a", "b.py": b"b"},
    )
    first = _raw_result((_classification("a.py"),))
    overrides = {
        "helper_sha256": ("c" * 64 if field == "digest" else _HELPER_DIGEST),
        "helper_version": ("9.9.9" if field == "helper_version" else "0.2.3"),
        "enry_version": ("v9.9.9" if field == "enry_version" else "v2.9.6"),
    }
    second = _raw_result((_classification("b.py"),), **overrides)
    client = _FakeClient(maximum_files=1, results=[first, second])
    try:
        with pytest.raises(SourceLanguageCorrelationError):
            profile_repository_languages(workspace, inventory, client)
    finally:
        manager.cleanup_workspace(workspace)


def test_later_batch_failure_propagates_without_partial_profile(tmp_path: Path) -> None:
    manager, workspace, inventory = _prepared_repository(
        tmp_path,
        {"a.py": b"a", "b.py": b"b"},
    )
    client = _FakeClient(maximum_files=1, failure_index=1)
    try:
        with pytest.raises(EnryHelperTimeoutError):
            profile_repository_languages(workspace, inventory, client)
        assert len(client.calls) == 2
    finally:
        manager.cleanup_workspace(workspace)


def test_enry_facts_are_copied_exactly_to_evidence(tmp_path: Path) -> None:
    manager, workspace, inventory = _prepared_repository(tmp_path, {"facts.txt": b"facts"})
    classification = _classification(
        "facts.txt",
        language=None,
        candidate_languages=(),
        is_binary=True,
        is_vendor=True,
        is_generated=True,
        is_test=True,
        is_configuration=True,
        is_documentation=True,
        is_dot_file=True,
        is_image=True,
    )
    client = _FakeClient(results=[_raw_result((classification,))])
    try:
        evidence = profile_repository_languages(workspace, inventory, client).evidence[0]
        assert evidence.language is None
        assert evidence.candidate_languages == ()
        assert evidence.is_binary is True
        assert evidence.is_vendor is True
        assert evidence.is_generated is True
        assert evidence.is_test is True
        assert evidence.is_configuration is True
        assert evidence.is_documentation is True
        assert evidence.is_dot_file is True
        assert evidence.is_image is True
    finally:
        manager.cleanup_workspace(workspace)


def test_candidate_languages_are_preserved_exactly(tmp_path: Path) -> None:
    manager, workspace, inventory = _prepared_repository(tmp_path, {"ambiguous.h": b"header"})
    classification = _classification(
        "ambiguous.h",
        language="C",
        candidate_languages=("C", "C++"),
    )
    client = _FakeClient(results=[_raw_result((classification,))])
    try:
        evidence = profile_repository_languages(workspace, inventory, client).evidence[0]
        assert evidence.language == "C"
        assert evidence.candidate_languages == ("C", "C++")
    finally:
        manager.cleanup_workspace(workspace)


def test_final_snapshot_file_set_change_is_rejected(tmp_path: Path) -> None:
    manager, workspace, inventory = _prepared_repository(tmp_path, {"a.py": b"a"})

    class _MutatingClient(_FakeClient):
        def classify(self, files: tuple[EnryFileInput, ...]) -> object:
            result = super().classify(files)
            workspace.source_directory.chmod(0o700)
            (workspace.source_directory / "added.py").write_bytes(b"added")
            return result

    try:
        with pytest.raises(SourceSnapshotIntegrityError):
            profile_repository_languages(workspace, inventory, _MutatingClient())
    finally:
        manager.cleanup_workspace(workspace)


def test_large_file_records_incomplete_sample_without_retaining_bytes(tmp_path: Path) -> None:
    content = b"print('sampled')\n" + b"# padding\n" * 1000
    manager, workspace, inventory = _prepared_repository(tmp_path, {"large.py": content})
    client = _FakeClient()
    try:
        profile = profile_repository_languages(
            workspace,
            inventory,
            client,
            policy=SourceLanguageProfilingPolicy(sample_bytes=64),
        )
        assert profile.evidence[0].analyzed_bytes == 64
        assert profile.evidence[0].content_complete is False
        assert content[:64].decode("ascii") not in repr(profile)
        assert not any(
            isinstance(value, bytes)
            for evidence in profile.evidence
            for value in (
                evidence.relative_path,
                evidence.language,
                evidence.candidate_languages,
            )
        )
    finally:
        manager.cleanup_workspace(workspace)


@pytest.mark.skipif(not _LOCAL_HELPER.exists(), reason="local Enry helper is absent")
def test_real_enry_language_profile_pipeline(tmp_path: Path) -> None:
    files = {
        "README.md": b"# SecureScan\n\nRepository documentation.\n",
        "asset.bin": b"\x00\x01\x02\x03",
        "config.yaml": b"enabled: true\n",
        "generated/generated.go": (
            b"// Code generated by SecureScan. DO NOT EDIT.\npackage generated\n"
        ),
        "large.py": b"def large():\n    return True\n" + b"# padding\n" * 300,
        "pkg/example_test.go": b"package example\n",
        "src/app.py": b"def main():\n    return True\n",
        "vendor/example/lib.go": b"package example\n",
        "web/app.js": b"export function main() { return true; }\n",
    }
    manager, workspace, inventory = _prepared_repository(tmp_path, files)
    with _LOCAL_HELPER.open("rb") as helper_stream:
        helper_digest = hashlib.file_digest(helper_stream, "sha256").hexdigest()
    client = EnryClient(
        TrustedEnryHelper(
            helper_path=_LOCAL_HELPER,
            expected_sha256=helper_digest,
        )
    )
    try:
        profile = profile_repository_languages(
            workspace,
            inventory,
            client,
            policy=SourceLanguageProfilingPolicy(sample_bytes=1024),
        )
        evidence = {item.relative_path: item for item in profile.evidence}
        assert evidence["src/app.py"].language == "Python"
        assert evidence["web/app.js"].language == "JavaScript"
        assert evidence["generated/generated.go"].is_generated is True
        assert evidence["vendor/example/lib.go"].is_vendor is True
        assert evidence["pkg/example_test.go"].is_test is True
        assert evidence["config.yaml"].is_configuration is True
        assert evidence["README.md"].is_documentation is True
        assert evidence["large.py"].content_complete is False
        assert profile.skipped_binary_paths == ("asset.bin",)
        assert profile.helper_sha256 == helper_digest
        assert profile.helper_version == "0.2.3"
        assert profile.enry_version == "v2.9.6"
        rendered = repr(profile)
        assert str(tmp_path) not in rendered
        assert str(workspace.source_directory) not in rendered
        assert "def main" not in rendered
    finally:
        manager.cleanup_workspace(workspace)
