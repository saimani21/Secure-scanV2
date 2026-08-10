from __future__ import annotations

import builtins
import hashlib
import os
import subprocess
from dataclasses import FrozenInstanceError, fields
from pathlib import Path

import pytest

from securescan.source import (
    AnalysisCapability,
    EnrichedRepositoryInventory,
    EnryClient,
    FileContentKind,
    RepositoryInventory,
    SourceEnrichmentCorrelationError,
    SourceEnrichmentError,
    SourceFileFlag,
    SourceFileRecord,
    SourceFileRole,
    SourceLanguageEvidence,
    SourceLanguageProfile,
    SourceLanguageProfilingPolicy,
    TrustedEnryHelper,
    build_repository_inventory,
    enrich_repository_inventory,
    profile_repository_languages,
)
from securescan.workspaces import (
    RepositoryManifestEntry,
    RepositoryWorkspaceManager,
)
from securescan.workspaces.models import repository_content_digest

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_LOCAL_HELPER = _PROJECT_ROOT / "tools/enry-helper/bin/securescan-enry-helper"
_HELPER_DIGEST = "a" * 64


def _entry(relative_path: str, content: bytes) -> RepositoryManifestEntry:
    return RepositoryManifestEntry(
        relative_path=relative_path,
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
    )


def _record(
    relative_path: str = "src/app.py",
    content: bytes = b"print('hello')\n",
    *,
    content_kind: FileContentKind = FileContentKind.TEXT,
    role: SourceFileRole = SourceFileRole.SOURCE,
    language: str | None = None,
    component_id: str | None = None,
    flags: tuple[SourceFileFlag, ...] = (),
    eligible_capabilities: tuple[AnalysisCapability, ...] = (
        AnalysisCapability.REPOSITORY_PROFILING,
    ),
) -> SourceFileRecord:
    return SourceFileRecord(
        entry=_entry(relative_path, content),
        content_kind=content_kind,
        role=role,
        language=language,
        component_id=component_id,
        flags=flags,
        eligible_capabilities=eligible_capabilities,
    )


def _binary_record(relative_path: str = "asset.bin") -> SourceFileRecord:
    return _record(
        relative_path,
        b"\x00\x01\x02",
        content_kind=FileContentKind.BINARY,
        role=SourceFileRole.BINARY,
        flags=(SourceFileFlag.BINARY,),
    )


def _inventory(*records: SourceFileRecord) -> RepositoryInventory:
    files = tuple(records)
    return RepositoryInventory(
        repository_digest=repository_content_digest(
            tuple(record.entry for record in files)
        ),
        files=files,
    )


def _evidence(
    relative_path: str = "src/app.py",
    *,
    language: str | None = "Python",
    candidate_languages: tuple[str, ...] | None = None,
    is_binary: bool = False,
    is_vendor: bool = False,
    is_generated: bool = False,
    is_test: bool = False,
    is_configuration: bool = False,
    is_documentation: bool = False,
    is_dot_file: bool = False,
    is_image: bool = False,
    analyzed_bytes: int = 10,
    content_complete: bool = True,
) -> SourceLanguageEvidence:
    if candidate_languages is None:
        candidate_languages = () if language is None else (language,)
    return SourceLanguageEvidence(
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
        analyzed_bytes=analyzed_bytes,
        content_complete=content_complete,
    )


def _profile(
    inventory: RepositoryInventory,
    *,
    evidence: tuple[SourceLanguageEvidence, ...] | None = None,
    skipped_binary_paths: tuple[str, ...] = (),
    repository_digest: str | None = None,
) -> SourceLanguageProfile:
    if evidence is None:
        evidence = tuple(
            _evidence(record.relative_path)
            for record in inventory.files
            if record.relative_path not in skipped_binary_paths
        )
    has_evidence = bool(evidence)
    return SourceLanguageProfile(
        repository_digest=(
            inventory.repository_digest
            if repository_digest is None
            else repository_digest
        ),
        evidence=evidence,
        skipped_binary_paths=skipped_binary_paths,
        helper_sha256=_HELPER_DIGEST if has_evidence else None,
        helper_version="0.2.3" if has_evidence else None,
        enry_version="v2.9.6" if has_evidence else None,
        batch_count=1 if has_evidence else 0,
        duration_ms=5 if has_evidence else 0,
    )


def _unsafe_profile(
    profile: SourceLanguageProfile,
    **overrides: object,
) -> SourceLanguageProfile:
    unsafe = object.__new__(SourceLanguageProfile)
    for field in fields(SourceLanguageProfile):
        object.__setattr__(
            unsafe,
            field.name,
            overrides.get(field.name, getattr(profile, field.name)),
        )
    return unsafe


def test_empty_enriched_inventory_is_valid() -> None:
    digest = repository_content_digest(())
    inventory = RepositoryInventory(repository_digest=digest, files=())
    profile = _profile(inventory, evidence=())

    enriched = enrich_repository_inventory(inventory, profile)

    assert enriched == EnrichedRepositoryInventory(
        repository_digest=digest,
        files=(),
    )
    assert enriched.file_count == 0
    assert enriched.total_bytes == 0


def test_enriched_inventory_requires_files_tuple() -> None:
    with pytest.raises(ValueError, match="Enriched repository inventory is invalid"):
        EnrichedRepositoryInventory(
            repository_digest=repository_content_digest(()),
            files=[],  # type: ignore[arg-type]
        )


def test_enriched_inventory_requires_source_file_records() -> None:
    with pytest.raises(ValueError, match="Enriched repository inventory is invalid"):
        EnrichedRepositoryInventory(
            repository_digest=repository_content_digest(()),
            files=(object(),),  # type: ignore[arg-type]
        )


def test_enriched_inventory_requires_sorted_files() -> None:
    files = (_record("z.py"), _record("a.py"))
    with pytest.raises(ValueError, match="Enriched repository inventory is invalid"):
        EnrichedRepositoryInventory(
            repository_digest=repository_content_digest(
                tuple(file.entry for file in files)
            ),
            files=files,
        )


def test_enriched_inventory_rejects_duplicate_paths() -> None:
    record = _record()
    files = (record, record)
    with pytest.raises(ValueError, match="Enriched repository inventory is invalid"):
        EnrichedRepositoryInventory(
            repository_digest=repository_content_digest(
                tuple(file.entry for file in files)
            ),
            files=files,
        )


@pytest.mark.parametrize(
    "repository_digest",
    ["A" * 64, "a" * 63, "g" * 64, b"a" * 64],
)
def test_enriched_inventory_rejects_malformed_repository_digest(
    repository_digest: object,
) -> None:
    with pytest.raises(ValueError, match="Enriched repository inventory is invalid"):
        EnrichedRepositoryInventory(
            repository_digest=repository_digest,  # type: ignore[arg-type]
            files=(),
        )


def test_enriched_inventory_rejects_digest_files_mismatch() -> None:
    with pytest.raises(
        ValueError,
        match="Enriched repository inventory digest does not match its files",
    ):
        EnrichedRepositoryInventory(
            repository_digest="a" * 64,
            files=(_record(),),
        )


def test_enriched_inventory_rejects_wrong_schema_version() -> None:
    with pytest.raises(ValueError, match="Enriched repository inventory is invalid"):
        EnrichedRepositoryInventory(
            repository_digest=repository_content_digest(()),
            files=(),
            schema_version="0.2.2",
        )


def test_enriched_inventory_has_deterministic_canonical_representation() -> None:
    inventory = _inventory(_record())
    enriched = enrich_repository_inventory(inventory, _profile(inventory))

    assert enriched.canonical_data() == {
        "file_count": 1,
        "files": [enriched.files[0].canonical_data()],
        "repository_digest": inventory.repository_digest,
        "schema_version": "0.2.3",
        "total_bytes": inventory.total_bytes,
    }
    assert enriched.canonical_data() == enriched.canonical_data()


def test_enrichment_digest_is_stable() -> None:
    inventory = _inventory(_record())
    enriched = enrich_repository_inventory(inventory, _profile(inventory))

    assert len(enriched.enrichment_digest()) == 64
    assert enriched.enrichment_digest() == (
        "b26833a840142c57f3cb1fc0f6cfc755"
        "7027eb80d833bf1cb23b5c01a7eb6f48"
    )


def test_different_semantic_content_changes_enrichment_digest() -> None:
    first_inventory = _inventory(_record(content=b"first"))
    second_inventory = _inventory(_record(content=b"second"))

    first = enrich_repository_inventory(first_inventory, _profile(first_inventory))
    second = enrich_repository_inventory(second_inventory, _profile(second_inventory))

    assert first.enrichment_digest() != second.enrichment_digest()


def test_enrichment_digest_uses_distinct_domain_separator() -> None:
    inventory = _inventory(_record())
    enriched = enrich_repository_inventory(inventory, _profile(inventory))

    assert enriched.enrichment_digest() != inventory.inventory_digest()


def test_enriched_inventory_is_immutable() -> None:
    inventory = _inventory(_record())
    enriched = enrich_repository_inventory(inventory, _profile(inventory))

    with pytest.raises(FrozenInstanceError):
        enriched.files = ()  # type: ignore[misc]


@pytest.mark.parametrize("invalid_input", [object(), None])
def test_enrichment_rejects_invalid_input_types(invalid_input: object) -> None:
    inventory = _inventory(_record())
    profile = _profile(inventory)

    with pytest.raises(SourceEnrichmentError, match="Source repository enrichment failed"):
        enrich_repository_inventory(invalid_input, profile)  # type: ignore[arg-type]
    with pytest.raises(SourceEnrichmentError, match="Source repository enrichment failed"):
        enrich_repository_inventory(inventory, invalid_input)  # type: ignore[arg-type]


def test_mismatched_repository_digests_are_rejected() -> None:
    inventory = _inventory(_record())
    profile = _profile(inventory, repository_digest="b" * 64)

    with pytest.raises(SourceEnrichmentCorrelationError):
        enrich_repository_inventory(inventory, profile)


def test_missing_language_evidence_is_rejected() -> None:
    inventory = _inventory(_record("a.py"), _record("b.py"))
    profile = _profile(inventory, evidence=(_evidence("a.py"),))

    with pytest.raises(SourceEnrichmentCorrelationError):
        enrich_repository_inventory(inventory, profile)


def test_extra_language_evidence_is_rejected() -> None:
    inventory = _inventory(_record("a.py"))
    profile = _profile(
        inventory,
        evidence=(_evidence("a.py"), _evidence("extra.py")),
    )

    with pytest.raises(SourceEnrichmentCorrelationError):
        enrich_repository_inventory(inventory, profile)


def test_missing_skipped_binary_path_is_rejected() -> None:
    inventory = _inventory(_binary_record(), _record("src/app.py"))
    profile = _profile(inventory, evidence=(_evidence("src/app.py"),))

    with pytest.raises(SourceEnrichmentCorrelationError):
        enrich_repository_inventory(inventory, profile)


def test_extra_skipped_binary_path_is_rejected() -> None:
    inventory = _inventory(_record("src/app.py"))
    profile = _profile(
        inventory,
        evidence=(_evidence("src/app.py"),),
        skipped_binary_paths=("unexpected.bin",),
    )

    with pytest.raises(SourceEnrichmentCorrelationError):
        enrich_repository_inventory(inventory, profile)


def test_skipped_nonbinary_inventory_path_is_rejected() -> None:
    inventory = _inventory(_record())
    profile = _profile(
        inventory,
        evidence=(),
        skipped_binary_paths=("src/app.py",),
    )

    with pytest.raises(SourceEnrichmentCorrelationError):
        enrich_repository_inventory(inventory, profile)


def test_skipped_binary_without_binary_flag_is_rejected() -> None:
    record = _binary_record()
    object.__setattr__(record, "flags", ())
    inventory = _inventory(record)
    profile = _profile(
        inventory,
        evidence=(),
        skipped_binary_paths=("asset.bin",),
    )

    with pytest.raises(SourceEnrichmentCorrelationError):
        enrich_repository_inventory(inventory, profile)


def test_evidence_and_skipped_paths_cannot_overlap() -> None:
    inventory = _inventory(_record())
    profile = _profile(inventory)
    unsafe = _unsafe_profile(profile, skipped_binary_paths=("src/app.py",))

    with pytest.raises(SourceEnrichmentCorrelationError):
        enrich_repository_inventory(inventory, unsafe)


@pytest.mark.parametrize("group", ["evidence", "skipped_binary_paths"])
def test_duplicate_profile_paths_are_rejected(group: str) -> None:
    record = _record("a.py")
    inventory = _inventory(record)
    profile = _profile(inventory)
    if group == "evidence":
        unsafe = _unsafe_profile(
            profile,
            evidence=(_evidence("a.py"), _evidence("a.py")),
        )
    else:
        binary = _binary_record("asset.bin")
        inventory = _inventory(binary)
        profile = _profile(
            inventory,
            evidence=(),
            skipped_binary_paths=("asset.bin",),
        )
        unsafe = _unsafe_profile(
            profile,
            skipped_binary_paths=("asset.bin", "asset.bin"),
        )

    with pytest.raises(SourceEnrichmentCorrelationError):
        enrich_repository_inventory(inventory, unsafe)


@pytest.mark.parametrize("group", ["evidence", "skipped_binary_paths"])
def test_unsorted_profile_paths_are_rejected(group: str) -> None:
    inventory = _inventory(_record("a.py"), _record("z.py"))
    profile = _profile(inventory)
    if group == "evidence":
        unsafe = _unsafe_profile(
            profile,
            evidence=(_evidence("z.py"), _evidence("a.py")),
        )
    else:
        inventory = _inventory(_binary_record("a.bin"), _binary_record("z.bin"))
        profile = _profile(
            inventory,
            evidence=(),
            skipped_binary_paths=("a.bin", "z.bin"),
        )
        unsafe = _unsafe_profile(
            profile,
            skipped_binary_paths=("z.bin", "a.bin"),
        )

    with pytest.raises(SourceEnrichmentCorrelationError):
        enrich_repository_inventory(inventory, unsafe)


def test_conflicting_preexisting_language_is_rejected() -> None:
    inventory = _inventory(_record(language="Go"))

    with pytest.raises(SourceEnrichmentCorrelationError):
        enrich_repository_inventory(inventory, _profile(inventory))


def test_same_preexisting_language_is_accepted() -> None:
    inventory = _inventory(_record(language="Python"))

    enriched = enrich_repository_inventory(inventory, _profile(inventory))

    assert enriched.files[0].language == "Python"


@pytest.mark.parametrize("language", ["Python", "Go", "JavaScript"])
def test_language_is_applied(language: str) -> None:
    inventory = _inventory(_record())
    profile = _profile(inventory, evidence=(_evidence(language=language),))

    enriched = enrich_repository_inventory(inventory, profile)

    assert enriched.files[0].language == language


def test_unknown_language_remains_none() -> None:
    inventory = _inventory(_record())
    profile = _profile(inventory, evidence=(_evidence(language=None),))

    assert enrich_repository_inventory(inventory, profile).files[0].language is None


def test_candidate_languages_are_not_copied_to_source_file_record() -> None:
    inventory = _inventory(_record())
    profile = _profile(
        inventory,
        evidence=(
            _evidence(
                language="C",
                candidate_languages=("C", "C++"),
            ),
        ),
    )

    enriched = enrich_repository_inventory(inventory, profile)

    assert enriched.files[0].language == "C"
    assert "candidate_languages" not in enriched.files[0].canonical_data()


@pytest.mark.parametrize(
    ("evidence_field", "expected_flag"),
    [
        ("is_generated", SourceFileFlag.GENERATED),
        ("is_vendor", SourceFileFlag.VENDORED),
        ("is_test", SourceFileFlag.TEST),
    ],
)
def test_direct_evidence_flags_are_added(
    evidence_field: str,
    expected_flag: SourceFileFlag,
) -> None:
    inventory = _inventory(_record())
    profile = _profile(
        inventory,
        evidence=(_evidence(**{evidence_field: True}),),
    )

    assert expected_flag in enrich_repository_inventory(inventory, profile).files[0].flags


def test_multiple_direct_flags_are_merged_deterministically() -> None:
    inventory = _inventory(_record())
    profile = _profile(
        inventory,
        evidence=(
            _evidence(is_generated=True, is_vendor=True, is_test=True),
        ),
    )

    flags = enrich_repository_inventory(inventory, profile).files[0].flags

    assert flags == (
        SourceFileFlag.GENERATED,
        SourceFileFlag.TEST,
        SourceFileFlag.VENDORED,
    )


def test_existing_flags_are_preserved() -> None:
    inventory = _inventory(_record(flags=(SourceFileFlag.UNSUPPORTED,)))
    profile = _profile(inventory, evidence=(_evidence(is_generated=True),))

    assert enrich_repository_inventory(inventory, profile).files[0].flags == (
        SourceFileFlag.GENERATED,
        SourceFileFlag.UNSUPPORTED,
    )


def test_duplicate_flags_are_impossible() -> None:
    inventory = _inventory(_record(flags=(SourceFileFlag.GENERATED,)))
    profile = _profile(inventory, evidence=(_evidence(is_generated=True),))

    flags = enrich_repository_inventory(inventory, profile).files[0].flags

    assert flags == (SourceFileFlag.GENERATED,)


def test_unsupported_flag_remains_unchanged() -> None:
    inventory = _inventory(_record(flags=(SourceFileFlag.UNSUPPORTED,)))

    enriched = enrich_repository_inventory(inventory, _profile(inventory))

    assert SourceFileFlag.UNSUPPORTED in enriched.files[0].flags


def test_false_evidence_flags_do_not_remove_existing_flags() -> None:
    inventory = _inventory(
        _record(
            flags=(
                SourceFileFlag.GENERATED,
                SourceFileFlag.TEST,
                SourceFileFlag.VENDORED,
            )
        )
    )

    enriched = enrich_repository_inventory(inventory, _profile(inventory))

    assert enriched.files[0].flags == inventory.files[0].flags


def test_inventory_file_facts_are_preserved_exactly() -> None:
    record = _record(
        content_kind=FileContentKind.TEXT,
        role=SourceFileRole.CONFIGURATION,
        component_id="component",
        flags=(SourceFileFlag.UNSUPPORTED,),
        eligible_capabilities=(
            AnalysisCapability.PACKAGE_INVENTORY,
            AnalysisCapability.REPOSITORY_PROFILING,
        ),
    )
    inventory = _inventory(record)
    profile = _profile(inventory, evidence=(_evidence(is_generated=True),))

    enriched = enrich_repository_inventory(inventory, profile)
    result = enriched.files[0]

    assert result is not record
    assert result.entry is record.entry
    assert result.entry.sha256 == record.entry.sha256
    assert result.entry.size_bytes == record.entry.size_bytes
    assert result.content_kind is record.content_kind
    assert result.role is record.role
    assert result.component_id == record.component_id
    assert result.eligible_capabilities is record.eligible_capabilities
    assert enriched.repository_digest == inventory.repository_digest


@pytest.mark.parametrize(
    "evidence_field",
    ["is_configuration", "is_documentation", "is_dot_file", "is_image"],
)
def test_evidence_only_role_facts_do_not_change_role(evidence_field: str) -> None:
    inventory = _inventory(_record(role=SourceFileRole.OTHER))
    profile = _profile(
        inventory,
        evidence=(_evidence(**{evidence_field: True}),),
    )

    assert enrich_repository_inventory(inventory, profile).files[0].role is SourceFileRole.OTHER


def test_enry_binary_disagreement_does_not_rewrite_inventory_binary_facts() -> None:
    inventory = _inventory(_record(content_kind=FileContentKind.TEXT))
    profile = _profile(
        inventory,
        evidence=(_evidence(language=None, is_binary=True),),
    )

    result = enrich_repository_inventory(inventory, profile).files[0]

    assert result.content_kind is FileContentKind.TEXT
    assert SourceFileFlag.BINARY not in result.flags


def test_sampling_metadata_is_not_copied_to_source_file_record() -> None:
    inventory = _inventory(_record())
    profile = _profile(
        inventory,
        evidence=(
            _evidence(analyzed_bytes=4, content_complete=False),
        ),
    )

    canonical = enrich_repository_inventory(inventory, profile).files[0].canonical_data()

    assert "analyzed_bytes" not in canonical
    assert "content_complete" not in canonical


def test_enrichment_does_not_mutate_inputs() -> None:
    inventory = _inventory(_record())
    profile = _profile(inventory, evidence=(_evidence(is_generated=True),))
    inventory_before = inventory.canonical_data()
    profile_before = repr(profile)
    inventory_files = inventory.files
    profile_evidence = profile.evidence

    enrich_repository_inventory(inventory, profile)

    assert inventory.canonical_data() == inventory_before
    assert repr(profile) == profile_before
    assert inventory.files is inventory_files
    assert profile.evidence is profile_evidence


def test_repeated_enrichment_is_equal_and_has_equal_digest() -> None:
    inventory = _inventory(_record())
    profile = _profile(inventory, evidence=(_evidence(is_test=True),))

    first = enrich_repository_inventory(inventory, profile)
    second = enrich_repository_inventory(inventory, profile)

    assert first == second
    assert first.enrichment_digest() == second.enrichment_digest()


def test_enrichment_preserves_deterministic_file_order() -> None:
    inventory = _inventory(_record("a.py"), _record("z.py"))

    enriched = enrich_repository_inventory(inventory, _profile(inventory))

    assert tuple(file.relative_path for file in enriched.files) == ("a.py", "z.py")


def test_enrichment_has_no_filesystem_process_or_enry_side_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventory = _inventory(_record())
    profile = _profile(inventory)

    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("external operation attempted")

    monkeypatch.setattr(builtins, "open", fail)
    monkeypatch.setattr(os, "open", fail)
    monkeypatch.setattr(Path, "open", fail)
    monkeypatch.setattr(Path, "read_bytes", fail)
    monkeypatch.setattr(Path, "read_text", fail)
    monkeypatch.setattr(subprocess, "Popen", fail)
    monkeypatch.setattr(subprocess, "run", fail)
    monkeypatch.setattr(EnryClient, "classify", fail)

    assert enrich_repository_inventory(inventory, profile).file_count == 1


def test_enriched_inventory_retains_no_source_bytes_or_absolute_paths() -> None:
    sensitive = b"private source content"
    inventory = _inventory(_record(content=sensitive))
    enriched = enrich_repository_inventory(inventory, _profile(inventory))
    rendered = repr(enriched)

    assert sensitive.decode("ascii") not in rendered
    assert not any(
        isinstance(value, bytes)
        for file in enriched.files
        for value in (
            file.entry.relative_path,
            file.entry.sha256,
            file.language,
        )
    )
    assert all(not file.relative_path.startswith("/") for file in enriched.files)


def test_correlation_errors_are_fixed_and_sanitized() -> None:
    inventory = _inventory(_record("src/app.py"))
    sensitive_path = "private/workspace/secret.py"
    profile = _profile(
        inventory,
        evidence=(_evidence(sensitive_path), _evidence("src/app.py")),
    )

    with pytest.raises(SourceEnrichmentCorrelationError) as raised:
        enrich_repository_inventory(inventory, profile)

    assert str(raised.value) == "Source repository enrichment correlation failed"
    assert sensitive_path not in str(raised.value)
    assert inventory.repository_digest not in str(raised.value)


@pytest.mark.skipif(not _LOCAL_HELPER.exists(), reason="local Enry helper is absent")
def test_real_enry_repository_enrichment_pipeline(tmp_path: Path) -> None:
    source = tmp_path / "repository"
    files = {
        "asset.bin": b"\x00\x01\x02\x03",
        "generated/generated.go": (
            b"// Code generated by SecureScan. DO NOT EDIT.\npackage generated\n"
        ),
        "pkg/example_test.go": b"package example\n",
        "src/app.py": b"def main():\n    return True\n",
        "vendor/example/lib.go": b"package example\n",
    }
    for relative_path, content in files.items():
        path = source / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    manager = RepositoryWorkspaceManager(tmp_path / "managed")
    workspace = manager.prepare_repository(source)
    with _LOCAL_HELPER.open("rb") as helper_stream:
        helper_digest = hashlib.file_digest(helper_stream, "sha256").hexdigest()
    client = EnryClient(
        TrustedEnryHelper(
            helper_path=_LOCAL_HELPER,
            expected_sha256=helper_digest,
        )
    )

    try:
        inventory = build_repository_inventory(workspace)
        profile = profile_repository_languages(
            workspace,
            inventory,
            client,
            policy=SourceLanguageProfilingPolicy(sample_bytes=1024),
        )
        enriched = enrich_repository_inventory(inventory, profile)
        input_files = {file.relative_path: file for file in inventory.files}
        output_files = {file.relative_path: file for file in enriched.files}

        assert output_files["src/app.py"].language == "Python"
        assert output_files["generated/generated.go"].language == "Go"
        assert SourceFileFlag.GENERATED in output_files["generated/generated.go"].flags
        assert output_files["vendor/example/lib.go"].language == "Go"
        assert SourceFileFlag.VENDORED in output_files["vendor/example/lib.go"].flags
        assert output_files["pkg/example_test.go"].language == "Go"
        assert SourceFileFlag.TEST in output_files["pkg/example_test.go"].flags
        assert output_files["asset.bin"] == input_files["asset.bin"]
        assert output_files["asset.bin"] is not input_files["asset.bin"]
        assert all(
            output_files[path].component_id == input_files[path].component_id
            for path in output_files
        )
        assert all(
            output_files[path].eligible_capabilities
            == input_files[path].eligible_capabilities
            for path in output_files
        )
        assert not hasattr(enriched, "components")
        assert not hasattr(enriched, "languages")
        assert not hasattr(enriched, "surfaces")
        assert not hasattr(enriched, "support_state")
    finally:
        manager.cleanup_workspace(workspace)
