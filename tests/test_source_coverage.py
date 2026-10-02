from __future__ import annotations

import builtins
import hashlib
import os
import socket
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
import sqlalchemy

from securescan.adapters.fake_scanner import FakeScannerAdapter
from securescan.execution import DockerSandboxExecutor
from securescan.scanners.semgrep.adapter import SemgrepScannerAdapter
from securescan.source import (
    AnalysisCapability,
    CapabilitySupportRule,
    ComponentizedRepositoryInventory,
    EnrichedRepositoryInventory,
    EnryClient,
    FileContentKind,
    InvalidSourceCoverageRequestError,
    LanguageSupportRule,
    RepositoryComponent,
    RepositoryProfile,
    SourceCoverageCorrelationError,
    SourceFileFlag,
    SourceFileRecord,
    SourceFileRole,
    SourceLanguageProfilingPolicy,
    SourceSupportPolicy,
    SourceSupportState,
    TrustedEnryHelper,
    assess_repository_language_support,
    build_repository_inventory,
    build_repository_profile,
    detect_repository_components,
    enrich_repository_inventory,
    profile_repository_languages,
)
from securescan.workspaces import RepositoryManifestEntry, RepositoryWorkspaceManager
from securescan.workspaces.models import repository_content_digest

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_LOCAL_HELPER = _PROJECT_ROOT / "tools/enry-helper/bin/securescan-enry-helper"
_PROFILE_GOLDEN_DIGEST = "6ab9b48c1b4024e4b8e7cdcb2332b0938969d41c6e521a6727aa464485d88c01"


def _entry(relative_path: str, content: bytes) -> RepositoryManifestEntry:
    return RepositoryManifestEntry(
        relative_path=relative_path,
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
    )


def _record(
    relative_path: str,
    *,
    language: str | None = None,
    role: SourceFileRole = SourceFileRole.SOURCE,
    content_kind: FileContentKind = FileContentKind.TEXT,
    flags: tuple[SourceFileFlag, ...] = (),
    component_id: str | None = None,
    eligible_capabilities: tuple[AnalysisCapability, ...] = (
        AnalysisCapability.REPOSITORY_PROFILING,
    ),
    content: bytes = b"content\n",
) -> SourceFileRecord:
    return SourceFileRecord(
        entry=_entry(relative_path, content),
        content_kind=content_kind,
        role=role,
        language=language,
        component_id=component_id,
        flags=tuple(sorted(flags, key=lambda flag: flag.value)),
        eligible_capabilities=tuple(
            sorted(
                eligible_capabilities,
                key=lambda capability: capability.value,
            )
        ),
    )


def _component(
    component_id: str,
    root_path: str,
) -> RepositoryComponent:
    return RepositoryComponent(
        component_id=component_id,
        display_name=root_path,
        root_path=root_path,
    )


def _componentized(
    *records: SourceFileRecord,
    components: tuple[RepositoryComponent, ...] = (),
) -> ComponentizedRepositoryInventory:
    files = tuple(sorted(records, key=lambda record: record.relative_path))
    return ComponentizedRepositoryInventory(
        repository_digest=repository_content_digest(tuple(record.entry for record in files)),
        files=files,
        components=tuple(sorted(components, key=lambda component: component.component_id)),
    )


def _enriched(*records: SourceFileRecord) -> EnrichedRepositoryInventory:
    files = tuple(sorted(records, key=lambda record: record.relative_path))
    return EnrichedRepositoryInventory(
        repository_digest=repository_content_digest(tuple(record.entry for record in files)),
        files=files,
    )


def _reason(prefix: str, state: SourceSupportState) -> str | None:
    return f"{prefix}_UNSUPPORTED" if state is SourceSupportState.UNSUPPORTED else None


def _policy(
    *,
    language_states: dict[str, SourceSupportState] | None = None,
    capability_states: dict[AnalysisCapability, SourceSupportState] | None = None,
) -> SourceSupportPolicy:
    return SourceSupportPolicy(
        language_rules=tuple(
            sorted(
                (
                    LanguageSupportRule(
                        language,
                        state,
                        _reason("LANGUAGE", state),
                    )
                    for language, state in (language_states or {}).items()
                ),
                key=lambda rule: rule.language.casefold(),
            )
        ),
        capability_rules=tuple(
            sorted(
                (
                    CapabilitySupportRule(
                        capability,
                        state,
                        _reason("CAPABILITY", state),
                    )
                    for capability, state in (capability_states or {}).items()
                ),
                key=lambda rule: rule.capability.value,
            )
        ),
    )


def _build(
    inventory: ComponentizedRepositoryInventory,
    policy: SourceSupportPolicy | None = None,
) -> RepositoryProfile:
    selected_policy = policy or SourceSupportPolicy(
        language_rules=(
            LanguageSupportRule("JavaScript", SourceSupportState.SCANNABLE),
            LanguageSupportRule("Python", SourceSupportState.SCANNABLE),
            LanguageSupportRule("TypeScript", SourceSupportState.SCANNABLE),
        ),
        capability_rules=(
            CapabilitySupportRule(
                AnalysisCapability.SOURCE_SAST,
                SourceSupportState.SCANNABLE,
            ),
        ),
    )
    assessment = assess_repository_language_support(inventory, selected_policy)
    return build_repository_profile(inventory, assessment, selected_policy)


def _files(profile: RepositoryProfile) -> dict[str, SourceFileRecord]:
    return {file.relative_path: file for file in profile.files}


def _surfaces(
    profile: RepositoryProfile,
    capability: AnalysisCapability,
) -> tuple[object, ...]:
    return tuple(surface for surface in profile.surfaces if surface.capability is capability)


@pytest.mark.parametrize(
    ("inventory", "assessment", "policy"),
    [
        (object(), None, None),
        (None, object(), None),
        (None, None, object()),
    ],
)
def test_invalid_request_types_are_rejected(
    inventory: object,
    assessment: object,
    policy: object,
) -> None:
    valid_inventory = _componentized()
    valid_policy = SourceSupportPolicy()
    valid_assessment = assess_repository_language_support(
        valid_inventory,
        valid_policy,
    )

    with pytest.raises(InvalidSourceCoverageRequestError) as raised:
        build_repository_profile(
            valid_inventory if inventory is None else inventory,  # type: ignore[arg-type]
            valid_assessment if assessment is None else assessment,  # type: ignore[arg-type]
            valid_policy if policy is None else policy,  # type: ignore[arg-type]
        )

    assert str(raised.value) == "Source coverage request is invalid"


def test_repository_digest_mismatch_is_rejected_without_leakage() -> None:
    inventory = _componentized(_record("private/app.py", language="Python"))
    policy = SourceSupportPolicy()
    assessment = replace(
        assess_repository_language_support(inventory, policy),
        repository_digest="a" * 64,
    )

    with pytest.raises(SourceCoverageCorrelationError) as raised:
        build_repository_profile(inventory, assessment, policy)

    assert str(raised.value) == "Source coverage correlation failed"
    assert "private" not in str(raised.value)
    assert inventory.repository_digest not in str(raised.value)


def test_policy_digest_mismatch_is_rejected() -> None:
    inventory = _componentized()
    policy = SourceSupportPolicy()
    assessment = replace(
        assess_repository_language_support(inventory, policy),
        policy_digest="a" * 64,
    )

    with pytest.raises(SourceCoverageCorrelationError):
        build_repository_profile(inventory, assessment, policy)


def test_stale_or_fabricated_language_assessment_is_rejected() -> None:
    inventory = _componentized(_record("app.py", language="Python"))
    policy = SourceSupportPolicy()
    assessment = assess_repository_language_support(inventory, policy)
    fabricated_decision = replace(assessment.languages[0], file_count=2)
    fabricated = replace(assessment, languages=(fabricated_decision,))

    with pytest.raises(SourceCoverageCorrelationError):
        build_repository_profile(inventory, fabricated, policy)


@pytest.mark.parametrize(
    ("role", "flags"),
    [
        (SourceFileRole.SOURCE, ()),
        (SourceFileRole.SOURCE, (SourceFileFlag.TEST,)),
        (SourceFileRole.SOURCE, (SourceFileFlag.GENERATED,)),
        (SourceFileRole.SOURCE, (SourceFileFlag.VENDORED,)),
        (SourceFileRole.MANIFEST, ()),
    ],
)
def test_python_text_applicability_is_broad_and_role_independent(
    role: SourceFileRole,
    flags: tuple[SourceFileFlag, ...],
) -> None:
    inventory = _componentized(_record("setup.py", language="Python", role=role, flags=flags))

    result = _build(inventory).files[0]

    assert AnalysisCapability.SOURCE_SAST in result.eligible_capabilities


@pytest.mark.parametrize(
    "content_kind",
    [FileContentKind.UNKNOWN, FileContentKind.BINARY],
)
def test_python_non_text_does_not_gain_sast(
    content_kind: FileContentKind,
) -> None:
    is_binary = content_kind is FileContentKind.BINARY
    inventory = _componentized(
        _record(
            "app.py",
            language="Python",
            role=SourceFileRole.BINARY if is_binary else SourceFileRole.SOURCE,
            content_kind=content_kind,
            flags=(SourceFileFlag.BINARY,) if is_binary else (),
        )
    )

    result = _build(inventory).files[0]

    assert AnalysisCapability.SOURCE_SAST not in result.eligible_capabilities


@pytest.mark.parametrize("language", ["Go", None])
def test_unsupported_or_unknown_language_does_not_gain_sast(
    language: str | None,
) -> None:
    result = _build(_componentized(_record("app.txt", language=language))).files[0]

    assert AnalysisCapability.SOURCE_SAST not in result.eligible_capabilities


@pytest.mark.parametrize(
    ("language", "path"),
    [
        ("JavaScript", "app.js"),
        ("JavaScript", "component.jsx"),
        ("TypeScript", "app.ts"),
        ("TypeScript", "component.tsx"),
    ],
)
def test_javascript_and_typescript_text_sources_gain_source_sast(
    language: str,
    path: str,
) -> None:
    result = _build(_componentized(_record(path, language=language))).files[0]

    assert AnalysisCapability.SOURCE_SAST in result.eligible_capabilities


def test_python_matching_is_case_insensitive_without_normalizing_language() -> None:
    result = _build(_componentized(_record("app.py", language="pYtHoN"))).files[0]

    assert result.language == "pYtHoN"
    assert AnalysisCapability.SOURCE_SAST in result.eligible_capabilities


def test_existing_capabilities_are_preserved_sorted_and_unique() -> None:
    inventory = _componentized(
        _record(
            "app.py",
            language="Python",
            eligible_capabilities=(
                AnalysisCapability.SECRET_DETECTION,
                AnalysisCapability.REPOSITORY_PROFILING,
            ),
        )
    )

    capabilities = _build(inventory).files[0].eligible_capabilities

    assert set(capabilities) == {
        AnalysisCapability.REPOSITORY_PROFILING,
        AnalysisCapability.SOURCE_SAST,
        AnalysisCapability.SECRET_DETECTION,
    }
    assert capabilities == tuple(sorted(capabilities, key=lambda item: item.value))
    assert len(capabilities) == len(set(capabilities))


def test_profile_preserves_every_v024_file_fact_and_component_tuple() -> None:
    component = _component("component-root", ".")
    original = _record(
        "src/app.py",
        language="Python",
        role=SourceFileRole.SOURCE,
        flags=(SourceFileFlag.GENERATED, SourceFileFlag.TEST),
        component_id=component.component_id,
        content=b"print('sensitive')\n",
    )
    inventory = _componentized(original, components=(component,))

    profile = _build(inventory)
    result = profile.files[0]

    assert result is not original
    assert result.entry is original.entry
    assert result.entry.sha256 == original.entry.sha256
    assert result.entry.size_bytes == original.entry.size_bytes
    assert result.content_kind is original.content_kind
    assert result.role is original.role
    assert result.language == original.language
    assert result.component_id == original.component_id
    assert result.flags is original.flags
    assert profile.repository_digest == inventory.repository_digest
    assert profile.components is inventory.components
    assert profile.components == inventory.components


def test_build_does_not_mutate_inventory_assessment_or_policy() -> None:
    inventory = _componentized(_record("app.py", language="Python"))
    policy = SourceSupportPolicy()
    assessment = assess_repository_language_support(inventory, policy)
    inventory_before = inventory.canonical_data()
    assessment_before = assessment.canonical_data()
    policy_before = policy.canonical_data()

    build_repository_profile(inventory, assessment, policy)

    assert inventory.canonical_data() == inventory_before
    assert assessment.canonical_data() == assessment_before
    assert policy.canonical_data() == policy_before


def test_repository_profiling_surface_always_exists_and_spans_all_files() -> None:
    inventory = _componentized(
        _record("a.py", language="Python"),
        _record("z.bin", content_kind=FileContentKind.BINARY, flags=(SourceFileFlag.BINARY,)),
    )

    surface = _surfaces(
        _build(inventory),
        AnalysisCapability.REPOSITORY_PROFILING,
    )[0]

    assert surface.component_id is None
    assert surface.eligible_paths == ("a.py", "z.bin")
    assert surface.support_state is SourceSupportState.DETECTED


def test_empty_repository_still_has_repository_profiling_surface() -> None:
    profile = _build(_componentized())
    surfaces = _surfaces(profile, AnalysisCapability.REPOSITORY_PROFILING)

    assert len(surfaces) == 1
    assert surfaces[0].component_id is None
    assert surfaces[0].eligible_paths == ()


def test_secret_surface_uses_existing_applicability_and_spans_components() -> None:
    components = (
        _component("component-a", "a"),
        _component("component-b", "b"),
    )
    secret_capabilities = (
        AnalysisCapability.REPOSITORY_PROFILING,
        AnalysisCapability.SECRET_DETECTION,
    )
    inventory = _componentized(
        _record(
            "a/app.py",
            component_id="component-a",
            eligible_capabilities=secret_capabilities,
        ),
        _record(
            "b/app.js",
            component_id="component-b",
            eligible_capabilities=secret_capabilities,
        ),
        _record(
            "b/unknown.data",
            content_kind=FileContentKind.UNKNOWN,
            component_id="component-b",
        ),
        _record(
            "binary.bin",
            role=SourceFileRole.BINARY,
            content_kind=FileContentKind.BINARY,
            flags=(SourceFileFlag.BINARY,),
        ),
        components=components,
    )

    surfaces = _surfaces(_build(inventory), AnalysisCapability.SECRET_DETECTION)

    assert len(surfaces) == 1
    assert surfaces[0].component_id is None
    assert surfaces[0].eligible_paths == ("a/app.py", "b/app.js")


def test_secret_surface_is_absent_without_applicable_files() -> None:
    assert not _surfaces(
        _build(_componentized(_record("unknown.data", content_kind=FileContentKind.UNKNOWN))),
        AnalysisCapability.SECRET_DETECTION,
    )


def test_python_sast_surface_spans_components_and_retains_flagged_files() -> None:
    components = (
        _component("component-a", "a"),
        _component("component-b", "b"),
    )
    inventory = _componentized(
        _record(
            "a/generated.py",
            language="Python",
            component_id="component-a",
            flags=(SourceFileFlag.GENERATED,),
        ),
        _record(
            "b/test_app.py",
            language="Python",
            component_id="component-b",
            flags=(SourceFileFlag.TEST, SourceFileFlag.VENDORED),
        ),
        components=components,
    )

    surface = _surfaces(_build(inventory), AnalysisCapability.SOURCE_SAST)[0]

    assert surface.component_id is None
    assert surface.eligible_paths == ("a/generated.py", "b/test_app.py")


def test_source_sast_surface_absent_without_applicability() -> None:
    assert not _surfaces(
        _build(_componentized(_record("app.go", language="Go"))),
        AnalysisCapability.SOURCE_SAST,
    )


def test_unsupported_python_surface_hides_paths_but_preserves_applicability() -> None:
    policy = _policy(
        language_states={"Python": SourceSupportState.SCANNABLE},
        capability_states={
            AnalysisCapability.SOURCE_SAST: SourceSupportState.UNSUPPORTED,
        },
    )

    profile = _build(
        _componentized(_record("app.py", language="Python")),
        policy,
    )
    surface = _surfaces(profile, AnalysisCapability.SOURCE_SAST)[0]

    assert AnalysisCapability.SOURCE_SAST in profile.files[0].eligible_capabilities
    assert surface.support_state is SourceSupportState.UNSUPPORTED
    assert surface.eligible_paths == ()
    assert surface.reason_code == "CAPABILITY_UNSUPPORTED"


def test_policy_rule_alone_does_not_create_nonprofiling_surface() -> None:
    policy = _policy(
        capability_states={
            AnalysisCapability.DOCKERFILE_POLICY: SourceSupportState.SCANNABLE,
        }
    )

    assert not _surfaces(
        _build(_componentized(), policy),
        AnalysisCapability.DOCKERFILE_POLICY,
    )


@pytest.mark.parametrize(
    "capability",
    [
        AnalysisCapability.PACKAGE_INVENTORY,
        AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING,
        AnalysisCapability.TERRAFORM_SOURCE_POLICY,
        AnalysisCapability.DOCKERFILE_POLICY,
    ],
)
def test_component_capabilities_group_by_component_and_orphan(
    capability: AnalysisCapability,
) -> None:
    components = (
        _component("component-a", "a"),
        _component("component-b", "b"),
    )
    applicable = (
        capability,
        AnalysisCapability.REPOSITORY_PROFILING,
    )
    inventory = _componentized(
        _record(
            "a/one",
            component_id="component-a",
            eligible_capabilities=applicable,
        ),
        _record(
            "a/two",
            component_id="component-a",
            eligible_capabilities=applicable,
        ),
        _record(
            "b/one",
            component_id="component-b",
            eligible_capabilities=applicable,
        ),
        _record("orphan", eligible_capabilities=applicable),
        components=components,
    )

    surfaces = _surfaces(_build(inventory), capability)

    assert tuple(surface.component_id for surface in surfaces) == (
        None,
        "component-a",
        "component-b",
    )
    assert surfaces[0].eligible_paths == ("orphan",)
    assert surfaces[1].eligible_paths == ("a/one", "a/two")
    assert surfaces[2].eligible_paths == ("b/one",)


def test_package_inventory_uses_only_preexisting_manifest_and_lock_applicability() -> None:
    applicable = (
        AnalysisCapability.PACKAGE_INVENTORY,
        AnalysisCapability.REPOSITORY_PROFILING,
    )
    inventory = _componentized(
        _record(
            "package.json",
            role=SourceFileRole.MANIFEST,
            eligible_capabilities=applicable,
        ),
        _record(
            "package-lock.json",
            role=SourceFileRole.LOCKFILE,
            eligible_capabilities=applicable,
        ),
    )

    surface = _surfaces(_build(inventory), AnalysisCapability.PACKAGE_INVENTORY)[0]

    assert surface.eligible_paths == ("package-lock.json", "package.json")


def test_advisory_surface_does_not_expand_manifest_applicability() -> None:
    inventory = _componentized(
        _record(
            "package-lock.json",
            role=SourceFileRole.LOCKFILE,
            eligible_capabilities=(
                AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING,
                AnalysisCapability.REPOSITORY_PROFILING,
            ),
        ),
        _record(
            "package.json",
            role=SourceFileRole.MANIFEST,
            eligible_capabilities=(
                AnalysisCapability.PACKAGE_INVENTORY,
                AnalysisCapability.REPOSITORY_PROFILING,
            ),
        ),
    )

    profile = _build(inventory)
    surface = _surfaces(
        profile,
        AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING,
    )[0]

    assert surface.eligible_paths == ("package-lock.json",)
    assert not hasattr(profile, "resolved_dependency_versions")


def test_nested_terraform_components_remain_separate_without_parsing() -> None:
    components = (
        _component("component-infra", "infra"),
        _component("component-module", "infra/modules/db"),
    )
    applicable = (
        AnalysisCapability.REPOSITORY_PROFILING,
        AnalysisCapability.TERRAFORM_SOURCE_POLICY,
    )
    inventory = _componentized(
        _record(
            "infra/main.tf",
            role=SourceFileRole.TERRAFORM,
            component_id="component-infra",
            eligible_capabilities=applicable,
        ),
        _record(
            "infra/variables.tf",
            role=SourceFileRole.TERRAFORM,
            component_id="component-infra",
            eligible_capabilities=applicable,
        ),
        _record(
            "infra/modules/db/main.tf",
            role=SourceFileRole.TERRAFORM,
            component_id="component-module",
            eligible_capabilities=applicable,
        ),
        components=components,
    )

    surfaces = _surfaces(_build(inventory), AnalysisCapability.TERRAFORM_SOURCE_POLICY)

    assert len(surfaces) == 2
    assert surfaces[0].eligible_paths == ("infra/main.tf", "infra/variables.tf")
    assert surfaces[1].eligible_paths == ("infra/modules/db/main.tf",)


def test_dockerfile_surface_uses_membership_without_build_context_inference() -> None:
    component = _component("component-service", "service")
    applicable = (
        AnalysisCapability.DOCKERFILE_POLICY,
        AnalysisCapability.REPOSITORY_PROFILING,
    )
    inventory = _componentized(
        _record(
            "service/Dockerfile",
            role=SourceFileRole.DOCKERFILE,
            component_id=component.component_id,
            eligible_capabilities=applicable,
        ),
        _record(
            "Dockerfile",
            role=SourceFileRole.DOCKERFILE,
            eligible_capabilities=applicable,
        ),
        components=(component,),
    )

    surfaces = _surfaces(_build(inventory), AnalysisCapability.DOCKERFILE_POLICY)

    assert tuple(surface.component_id for surface in surfaces) == (
        None,
        component.component_id,
    )
    assert not hasattr(surfaces[0], "build_context")


@pytest.mark.parametrize(
    "capability",
    [
        AnalysisCapability.PACKAGE_INVENTORY,
        AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING,
        AnalysisCapability.TERRAFORM_SOURCE_POLICY,
        AnalysisCapability.DOCKERFILE_POLICY,
    ],
)
def test_component_capability_surface_absent_when_not_applicable(
    capability: AnalysisCapability,
) -> None:
    assert not _surfaces(_build(_componentized()), capability)


@pytest.mark.parametrize("support_state", tuple(SourceSupportState))
def test_surface_support_state_comes_only_from_policy(
    support_state: SourceSupportState,
) -> None:
    capability = AnalysisCapability.SECRET_DETECTION
    policy = _policy(capability_states={capability: support_state})
    inventory = _componentized(
        _record(
            "app.py",
            eligible_capabilities=(
                AnalysisCapability.REPOSITORY_PROFILING,
                capability,
            ),
        )
    )

    surface = _surfaces(_build(inventory, policy), capability)[0]

    assert surface.support_state is support_state
    assert surface.reason_code == _reason("CAPABILITY", support_state)
    if support_state is SourceSupportState.UNSUPPORTED:
        assert surface.eligible_paths == ()
    else:
        assert surface.eligible_paths == ("app.py",)


def test_unsupported_component_capability_keeps_each_detected_group() -> None:
    capability = AnalysisCapability.TERRAFORM_SOURCE_POLICY
    components = (
        _component("component-a", "a"),
        _component("component-b", "b"),
    )
    applicable = (
        AnalysisCapability.REPOSITORY_PROFILING,
        capability,
    )
    inventory = _componentized(
        _record("a/main.tf", component_id="component-a", eligible_capabilities=applicable),
        _record("b/main.tf", component_id="component-b", eligible_capabilities=applicable),
        components=components,
    )
    policy = _policy(capability_states={capability: SourceSupportState.UNSUPPORTED})

    surfaces = _surfaces(_build(inventory, policy), capability)

    assert tuple(surface.component_id for surface in surfaces) == (
        "component-a",
        "component-b",
    )
    assert all(surface.eligible_paths == () for surface in surfaces)
    assert all(surface.reason_code == "CAPABILITY_UNSUPPORTED" for surface in surfaces)


def test_surface_state_is_unaffected_by_file_count() -> None:
    capability = AnalysisCapability.SECRET_DETECTION
    policy = _policy(capability_states={capability: SourceSupportState.SCANNABLE})
    applicable = (
        AnalysisCapability.REPOSITORY_PROFILING,
        capability,
    )
    one = _componentized(_record("a", eligible_capabilities=applicable))
    two = _componentized(
        _record("a", eligible_capabilities=applicable),
        _record("b", eligible_capabilities=applicable),
    )

    assert _surfaces(_build(one, policy), capability)[0].support_state is (
        _surfaces(_build(two, policy), capability)[0].support_state
    )


@pytest.mark.parametrize("support_state", tuple(SourceSupportState))
def test_language_support_conversion_uses_explicit_executable_states(
    support_state: SourceSupportState,
) -> None:
    inventory = _componentized(
        _record("app.py", language="Python"),
        _record(
            "setup.py",
            language="Python",
            role=SourceFileRole.MANIFEST,
        ),
    )
    policy = _policy(language_states={"Python": support_state})

    language = _build(inventory, policy).languages[0]

    expected_eligible = (
        1
        if support_state
        in {
            SourceSupportState.SCANNABLE,
            SourceSupportState.BENCHMARKED,
            SourceSupportState.PRODUCT_SUPPORTED,
        }
        else 0
    )
    assert language.file_count == 2
    assert language.eligible_file_count == expected_eligible
    assert language.support_state is support_state
    assert language.reason_code == _reason("LANGUAGE", support_state)


def test_generated_and_test_source_files_still_count_as_language_eligible() -> None:
    inventory = _componentized(
        _record(
            "generated.py",
            language="Python",
            flags=(SourceFileFlag.GENERATED,),
        ),
        _record(
            "test_app.py",
            language="Python",
            flags=(SourceFileFlag.TEST,),
        ),
    )
    policy = _policy(language_states={"Python": SourceSupportState.SCANNABLE})

    language = _build(inventory, policy).languages[0]

    assert language.file_count == 2
    assert language.eligible_file_count == 2


@pytest.mark.parametrize(
    ("language_state", "capability_state"),
    [
        (SourceSupportState.SCANNABLE, SourceSupportState.DETECTED),
        (SourceSupportState.DETECTED, SourceSupportState.SCANNABLE),
    ],
)
def test_language_state_gates_source_sast_applicability(
    language_state: SourceSupportState,
    capability_state: SourceSupportState,
) -> None:
    policy = _policy(
        language_states={"Python": language_state},
        capability_states={AnalysisCapability.SOURCE_SAST: capability_state},
    )

    profile = _build(
        _componentized(_record("app.py", language="Python")),
        policy,
    )

    assert profile.languages[0].support_state is language_state
    surfaces = _surfaces(profile, AnalysisCapability.SOURCE_SAST)
    if language_state is SourceSupportState.DETECTED:
        assert surfaces == ()
    else:
        assert surfaces[0].support_state is capability_state


def test_profile_is_complete_sorted_repeatable_and_golden() -> None:
    inventory = _componentized(
        _record(
            "app.py",
            language="Python",
            content=b"print('hello')\n",
        )
    )
    policy = SourceSupportPolicy()
    assessment = assess_repository_language_support(inventory, policy)

    first = build_repository_profile(inventory, assessment, policy)
    second = build_repository_profile(inventory, assessment, policy)

    assert first == second
    assert first.profile_digest() == second.profile_digest()
    assert first.profile_digest() == _PROFILE_GOLDEN_DIGEST
    assert first.files == tuple(sorted(first.files, key=lambda file: file.relative_path))
    assert first.components == tuple(
        sorted(first.components, key=lambda component: component.component_id)
    )
    assert first.languages == tuple(
        sorted(first.languages, key=lambda language: language.language.casefold())
    )
    assert first.surfaces == tuple(
        sorted(
            first.surfaces,
            key=lambda surface: (
                surface.capability.value,
                surface.component_id or "",
            ),
        )
    )


def test_semantic_profile_change_changes_digest() -> None:
    inventory = _componentized(_record("app.py", language="Python"))
    default = _build(inventory)
    changed = _build(
        inventory,
        _policy(
            capability_states={
                AnalysisCapability.SOURCE_SAST: SourceSupportState.SCANNABLE,
            }
        ),
    )

    assert default.profile_digest() != changed.profile_digest()


def test_profile_has_no_execution_or_runtime_coverage_claims() -> None:
    profile = _build(_componentized(_record("app.py", language="Python")))

    assert not hasattr(profile, "coverage_status")
    assert not hasattr(profile, "execution_status")
    assert not hasattr(profile, "execution_plan")
    assert not hasattr(profile, "scanner")


def test_profile_build_has_no_external_side_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventory = _componentized(_record("app.py", language="Python"))
    policy = SourceSupportPolicy()
    assessment = assess_repository_language_support(inventory, policy)

    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("external operation attempted")

    monkeypatch.setattr(builtins, "open", fail)
    monkeypatch.setattr(os, "open", fail)
    monkeypatch.setattr(os, "system", fail)
    monkeypatch.setattr(Path, "open", fail)
    monkeypatch.setattr(Path, "read_bytes", fail)
    monkeypatch.setattr(Path, "read_text", fail)
    monkeypatch.setattr(subprocess, "Popen", fail)
    monkeypatch.setattr(subprocess, "run", fail)
    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(sqlalchemy, "create_engine", fail)
    monkeypatch.setattr(DockerSandboxExecutor, "execute", fail)
    monkeypatch.setattr(EnryClient, "classify", fail)
    monkeypatch.setattr(FakeScannerAdapter, "build_plan", fail)
    monkeypatch.setattr(SemgrepScannerAdapter, "execute", fail)

    assert build_repository_profile(inventory, assessment, policy).file_count == 1


@pytest.mark.skipif(not _LOCAL_HELPER.exists(), reason="local Enry helper is absent")
def test_real_enry_repository_profile_pipeline(tmp_path: Path) -> None:
    source = tmp_path / "repository"
    contents = {
        "Dockerfile": b"FROM scratch\n",
        "README.md": b"# Documentation\n",
        "asset.bin": b"\x00\x01\x02\x03",
        "config.yaml": b"enabled: true\n",
        "frontend/package-lock.json": b'{"lockfileVersion": 3}\n',
        "frontend/package.json": b'{"name": "frontend"}\n',
        "frontend/src/app.js": b"export const app = true;\n",
        "generated/__generated__/generated_client.py": (
            b"# Code generated by SecureScan. DO NOT EDIT.\nVALUE = True\n"
        ),
        "generated/client.py": b"VALUE = True\n",
        "infra/main.tf": b'terraform { required_version = ">= 1.0" }\n',
        "infra/modules/db/main.tf": b'resource "null_resource" "db" {}\n',
        "infra/variables.tf": b'variable "region" { type = string }\n',
        "pyproject.toml": b"[project]\nname = 'root'\n",
        "services/api/Dockerfile": b"FROM scratch\n",
        "services/api/poetry.lock": b"package = []\n",
        "services/api/pyproject.toml": b"[project]\nname = 'api'\n",
        "services/api/src/service.py": b"SERVICE = True\n",
        "src/app.py": b"APP = True\n",
        "tests/test_app.py": b"def test_app():\n    assert True\n",
        "vendor/sdk.py": b"SDK = True\n",
    }
    for relative_path, content in contents.items():
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
    policy = _policy(
        language_states={
            "JavaScript": SourceSupportState.DETECTED,
            "Python": SourceSupportState.SCANNABLE,
        },
        capability_states={
            AnalysisCapability.REPOSITORY_PROFILING: (SourceSupportState.PRODUCT_SUPPORTED),
            AnalysisCapability.SOURCE_SAST: SourceSupportState.SCANNABLE,
            AnalysisCapability.SECRET_DETECTION: SourceSupportState.SCANNABLE,
            AnalysisCapability.PACKAGE_INVENTORY: SourceSupportState.DETECTED,
            AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING: (SourceSupportState.DETECTED),
            AnalysisCapability.TERRAFORM_SOURCE_POLICY: (SourceSupportState.SCANNABLE),
            AnalysisCapability.DOCKERFILE_POLICY: SourceSupportState.DETECTED,
        },
    )

    try:
        base_inventory = build_repository_inventory(workspace)
        language_profile = profile_repository_languages(
            workspace,
            base_inventory,
            client,
            policy=SourceLanguageProfilingPolicy(sample_bytes=1024),
        )
        enriched = enrich_repository_inventory(base_inventory, language_profile)
        componentized = detect_repository_components(enriched)
        assessment = assess_repository_language_support(componentized, policy)
        profile = build_repository_profile(componentized, assessment, policy)
        files = _files(profile)
        languages = {language.language: language for language in profile.languages}
        components = {
            component.root_path: component.component_id for component in profile.components
        }

        assert languages["Python"].support_state is SourceSupportState.SCANNABLE
        assert languages["Python"].file_count == 6
        assert languages["Python"].eligible_file_count == 6
        assert languages["JavaScript"].support_state is SourceSupportState.DETECTED
        assert languages["JavaScript"].eligible_file_count == 0
        python_surface = _surfaces(profile, AnalysisCapability.SOURCE_SAST)[0]
        assert python_surface.support_state is SourceSupportState.SCANNABLE
        assert python_surface.eligible_paths == (
            "generated/__generated__/generated_client.py",
            "generated/client.py",
            "services/api/src/service.py",
            "src/app.py",
            "tests/test_app.py",
            "vendor/sdk.py",
        )
        secret_surface = _surfaces(profile, AnalysisCapability.SECRET_DETECTION)[0]
        assert "asset.bin" not in secret_surface.eligible_paths
        assert set(secret_surface.eligible_paths) == set(contents) - {"asset.bin"}
        package_surfaces = _surfaces(profile, AnalysisCapability.PACKAGE_INVENTORY)
        assert {surface.component_id for surface in package_surfaces} == {
            components["."],
            components["frontend"],
            components["services/api"],
        }
        advisory_surfaces = _surfaces(
            profile,
            AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING,
        )
        assert {surface.component_id for surface in advisory_surfaces} == {
            components["frontend"],
            components["services/api"],
        }
        terraform_surfaces = _surfaces(
            profile,
            AnalysisCapability.TERRAFORM_SOURCE_POLICY,
        )
        assert {surface.component_id for surface in terraform_surfaces} == {
            components["infra"],
            components["infra/modules/db"],
        }
        docker_surfaces = _surfaces(profile, AnalysisCapability.DOCKERFILE_POLICY)
        assert {surface.component_id for surface in docker_surfaces} == {
            components["."],
            components["services/api"],
        }
        assert profile.components is componentized.components
        assert profile.repository_digest == componentized.repository_digest
        assert (
            SourceFileFlag.GENERATED in files["generated/__generated__/generated_client.py"].flags
        )
        assert SourceFileFlag.TEST in files["tests/test_app.py"].flags
        assert SourceFileFlag.VENDORED in files["vendor/sdk.py"].flags
        assert not hasattr(profile, "coverage_status")
        assert not hasattr(profile, "execution_plan")
    finally:
        manager.cleanup_workspace(workspace)
