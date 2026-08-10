from __future__ import annotations

import builtins
import hashlib
import os
import shutil
import socket
import subprocess
from pathlib import Path

import pytest
import sqlalchemy

from securescan.adapters.fake_scanner import FakeScannerAdapter
from securescan.execution import DockerSandboxExecutor
from securescan.scanners.semgrep.adapter import SemgrepScannerAdapter
from securescan.source import (
    AnalysisCapability,
    AnalysisSurface,
    CapabilityPathSelectionRule,
    CapabilitySupportRule,
    ComponentizedRepositoryInventory,
    EnryClient,
    FileContentKind,
    InvalidSourcePlanningRequestError,
    LanguageSupportRule,
    RepositoryProfile,
    SourceAnalysisPlan,
    SourceAnalysisPlanEntry,
    SourceFileFlag,
    SourceFileRecord,
    SourceFileRole,
    SourceLanguageProfilingPolicy,
    SourcePlanAction,
    SourcePlanningCorrelationError,
    SourcePlanningPolicy,
    SourcePlanPathExclusion,
    SourceSupportPolicy,
    SourceSupportState,
    TrustedEnryHelper,
    TrustedSourceAnalyzer,
    TrustedSourceAnalyzerRegistry,
    assess_repository_language_support,
    build_repository_inventory,
    build_repository_profile,
    build_source_analysis_plan,
    detect_repository_components,
    enrich_repository_inventory,
    profile_repository_languages,
)
from securescan.source.models import RepositoryComponent
from securescan.workspaces import RepositoryManifestEntry, RepositoryWorkspaceManager
from securescan.workspaces.models import repository_content_digest

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_LOCAL_HELPER = _PROJECT_ROOT / "tools/enry-helper/bin/securescan-enry-helper"
_REGISTRY_GOLDEN_DIGEST = (
    "9992c01eea13e4d47f51172cfae33ff792ea72fdcf1a8d25a8507bb0e7a0c551"
)
_POLICY_GOLDEN_DIGEST = (
    "6bd523fea58d90c956492b8482293375001b5bcf114014db83a6bfa5ebbd97e0"
)
_PLAN_GOLDEN_DIGEST = (
    "a947fea7b829a2f60c1d4c3e395527c1b4ab149f9ce67f241d458c0d0fbddfca"
)


def _entry(relative_path: str, content: bytes) -> RepositoryManifestEntry:
    return RepositoryManifestEntry(
        relative_path=relative_path,
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
    )


def _record(
    relative_path: str,
    *,
    flags: tuple[SourceFileFlag, ...] = (),
    component_id: str | None = None,
    capability: AnalysisCapability = AnalysisCapability.SECRET_DETECTION,
    language: str | None = None,
    content: bytes = b"content\n",
) -> SourceFileRecord:
    content_kind = (
        FileContentKind.BINARY
        if SourceFileFlag.BINARY in flags
        else FileContentKind.TEXT
    )
    return SourceFileRecord(
        entry=_entry(relative_path, content),
        content_kind=content_kind,
        role=(
            SourceFileRole.BINARY
            if content_kind is FileContentKind.BINARY
            else SourceFileRole.SOURCE
        ),
        language=language,
        component_id=component_id,
        flags=tuple(sorted(flags, key=lambda flag: flag.value)),
        eligible_capabilities=tuple(
            sorted(
                {capability, AnalysisCapability.REPOSITORY_PROFILING},
                key=lambda item: item.value,
            )
        ),
    )


def _component(component_id: str, root_path: str) -> RepositoryComponent:
    return RepositoryComponent(
        component_id=component_id,
        display_name=root_path,
        root_path=root_path,
    )


def _profile(
    files: tuple[SourceFileRecord, ...],
    surfaces: tuple[AnalysisSurface, ...],
    *,
    components: tuple[RepositoryComponent, ...] = (),
) -> RepositoryProfile:
    sorted_files = tuple(sorted(files, key=lambda file: file.relative_path))
    return RepositoryProfile(
        repository_digest=repository_content_digest(
            tuple(file.entry for file in sorted_files)
        ),
        files=sorted_files,
        components=tuple(
            sorted(components, key=lambda component: component.component_id)
        ),
        surfaces=tuple(
            sorted(
                surfaces,
                key=lambda surface: (
                    surface.capability.value,
                    surface.component_id or "",
                ),
            )
        ),
    )


def _profile_for_capability(
    capability: AnalysisCapability,
    support_state: SourceSupportState,
    *,
    file_flags: tuple[tuple[SourceFileFlag, ...], ...] = ((),),
    component_id: str | None = None,
) -> RepositoryProfile:
    files = tuple(
        _record(
            f"file-{index}.txt",
            flags=flags,
            component_id=component_id,
            capability=capability,
        )
        for index, flags in enumerate(file_flags)
    )
    paths = tuple(file.relative_path for file in files)
    components = (
        (_component(component_id, "component"),)
        if component_id is not None
        else ()
    )
    profiling = AnalysisSurface(
        capability=AnalysisCapability.REPOSITORY_PROFILING,
        support_state=SourceSupportState.DETECTED,
        eligible_paths=paths,
    )
    target = AnalysisSurface(
        capability=capability,
        component_id=component_id,
        support_state=support_state,
        eligible_paths=(
            () if support_state is SourceSupportState.UNSUPPORTED else paths
        ),
        reason_code=(
            "CAPABILITY_UNSUPPORTED"
            if support_state is SourceSupportState.UNSUPPORTED
            else None
        ),
    )
    return _profile(files, (profiling, target), components=components)


def _analyzer(
    capability: AnalysisCapability = AnalysisCapability.SECRET_DETECTION,
    *,
    analyzer_id: str = "test-analyzer",
    available: bool = True,
) -> TrustedSourceAnalyzer:
    return TrustedSourceAnalyzer(
        analyzer_id=analyzer_id,
        capabilities=(capability,),
        available=available,
        unavailable_reason_code=None if available else "TEST_ANALYZER_UNAVAILABLE",
    )


def _registry(
    capability: AnalysisCapability = AnalysisCapability.SECRET_DETECTION,
    *,
    available: bool = True,
) -> TrustedSourceAnalyzerRegistry:
    return TrustedSourceAnalyzerRegistry(
        analyzers=(_analyzer(capability, available=available),)
    )


def _policy(
    capability: AnalysisCapability,
    *flags: SourceFileFlag,
) -> SourcePlanningPolicy:
    return SourcePlanningPolicy(
        path_rules=(
            CapabilityPathSelectionRule(
                capability=capability,
                excluded_flags=tuple(sorted(flags, key=lambda flag: flag.value)),
            ),
        )
    )


def _target_entry(
    plan: SourceAnalysisPlan,
    capability: AnalysisCapability,
    component_id: str | None = None,
) -> SourceAnalysisPlanEntry:
    return next(
        entry
        for entry in plan.entries
        if entry.capability is capability and entry.component_id == component_id
    )


def _plan_entry_arguments() -> dict[str, object]:
    return {
        "capability": AnalysisCapability.SECRET_DETECTION,
        "component_id": None,
        "support_state": SourceSupportState.SCANNABLE,
        "action": SourcePlanAction.RUN,
        "reason_code": "PLANNED",
        "analyzer_id": "test-analyzer",
        "surface_paths": ("app.py",),
        "selected_paths": ("app.py",),
        "excluded_paths": (),
    }


def _golden_profile() -> RepositoryProfile:
    content = b"print('hello')\n"
    file = SourceFileRecord(
        entry=_entry("app.py", content),
        content_kind=FileContentKind.TEXT,
        role=SourceFileRole.SOURCE,
        language="Python",
        eligible_capabilities=(AnalysisCapability.REPOSITORY_PROFILING,),
    )
    inventory = ComponentizedRepositoryInventory(
        repository_digest=repository_content_digest((file.entry,)),
        files=(file,),
        components=(),
    )
    support_policy = SourceSupportPolicy()
    assessment = assess_repository_language_support(inventory, support_policy)
    return build_repository_profile(inventory, assessment, support_policy)


def test_source_plan_actions_are_explicit_string_states() -> None:
    assert tuple(action.value for action in SourcePlanAction) == (
        "run",
        "skip",
        "satisfied",
    )


def test_available_and_unavailable_analyzers_are_valid() -> None:
    available = _analyzer()
    unavailable = _analyzer(available=False)

    assert available.available is True
    assert available.unavailable_reason_code is None
    assert unavailable.available is False
    assert unavailable.unavailable_reason_code == "TEST_ANALYZER_UNAVAILABLE"


def test_analyzer_availability_reason_contract_is_strict() -> None:
    with pytest.raises(InvalidSourcePlanningRequestError):
        TrustedSourceAnalyzer(
            analyzer_id="test",
            capabilities=(AnalysisCapability.SECRET_DETECTION,),
            available=False,
        )
    with pytest.raises(InvalidSourcePlanningRequestError):
        TrustedSourceAnalyzer(
            analyzer_id="test",
            capabilities=(AnalysisCapability.SECRET_DETECTION,),
            available=True,
            unavailable_reason_code="NOT_NEEDED",
        )
    with pytest.raises(InvalidSourcePlanningRequestError):
        TrustedSourceAnalyzer(
            analyzer_id="test",
            capabilities=(AnalysisCapability.SECRET_DETECTION,),
            available=1,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("analyzer_id", ["", "Upper", "has space", "../tool", "a" * 129])
def test_analyzer_rejects_invalid_identifier(analyzer_id: str) -> None:
    with pytest.raises(InvalidSourcePlanningRequestError):
        TrustedSourceAnalyzer(
            analyzer_id=analyzer_id,
            capabilities=(AnalysisCapability.SECRET_DETECTION,),
            available=True,
        )


def test_analyzer_requires_sorted_unique_nonempty_capabilities() -> None:
    with pytest.raises(InvalidSourcePlanningRequestError):
        TrustedSourceAnalyzer("test", (), True)
    with pytest.raises(InvalidSourcePlanningRequestError):
        TrustedSourceAnalyzer(
            "test",
            (
                AnalysisCapability.SECRET_DETECTION,
                AnalysisCapability.PYTHON_SAST,
            ),
            True,
        )
    with pytest.raises(InvalidSourcePlanningRequestError):
        TrustedSourceAnalyzer(
            "test",
            (
                AnalysisCapability.PYTHON_SAST,
                AnalysisCapability.PYTHON_SAST,
            ),
            True,
        )


def test_repository_profiling_cannot_be_registered_to_analyzer() -> None:
    with pytest.raises(InvalidSourcePlanningRequestError):
        _analyzer(AnalysisCapability.REPOSITORY_PROFILING)


def test_empty_registry_is_valid_conservative_and_golden() -> None:
    registry = TrustedSourceAnalyzerRegistry()

    assert registry.analyzers == ()
    assert registry.canonical_data() == {
        "analyzers": [],
        "schema_version": "0.2.6",
    }
    assert registry.registry_digest() == _REGISTRY_GOLDEN_DIGEST


def test_registry_rejects_wrong_schema_and_non_tuple() -> None:
    with pytest.raises(InvalidSourcePlanningRequestError):
        TrustedSourceAnalyzerRegistry(schema_version="0.2.5")
    with pytest.raises(InvalidSourcePlanningRequestError):
        TrustedSourceAnalyzerRegistry(analyzers=[])  # type: ignore[arg-type]


def test_registry_requires_sorted_unique_analyzer_ids() -> None:
    first = _analyzer(
        AnalysisCapability.PYTHON_SAST,
        analyzer_id="a-analyzer",
    )
    second = _analyzer(
        AnalysisCapability.SECRET_DETECTION,
        analyzer_id="b-analyzer",
    )

    with pytest.raises(InvalidSourcePlanningRequestError):
        TrustedSourceAnalyzerRegistry(analyzers=(second, first))
    with pytest.raises(InvalidSourcePlanningRequestError):
        TrustedSourceAnalyzerRegistry(analyzers=(first, first))


def test_registry_rejects_multiple_analyzers_for_one_capability() -> None:
    first = _analyzer(analyzer_id="a-analyzer")
    second = _analyzer(analyzer_id="b-analyzer")

    with pytest.raises(InvalidSourcePlanningRequestError):
        TrustedSourceAnalyzerRegistry(analyzers=(first, second))


def test_registry_lookup_is_exact_and_digest_is_deterministic() -> None:
    analyzer = _analyzer()
    registry = TrustedSourceAnalyzerRegistry(analyzers=(analyzer,))

    assert registry.analyzer_for(AnalysisCapability.SECRET_DETECTION) is analyzer
    assert registry.analyzer_for(AnalysisCapability.PYTHON_SAST) is None
    assert registry.registry_digest() == registry.registry_digest()
    assert registry.registry_digest() != TrustedSourceAnalyzerRegistry().registry_digest()
    with pytest.raises(InvalidSourcePlanningRequestError):
        registry.analyzer_for("secret_detection")  # type: ignore[arg-type]


def test_default_planning_policy_has_no_exclusions_and_is_golden() -> None:
    policy = SourcePlanningPolicy()

    assert policy.path_rules == ()
    assert policy.excluded_flags_for(AnalysisCapability.PYTHON_SAST) == ()
    assert policy.policy_digest() == _POLICY_GOLDEN_DIGEST
    assert policy.policy_digest() == SourcePlanningPolicy().policy_digest()


def test_path_selection_rule_requires_valid_nonprofiling_capability() -> None:
    with pytest.raises(InvalidSourcePlanningRequestError):
        CapabilityPathSelectionRule(
            capability="python_sast",  # type: ignore[arg-type]
        )
    with pytest.raises(InvalidSourcePlanningRequestError):
        CapabilityPathSelectionRule(
            capability=AnalysisCapability.REPOSITORY_PROFILING,
        )


def test_path_selection_rule_requires_sorted_unique_flag_tuple() -> None:
    with pytest.raises(InvalidSourcePlanningRequestError):
        CapabilityPathSelectionRule(
            capability=AnalysisCapability.PYTHON_SAST,
            excluded_flags=(SourceFileFlag.TEST, SourceFileFlag.GENERATED),
        )
    with pytest.raises(InvalidSourcePlanningRequestError):
        CapabilityPathSelectionRule(
            capability=AnalysisCapability.PYTHON_SAST,
            excluded_flags=(SourceFileFlag.TEST, SourceFileFlag.TEST),
        )
    with pytest.raises(InvalidSourcePlanningRequestError):
        CapabilityPathSelectionRule(
            capability=AnalysisCapability.PYTHON_SAST,
            excluded_flags=[],  # type: ignore[arg-type]
        )


def test_planning_policy_requires_schema_sorted_unique_rules() -> None:
    python = CapabilityPathSelectionRule(AnalysisCapability.PYTHON_SAST)
    secret = CapabilityPathSelectionRule(AnalysisCapability.SECRET_DETECTION)

    with pytest.raises(InvalidSourcePlanningRequestError):
        SourcePlanningPolicy(schema_version="0.2.5")
    with pytest.raises(InvalidSourcePlanningRequestError):
        SourcePlanningPolicy(path_rules=(secret, python))
    with pytest.raises(InvalidSourcePlanningRequestError):
        SourcePlanningPolicy(path_rules=(python, python))
    changed = SourcePlanningPolicy(path_rules=(python,))
    assert changed.policy_digest() != SourcePlanningPolicy().policy_digest()


def test_plan_path_exclusion_requires_safe_path_and_fixed_reason() -> None:
    valid = SourcePlanPathExclusion("app.py", "EXCLUDED_TEST")
    assert valid.canonical_data() == {
        "reason_code": "EXCLUDED_TEST",
        "relative_path": "app.py",
    }
    with pytest.raises(InvalidSourcePlanningRequestError):
        SourcePlanPathExclusion("/absolute.py", "EXCLUDED_TEST")
    with pytest.raises(InvalidSourcePlanningRequestError):
        SourcePlanPathExclusion("app.py", "ARBITRARY_REASON")


def test_valid_run_entry_is_canonical() -> None:
    entry = SourceAnalysisPlanEntry(**_plan_entry_arguments())  # type: ignore[arg-type]

    assert entry.action is SourcePlanAction.RUN
    assert entry.canonical_data()["selected_paths"] == ["app.py"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("surface_paths", ("z.py", "a.py")),
        ("surface_paths", ("app.py", "app.py")),
        ("selected_paths", ("other.py",)),
        ("action", "run"),
        ("analyzer_id", "INVALID ID"),
        ("reason_code", "UNKNOWN_REASON"),
    ],
)
def test_plan_entry_rejects_invalid_contract(field: str, value: object) -> None:
    arguments = _plan_entry_arguments()
    arguments[field] = value

    with pytest.raises(InvalidSourcePlanningRequestError):
        SourceAnalysisPlanEntry(**arguments)  # type: ignore[arg-type]


def test_plan_entry_rejects_selected_excluded_overlap_and_unsorted_exclusions() -> None:
    arguments = _plan_entry_arguments()
    arguments["surface_paths"] = ("app.py", "test.py")
    arguments["selected_paths"] = ("app.py",)
    arguments["excluded_paths"] = (
        SourcePlanPathExclusion("app.py", "EXCLUDED_TEST"),
    )
    with pytest.raises(InvalidSourcePlanningRequestError):
        SourceAnalysisPlanEntry(**arguments)  # type: ignore[arg-type]

    arguments["excluded_paths"] = (
        SourcePlanPathExclusion("test.py", "EXCLUDED_TEST"),
        SourcePlanPathExclusion("app.py", "EXCLUDED_TEST"),
    )
    with pytest.raises(InvalidSourcePlanningRequestError):
        SourceAnalysisPlanEntry(**arguments)  # type: ignore[arg-type]


def test_run_requires_analyzer_selected_paths_and_complete_partition() -> None:
    for field, value in (
        ("analyzer_id", None),
        ("selected_paths", ()),
        ("surface_paths", ("app.py", "missing.py")),
    ):
        arguments = _plan_entry_arguments()
        arguments[field] = value
        with pytest.raises(InvalidSourcePlanningRequestError):
            SourceAnalysisPlanEntry(**arguments)  # type: ignore[arg-type]


def test_repository_profiling_satisfied_entry_rejects_analyzer() -> None:
    arguments: dict[str, object] = {
        "capability": AnalysisCapability.REPOSITORY_PROFILING,
        "component_id": None,
        "support_state": SourceSupportState.PRODUCT_SUPPORTED,
        "action": SourcePlanAction.SATISFIED,
        "reason_code": "UPSTREAM_CAPABILITY_SATISFIED",
        "analyzer_id": None,
        "surface_paths": ("app.py",),
        "selected_paths": (),
        "excluded_paths": (),
    }
    assert SourceAnalysisPlanEntry(**arguments)  # type: ignore[arg-type]
    arguments["analyzer_id"] = "profiler"
    with pytest.raises(InvalidSourcePlanningRequestError):
        SourceAnalysisPlanEntry(**arguments)  # type: ignore[arg-type]
    arguments["analyzer_id"] = None
    arguments["component_id"] = "component-a"
    with pytest.raises(InvalidSourcePlanningRequestError):
        SourceAnalysisPlanEntry(**arguments)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("support_state", "expected_action", "expected_reason"),
    [
        (
            SourceSupportState.DETECTED,
            SourcePlanAction.SKIP,
            "CAPABILITY_DETECTED_ONLY",
        ),
        (
            SourceSupportState.UNSUPPORTED,
            SourcePlanAction.SKIP,
            "CAPABILITY_UNSUPPORTED",
        ),
        (SourceSupportState.SCANNABLE, SourcePlanAction.RUN, "PLANNED"),
        (SourceSupportState.BENCHMARKED, SourcePlanAction.RUN, "PLANNED"),
        (SourceSupportState.PRODUCT_SUPPORTED, SourcePlanAction.RUN, "PLANNED"),
    ],
)
def test_support_state_gates_are_explicit(
    support_state: SourceSupportState,
    expected_action: SourcePlanAction,
    expected_reason: str,
) -> None:
    capability = AnalysisCapability.SECRET_DETECTION
    profile = _profile_for_capability(capability, support_state)

    plan = build_source_analysis_plan(
        profile,
        _registry(capability),
        SourcePlanningPolicy(),
    )
    entry = _target_entry(plan, capability)

    assert entry.action is expected_action
    assert entry.reason_code == expected_reason


def test_detected_surface_never_consults_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _profile_for_capability(
        AnalysisCapability.SECRET_DETECTION,
        SourceSupportState.DETECTED,
    )

    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("analyzer lookup attempted")

    monkeypatch.setattr(TrustedSourceAnalyzerRegistry, "analyzer_for", fail)

    entry = _target_entry(
        build_source_analysis_plan(
            profile,
            TrustedSourceAnalyzerRegistry(),
            SourcePlanningPolicy(),
        ),
        AnalysisCapability.SECRET_DETECTION,
    )
    assert entry.reason_code == "CAPABILITY_DETECTED_ONLY"


def test_approved_surface_without_analyzer_skips_honestly() -> None:
    capability = AnalysisCapability.SECRET_DETECTION
    profile = _profile_for_capability(capability, SourceSupportState.SCANNABLE)

    entry = _target_entry(
        build_source_analysis_plan(
            profile,
            TrustedSourceAnalyzerRegistry(),
            SourcePlanningPolicy(),
        ),
        capability,
    )

    assert entry.action is SourcePlanAction.SKIP
    assert entry.reason_code == "NO_ANALYZER_REGISTERED"
    assert entry.analyzer_id is None
    assert entry.surface_paths == ("file-0.txt",)
    assert entry.selected_paths == ()
    assert entry.excluded_paths == ()


def test_unavailable_analyzer_skips_without_filtering_or_reason_leakage() -> None:
    capability = AnalysisCapability.SECRET_DETECTION
    profile = _profile_for_capability(
        capability,
        SourceSupportState.SCANNABLE,
        file_flags=((SourceFileFlag.GENERATED,),),
    )

    entry = _target_entry(
        build_source_analysis_plan(
            profile,
            _registry(capability, available=False),
            _policy(capability, SourceFileFlag.GENERATED),
        ),
        capability,
    )

    assert entry.action is SourcePlanAction.SKIP
    assert entry.reason_code == "ANALYZER_UNAVAILABLE"
    assert entry.analyzer_id == "test-analyzer"
    assert entry.selected_paths == ()
    assert entry.excluded_paths == ()
    assert "TEST_ANALYZER_UNAVAILABLE" not in str(entry.canonical_data())


def test_default_policy_retains_generated_vendored_and_test_paths() -> None:
    capability = AnalysisCapability.PYTHON_SAST
    profile = _profile_for_capability(
        capability,
        SourceSupportState.SCANNABLE,
        file_flags=(
            (SourceFileFlag.GENERATED,),
            (SourceFileFlag.VENDORED,),
            (SourceFileFlag.TEST,),
        ),
    )

    entry = _target_entry(
        build_source_analysis_plan(
            profile,
            _registry(capability),
            SourcePlanningPolicy(),
        ),
        capability,
    )

    assert entry.action is SourcePlanAction.RUN
    assert entry.selected_paths == (
        "file-0.txt",
        "file-1.txt",
        "file-2.txt",
    )
    assert entry.excluded_paths == ()


@pytest.mark.parametrize(
    ("flag", "reason_code"),
    [
        (SourceFileFlag.BINARY, "EXCLUDED_BINARY"),
        (SourceFileFlag.UNSUPPORTED, "EXCLUDED_UNSUPPORTED"),
        (SourceFileFlag.VENDORED, "EXCLUDED_VENDORED"),
        (SourceFileFlag.GENERATED, "EXCLUDED_GENERATED"),
        (SourceFileFlag.TEST, "EXCLUDED_TEST"),
    ],
)
def test_custom_path_exclusions_are_explicit(
    flag: SourceFileFlag,
    reason_code: str,
) -> None:
    capability = AnalysisCapability.SECRET_DETECTION
    profile = _profile_for_capability(
        capability,
        SourceSupportState.SCANNABLE,
        file_flags=((), (flag,)),
    )

    entry = _target_entry(
        build_source_analysis_plan(
            profile,
            _registry(capability),
            _policy(capability, flag),
        ),
        capability,
    )

    assert entry.selected_paths == ("file-0.txt",)
    assert entry.excluded_paths == (
        SourcePlanPathExclusion("file-1.txt", reason_code),
    )
    assert set(entry.selected_paths) | {
        exclusion.relative_path for exclusion in entry.excluded_paths
    } == set(entry.surface_paths)


def test_multiple_excluded_flags_use_fixed_precedence() -> None:
    capability = AnalysisCapability.SECRET_DETECTION
    flags = (
        SourceFileFlag.BINARY,
        SourceFileFlag.GENERATED,
        SourceFileFlag.TEST,
        SourceFileFlag.UNSUPPORTED,
        SourceFileFlag.VENDORED,
    )
    profile = _profile_for_capability(
        capability,
        SourceSupportState.SCANNABLE,
        file_flags=(flags,),
    )

    entry = _target_entry(
        build_source_analysis_plan(
            profile,
            _registry(capability),
            _policy(capability, *flags),
        ),
        capability,
    )

    assert entry.action is SourcePlanAction.SKIP
    assert entry.reason_code == "NO_PATHS_AFTER_SELECTION_POLICY"
    assert entry.excluded_paths == (
        SourcePlanPathExclusion("file-0.txt", "EXCLUDED_BINARY"),
    )


def test_all_filtered_paths_produce_explicit_nonrun_entry() -> None:
    capability = AnalysisCapability.SECRET_DETECTION
    profile = _profile_for_capability(
        capability,
        SourceSupportState.PRODUCT_SUPPORTED,
        file_flags=(
            (SourceFileFlag.GENERATED,),
            (SourceFileFlag.GENERATED,),
        ),
    )

    entry = _target_entry(
        build_source_analysis_plan(
            profile,
            _registry(capability),
            _policy(capability, SourceFileFlag.GENERATED),
        ),
        capability,
    )

    assert entry.action is SourcePlanAction.SKIP
    assert entry.reason_code == "NO_PATHS_AFTER_SELECTION_POLICY"
    assert entry.selected_paths == ()
    assert tuple(item.relative_path for item in entry.excluded_paths) == (
        "file-0.txt",
        "file-1.txt",
    )


def test_repository_profiling_is_always_satisfied_without_analyzer() -> None:
    profile = _profile_for_capability(
        AnalysisCapability.SECRET_DETECTION,
        SourceSupportState.DETECTED,
    )

    entry = _target_entry(
        build_source_analysis_plan(
            profile,
            TrustedSourceAnalyzerRegistry(),
            SourcePlanningPolicy(),
        ),
        AnalysisCapability.REPOSITORY_PROFILING,
    )

    assert entry.action is SourcePlanAction.SATISFIED
    assert entry.reason_code == "UPSTREAM_CAPABILITY_SATISFIED"
    assert entry.analyzer_id is None
    assert entry.surface_paths == ("file-0.txt",)
    assert entry.selected_paths == ()


@pytest.mark.parametrize(
    "capability",
    [
        AnalysisCapability.PACKAGE_INVENTORY,
        AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING,
        AnalysisCapability.TERRAFORM_SOURCE_POLICY,
        AnalysisCapability.DOCKERFILE_POLICY,
    ],
)
def test_component_and_orphan_surface_boundaries_become_separate_entries(
    capability: AnalysisCapability,
) -> None:
    files = (
        _record("a/file", component_id="component-a", capability=capability),
        _record("b/file", component_id="component-b", capability=capability),
        _record("orphan", capability=capability),
    )
    paths = tuple(file.relative_path for file in files)
    components = (
        _component("component-a", "a"),
        _component("component-b", "b"),
    )
    surfaces = (
        AnalysisSurface(
            capability=AnalysisCapability.REPOSITORY_PROFILING,
            support_state=SourceSupportState.DETECTED,
            eligible_paths=paths,
        ),
        AnalysisSurface(
            capability=capability,
            component_id="component-a",
            support_state=SourceSupportState.SCANNABLE,
            eligible_paths=("a/file",),
        ),
        AnalysisSurface(
            capability=capability,
            component_id="component-b",
            support_state=SourceSupportState.SCANNABLE,
            eligible_paths=("b/file",),
        ),
        AnalysisSurface(
            capability=capability,
            support_state=SourceSupportState.SCANNABLE,
            eligible_paths=("orphan",),
        ),
    )
    profile = _profile(files, surfaces, components=components)

    plan = build_source_analysis_plan(
        profile,
        _registry(capability),
        SourcePlanningPolicy(),
    )
    entries = tuple(entry for entry in plan.entries if entry.capability is capability)

    assert tuple(entry.component_id for entry in entries) == (
        None,
        "component-a",
        "component-b",
    )
    assert all(entry.action is SourcePlanAction.RUN for entry in entries)


def test_python_and_secret_repository_surfaces_each_plan_once() -> None:
    files = (
        _record("a.py", capability=AnalysisCapability.PYTHON_SAST),
        _record("b.py", capability=AnalysisCapability.PYTHON_SAST),
    )
    paths = tuple(file.relative_path for file in files)
    profile = _profile(
        files,
        (
            AnalysisSurface(
                capability=AnalysisCapability.REPOSITORY_PROFILING,
                support_state=SourceSupportState.DETECTED,
                eligible_paths=paths,
            ),
            AnalysisSurface(
                capability=AnalysisCapability.PYTHON_SAST,
                support_state=SourceSupportState.SCANNABLE,
                eligible_paths=paths,
            ),
        ),
    )

    plan = build_source_analysis_plan(
        profile,
        _registry(AnalysisCapability.PYTHON_SAST),
        SourcePlanningPolicy(),
    )

    assert len(
        tuple(
            entry
            for entry in plan.entries
            if entry.capability is AnalysisCapability.PYTHON_SAST
        )
    ) == 1


def test_profile_with_missing_profiling_surface_is_rejected() -> None:
    file = _record("app.py")
    profile = _profile(
        (file,),
        (
            AnalysisSurface(
                capability=AnalysisCapability.SECRET_DETECTION,
                support_state=SourceSupportState.DETECTED,
                eligible_paths=("app.py",),
            ),
        ),
    )

    with pytest.raises(SourcePlanningCorrelationError):
        build_source_analysis_plan(
            profile,
            TrustedSourceAnalyzerRegistry(),
            SourcePlanningPolicy(),
        )


def test_corrupted_surface_path_and_component_boundary_are_rejected() -> None:
    profile = _profile_for_capability(
        AnalysisCapability.SECRET_DETECTION,
        SourceSupportState.SCANNABLE,
        component_id="component-a",
    )
    target = next(
        surface
        for surface in profile.surfaces
        if surface.capability is AnalysisCapability.SECRET_DETECTION
    )
    object.__setattr__(target, "eligible_paths", ("missing.py",))

    with pytest.raises(SourcePlanningCorrelationError):
        build_source_analysis_plan(
            profile,
            _registry(),
            SourcePlanningPolicy(),
        )

    object.__setattr__(target, "eligible_paths", ("file-0.txt",))
    object.__setattr__(target, "component_id", "component-other")
    with pytest.raises(SourcePlanningCorrelationError):
        build_source_analysis_plan(
            profile,
            _registry(),
            SourcePlanningPolicy(),
        )


def test_corrupted_surface_order_or_duplicate_is_rejected() -> None:
    for mutation in ("reverse", "duplicate"):
        profile = _profile_for_capability(
            AnalysisCapability.SECRET_DETECTION,
            SourceSupportState.DETECTED,
        )
        if mutation == "reverse":
            object.__setattr__(profile, "surfaces", tuple(reversed(profile.surfaces)))
        else:
            object.__setattr__(
                profile,
                "surfaces",
                (*profile.surfaces, profile.surfaces[-1]),
            )
        with pytest.raises(SourcePlanningCorrelationError):
            build_source_analysis_plan(
                profile,
                TrustedSourceAnalyzerRegistry(),
                SourcePlanningPolicy(),
            )


def test_corrupted_surface_path_order_is_rejected_as_correlation_failure() -> None:
    profile = _profile_for_capability(
        AnalysisCapability.SECRET_DETECTION,
        SourceSupportState.DETECTED,
        file_flags=((), ()),
    )
    target = next(
        surface
        for surface in profile.surfaces
        if surface.capability is AnalysisCapability.SECRET_DETECTION
    )
    object.__setattr__(target, "eligible_paths", tuple(reversed(target.eligible_paths)))

    with pytest.raises(SourcePlanningCorrelationError):
        build_source_analysis_plan(
            profile,
            TrustedSourceAnalyzerRegistry(),
            SourcePlanningPolicy(),
        )


def test_execution_approved_empty_nonprofiling_surface_is_rejected() -> None:
    profile = _profile(
        (),
        (
            AnalysisSurface(
                capability=AnalysisCapability.REPOSITORY_PROFILING,
                support_state=SourceSupportState.DETECTED,
            ),
            AnalysisSurface(
                capability=AnalysisCapability.SECRET_DETECTION,
                support_state=SourceSupportState.SCANNABLE,
            ),
        ),
    )

    with pytest.raises(SourcePlanningCorrelationError):
        build_source_analysis_plan(
            profile,
            TrustedSourceAnalyzerRegistry(),
            SourcePlanningPolicy(),
        )


def test_plan_contract_allows_empty_entries_but_requires_canonical_digests() -> None:
    plan = SourceAnalysisPlan(
        repository_digest="a" * 64,
        profile_digest="b" * 64,
        analyzer_registry_digest="c" * 64,
        planning_policy_digest="d" * 64,
        entries=(),
    )

    assert plan.run_count == 0
    assert plan.skip_count == 0
    assert plan.satisfied_count == 0
    with pytest.raises(InvalidSourcePlanningRequestError):
        SourceAnalysisPlan(
            repository_digest="A" * 64,
            profile_digest="b" * 64,
            analyzer_registry_digest="c" * 64,
            planning_policy_digest="d" * 64,
            entries=(),
        )


def test_plan_requires_sorted_unique_entries() -> None:
    run = SourceAnalysisPlanEntry(**_plan_entry_arguments())  # type: ignore[arg-type]
    satisfied = SourceAnalysisPlanEntry(
        capability=AnalysisCapability.REPOSITORY_PROFILING,
        component_id=None,
        support_state=SourceSupportState.DETECTED,
        action=SourcePlanAction.SATISFIED,
        reason_code="UPSTREAM_CAPABILITY_SATISFIED",
        analyzer_id=None,
        surface_paths=("app.py",),
        selected_paths=(),
        excluded_paths=(),
    )

    with pytest.raises(InvalidSourcePlanningRequestError):
        SourceAnalysisPlan(
            repository_digest="a" * 64,
            profile_digest="b" * 64,
            analyzer_registry_digest="c" * 64,
            planning_policy_digest="d" * 64,
            entries=(run, satisfied),
        )
    with pytest.raises(InvalidSourcePlanningRequestError):
        SourceAnalysisPlan(
            repository_digest="a" * 64,
            profile_digest="b" * 64,
            analyzer_registry_digest="c" * 64,
            planning_policy_digest="d" * 64,
            entries=(run, run),
        )


def test_built_plan_attaches_inputs_counts_and_literal_golden_digest() -> None:
    profile = _golden_profile()
    registry = TrustedSourceAnalyzerRegistry()
    policy = SourcePlanningPolicy()

    first = build_source_analysis_plan(profile, registry, policy)
    second = build_source_analysis_plan(profile, registry, policy)

    assert first == second
    assert first.repository_digest == profile.repository_digest
    assert first.profile_digest == profile.profile_digest()
    assert first.analyzer_registry_digest == registry.registry_digest()
    assert first.planning_policy_digest == policy.policy_digest()
    assert first.run_count == 0
    assert first.skip_count == 1
    assert first.satisfied_count == 1
    assert first.plan_digest() == _PLAN_GOLDEN_DIGEST
    assert first.plan_digest() == second.plan_digest()


def test_semantic_planning_change_changes_plan_digest() -> None:
    capability = AnalysisCapability.SECRET_DETECTION
    profile = _profile_for_capability(capability, SourceSupportState.SCANNABLE)
    skipped = build_source_analysis_plan(
        profile,
        TrustedSourceAnalyzerRegistry(),
        SourcePlanningPolicy(),
    )
    runnable = build_source_analysis_plan(
        profile,
        _registry(capability),
        SourcePlanningPolicy(),
    )

    assert skipped.plan_digest() != runnable.plan_digest()


@pytest.mark.parametrize("invalid_argument", ["profile", "registry", "policy"])
def test_planner_rejects_invalid_argument_types(invalid_argument: str) -> None:
    profile = _golden_profile()
    registry = TrustedSourceAnalyzerRegistry()
    policy = SourcePlanningPolicy()
    arguments: list[object] = [profile, registry, policy]
    arguments[{"profile": 0, "registry": 1, "policy": 2}[invalid_argument]] = object()

    with pytest.raises(InvalidSourcePlanningRequestError) as raised:
        build_source_analysis_plan(*arguments)  # type: ignore[arg-type]

    assert str(raised.value) == "Source planning request is invalid"


def test_planner_is_pure_and_does_not_mutate_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability = AnalysisCapability.SECRET_DETECTION
    profile = _profile_for_capability(capability, SourceSupportState.SCANNABLE)
    registry = _registry(capability)
    policy = SourcePlanningPolicy()
    profile_before = profile.canonical_data()
    registry_before = registry.canonical_data()
    policy_before = policy.canonical_data()

    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("external operation attempted")

    monkeypatch.setattr(builtins, "open", fail)
    monkeypatch.setattr(os, "open", fail)
    monkeypatch.setattr(os, "getenv", fail)
    monkeypatch.setattr(os, "system", fail)
    monkeypatch.setattr(shutil, "which", fail)
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

    plan = build_source_analysis_plan(profile, registry, policy)

    assert plan.run_count == 1
    assert profile.canonical_data() == profile_before
    assert registry.canonical_data() == registry_before
    assert policy.canonical_data() == policy_before
    assert not hasattr(plan, "command")
    assert not hasattr(plan, "environment")
    assert not hasattr(plan, "execution_status")


@pytest.mark.skipif(not _LOCAL_HELPER.exists(), reason="local Enry helper is absent")
def test_real_enry_source_analysis_planning_pipeline(tmp_path: Path) -> None:
    source = tmp_path / "repository"
    contents = {
        "Dockerfile": b"FROM scratch\n",
        "asset.bin": b"\x00\x01\x02\x03",
        "frontend/package-lock.json": b'{"lockfileVersion": 3}\n',
        "frontend/package.json": b'{"name": "frontend"}\n',
        "frontend/src/app.js": b"export const app = true;\n",
        "generated/__generated__/client.py": b"VALUE = True\n",
        "infra/main.tf": b'resource "null_resource" "main" {}\n',
        "pyproject.toml": b"[project]\nname = 'root'\n",
        "src/app.py": b"APP = True\n",
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
    support_policy = SourceSupportPolicy(
        language_rules=(
            LanguageSupportRule(
                "JavaScript",
                SourceSupportState.DETECTED,
                "JAVASCRIPT_DETECTED_ONLY",
            ),
            LanguageSupportRule(
                "Python",
                SourceSupportState.SCANNABLE,
                "PYTHON_SCANNABLE_BY_POLICY",
            ),
        ),
        capability_rules=tuple(
            sorted(
                (
                    CapabilitySupportRule(
                        AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING,
                        SourceSupportState.DETECTED,
                    ),
                    CapabilitySupportRule(
                        AnalysisCapability.DOCKERFILE_POLICY,
                        SourceSupportState.UNSUPPORTED,
                        "DOCKERFILE_UNSUPPORTED",
                    ),
                    CapabilitySupportRule(
                        AnalysisCapability.PACKAGE_INVENTORY,
                        SourceSupportState.SCANNABLE,
                    ),
                    CapabilitySupportRule(
                        AnalysisCapability.PYTHON_SAST,
                        SourceSupportState.SCANNABLE,
                    ),
                    CapabilitySupportRule(
                        AnalysisCapability.REPOSITORY_PROFILING,
                        SourceSupportState.PRODUCT_SUPPORTED,
                    ),
                    CapabilitySupportRule(
                        AnalysisCapability.SECRET_DETECTION,
                        SourceSupportState.SCANNABLE,
                    ),
                    CapabilitySupportRule(
                        AnalysisCapability.TERRAFORM_SOURCE_POLICY,
                        SourceSupportState.SCANNABLE,
                    ),
                ),
                key=lambda rule: rule.capability.value,
            )
        ),
    )
    registry = TrustedSourceAnalyzerRegistry(
        analyzers=tuple(
            sorted(
                (
                    TrustedSourceAnalyzer(
                        "package-test",
                        (AnalysisCapability.PACKAGE_INVENTORY,),
                        False,
                        "PACKAGE_ANALYZER_UNAVAILABLE",
                    ),
                    TrustedSourceAnalyzer(
                        "python-sast-test",
                        (AnalysisCapability.PYTHON_SAST,),
                        True,
                    ),
                    TrustedSourceAnalyzer(
                        "secret-test",
                        (AnalysisCapability.SECRET_DETECTION,),
                        True,
                    ),
                    TrustedSourceAnalyzer(
                        "terraform-test",
                        (AnalysisCapability.TERRAFORM_SOURCE_POLICY,),
                        True,
                    ),
                ),
                key=lambda analyzer: analyzer.analyzer_id,
            )
        )
    )
    planning_policy = _policy(
        AnalysisCapability.PYTHON_SAST,
        SourceFileFlag.GENERATED,
        SourceFileFlag.VENDORED,
    )

    try:
        inventory = build_repository_inventory(workspace)
        language_profile = profile_repository_languages(
            workspace,
            inventory,
            client,
            policy=SourceLanguageProfilingPolicy(sample_bytes=1024),
        )
        enriched = enrich_repository_inventory(inventory, language_profile)
        componentized = detect_repository_components(enriched)
        assessment = assess_repository_language_support(
            componentized,
            support_policy,
        )
        profile = build_repository_profile(
            componentized,
            assessment,
            support_policy,
        )
        plan = build_source_analysis_plan(profile, registry, planning_policy)
        components = {
            component.root_path: component.component_id
            for component in profile.components
        }

        profiling = _target_entry(plan, AnalysisCapability.REPOSITORY_PROFILING)
        assert profiling.action is SourcePlanAction.SATISFIED
        assert profiling.analyzer_id is None

        python = _target_entry(plan, AnalysisCapability.PYTHON_SAST)
        assert python.action is SourcePlanAction.RUN
        assert python.analyzer_id == "python-sast-test"
        assert python.selected_paths == ("src/app.py",)
        assert python.excluded_paths == (
            SourcePlanPathExclusion(
                "generated/__generated__/client.py",
                "EXCLUDED_GENERATED",
            ),
            SourcePlanPathExclusion("vendor/sdk.py", "EXCLUDED_VENDORED"),
        )

        secret = _target_entry(plan, AnalysisCapability.SECRET_DETECTION)
        assert secret.action is SourcePlanAction.RUN
        assert "asset.bin" not in secret.selected_paths

        package_entries = tuple(
            entry
            for entry in plan.entries
            if entry.capability is AnalysisCapability.PACKAGE_INVENTORY
        )
        assert package_entries
        assert all(entry.reason_code == "ANALYZER_UNAVAILABLE" for entry in package_entries)
        assert all(entry.analyzer_id == "package-test" for entry in package_entries)

        advisory_entries = tuple(
            entry
            for entry in plan.entries
            if entry.capability is AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING
        )
        assert advisory_entries
        assert all(
            entry.reason_code == "CAPABILITY_DETECTED_ONLY"
            for entry in advisory_entries
        )

        docker_entries = tuple(
            entry
            for entry in plan.entries
            if entry.capability is AnalysisCapability.DOCKERFILE_POLICY
        )
        assert docker_entries
        assert all(entry.reason_code == "CAPABILITY_UNSUPPORTED" for entry in docker_entries)

        terraform = _target_entry(
            plan,
            AnalysisCapability.TERRAFORM_SOURCE_POLICY,
            components["infra"],
        )
        assert terraform.action is SourcePlanAction.RUN
        assert terraform.selected_paths == ("infra/main.tf",)
        assert not hasattr(plan, "execution_status")
        assert not hasattr(plan, "coverage_status")
        assert not hasattr(plan, "tool_executions")
    finally:
        manager.cleanup_workspace(workspace)
