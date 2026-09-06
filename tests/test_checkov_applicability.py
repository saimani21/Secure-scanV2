from __future__ import annotations

import hashlib

from securescan.scanners.checkov import (
    CHECKOV_SCANNABLE_REASON,
    apply_checkov_source_applicability,
    with_checkov_planning_policy,
    with_checkov_source_support,
)
from securescan.source.enums import (
    AnalysisCapability,
    FileContentKind,
    SourceFileFlag,
    SourceFileRole,
    SourceSupportState,
)
from securescan.source.models import AnalysisSurface, RepositoryProfile, SourceFileRecord
from securescan.source.planning import (
    SourcePlanAction,
    SourcePlanningPolicy,
    TrustedSourceAnalyzer,
    TrustedSourceAnalyzerRegistry,
    build_source_analysis_plan,
)
from securescan.source.support import SourceSupportPolicy
from securescan.workspaces.models import RepositoryManifestEntry, repository_content_digest


def _record(
    path: str,
    *,
    binary: bool = False,
) -> SourceFileRecord:
    content = path.encode()
    return SourceFileRecord(
        entry=RepositoryManifestEntry(path, len(content), hashlib.sha256(content).hexdigest()),
        content_kind=FileContentKind.BINARY if binary else FileContentKind.TEXT,
        role=SourceFileRole.BINARY if binary else SourceFileRole.CONFIGURATION,
        flags=(SourceFileFlag.BINARY,) if binary else (),
        eligible_capabilities=(AnalysisCapability.REPOSITORY_PROFILING,),
    )


def _profile(*records: SourceFileRecord) -> RepositoryProfile:
    files = tuple(sorted(records, key=lambda item: item.relative_path))
    paths = tuple(item.relative_path for item in files)
    return RepositoryProfile(
        repository_digest=repository_content_digest(tuple(item.entry for item in files)),
        files=files,
        surfaces=(
            AnalysisSurface(
                capability=AnalysisCapability.REPOSITORY_PROFILING,
                support_state=SourceSupportState.DETECTED,
                component_id=None,
                eligible_paths=paths,
            ),
        ),
    )


def test_five_framework_applicability_and_planning() -> None:
    profile = _profile(
        _record("infra/main.tf"),
        _record("cloud/template.yaml"),
        _record("deploy/pod.yml"),
        _record("containers/Dockerfile"),
        _record(".github/workflows/build.yml"),
        _record("README.md"),
        _record("binary.yaml", binary=True),
    )
    support = with_checkov_source_support(SourceSupportPolicy())
    result = apply_checkov_source_applicability(profile, support)
    surface = next(
        item
        for item in result.surfaces
        if item.capability is AnalysisCapability.CONFIGURATION_SECURITY
    )
    assert surface.support_state is SourceSupportState.SCANNABLE
    assert surface.reason_code == CHECKOV_SCANNABLE_REASON
    assert surface.eligible_paths == (
        ".github/workflows/build.yml",
        "cloud/template.yaml",
        "containers/Dockerfile",
        "deploy/pod.yml",
        "infra/main.tf",
    )
    analyzer = TrustedSourceAnalyzer(
        analyzer_id="checkov-source-v1",
        capabilities=(AnalysisCapability.CONFIGURATION_SECURITY,),
        available=True,
    )
    plan = build_source_analysis_plan(
        result,
        TrustedSourceAnalyzerRegistry(analyzers=(analyzer,)),
        with_checkov_planning_policy(SourcePlanningPolicy()),
    )
    entry = next(
        item
        for item in plan.entries
        if item.capability is AnalysisCapability.CONFIGURATION_SECURITY
    )
    assert entry.action is SourcePlanAction.RUN
    assert entry.selected_paths == surface.eligible_paths


def test_repository_checkov_configuration_cannot_enter_scanner_projection() -> None:
    profile = _profile(
        _record(".checkov.yml"),
        _record("nested/.checkov.yaml"),
        _record(".checkov.baseline"),
        _record("main.tf"),
    )
    result = apply_checkov_source_applicability(
        profile,
        with_checkov_source_support(SourceSupportPolicy()),
    )
    surface = next(
        item
        for item in result.surfaces
        if item.capability is AnalysisCapability.CONFIGURATION_SECURITY
    )
    assert surface.eligible_paths == ("main.tf",)


def test_no_iac_or_configuration_is_not_applicable() -> None:
    result = apply_checkov_source_applicability(
        _profile(_record("README.md")),
        with_checkov_source_support(SourceSupportPolicy()),
    )
    assert all(
        item.capability is not AnalysisCapability.CONFIGURATION_SECURITY for item in result.surfaces
    )


def test_generic_yaml_and_json_are_conservative_discovery_candidates() -> None:
    result = apply_checkov_source_applicability(
        _profile(_record("settings.yaml"), _record("data.json")),
        with_checkov_source_support(SourceSupportPolicy()),
    )
    surface = next(
        item
        for item in result.surfaces
        if item.capability is AnalysisCapability.CONFIGURATION_SECURITY
    )
    assert surface.eligible_paths == ("data.json", "settings.yaml")
