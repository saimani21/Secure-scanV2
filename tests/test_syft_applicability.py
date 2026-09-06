from __future__ import annotations

import hashlib

from securescan.scanners.syft import (
    SYFT_SCANNABLE_REASON,
    apply_syft_source_applicability,
    with_syft_planning_policy,
    with_syft_source_support,
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


def _record(path: str, flag: SourceFileFlag | None = None) -> SourceFileRecord:
    content = path.encode()
    binary = flag is SourceFileFlag.BINARY
    return SourceFileRecord(
        entry=RepositoryManifestEntry(path, len(content), hashlib.sha256(content).hexdigest()),
        content_kind=FileContentKind.BINARY if binary else FileContentKind.TEXT,
        role=SourceFileRole.BINARY if binary else SourceFileRole.OTHER,
        flags=() if flag is None else (flag,),
        eligible_capabilities=(AnalysisCapability.REPOSITORY_PROFILING,),
    )


def test_syft_is_scannable_and_excludes_no_source_flags() -> None:
    support = with_syft_source_support(SourceSupportPolicy())
    rule = support.capability_rule_for(AnalysisCapability.PACKAGE_INVENTORY)
    assert rule.support_state is SourceSupportState.SCANNABLE
    assert rule.reason_code == SYFT_SCANNABLE_REASON
    planning = with_syft_planning_policy(SourcePlanningPolicy())
    assert planning.excluded_flags_for(AnalysisCapability.PACKAGE_INVENTORY) == ()


def test_repository_wide_overlay_includes_test_vendor_generated_binary_and_unknown() -> None:
    files = tuple(
        sorted(
            (
                _record("binary.bin", SourceFileFlag.BINARY),
                _record("generated/out.txt", SourceFileFlag.GENERATED),
                _record("tests/data.txt", SourceFileFlag.TEST),
                _record("vendor/pkg.txt", SourceFileFlag.VENDORED),
                _record("unknown.weird"),
            ),
            key=lambda item: item.relative_path,
        )
    )
    profile = RepositoryProfile(
        repository_digest=repository_content_digest(tuple(item.entry for item in files)),
        files=files,
        surfaces=(
            AnalysisSurface(
                capability=AnalysisCapability.REPOSITORY_PROFILING,
                support_state=SourceSupportState.DETECTED,
                eligible_paths=tuple(item.relative_path for item in files),
            ),
        ),
    )
    result = apply_syft_source_applicability(
        profile, with_syft_source_support(SourceSupportPolicy())
    )
    surface = next(
        item for item in result.surfaces if item.capability is AnalysisCapability.PACKAGE_INVENTORY
    )
    assert surface.eligible_paths == tuple(item.relative_path for item in files)
    assert all(
        AnalysisCapability.PACKAGE_INVENTORY in item.eligible_capabilities for item in result.files
    )
    analyzer = TrustedSourceAnalyzer(
        analyzer_id="syft-source-v1",
        capabilities=(AnalysisCapability.PACKAGE_INVENTORY,),
        available=True,
    )
    plan = build_source_analysis_plan(
        result,
        TrustedSourceAnalyzerRegistry(analyzers=(analyzer,)),
        with_syft_planning_policy(SourcePlanningPolicy()),
    )
    entry = next(
        item for item in plan.entries if item.capability is AnalysisCapability.PACKAGE_INVENTORY
    )
    assert entry.action is SourcePlanAction.RUN
    assert entry.selected_paths == tuple(item.relative_path for item in files)
    assert entry.excluded_paths == ()
