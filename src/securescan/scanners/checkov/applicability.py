from __future__ import annotations

from dataclasses import replace
from pathlib import PurePosixPath
from typing import Final

from securescan.scanners.checkov.binding import (
    CHECKOV_SOURCE_ANALYZER_ID,
    CheckovBindingError,
    CheckovConfigurationIntegrityError,
    CheckovExecutableIntegrityError,
    CheckovToolchainIntegrityError,
    CheckovVersionVerificationError,
    TrustedCheckovBinding,
)
from securescan.source.enums import AnalysisCapability, FileContentKind, SourceSupportState
from securescan.source.models import AnalysisSurface, RepositoryProfile
from securescan.source.planning import (
    CapabilityPathSelectionRule,
    SourcePlanningPolicy,
    TrustedSourceAnalyzer,
)
from securescan.source.support import CapabilitySupportRule, SourceSupportPolicy

CHECKOV_APPLICABILITY_SCHEMA_VERSION: Final = "securescan-checkov-applicability-s3"
CHECKOV_SCANNABLE_REASON: Final = "CHECKOV_FIVE_FRAMEWORK_SOURCE_SCANNABLE"
CHECKOV_EXECUTABLE_UNAVAILABLE: Final = "CHECKOV_EXECUTABLE_UNAVAILABLE"
CHECKOV_VERSION_UNAVAILABLE: Final = "CHECKOV_VERSION_UNAVAILABLE"
CHECKOV_CONFIGURATION_UNAVAILABLE: Final = "CHECKOV_CONFIGURATION_UNAVAILABLE"
CHECKOV_TOOLCHAIN_UNAVAILABLE: Final = "CHECKOV_TOOLCHAIN_UNAVAILABLE"


class CheckovApplicabilityError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Checkov Source applicability policy failed")


def _is_checkov_candidate(path: str) -> bool:
    item = PurePosixPath(path)
    name = item.name.casefold()
    lower = path.casefold()
    if name in {".checkov.yml", ".checkov.yaml", ".checkov.baseline"}:
        return False
    return (
        name == "dockerfile"
        or name.startswith("dockerfile.")
        or name.endswith(".tf")
        or name.endswith(".tf.json")
        or name.endswith((".yaml", ".yml", ".json"))
        or (lower.startswith(".github/workflows/") and name.endswith((".yaml", ".yml")))
    )


def with_checkov_source_support(policy: SourceSupportPolicy) -> SourceSupportPolicy:
    if not isinstance(policy, SourceSupportPolicy):
        raise CheckovApplicabilityError
    expected = CapabilitySupportRule(
        AnalysisCapability.CONFIGURATION_SECURITY,
        SourceSupportState.SCANNABLE,
        CHECKOV_SCANNABLE_REASON,
    )
    existing = next(
        (
            rule
            for rule in policy.capability_rules
            if rule.capability is AnalysisCapability.CONFIGURATION_SECURITY
        ),
        None,
    )
    if existing is not None:
        if existing != expected:
            raise CheckovApplicabilityError
        return policy
    return replace(
        policy,
        capability_rules=tuple(
            sorted((*policy.capability_rules, expected), key=lambda item: item.capability.value)
        ),
    )


def with_checkov_planning_policy(policy: SourcePlanningPolicy) -> SourcePlanningPolicy:
    if not isinstance(policy, SourcePlanningPolicy):
        raise CheckovApplicabilityError
    expected = CapabilityPathSelectionRule(AnalysisCapability.CONFIGURATION_SECURITY, ())
    existing = next(
        (
            rule
            for rule in policy.path_rules
            if rule.capability is AnalysisCapability.CONFIGURATION_SECURITY
        ),
        None,
    )
    if existing is not None:
        if existing != expected:
            raise CheckovApplicabilityError
        return policy
    return replace(
        policy,
        path_rules=tuple(
            sorted((*policy.path_rules, expected), key=lambda item: item.capability.value)
        ),
    )


def apply_checkov_source_applicability(
    profile: RepositoryProfile,
    support_policy: SourceSupportPolicy,
) -> RepositoryProfile:
    if not isinstance(profile, RepositoryProfile) or not isinstance(
        support_policy, SourceSupportPolicy
    ):
        raise CheckovApplicabilityError
    support = support_policy.capability_rule_for(AnalysisCapability.CONFIGURATION_SECURITY)
    if support.support_state is not SourceSupportState.SCANNABLE:
        raise CheckovApplicabilityError
    existing = tuple(
        surface
        for surface in profile.surfaces
        if surface.capability is AnalysisCapability.CONFIGURATION_SECURITY
    )
    if len(existing) > 1 or any(item.component_id is not None for item in existing):
        raise CheckovApplicabilityError
    paths = tuple(
        file.relative_path
        for file in profile.files
        if file.content_kind is FileContentKind.TEXT and _is_checkov_candidate(file.relative_path)
    )
    path_set = frozenset(paths)
    files = tuple(
        replace(
            file,
            eligible_capabilities=tuple(
                sorted(
                    (
                        {*file.eligible_capabilities, AnalysisCapability.CONFIGURATION_SECURITY}
                        if file.relative_path in path_set
                        else set(file.eligible_capabilities)
                        - {AnalysisCapability.CONFIGURATION_SECURITY}
                    ),
                    key=lambda capability: capability.value,
                )
            ),
        )
        for file in profile.files
    )
    other_surfaces = tuple(
        item
        for item in profile.surfaces
        if item.capability is not AnalysisCapability.CONFIGURATION_SECURITY
    )
    surfaces = (*other_surfaces,)
    if paths:
        surfaces = (
            *surfaces,
            AnalysisSurface(
                capability=AnalysisCapability.CONFIGURATION_SECURITY,
                support_state=SourceSupportState.SCANNABLE,
                component_id=None,
                eligible_paths=paths,
                reason_code=CHECKOV_SCANNABLE_REASON,
            ),
        )
    return replace(
        profile,
        files=files,
        surfaces=tuple(
            sorted(surfaces, key=lambda item: (item.capability.value, item.component_id or ""))
        ),
    )


def build_checkov_source_analyzer_snapshot(
    binding: TrustedCheckovBinding,
    executor: object | None = None,
) -> TrustedSourceAnalyzer:
    if not isinstance(binding, TrustedCheckovBinding):
        raise CheckovApplicabilityError
    unavailable: str | None = None
    try:
        binding.verify_runtime(executor)  # type: ignore[arg-type]
    except CheckovExecutableIntegrityError:
        unavailable = CHECKOV_EXECUTABLE_UNAVAILABLE
    except CheckovVersionVerificationError:
        unavailable = CHECKOV_VERSION_UNAVAILABLE
    except CheckovConfigurationIntegrityError:
        unavailable = CHECKOV_CONFIGURATION_UNAVAILABLE
    except CheckovToolchainIntegrityError:
        unavailable = CHECKOV_TOOLCHAIN_UNAVAILABLE
    except CheckovBindingError:
        raise CheckovApplicabilityError from None
    return TrustedSourceAnalyzer(
        analyzer_id=CHECKOV_SOURCE_ANALYZER_ID,
        capabilities=(AnalysisCapability.CONFIGURATION_SECURITY,),
        available=unavailable is None,
        unavailable_reason_code=unavailable,
    )
