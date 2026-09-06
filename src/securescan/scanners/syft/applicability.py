from __future__ import annotations

from dataclasses import replace
from typing import Final

from securescan.scanners.syft.binding import (
    SYFT_SOURCE_ANALYZER_ID,
    SyftBindingError,
    SyftConfigurationIntegrityError,
    SyftExecutableIntegrityError,
    SyftVersionVerificationError,
    TrustedSyftBinding,
)
from securescan.source.enums import AnalysisCapability, SourceSupportState
from securescan.source.models import AnalysisSurface, RepositoryProfile
from securescan.source.planning import (
    CapabilityPathSelectionRule,
    SourcePlanningPolicy,
    TrustedSourceAnalyzer,
)
from securescan.source.support import CapabilitySupportRule, SourceSupportPolicy

SYFT_APPLICABILITY_SCHEMA_VERSION: Final = "securescan-syft-applicability-s1"
SYFT_SCANNABLE_REASON: Final = "SYFT_DIRECTORY_INVENTORY_SCANNABLE"
SYFT_EXECUTABLE_UNAVAILABLE: Final = "SYFT_EXECUTABLE_UNAVAILABLE"
SYFT_VERSION_UNAVAILABLE: Final = "SYFT_VERSION_UNAVAILABLE"
SYFT_CONFIGURATION_UNAVAILABLE: Final = "SYFT_CONFIGURATION_UNAVAILABLE"


class SyftApplicabilityError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Syft Source applicability policy failed")


def with_syft_source_support(policy: SourceSupportPolicy) -> SourceSupportPolicy:
    if not isinstance(policy, SourceSupportPolicy):
        raise SyftApplicabilityError
    expected = CapabilitySupportRule(
        AnalysisCapability.PACKAGE_INVENTORY,
        SourceSupportState.SCANNABLE,
        SYFT_SCANNABLE_REASON,
    )
    existing = next(
        (
            rule
            for rule in policy.capability_rules
            if rule.capability is AnalysisCapability.PACKAGE_INVENTORY
        ),
        None,
    )
    if existing is not None:
        if existing != expected:
            raise SyftApplicabilityError
        return policy
    return replace(
        policy,
        capability_rules=tuple(
            sorted(
                (*policy.capability_rules, expected),
                key=lambda item: item.capability.value,
            )
        ),
    )


def with_syft_planning_policy(policy: SourcePlanningPolicy) -> SourcePlanningPolicy:
    if not isinstance(policy, SourcePlanningPolicy):
        raise SyftApplicabilityError
    expected = CapabilityPathSelectionRule(
        AnalysisCapability.PACKAGE_INVENTORY,
        (),
    )
    existing = next(
        (
            rule
            for rule in policy.path_rules
            if rule.capability is AnalysisCapability.PACKAGE_INVENTORY
        ),
        None,
    )
    if existing is not None:
        if existing != expected:
            raise SyftApplicabilityError
        return policy
    return replace(
        policy,
        path_rules=tuple(
            sorted((*policy.path_rules, expected), key=lambda item: item.capability.value)
        ),
    )


def apply_syft_source_applicability(
    profile: RepositoryProfile,
    support_policy: SourceSupportPolicy,
) -> RepositoryProfile:
    if not isinstance(profile, RepositoryProfile) or not isinstance(
        support_policy, SourceSupportPolicy
    ):
        raise SyftApplicabilityError
    support = support_policy.capability_rule_for(AnalysisCapability.PACKAGE_INVENTORY)
    if support.support_state is not SourceSupportState.SCANNABLE:
        raise SyftApplicabilityError
    existing = tuple(
        surface
        for surface in profile.surfaces
        if surface.capability is AnalysisCapability.PACKAGE_INVENTORY
    )
    if len(existing) > 1 or any(surface.component_id is not None for surface in existing):
        raise SyftApplicabilityError
    paths = tuple(file.relative_path for file in profile.files)
    files = tuple(
        replace(
            file,
            eligible_capabilities=tuple(
                sorted(
                    {*file.eligible_capabilities, AnalysisCapability.PACKAGE_INVENTORY},
                    key=lambda capability: capability.value,
                )
            ),
        )
        for file in profile.files
    )
    surfaces = tuple(
        sorted(
            (
                *(
                    surface
                    for surface in profile.surfaces
                    if surface.capability is not AnalysisCapability.PACKAGE_INVENTORY
                ),
                *(
                    (
                        AnalysisSurface(
                            capability=AnalysisCapability.PACKAGE_INVENTORY,
                            support_state=SourceSupportState.SCANNABLE,
                            component_id=None,
                            eligible_paths=paths,
                            reason_code=SYFT_SCANNABLE_REASON,
                        ),
                    )
                    if paths
                    else ()
                ),
            ),
            key=lambda surface: (surface.capability.value, surface.component_id or ""),
        )
    )
    return replace(profile, files=files, surfaces=surfaces)


def build_syft_source_analyzer_snapshot(
    binding: TrustedSyftBinding,
    executor: object | None = None,
) -> TrustedSourceAnalyzer:
    if not isinstance(binding, TrustedSyftBinding):
        raise SyftApplicabilityError
    unavailable: str | None = None
    try:
        binding.verify_runtime(executor)  # type: ignore[arg-type]
    except SyftExecutableIntegrityError:
        unavailable = SYFT_EXECUTABLE_UNAVAILABLE
    except SyftVersionVerificationError:
        unavailable = SYFT_VERSION_UNAVAILABLE
    except SyftConfigurationIntegrityError:
        unavailable = SYFT_CONFIGURATION_UNAVAILABLE
    except SyftBindingError:
        raise SyftApplicabilityError from None
    return TrustedSourceAnalyzer(
        analyzer_id=SYFT_SOURCE_ANALYZER_ID,
        capabilities=(AnalysisCapability.PACKAGE_INVENTORY,),
        available=unavailable is None,
        unavailable_reason_code=unavailable,
    )
