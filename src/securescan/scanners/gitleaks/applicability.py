from __future__ import annotations

from dataclasses import replace
from typing import Final

from securescan.scanners.gitleaks.binding import (
    GitleaksBindingError,
    GitleaksConfigurationIntegrityError,
    GitleaksExecutableIntegrityError,
    GitleaksVersionVerificationError,
    TrustedGitleaksBinding,
)
from securescan.scanners.gitleaks.source_execution import (
    GITLEAKS_SOURCE_ANALYZER_ID,
)
from securescan.source.enums import (
    AnalysisCapability,
    SourceSupportState,
)
from securescan.source.models import (
    AnalysisSurface,
    RepositoryProfile,
    SourceFileRecord,
)
from securescan.source.planning import (
    CapabilityPathSelectionRule,
    SourcePlanningPolicy,
    TrustedSourceAnalyzer,
)
from securescan.source.support import (
    CapabilitySupportRule,
    SourceSupportPolicy,
)

GITLEAKS_APPLICABILITY_SCHEMA_VERSION: Final = (
    "securescan-gitleaks-applicability-v0.4D"
)
GITLEAKS_V04C_BASELINE_COMMIT: Final = (
    "d488fd96eb573687d9887c829d4d5bf26b31fc9a"
)

GITLEAKS_SCANNABLE_REASON: Final = (
    "GITLEAKS_CURRENT_SNAPSHOT_SCANNABLE"
)
GITLEAKS_EXECUTABLE_UNAVAILABLE: Final = (
    "GITLEAKS_EXECUTABLE_UNAVAILABLE"
)
GITLEAKS_VERSION_UNAVAILABLE: Final = (
    "GITLEAKS_VERSION_UNAVAILABLE"
)
GITLEAKS_CONFIGURATION_UNAVAILABLE: Final = (
    "GITLEAKS_CONFIGURATION_UNAVAILABLE"
)


class GitleaksApplicabilityError(RuntimeError):
    """Fixed-message failure for Gitleaks Source applicability policy."""

    def __init__(self) -> None:
        super().__init__("Gitleaks Source applicability policy failed")


def _validated_profile(profile: object) -> RepositoryProfile:
    if not isinstance(profile, RepositoryProfile):
        raise GitleaksApplicabilityError

    try:
        validated = replace(
            profile,
            files=tuple(replace(file) for file in profile.files),
            components=tuple(
                replace(component) for component in profile.components
            ),
            languages=tuple(
                replace(language) for language in profile.languages
            ),
            surfaces=tuple(
                replace(surface) for surface in profile.surfaces
            ),
        )
    except Exception:
        raise GitleaksApplicabilityError from None

    if validated != profile:
        raise GitleaksApplicabilityError

    return profile


def _validated_support_policy(
    policy: object,
) -> SourceSupportPolicy:
    if not isinstance(policy, SourceSupportPolicy):
        raise GitleaksApplicabilityError

    try:
        validated = replace(
            policy,
            language_rules=tuple(
                replace(rule) for rule in policy.language_rules
            ),
            capability_rules=tuple(
                replace(rule) for rule in policy.capability_rules
            ),
        )
    except Exception:
        raise GitleaksApplicabilityError from None

    if validated != policy:
        raise GitleaksApplicabilityError

    return policy


def _validated_planning_policy(
    policy: object,
) -> SourcePlanningPolicy:
    if not isinstance(policy, SourcePlanningPolicy):
        raise GitleaksApplicabilityError

    try:
        validated = replace(
            policy,
            path_rules=tuple(
                replace(rule) for rule in policy.path_rules
            ),
        )
    except Exception:
        raise GitleaksApplicabilityError from None

    if validated != policy:
        raise GitleaksApplicabilityError

    return policy


def with_gitleaks_source_support(
    policy: SourceSupportPolicy,
) -> SourceSupportPolicy:
    """
    Add the frozen Source-v1 Gitleaks support declaration.

    An explicit contradictory SECRET_DETECTION rule is rejected instead of
    silently replacing policy selected elsewhere.
    """

    trusted = _validated_support_policy(policy)

    expected = CapabilitySupportRule(
        capability=AnalysisCapability.SECRET_DETECTION,
        support_state=SourceSupportState.SCANNABLE,
        reason_code=GITLEAKS_SCANNABLE_REASON,
    )

    existing = next(
        (
            rule
            for rule in trusted.capability_rules
            if rule.capability is AnalysisCapability.SECRET_DETECTION
        ),
        None,
    )

    if existing is not None:
        if existing.support_state is not SourceSupportState.SCANNABLE:
            raise GitleaksApplicabilityError
        return trusted

    rules = tuple(
        sorted(
            (*trusted.capability_rules, expected),
            key=lambda rule: rule.capability.value,
        )
    )

    try:
        return replace(
            trusted,
            capability_rules=rules,
        )
    except Exception:
        raise GitleaksApplicabilityError from None


def with_gitleaks_planning_policy(
    policy: SourcePlanningPolicy,
) -> SourcePlanningPolicy:
    """
    Freeze Gitleaks Source-v1 path selection to zero SecureScan exclusions.

    Gitleaks receives the whole declared current-snapshot surface. Test,
    generated, vendored and binary flags are not silently suppressed here.
    """

    trusted = _validated_planning_policy(policy)

    expected = CapabilityPathSelectionRule(
        capability=AnalysisCapability.SECRET_DETECTION,
        excluded_flags=(),
    )

    existing = next(
        (
            rule
            for rule in trusted.path_rules
            if rule.capability is AnalysisCapability.SECRET_DETECTION
        ),
        None,
    )

    if existing is not None and existing != expected:
        raise GitleaksApplicabilityError

    if existing is not None:
        return trusted

    rules = tuple(
        sorted(
            (*trusted.path_rules, expected),
            key=lambda rule: rule.capability.value,
        )
    )

    try:
        return replace(
            trusted,
            path_rules=rules,
        )
    except Exception:
        raise GitleaksApplicabilityError from None


def apply_gitleaks_source_applicability(
    profile: RepositoryProfile,
    support_policy: SourceSupportPolicy,
) -> RepositoryProfile:
    """
    Expand SECRET_DETECTION to the repository-wide immutable Source surface.

    Generic inventory remains untouched. This scanner-specific enrichment is
    what allows path-only Gitleaks rules such as pkcs12-file to remain
    reachable even when inventory classified the target as binary.
    """

    trusted = _validated_profile(profile)
    trusted_policy = _validated_support_policy(support_policy)

    support_rule = trusted_policy.capability_rule_for(
        AnalysisCapability.SECRET_DETECTION
    )
    if support_rule.support_state is not SourceSupportState.SCANNABLE:
        raise GitleaksApplicabilityError

    existing_secret_surfaces = tuple(
        surface
        for surface in trusted.surfaces
        if surface.capability is AnalysisCapability.SECRET_DETECTION
    )

    if (
        len(existing_secret_surfaces) > 1
        or any(
            surface.component_id is not None
            for surface in existing_secret_surfaces
        )
    ):
        raise GitleaksApplicabilityError

    existing_secret_surface = (
        existing_secret_surfaces[0]
        if existing_secret_surfaces
        else None
    )

    if (
        existing_secret_surface is not None
        and (
            existing_secret_surface.support_state
            is not SourceSupportState.SCANNABLE
            or existing_secret_surface.reason_code
            != support_rule.reason_code
        )
    ):
        # The scanner overlay expands technical scope only. Support maturity
        # remains authoritative in SourceSupportPolicy.
        raise GitleaksApplicabilityError

    all_paths = tuple(
        file.relative_path
        for file in trusted.files
    )

    enriched_files: list[SourceFileRecord] = []
    for file in trusted.files:
        capabilities = tuple(
            sorted(
                {
                    *file.eligible_capabilities,
                    AnalysisCapability.SECRET_DETECTION,
                },
                key=lambda capability: capability.value,
            )
        )
        try:
            enriched_files.append(
                replace(
                    file,
                    eligible_capabilities=capabilities,
                )
            )
        except Exception:
            raise GitleaksApplicabilityError from None

    secret_surfaces = (
        (
            AnalysisSurface(
                capability=AnalysisCapability.SECRET_DETECTION,
                support_state=SourceSupportState.SCANNABLE,
                component_id=None,
                eligible_paths=all_paths,
                reason_code=support_rule.reason_code,
            ),
        )
        if all_paths
        else ()
    )

    surfaces = tuple(
        sorted(
            (
                *(
                    surface
                    for surface in trusted.surfaces
                    if surface.capability
                    is not AnalysisCapability.SECRET_DETECTION
                ),
                *secret_surfaces,
            ),
            key=lambda surface: (
                surface.capability.value,
                surface.component_id or "",
            ),
        )
    )

    try:
        return replace(
            trusted,
            files=tuple(enriched_files),
            surfaces=surfaces,
        )
    except Exception:
        raise GitleaksApplicabilityError from None


def build_gitleaks_source_analyzer_snapshot(
    binding: TrustedGitleaksBinding,
    executor: object | None = None,
) -> TrustedSourceAnalyzer:
    """
    Produce planner-visible availability from the frozen trusted binding.

    This performs only Gitleaks runtime identity/configuration verification.
    It does not scan a repository.
    """

    if not isinstance(binding, TrustedGitleaksBinding):
        raise GitleaksApplicabilityError

    try:
        binding.binding_digest()
    except GitleaksBindingError:
        raise GitleaksApplicabilityError from None

    unavailable_reason: str | None = None

    try:
        binding.verify_runtime(executor)  # type: ignore[arg-type]
    except GitleaksExecutableIntegrityError:
        unavailable_reason = GITLEAKS_EXECUTABLE_UNAVAILABLE
    except GitleaksVersionVerificationError:
        unavailable_reason = GITLEAKS_VERSION_UNAVAILABLE
    except GitleaksConfigurationIntegrityError:
        unavailable_reason = GITLEAKS_CONFIGURATION_UNAVAILABLE
    except GitleaksBindingError:
        raise GitleaksApplicabilityError from None
    except Exception:
        raise GitleaksApplicabilityError from None

    return TrustedSourceAnalyzer(
        analyzer_id=GITLEAKS_SOURCE_ANALYZER_ID,
        capabilities=(AnalysisCapability.SECRET_DETECTION,),
        available=unavailable_reason is None,
        unavailable_reason_code=unavailable_reason,
    )
