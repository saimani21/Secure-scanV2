from __future__ import annotations

from dataclasses import replace

from securescan.source.components import ComponentizedRepositoryInventory
from securescan.source.enums import (
    AnalysisCapability,
    FileContentKind,
    SourceFileFlag,
    SourceSupportState,
)
from securescan.source.models import (
    AnalysisSurface,
    LanguageSupport,
    RepositoryProfile,
    SourceFileRecord,
)
from securescan.source.support import (
    RepositoryLanguageSupportAssessment,
    SourceSupportPolicy,
    SourceSupportPolicyError,
    assess_repository_language_support,
)

_EXECUTABLE_LANGUAGE_STATES = frozenset(
    {
        SourceSupportState.BENCHMARKED,
        SourceSupportState.PRODUCT_SUPPORTED,
        SourceSupportState.SCANNABLE,
    }
)
_REPOSITORY_LEVEL_CAPABILITIES = (
    AnalysisCapability.CONFIGURATION_SECURITY,
    AnalysisCapability.PYTHON_SAST,
    AnalysisCapability.SECRET_DETECTION,
)
_COMPONENT_GROUPED_CAPABILITIES = tuple(
    sorted(
        (
            AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING,
            AnalysisCapability.DOCKERFILE_POLICY,
            AnalysisCapability.PACKAGE_INVENTORY,
            AnalysisCapability.TERRAFORM_SOURCE_POLICY,
        ),
        key=lambda capability: capability.value,
    )
)


class SourceCoverageError(RuntimeError):
    """Raised when deterministic source coverage assembly cannot complete."""

    def __init__(self) -> None:
        super().__init__("Source coverage assembly failed")


class InvalidSourceCoverageRequestError(SourceCoverageError, ValueError):
    """Raised when source coverage assembly receives an invalid request."""

    def __init__(self) -> None:
        RuntimeError.__init__(self, "Source coverage request is invalid")


class SourceCoverageCorrelationError(SourceCoverageError):
    """Raised when trusted profile inputs do not correlate exactly."""

    def __init__(self) -> None:
        RuntimeError.__init__(self, "Source coverage correlation failed")


def _finalize_file_applicability(file: SourceFileRecord) -> SourceFileRecord:
    capabilities = set(file.eligible_capabilities)
    if (
        file.language is not None
        and file.language.casefold() == "python"
        and file.content_kind is FileContentKind.TEXT
        and SourceFileFlag.BINARY not in file.flags
    ):
        capabilities.add(AnalysisCapability.PYTHON_SAST)
    return replace(
        file,
        eligible_capabilities=tuple(
            sorted(
                capabilities,
                key=lambda capability: capability.value,
            )
        ),
    )


def _surface(
    capability: AnalysisCapability,
    component_id: str | None,
    candidate_paths: tuple[str, ...],
    policy: SourceSupportPolicy,
) -> AnalysisSurface:
    rule = policy.capability_rule_for(capability)
    eligible_paths = (
        ()
        if rule.support_state is SourceSupportState.UNSUPPORTED
        else candidate_paths
    )
    return AnalysisSurface(
        capability=capability,
        component_id=component_id,
        eligible_paths=eligible_paths,
        support_state=rule.support_state,
        reason_code=rule.reason_code,
    )


def _build_surfaces(
    files: tuple[SourceFileRecord, ...],
    policy: SourceSupportPolicy,
) -> tuple[AnalysisSurface, ...]:
    surfaces = [
        _surface(
            AnalysisCapability.REPOSITORY_PROFILING,
            None,
            tuple(file.relative_path for file in files),
            policy,
        )
    ]

    for capability in _REPOSITORY_LEVEL_CAPABILITIES:
        paths = tuple(
            file.relative_path
            for file in files
            if capability in file.eligible_capabilities
        )
        if paths:
            surfaces.append(_surface(capability, None, paths, policy))

    for capability in _COMPONENT_GROUPED_CAPABILITIES:
        paths_by_component: dict[str | None, list[str]] = {}
        for file in files:
            if capability in file.eligible_capabilities:
                paths_by_component.setdefault(file.component_id, []).append(
                    file.relative_path
                )
        for component_id in sorted(
            paths_by_component,
            key=lambda value: value or "",
        ):
            surfaces.append(
                _surface(
                    capability,
                    component_id,
                    tuple(paths_by_component[component_id]),
                    policy,
                )
            )

    return tuple(
        sorted(
            surfaces,
            key=lambda surface: (
                surface.capability.value,
                surface.component_id or "",
            ),
        )
    )


def _build_language_support(
    assessment: RepositoryLanguageSupportAssessment,
) -> tuple[LanguageSupport, ...]:
    return tuple(
        LanguageSupport(
            language=decision.language,
            file_count=decision.file_count,
            eligible_file_count=(
                decision.source_file_count
                if decision.support_state in _EXECUTABLE_LANGUAGE_STATES
                else 0
            ),
            support_state=decision.support_state,
            reason_code=decision.reason_code,
        )
        for decision in assessment.languages
    )


def build_repository_profile(
    inventory: ComponentizedRepositoryInventory,
    language_assessment: RepositoryLanguageSupportAssessment,
    policy: SourceSupportPolicy,
) -> RepositoryProfile:
    if (
        not isinstance(inventory, ComponentizedRepositoryInventory)
        or not isinstance(
            language_assessment,
            RepositoryLanguageSupportAssessment,
        )
        or not isinstance(policy, SourceSupportPolicy)
    ):
        raise InvalidSourceCoverageRequestError

    if (
        language_assessment.repository_digest != inventory.repository_digest
        or language_assessment.policy_digest != policy.policy_digest()
    ):
        raise SourceCoverageCorrelationError

    try:
        expected_assessment = assess_repository_language_support(
            inventory,
            policy,
        )
    except SourceSupportPolicyError:
        raise SourceCoverageCorrelationError from None
    if language_assessment != expected_assessment:
        raise SourceCoverageCorrelationError

    try:
        files = tuple(_finalize_file_applicability(file) for file in inventory.files)
        return RepositoryProfile(
            repository_digest=inventory.repository_digest,
            files=files,
            components=inventory.components,
            languages=_build_language_support(language_assessment),
            surfaces=_build_surfaces(files, policy),
        )
    except (TypeError, ValueError, SourceSupportPolicyError):
        raise SourceCoverageCorrelationError from None
