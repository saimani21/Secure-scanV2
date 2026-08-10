from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any

from securescan.source.enums import (
    AnalysisCapability,
    SourceFileFlag,
    SourceSupportState,
)
from securescan.source.models import (
    AnalysisSurface,
    RepositoryProfile,
    SourceFileRecord,
)

_REGISTRY_STREAM_VERSION = b"securescan-source-analyzer-registry-v0.2.6\0"
_POLICY_STREAM_VERSION = b"securescan-source-planning-policy-v0.2.6\0"
_PLAN_STREAM_VERSION = b"securescan-source-analysis-plan-v0.2.6\0"
_IDENTIFIER_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z", re.ASCII)
_REASON_CODE_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{1,127}\Z", re.ASCII)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)

_EXECUTION_APPROVED_SUPPORT_STATES = frozenset(
    {
        SourceSupportState.BENCHMARKED,
        SourceSupportState.PRODUCT_SUPPORTED,
        SourceSupportState.SCANNABLE,
    }
)
_PLAN_REASON_CODES = frozenset(
    {
        "ANALYZER_UNAVAILABLE",
        "CAPABILITY_DETECTED_ONLY",
        "CAPABILITY_UNSUPPORTED",
        "NO_ANALYZER_REGISTERED",
        "NO_PATHS_AFTER_SELECTION_POLICY",
        "PLANNED",
        "UPSTREAM_CAPABILITY_SATISFIED",
    }
)
_EXCLUSION_REASON_CODES = frozenset(
    {
        "EXCLUDED_BINARY",
        "EXCLUDED_GENERATED",
        "EXCLUDED_TEST",
        "EXCLUDED_UNSUPPORTED",
        "EXCLUDED_VENDORED",
    }
)
_EXCLUSION_PRECEDENCE = (
    (SourceFileFlag.BINARY, "EXCLUDED_BINARY"),
    (SourceFileFlag.UNSUPPORTED, "EXCLUDED_UNSUPPORTED"),
    (SourceFileFlag.VENDORED, "EXCLUDED_VENDORED"),
    (SourceFileFlag.GENERATED, "EXCLUDED_GENERATED"),
    (SourceFileFlag.TEST, "EXCLUDED_TEST"),
)


class SourcePlanningError(RuntimeError):
    """Raised when deterministic Source planning cannot complete."""

    def __init__(self) -> None:
        super().__init__("Source planning failed")


class InvalidSourcePlanningRequestError(SourcePlanningError, ValueError):
    """Raised when a Source planning contract or request is invalid."""

    def __init__(self) -> None:
        RuntimeError.__init__(self, "Source planning request is invalid")


class SourcePlanningCorrelationError(SourcePlanningError):
    """Raised when trusted Source planning inputs do not correlate exactly."""

    def __init__(self) -> None:
        RuntimeError.__init__(self, "Source planning correlation failed")


class SourcePlanAction(StrEnum):
    RUN = "run"
    SKIP = "skip"
    SATISFIED = "satisfied"


def _valid_identifier(value: object) -> bool:
    return (
        isinstance(value, str)
        and _IDENTIFIER_PATTERN.fullmatch(value) is not None
    )


def _valid_reason_code(value: object) -> bool:
    return (
        isinstance(value, str)
        and _REASON_CODE_PATTERN.fullmatch(value) is not None
    )


def _valid_relative_path(value: object) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or any(unicodedata.category(character) == "Cc" for character in value)
    ):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and str(path) == value
        and all(component not in {"", ".", ".."} for component in path.parts)
    )


def _valid_sorted_path_tuple(value: object) -> bool:
    return (
        isinstance(value, tuple)
        and all(_valid_relative_path(path) for path in value)
        and value == tuple(sorted(value))
        and len(set(value)) == len(value)
    )


def _canonical_digest(domain: bytes, data: dict[str, Any]) -> str:
    payload = json.dumps(
        data,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    digest = hashlib.sha256()
    digest.update(domain)
    digest.update(payload)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class TrustedSourceAnalyzer:
    analyzer_id: str
    capabilities: tuple[AnalysisCapability, ...]
    available: bool
    unavailable_reason_code: str | None = None

    def __post_init__(self) -> None:
        if (
            not _valid_identifier(self.analyzer_id)
            or not isinstance(self.capabilities, tuple)
            or not self.capabilities
            or any(
                not isinstance(capability, AnalysisCapability)
                for capability in self.capabilities
            )
            or self.capabilities
            != tuple(
                sorted(
                    self.capabilities,
                    key=lambda capability: capability.value,
                )
            )
            or len(set(self.capabilities)) != len(self.capabilities)
            or AnalysisCapability.REPOSITORY_PROFILING in self.capabilities
            or type(self.available) is not bool
            or (
                self.available
                and self.unavailable_reason_code is not None
            )
            or (
                not self.available
                and not _valid_reason_code(self.unavailable_reason_code)
            )
        ):
            raise InvalidSourcePlanningRequestError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "analyzer_id": self.analyzer_id,
            "available": self.available,
            "capabilities": [
                capability.value for capability in self.capabilities
            ],
            "unavailable_reason_code": self.unavailable_reason_code,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class TrustedSourceAnalyzerRegistry:
    analyzers: tuple[TrustedSourceAnalyzer, ...] = ()
    schema_version: str = "0.2.6"

    def __post_init__(self) -> None:
        capabilities = (
            tuple(
                capability
                for analyzer in self.analyzers
                for capability in analyzer.capabilities
            )
            if isinstance(self.analyzers, tuple)
            and all(
                isinstance(analyzer, TrustedSourceAnalyzer)
                for analyzer in self.analyzers
            )
            else ()
        )
        if (
            self.schema_version != "0.2.6"
            or not isinstance(self.analyzers, tuple)
            or any(
                not isinstance(analyzer, TrustedSourceAnalyzer)
                for analyzer in self.analyzers
            )
            or self.analyzers
            != tuple(
                sorted(
                    self.analyzers,
                    key=lambda analyzer: analyzer.analyzer_id,
                )
            )
            or len({analyzer.analyzer_id for analyzer in self.analyzers})
            != len(self.analyzers)
            or len(set(capabilities)) != len(capabilities)
        ):
            raise InvalidSourcePlanningRequestError

    def analyzer_for(
        self,
        capability: AnalysisCapability,
    ) -> TrustedSourceAnalyzer | None:
        if not isinstance(capability, AnalysisCapability):
            raise InvalidSourcePlanningRequestError
        return next(
            (
                analyzer
                for analyzer in self.analyzers
                if capability in analyzer.capabilities
            ),
            None,
        )

    def canonical_data(self) -> dict[str, Any]:
        return {
            "analyzers": [
                analyzer.canonical_data() for analyzer in self.analyzers
            ],
            "schema_version": self.schema_version,
        }

    def registry_digest(self) -> str:
        return _canonical_digest(
            _REGISTRY_STREAM_VERSION,
            self.canonical_data(),
        )


@dataclass(frozen=True, slots=True)
class CapabilityPathSelectionRule:
    capability: AnalysisCapability
    excluded_flags: tuple[SourceFileFlag, ...] = ()

    def __post_init__(self) -> None:
        if (
            not isinstance(self.capability, AnalysisCapability)
            or self.capability is AnalysisCapability.REPOSITORY_PROFILING
            or not isinstance(self.excluded_flags, tuple)
            or any(
                not isinstance(flag, SourceFileFlag)
                for flag in self.excluded_flags
            )
            or self.excluded_flags
            != tuple(sorted(self.excluded_flags, key=lambda flag: flag.value))
            or len(set(self.excluded_flags)) != len(self.excluded_flags)
        ):
            raise InvalidSourcePlanningRequestError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "capability": self.capability.value,
            "excluded_flags": [flag.value for flag in self.excluded_flags],
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class SourcePlanningPolicy:
    path_rules: tuple[CapabilityPathSelectionRule, ...] = ()
    schema_version: str = "0.2.6"

    def __post_init__(self) -> None:
        if (
            self.schema_version != "0.2.6"
            or not isinstance(self.path_rules, tuple)
            or any(
                not isinstance(rule, CapabilityPathSelectionRule)
                for rule in self.path_rules
            )
            or self.path_rules
            != tuple(
                sorted(
                    self.path_rules,
                    key=lambda rule: rule.capability.value,
                )
            )
            or len({rule.capability for rule in self.path_rules})
            != len(self.path_rules)
        ):
            raise InvalidSourcePlanningRequestError

    def excluded_flags_for(
        self,
        capability: AnalysisCapability,
    ) -> tuple[SourceFileFlag, ...]:
        if not isinstance(capability, AnalysisCapability):
            raise InvalidSourcePlanningRequestError
        return next(
            (
                rule.excluded_flags
                for rule in self.path_rules
                if rule.capability is capability
            ),
            (),
        )

    def canonical_data(self) -> dict[str, Any]:
        return {
            "path_rules": [rule.canonical_data() for rule in self.path_rules],
            "schema_version": self.schema_version,
        }

    def policy_digest(self) -> str:
        return _canonical_digest(
            _POLICY_STREAM_VERSION,
            self.canonical_data(),
        )


@dataclass(frozen=True, slots=True)
class SourcePlanPathExclusion:
    relative_path: str
    reason_code: str

    def __post_init__(self) -> None:
        if (
            not _valid_relative_path(self.relative_path)
            or self.reason_code not in _EXCLUSION_REASON_CODES
        ):
            raise InvalidSourcePlanningRequestError

    def canonical_data(self) -> dict[str, str]:
        return {
            "reason_code": self.reason_code,
            "relative_path": self.relative_path,
        }


def _valid_entry_state(entry: SourceAnalysisPlanEntry) -> bool:
    excluded_path_names = tuple(
        exclusion.relative_path for exclusion in entry.excluded_paths
    )
    represented_paths = set(entry.selected_paths) | set(excluded_path_names)

    if entry.action is SourcePlanAction.RUN:
        return (
            entry.capability is not AnalysisCapability.REPOSITORY_PROFILING
            and entry.support_state in _EXECUTION_APPROVED_SUPPORT_STATES
            and entry.reason_code == "PLANNED"
            and entry.analyzer_id is not None
            and bool(entry.selected_paths)
            and represented_paths == set(entry.surface_paths)
        )

    if entry.action is SourcePlanAction.SATISFIED:
        return (
            entry.capability is AnalysisCapability.REPOSITORY_PROFILING
            and entry.component_id is None
            and entry.reason_code == "UPSTREAM_CAPABILITY_SATISFIED"
            and entry.analyzer_id is None
            and not entry.selected_paths
            and not entry.excluded_paths
        )

    if entry.action is not SourcePlanAction.SKIP:
        return False
    if entry.capability is AnalysisCapability.REPOSITORY_PROFILING:
        return False
    if entry.reason_code == "CAPABILITY_DETECTED_ONLY":
        return (
            entry.support_state is SourceSupportState.DETECTED
            and entry.analyzer_id is None
            and not entry.selected_paths
            and not entry.excluded_paths
        )
    if entry.reason_code == "CAPABILITY_UNSUPPORTED":
        return (
            entry.support_state is SourceSupportState.UNSUPPORTED
            and entry.analyzer_id is None
            and not entry.surface_paths
            and not entry.selected_paths
            and not entry.excluded_paths
        )
    if entry.reason_code == "NO_ANALYZER_REGISTERED":
        return (
            entry.support_state in _EXECUTION_APPROVED_SUPPORT_STATES
            and entry.analyzer_id is None
            and not entry.selected_paths
            and not entry.excluded_paths
        )
    if entry.reason_code == "ANALYZER_UNAVAILABLE":
        return (
            entry.support_state in _EXECUTION_APPROVED_SUPPORT_STATES
            and entry.analyzer_id is not None
            and not entry.selected_paths
            and not entry.excluded_paths
        )
    if entry.reason_code == "NO_PATHS_AFTER_SELECTION_POLICY":
        return (
            entry.support_state in _EXECUTION_APPROVED_SUPPORT_STATES
            and entry.analyzer_id is not None
            and not entry.selected_paths
            and bool(entry.excluded_paths)
            and represented_paths == set(entry.surface_paths)
        )
    return False


@dataclass(frozen=True, slots=True, kw_only=True)
class SourceAnalysisPlanEntry:
    capability: AnalysisCapability
    component_id: str | None
    support_state: SourceSupportState
    action: SourcePlanAction
    reason_code: str
    analyzer_id: str | None
    surface_paths: tuple[str, ...]
    selected_paths: tuple[str, ...]
    excluded_paths: tuple[SourcePlanPathExclusion, ...]

    def __post_init__(self) -> None:
        exclusion_names = (
            tuple(exclusion.relative_path for exclusion in self.excluded_paths)
            if isinstance(self.excluded_paths, tuple)
            and all(
                isinstance(exclusion, SourcePlanPathExclusion)
                for exclusion in self.excluded_paths
            )
            else ()
        )
        if (
            not isinstance(self.capability, AnalysisCapability)
            or (
                self.component_id is not None
                and not _valid_identifier(self.component_id)
            )
            or not isinstance(self.support_state, SourceSupportState)
            or not isinstance(self.action, SourcePlanAction)
            or self.reason_code not in _PLAN_REASON_CODES
            or (
                self.analyzer_id is not None
                and not _valid_identifier(self.analyzer_id)
            )
            or not _valid_sorted_path_tuple(self.surface_paths)
            or not _valid_sorted_path_tuple(self.selected_paths)
            or not isinstance(self.excluded_paths, tuple)
            or any(
                not isinstance(exclusion, SourcePlanPathExclusion)
                for exclusion in self.excluded_paths
            )
            or self.excluded_paths
            != tuple(
                sorted(
                    self.excluded_paths,
                    key=lambda exclusion: exclusion.relative_path,
                )
            )
            or len(set(exclusion_names)) != len(exclusion_names)
            or set(self.selected_paths) & set(exclusion_names)
            or not set(self.selected_paths).issubset(self.surface_paths)
            or not set(exclusion_names).issubset(self.surface_paths)
            or not _valid_entry_state(self)
        ):
            raise InvalidSourcePlanningRequestError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "analyzer_id": self.analyzer_id,
            "capability": self.capability.value,
            "component_id": self.component_id,
            "excluded_paths": [
                exclusion.canonical_data() for exclusion in self.excluded_paths
            ],
            "reason_code": self.reason_code,
            "selected_paths": list(self.selected_paths),
            "support_state": self.support_state.value,
            "surface_paths": list(self.surface_paths),
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class SourceAnalysisPlan:
    repository_digest: str
    profile_digest: str
    analyzer_registry_digest: str
    planning_policy_digest: str
    entries: tuple[SourceAnalysisPlanEntry, ...]
    schema_version: str = "0.2.6"

    def __post_init__(self) -> None:
        digests = (
            self.repository_digest,
            self.profile_digest,
            self.analyzer_registry_digest,
            self.planning_policy_digest,
        )
        if (
            self.schema_version != "0.2.6"
            or any(
                not isinstance(digest, str)
                or _SHA256_PATTERN.fullmatch(digest) is None
                for digest in digests
            )
            or not isinstance(self.entries, tuple)
            or any(
                not isinstance(entry, SourceAnalysisPlanEntry)
                for entry in self.entries
            )
            or self.entries
            != tuple(
                sorted(
                    self.entries,
                    key=lambda entry: (
                        entry.capability.value,
                        entry.component_id or "",
                    ),
                )
            )
            or len(
                {(entry.capability, entry.component_id) for entry in self.entries}
            )
            != len(self.entries)
        ):
            raise InvalidSourcePlanningRequestError

    @property
    def run_count(self) -> int:
        return sum(entry.action is SourcePlanAction.RUN for entry in self.entries)

    @property
    def skip_count(self) -> int:
        return sum(entry.action is SourcePlanAction.SKIP for entry in self.entries)

    @property
    def satisfied_count(self) -> int:
        return sum(
            entry.action is SourcePlanAction.SATISFIED for entry in self.entries
        )

    def canonical_data(self) -> dict[str, Any]:
        return {
            "analyzer_registry_digest": self.analyzer_registry_digest,
            "entries": [entry.canonical_data() for entry in self.entries],
            "planning_policy_digest": self.planning_policy_digest,
            "profile_digest": self.profile_digest,
            "repository_digest": self.repository_digest,
            "run_count": self.run_count,
            "satisfied_count": self.satisfied_count,
            "schema_version": self.schema_version,
            "skip_count": self.skip_count,
        }

    def plan_digest(self) -> str:
        return _canonical_digest(_PLAN_STREAM_VERSION, self.canonical_data())


def _validate_profile(
    profile: RepositoryProfile,
) -> tuple[str, dict[str, SourceFileRecord], tuple[AnalysisSurface, ...]]:
    try:
        profile_digest = profile.profile_digest()
        files = profile.files
        surfaces = profile.surfaces
        if (
            not isinstance(files, tuple)
            or any(not isinstance(file, SourceFileRecord) for file in files)
            or files != tuple(sorted(files, key=lambda file: file.relative_path))
            or len({file.relative_path for file in files}) != len(files)
            or not isinstance(surfaces, tuple)
            or any(not isinstance(surface, AnalysisSurface) for surface in surfaces)
            or any(
                not isinstance(surface.capability, AnalysisCapability)
                or not isinstance(surface.support_state, SourceSupportState)
                or (
                    surface.component_id is not None
                    and not _valid_identifier(surface.component_id)
                )
                or not _valid_sorted_path_tuple(surface.eligible_paths)
                or (
                    surface.support_state is SourceSupportState.UNSUPPORTED
                    and bool(surface.eligible_paths)
                )
                for surface in surfaces
            )
            or surfaces
            != tuple(
                sorted(
                    surfaces,
                    key=lambda surface: (
                        surface.capability.value,
                        surface.component_id or "",
                    ),
                )
            )
            or len(
                {
                    (surface.capability, surface.component_id)
                    for surface in surfaces
                }
            )
            != len(surfaces)
        ):
            raise ValueError

        files_by_path = {file.relative_path: file for file in files}
        components = {component.component_id for component in profile.components}
        profiling_surfaces = tuple(
            surface
            for surface in surfaces
            if surface.capability is AnalysisCapability.REPOSITORY_PROFILING
        )
        if (
            len(profiling_surfaces) != 1
            or profiling_surfaces[0].component_id is not None
        ):
            raise ValueError

        for surface in surfaces:
            if (
                surface.component_id is not None
                and surface.component_id not in components
            ):
                raise ValueError
            if (
                surface.capability is not AnalysisCapability.REPOSITORY_PROFILING
                and surface.support_state in _EXECUTION_APPROVED_SUPPORT_STATES
                and not surface.eligible_paths
            ):
                raise ValueError
            for path in surface.eligible_paths:
                file = files_by_path.get(path)
                if file is None or (
                    surface.component_id is not None
                    and file.component_id != surface.component_id
                ):
                    raise ValueError
    except (AttributeError, TypeError, ValueError):
        raise SourcePlanningCorrelationError from None
    return profile_digest, files_by_path, surfaces


def _entry_without_execution(
    surface: AnalysisSurface,
    *,
    action: SourcePlanAction,
    reason_code: str,
    analyzer_id: str | None = None,
) -> SourceAnalysisPlanEntry:
    return SourceAnalysisPlanEntry(
        capability=surface.capability,
        component_id=surface.component_id,
        support_state=surface.support_state,
        action=action,
        reason_code=reason_code,
        analyzer_id=analyzer_id,
        surface_paths=surface.eligible_paths,
        selected_paths=(),
        excluded_paths=(),
    )


def _selected_entry(
    surface: AnalysisSurface,
    analyzer: TrustedSourceAnalyzer,
    excluded_flags: tuple[SourceFileFlag, ...],
    files_by_path: dict[str, SourceFileRecord],
) -> SourceAnalysisPlanEntry:
    selected_paths: list[str] = []
    excluded_paths: list[SourcePlanPathExclusion] = []
    excluded_flag_set = frozenset(excluded_flags)
    for path in surface.eligible_paths:
        file = files_by_path.get(path)
        if file is None or (
            surface.component_id is not None
            and file.component_id != surface.component_id
        ):
            raise SourcePlanningCorrelationError
        exclusion_reason = next(
            (
                reason_code
                for flag, reason_code in _EXCLUSION_PRECEDENCE
                if flag in excluded_flag_set and flag in file.flags
            ),
            None,
        )
        if exclusion_reason is None:
            selected_paths.append(path)
        else:
            excluded_paths.append(
                SourcePlanPathExclusion(
                    relative_path=path,
                    reason_code=exclusion_reason,
                )
            )

    action = SourcePlanAction.RUN if selected_paths else SourcePlanAction.SKIP
    reason_code = "PLANNED" if selected_paths else "NO_PATHS_AFTER_SELECTION_POLICY"
    return SourceAnalysisPlanEntry(
        capability=surface.capability,
        component_id=surface.component_id,
        support_state=surface.support_state,
        action=action,
        reason_code=reason_code,
        analyzer_id=analyzer.analyzer_id,
        surface_paths=surface.eligible_paths,
        selected_paths=tuple(selected_paths),
        excluded_paths=tuple(excluded_paths),
    )


def build_source_analysis_plan(
    profile: RepositoryProfile,
    registry: TrustedSourceAnalyzerRegistry,
    policy: SourcePlanningPolicy,
) -> SourceAnalysisPlan:
    if (
        not isinstance(profile, RepositoryProfile)
        or not isinstance(registry, TrustedSourceAnalyzerRegistry)
        or not isinstance(policy, SourcePlanningPolicy)
    ):
        raise InvalidSourcePlanningRequestError

    profile_digest, files_by_path, surfaces = _validate_profile(profile)
    entries: list[SourceAnalysisPlanEntry] = []
    for surface in surfaces:
        if surface.capability is AnalysisCapability.REPOSITORY_PROFILING:
            entries.append(
                _entry_without_execution(
                    surface,
                    action=SourcePlanAction.SATISFIED,
                    reason_code="UPSTREAM_CAPABILITY_SATISFIED",
                )
            )
            continue
        if surface.support_state is SourceSupportState.UNSUPPORTED:
            entries.append(
                _entry_without_execution(
                    surface,
                    action=SourcePlanAction.SKIP,
                    reason_code="CAPABILITY_UNSUPPORTED",
                )
            )
            continue
        if surface.support_state is SourceSupportState.DETECTED:
            entries.append(
                _entry_without_execution(
                    surface,
                    action=SourcePlanAction.SKIP,
                    reason_code="CAPABILITY_DETECTED_ONLY",
                )
            )
            continue
        if surface.support_state not in _EXECUTION_APPROVED_SUPPORT_STATES:
            raise SourcePlanningCorrelationError

        analyzer = registry.analyzer_for(surface.capability)
        if analyzer is None:
            entries.append(
                _entry_without_execution(
                    surface,
                    action=SourcePlanAction.SKIP,
                    reason_code="NO_ANALYZER_REGISTERED",
                )
            )
            continue
        if not analyzer.available:
            entries.append(
                _entry_without_execution(
                    surface,
                    action=SourcePlanAction.SKIP,
                    reason_code="ANALYZER_UNAVAILABLE",
                    analyzer_id=analyzer.analyzer_id,
                )
            )
            continue
        entries.append(
            _selected_entry(
                surface,
                analyzer,
                policy.excluded_flags_for(surface.capability),
                files_by_path,
            )
        )

    try:
        return SourceAnalysisPlan(
            repository_digest=profile.repository_digest,
            profile_digest=profile_digest,
            analyzer_registry_digest=registry.registry_digest(),
            planning_policy_digest=policy.policy_digest(),
            entries=tuple(entries),
        )
    except (TypeError, ValueError, SourcePlanningError):
        raise SourcePlanningCorrelationError from None
