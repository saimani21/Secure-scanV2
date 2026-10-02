from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from uuid import UUID

from securescan.scanners.semgrep.source_binding import (
    PRODUCTION_SEMGREP_BINDING_DIGEST,
)
from securescan.source.enums import (
    AnalysisCapability,
    FileContentKind,
    SourceFileFlag,
    SourceFileRole,
    SourceInputType,
    SourceSupportState,
)
from securescan.source.models import (
    AnalysisSurface,
    LanguageSupport,
    RepositoryComponent,
    RepositoryProfile,
    SourceFileRecord,
)
from securescan.source.planning import (
    SourceAnalysisPlan,
    SourceAnalysisPlanEntry,
    SourcePlanAction,
    SourcePlanPathExclusion,
)
from securescan.workspaces.models import RepositoryManifestEntry

PLANNING_SNAPSHOT_SCHEMA_VERSION = "securescan-source-orchestration-planning-s6a-v1"
AUTHORITY_ROSTER_SCHEMA_VERSION = "securescan-source-authority-roster-s6a-v1"
PLANNING_SNAPSHOT_MEDIA_TYPE = "application/vnd.securescan.source-orchestration-planning+json"
SOURCE_V1_AUTHORITY_ROSTER_DIGEST = (
    "3f3a982d6858379595d4f9a01ceb07df2b4312c863155ce6c9e9e7fc2071c1cc"
)

_NODE_ID_DOMAIN = b"securescan-source-orchestration-node-s6a-v1\0"
_NODE_SCOPE_DOMAIN = b"securescan-source-orchestration-node-scope-s6a-v1\0"
_ROSTER_DOMAIN = b"securescan-source-authority-roster-s6a-v1\0"
_REQUEST_DOMAIN = b"securescan-source-orchestration-request-s6a-v1\0"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z", re.ASCII)


class SourceOrchestrationIntegrityError(RuntimeError):
    def __init__(self, message: str = "Source orchestration data is invalid") -> None:
        super().__init__(message)


class SourceAuthority(StrEnum):
    SEMGREP = "semgrep-ce"
    GITLEAKS = "gitleaks"
    SYFT = "syft"
    OSV = "osv.dev"
    CHECKOV = "checkov"


class OrchestrationLifecycleState(StrEnum):
    PREPARED = "PREPARED"
    ACTIVE = "ACTIVE"
    CANCELLATION_REQUESTED = "CANCELLATION_REQUESTED"
    ASSEMBLY_READY = "ASSEMBLY_READY"
    ASSEMBLING = "ASSEMBLING"
    COMMITTING = "COMMITTING"
    TERMINAL = "TERMINAL"


class OrchestrationTerminalOutcome(StrEnum):
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class OrchestrationNodeLifecycleState(StrEnum):
    PLANNED = "PLANNED"
    WAITING_DEPENDENCY = "WAITING_DEPENDENCY"
    READY = "READY"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    RETRY_PENDING = "RETRY_PENDING"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    TERMINAL = "TERMINAL"


class OrchestrationNodeDisposition(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    FAILED = "FAILED"
    BLOCKED_BY_DEPENDENCY = "BLOCKED_BY_DEPENDENCY"
    CANCELLED = "CANCELLED"


class OrchestrationContainmentState(StrEnum):
    NOT_STARTED = "NOT_STARTED"
    ACTIVE = "ACTIVE"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    CLEAN = "CLEAN"


_TRUSTED_AUTHORITY_IDENTITIES: tuple[dict[str, str], ...] = (
    {
        "analyzer_id": "checkov-source-v1",
        "authority": SourceAuthority.CHECKOV.value,
        "capability": AnalysisCapability.CONFIGURATION_SECURITY.value,
        "contract_digest": "a4dc1feb9948d453d22eda0ab39cbcee7c377421fb54aa3d7285cad18eb2143e",
        "contract_kind": "trusted-binding",
        "implementation_version": "3.3.16",
    },
    {
        "analyzer_id": "gitleaks-source-v1",
        "authority": SourceAuthority.GITLEAKS.value,
        "capability": AnalysisCapability.SECRET_DETECTION.value,
        "contract_digest": "8d9f224e1c5ddabef508a26be2966f51dc2a9c2e5805ea3bffcf444b3cae9561",
        "contract_kind": "trusted-binding",
        "implementation_version": "8.30.1",
    },
    {
        "analyzer_id": "osv-dependency-advisory-v1",
        "authority": SourceAuthority.OSV.value,
        "capability": AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING.value,
        "contract_digest": "f4e5f14799634e2da927e73fdba18510d15d13996563d0ad436da87179f73c6f",
        "contract_kind": "trusted-service-contract",
        "implementation_version": "v1",
    },
    {
        "analyzer_id": "semgrep-source-v1",
        "authority": SourceAuthority.SEMGREP.value,
        "capability": AnalysisCapability.SOURCE_SAST.value,
        "contract_digest": PRODUCTION_SEMGREP_BINDING_DIGEST,
        "contract_kind": "trusted-binding",
        "implementation_version": "1.171.0",
    },
    {
        "analyzer_id": "syft-source-v1",
        "authority": SourceAuthority.SYFT.value,
        "capability": AnalysisCapability.PACKAGE_INVENTORY.value,
        "contract_digest": "392fdda53e1192ca40fb22893e5fce90828a4171e67e28eb09632d9bc8159da0",
        "contract_kind": "trusted-binding",
        "implementation_version": "1.51.0",
    },
)

_V12_TRUSTED_AUTHORITY_IDENTITIES: tuple[dict[str, str], ...] = tuple(
    {
        **item,
        **(
            {
                "analyzer_id": "python-semgrep-v1",
                "capability": AnalysisCapability.PYTHON_SAST.value,
                "contract_digest": (
                    "265fd32e59296d6dc50fd7f8b7558f0e35ead821c4ee689f5ff953bf70393ed2"
                ),
            }
            if item["authority"] == SourceAuthority.SEMGREP.value
            else {}
        ),
    }
    for item in _TRUSTED_AUTHORITY_IDENTITIES
)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _domain_digest(domain: bytes, value: object) -> str:
    digest = hashlib.sha256()
    digest.update(domain)
    digest.update(_canonical_json(value))
    return digest.hexdigest()


def _valid_run_id(value: object) -> bool:
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except ValueError:
        return False


def _required_dict(value: object, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise SourceOrchestrationIntegrityError
    return value


@dataclass(frozen=True, slots=True)
class TrustedSourceAuthority:
    authority: SourceAuthority
    capability: AnalysisCapability
    analyzer_id: str
    contract_kind: str
    contract_digest: str
    implementation_version: str

    def __post_init__(self) -> None:
        if not isinstance(self.authority, SourceAuthority) or not isinstance(
            self.capability, AnalysisCapability
        ):
            raise SourceOrchestrationIntegrityError("Source authority identity is not trusted")
        data = self.canonical_data()
        if (
            data not in _TRUSTED_AUTHORITY_IDENTITIES
            and data not in _V12_TRUSTED_AUTHORITY_IDENTITIES
        ):
            raise SourceOrchestrationIntegrityError("Source authority identity is not trusted")

    def canonical_data(self) -> dict[str, str]:
        return {
            "analyzer_id": self.analyzer_id,
            "authority": self.authority.value,
            "capability": self.capability.value,
            "contract_digest": self.contract_digest,
            "contract_kind": self.contract_kind,
            "implementation_version": self.implementation_version,
        }


@dataclass(frozen=True, slots=True)
class TrustedSourceAuthorityRoster:
    authorities: tuple[TrustedSourceAuthority, ...]
    schema_version: str = AUTHORITY_ROSTER_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != AUTHORITY_ROSTER_SCHEMA_VERSION
            or not isinstance(self.authorities, tuple)
            or any(not isinstance(item, TrustedSourceAuthority) for item in self.authorities)
            or self.authorities
            != tuple(sorted(self.authorities, key=lambda item: item.authority.value))
            or len({item.authority for item in self.authorities}) != 5
            or len({item.capability for item in self.authorities}) != 5
            or tuple(item.canonical_data() for item in self.authorities)
            not in (
                _TRUSTED_AUTHORITY_IDENTITIES,
                _V12_TRUSTED_AUTHORITY_IDENTITIES,
            )
        ):
            raise SourceOrchestrationIntegrityError("Source authority roster is invalid")

    def canonical_data(self) -> dict[str, Any]:
        return {
            "authorities": [item.canonical_data() for item in self.authorities],
            "schema_version": self.schema_version,
        }

    def roster_digest(self) -> str:
        return _domain_digest(_ROSTER_DOMAIN, self.canonical_data())

    def for_capability(self, capability: AnalysisCapability) -> TrustedSourceAuthority:
        try:
            return next(item for item in self.authorities if item.capability is capability)
        except StopIteration:
            raise SourceOrchestrationIntegrityError from None


def frozen_source_v1_authority_roster() -> TrustedSourceAuthorityRoster:
    return TrustedSourceAuthorityRoster(
        tuple(
            TrustedSourceAuthority(
                authority=SourceAuthority(item["authority"]),
                capability=AnalysisCapability(item["capability"]),
                analyzer_id=item["analyzer_id"],
                contract_kind=item["contract_kind"],
                contract_digest=item["contract_digest"],
                implementation_version=item["implementation_version"],
            )
            for item in _TRUSTED_AUTHORITY_IDENTITIES
        )
    )


@dataclass(frozen=True, slots=True)
class PlannedSourceNode:
    node_id: str
    authority: SourceAuthority
    capability: AnalysisCapability
    component_id: str | None
    analyzer_id: str
    contract_digest: str
    plan_entry_keys: tuple[str, ...]
    selected_paths: tuple[str, ...]
    scope_digest: str
    initial_state: OrchestrationNodeLifecycleState

    def canonical_data(self) -> dict[str, Any]:
        return {
            "analyzer_id": self.analyzer_id,
            "authority": self.authority.value,
            "capability": self.capability.value,
            "component_id": self.component_id,
            "contract_digest": self.contract_digest,
            "initial_state": self.initial_state.value,
            "node_id": self.node_id,
            "plan_entry_keys": list(self.plan_entry_keys),
            "scope_digest": self.scope_digest,
            "selected_paths": list(self.selected_paths),
        }


@dataclass(frozen=True, slots=True)
class PlannedSourceDependency:
    node_id: str
    prerequisite_node_id: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.node_id, str)
            or not isinstance(self.prerequisite_node_id, str)
            or _SHA256.fullmatch(self.node_id) is None
            or _SHA256.fullmatch(self.prerequisite_node_id) is None
            or self.node_id == self.prerequisite_node_id
        ):
            raise SourceOrchestrationIntegrityError("Source dependency is invalid")

    def canonical_data(self) -> dict[str, str]:
        return {
            "node_id": self.node_id,
            "prerequisite_node_id": self.prerequisite_node_id,
        }


def source_node_id(
    run_id: str,
    authority: SourceAuthority,
    capability: AnalysisCapability,
    component_id: str | None,
) -> str:
    if (
        not _valid_run_id(run_id)
        or not isinstance(authority, SourceAuthority)
        or not isinstance(capability, AnalysisCapability)
        or (
            component_id is not None
            and (not isinstance(component_id, str) or _IDENTIFIER.fullmatch(component_id) is None)
        )
    ):
        raise SourceOrchestrationIntegrityError
    return _domain_digest(
        _NODE_ID_DOMAIN,
        {
            "authority": authority.value,
            "capability": capability.value,
            "component_id": component_id,
            "run_id": run_id,
        },
    )


def _entry_key(entry: SourceAnalysisPlanEntry) -> str:
    return f"{entry.capability.value}:{entry.component_id or '-'}"


def _node(
    *,
    run_id: str,
    authority: TrustedSourceAuthority,
    component_id: str | None,
    entries: tuple[SourceAnalysisPlanEntry, ...],
    initial_state: OrchestrationNodeLifecycleState,
    profile: RepositoryProfile,
    plan: SourceAnalysisPlan,
) -> PlannedSourceNode:
    selected_paths = tuple(sorted({path for entry in entries for path in entry.selected_paths}))
    keys = tuple(sorted(_entry_key(entry) for entry in entries))
    identity = source_node_id(run_id, authority.authority, authority.capability, component_id)
    scope_material = {
        "analyzer_id": authority.analyzer_id,
        "component_id": component_id,
        "contract_digest": authority.contract_digest,
        "plan_digest": plan.plan_digest(),
        "plan_entry_keys": list(keys),
        "profile_digest": profile.profile_digest(),
        "repository_digest": profile.repository_digest,
        "selected_paths": list(selected_paths),
    }
    return PlannedSourceNode(
        node_id=identity,
        authority=authority.authority,
        capability=authority.capability,
        component_id=component_id,
        analyzer_id=authority.analyzer_id,
        contract_digest=authority.contract_digest,
        plan_entry_keys=keys,
        selected_paths=selected_paths,
        scope_digest=_domain_digest(_NODE_SCOPE_DOMAIN, scope_material),
        initial_state=initial_state,
    )


def build_source_v1_topology(
    run_id: str,
    profile: RepositoryProfile,
    plan: SourceAnalysisPlan,
    roster: TrustedSourceAuthorityRoster,
) -> tuple[tuple[PlannedSourceNode, ...], tuple[PlannedSourceDependency, ...]]:
    if (
        not _valid_run_id(run_id)
        or plan.repository_digest != profile.repository_digest
        or plan.profile_digest != profile.profile_digest()
        or len({(item.capability, item.component_id) for item in plan.entries}) != len(plan.entries)
    ):
        raise SourceOrchestrationIntegrityError("Source planning inputs do not correlate")

    profile_surfaces = {
        (surface.capability, surface.component_id): surface for surface in profile.surfaces
    }
    plan_entries = {(entry.capability, entry.component_id): entry for entry in plan.entries}
    if set(profile_surfaces) != set(plan_entries):
        raise SourceOrchestrationIntegrityError("Source plan does not cover the frozen profile")

    roster_capabilities = {item.capability for item in roster.authorities}
    for entry in plan.entries:
        surface = profile_surfaces[(entry.capability, entry.component_id)]
        if (
            entry.support_state is not surface.support_state
            or entry.surface_paths != surface.eligible_paths
        ):
            raise SourceOrchestrationIntegrityError("Source plan scope is not frozen profile scope")
        if entry.capability not in roster_capabilities:
            continue
        trusted = roster.for_capability(entry.capability)
        if entry.analyzer_id is not None and entry.analyzer_id != trusted.analyzer_id:
            raise SourceOrchestrationIntegrityError("Source plan analyzer is not trusted")

    nodes: list[PlannedSourceNode] = []
    by_capability: dict[AnalysisCapability, list[SourceAnalysisPlanEntry]] = {}
    for entry in plan.entries:
        if entry.action is SourcePlanAction.RUN and entry.capability in roster_capabilities:
            by_capability.setdefault(entry.capability, []).append(entry)

    semgrep_capability = next(
        item.capability for item in roster.authorities if item.authority is SourceAuthority.SEMGREP
    )
    semgrep = roster.for_capability(semgrep_capability)
    for entry in by_capability.get(semgrep_capability, []):
        nodes.append(
            _node(
                run_id=run_id,
                authority=semgrep,
                component_id=entry.component_id,
                entries=(entry,),
                initial_state=OrchestrationNodeLifecycleState.READY,
                profile=profile,
                plan=plan,
            )
        )

    for capability in (
        AnalysisCapability.SECRET_DETECTION,
        AnalysisCapability.PACKAGE_INVENTORY,
        AnalysisCapability.CONFIGURATION_SECURITY,
    ):
        entries = tuple(by_capability.get(capability, ()))
        if not entries:
            continue
        if len(entries) != 1 or entries[0].component_id is not None:
            raise SourceOrchestrationIntegrityError("Repository-wide node topology is invalid")
        nodes.append(
            _node(
                run_id=run_id,
                authority=roster.for_capability(capability),
                component_id=None,
                entries=entries,
                initial_state=OrchestrationNodeLifecycleState.READY,
                profile=profile,
                plan=plan,
            )
        )

    advisory_entries = tuple(by_capability.get(AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING, ()))
    if advisory_entries:
        nodes.append(
            _node(
                run_id=run_id,
                authority=roster.for_capability(AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING),
                component_id=None,
                entries=advisory_entries,
                initial_state=OrchestrationNodeLifecycleState.WAITING_DEPENDENCY,
                profile=profile,
                plan=plan,
            )
        )

    ordered = tuple(sorted(nodes, key=lambda item: item.node_id))
    if len({item.node_id for item in ordered}) != len(ordered):
        raise SourceOrchestrationIntegrityError("Source node identity is ambiguous")

    dependencies: tuple[PlannedSourceDependency, ...] = ()
    osv_node = next((item for item in ordered if item.authority is SourceAuthority.OSV), None)
    if osv_node is not None:
        syft_node = next((item for item in ordered if item.authority is SourceAuthority.SYFT), None)
        if syft_node is None:
            raise SourceOrchestrationIntegrityError("OSV requires a planned Syft node")
        dependencies = (PlannedSourceDependency(osv_node.node_id, syft_node.node_id),)
    return ordered, dependencies


@dataclass(frozen=True, slots=True)
class SourcePlanningSnapshot:
    run_id: str
    profile: RepositoryProfile
    plan: SourceAnalysisPlan
    roster: TrustedSourceAuthorityRoster
    nodes: tuple[PlannedSourceNode, ...]
    dependencies: tuple[PlannedSourceDependency, ...]
    schema_version: str = PLANNING_SNAPSHOT_SCHEMA_VERSION

    @classmethod
    def create(
        cls,
        run_id: str,
        profile: RepositoryProfile,
        plan: SourceAnalysisPlan,
        roster: TrustedSourceAuthorityRoster,
    ) -> SourcePlanningSnapshot:
        try:
            nodes, dependencies = build_source_v1_topology(run_id, profile, plan, roster)
            return cls(run_id, profile, plan, roster, nodes, dependencies)
        except (AttributeError, TypeError, ValueError):
            raise SourceOrchestrationIntegrityError from None

    def __post_init__(self) -> None:
        if self.schema_version != PLANNING_SNAPSHOT_SCHEMA_VERSION:
            raise SourceOrchestrationIntegrityError
        expected_nodes, expected_dependencies = build_source_v1_topology(
            self.run_id, self.profile, self.plan, self.roster
        )
        if self.nodes != expected_nodes or self.dependencies != expected_dependencies:
            raise SourceOrchestrationIntegrityError("Source topology does not match planning")

    def canonical_data(self) -> dict[str, Any]:
        return {
            "dependencies": [item.canonical_data() for item in self.dependencies],
            "nodes": [item.canonical_data() for item in self.nodes],
            "plan": self.plan.canonical_data(),
            "profile": self.profile.canonical_data(),
            "roster": self.roster.canonical_data(),
            "run_id": self.run_id,
            "schema_version": self.schema_version,
        }

    def canonical_json(self) -> bytes:
        return _canonical_json(self.canonical_data()) + b"\n"

    def snapshot_digest(self) -> str:
        return hashlib.sha256(self.canonical_json()).hexdigest()

    @classmethod
    def from_json(cls, payload: bytes) -> SourcePlanningSnapshot:
        def reject_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError
                result[key] = value
            return result

        if not isinstance(payload, bytes) or not payload:
            raise SourceOrchestrationIntegrityError("Planning snapshot is invalid")
        try:
            raw = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=reject_pairs,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
            )
            root = _required_dict(
                raw,
                {"dependencies", "nodes", "plan", "profile", "roster", "run_id", "schema_version"},
            )
            if root["schema_version"] != PLANNING_SNAPSHOT_SCHEMA_VERSION:
                raise ValueError
            profile = _parse_profile(root["profile"])
            plan = _parse_plan(root["plan"])
            roster = _parse_roster(root["roster"])
            rebuilt = cls.create(root["run_id"], profile, plan, roster)
            if rebuilt.canonical_json() != payload:
                raise ValueError
            return rebuilt
        except (
            AttributeError,
            KeyError,
            TypeError,
            ValueError,
            UnicodeError,
            SourceOrchestrationIntegrityError,
        ):
            raise SourceOrchestrationIntegrityError("Planning snapshot is invalid") from None


def orchestration_request_digest(
    *,
    target_id: str,
    idempotency_key: str,
    deadline_iso: str,
    profile_digest: str,
    plan_digest: str,
    roster_digest: str,
) -> str:
    return _domain_digest(
        _REQUEST_DOMAIN,
        {
            "deadline": deadline_iso,
            "idempotency_key": idempotency_key,
            "plan_digest": plan_digest,
            "profile_digest": profile_digest,
            "roster_digest": roster_digest,
            "target_id": target_id,
        },
    )


def _parse_profile(value: object) -> RepositoryProfile:
    raw = _required_dict(
        value,
        {
            "components",
            "file_count",
            "files",
            "input_type",
            "languages",
            "repository_digest",
            "schema_version",
            "surfaces",
            "total_bytes",
        },
    )
    files = []
    for value in raw["files"]:
        item = _required_dict(
            value,
            {
                "component_id",
                "content_kind",
                "eligible_capabilities",
                "flags",
                "language",
                "relative_path",
                "role",
                "sha256",
                "size_bytes",
            },
        )
        files.append(
            SourceFileRecord(
                entry=RepositoryManifestEntry(
                    item["relative_path"], item["size_bytes"], item["sha256"]
                ),
                content_kind=FileContentKind(item["content_kind"]),
                role=SourceFileRole(item["role"]),
                language=item["language"],
                component_id=item["component_id"],
                flags=tuple(SourceFileFlag(flag) for flag in item["flags"]),
                eligible_capabilities=tuple(
                    AnalysisCapability(capability) for capability in item["eligible_capabilities"]
                ),
            )
        )
    components = []
    for value in raw["components"]:
        item = _required_dict(
            value,
            {"component_id", "display_name", "lockfile_paths", "manifest_paths", "root_path"},
        )
        components.append(
            RepositoryComponent(
                component_id=item["component_id"],
                display_name=item["display_name"],
                root_path=item["root_path"],
                manifest_paths=tuple(item["manifest_paths"]),
                lockfile_paths=tuple(item["lockfile_paths"]),
            )
        )
    languages = []
    for value in raw["languages"]:
        item = _required_dict(
            value,
            {"eligible_file_count", "file_count", "language", "reason_code", "support_state"},
        )
        languages.append(
            LanguageSupport(
                language=item["language"],
                file_count=item["file_count"],
                eligible_file_count=item["eligible_file_count"],
                support_state=SourceSupportState(item["support_state"]),
                reason_code=item["reason_code"],
            )
        )
    surfaces = []
    for value in raw["surfaces"]:
        item = _required_dict(
            value,
            {"capability", "component_id", "eligible_paths", "reason_code", "support_state"},
        )
        surfaces.append(
            AnalysisSurface(
                capability=AnalysisCapability(item["capability"]),
                component_id=item["component_id"],
                eligible_paths=tuple(item["eligible_paths"]),
                support_state=SourceSupportState(item["support_state"]),
                reason_code=item["reason_code"],
            )
        )
    profile = RepositoryProfile(
        repository_digest=raw["repository_digest"],
        files=tuple(files),
        components=tuple(components),
        languages=tuple(languages),
        surfaces=tuple(surfaces),
        input_type=SourceInputType(raw["input_type"]),
        schema_version=raw["schema_version"],
    )
    if profile.file_count != raw["file_count"] or profile.total_bytes != raw["total_bytes"]:
        raise SourceOrchestrationIntegrityError
    return profile


def _parse_plan(value: object) -> SourceAnalysisPlan:
    raw = _required_dict(
        value,
        {
            "analyzer_registry_digest",
            "entries",
            "planning_policy_digest",
            "profile_digest",
            "repository_digest",
            "run_count",
            "satisfied_count",
            "schema_version",
            "skip_count",
        },
    )
    entries = []
    for value in raw["entries"]:
        item = _required_dict(
            value,
            {
                "action",
                "analyzer_id",
                "capability",
                "component_id",
                "excluded_paths",
                "reason_code",
                "selected_paths",
                "support_state",
                "surface_paths",
            },
        )
        exclusions = tuple(
            SourcePlanPathExclusion(**_required_dict(exclusion, {"relative_path", "reason_code"}))
            for exclusion in item["excluded_paths"]
        )
        entries.append(
            SourceAnalysisPlanEntry(
                capability=AnalysisCapability(item["capability"]),
                component_id=item["component_id"],
                support_state=SourceSupportState(item["support_state"]),
                action=SourcePlanAction(item["action"]),
                reason_code=item["reason_code"],
                analyzer_id=item["analyzer_id"],
                surface_paths=tuple(item["surface_paths"]),
                selected_paths=tuple(item["selected_paths"]),
                excluded_paths=exclusions,
            )
        )
    plan = SourceAnalysisPlan(
        repository_digest=raw["repository_digest"],
        profile_digest=raw["profile_digest"],
        analyzer_registry_digest=raw["analyzer_registry_digest"],
        planning_policy_digest=raw["planning_policy_digest"],
        entries=tuple(entries),
        schema_version=raw["schema_version"],
    )
    if (plan.run_count, plan.skip_count, plan.satisfied_count) != (
        raw["run_count"],
        raw["skip_count"],
        raw["satisfied_count"],
    ):
        raise SourceOrchestrationIntegrityError
    return plan


def _parse_roster(value: object) -> TrustedSourceAuthorityRoster:
    raw = _required_dict(value, {"authorities", "schema_version"})
    authorities = []
    for value in raw["authorities"]:
        item = _required_dict(
            value,
            {
                "analyzer_id",
                "authority",
                "capability",
                "contract_digest",
                "contract_kind",
                "implementation_version",
            },
        )
        authorities.append(
            TrustedSourceAuthority(
                authority=SourceAuthority(item["authority"]),
                capability=AnalysisCapability(item["capability"]),
                analyzer_id=item["analyzer_id"],
                contract_kind=item["contract_kind"],
                contract_digest=item["contract_digest"],
                implementation_version=item["implementation_version"],
            )
        )
    return TrustedSourceAuthorityRoster(tuple(authorities), raw["schema_version"])
