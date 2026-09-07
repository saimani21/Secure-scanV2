from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import threading
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from postgres_test_guard import validated_postgres_test_url
from sqlalchemy import create_engine, delete, event, func, inspect, select, text, update
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.config import Settings, get_settings
from securescan.domain.enums import TargetType
from securescan.orchestration import (
    SOURCE_V1_AUTHORITY_ROSTER_DIGEST,
    OrchestrationLifecycleState,
    OrchestrationNodeLifecycleState,
    PlannedSourceDependency,
    SourceAuthority,
    SourceOrchestrationConflictError,
    SourceOrchestrationCreateRequest,
    SourceOrchestrationIntegrityError,
    SourceOrchestrationNotFoundError,
    SourceOrchestrationRecord,
    SourceOrchestrationService,
    SourceOrchestrationStaleVersionError,
    SourcePlanningSnapshot,
    TrustedSourceAuthorityRoster,
    frozen_source_v1_authority_roster,
    source_node_id,
)
from securescan.orchestration import models as orchestration_models
from securescan.orchestration.models import orchestration_request_digest
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    ProjectRow,
    SourceOrchestrationAuthorityRow,
    SourceOrchestrationDependencyRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationRow,
    TargetRow,
    ToolExecutionRow,
    create_session_factory,
    initialize_database,
)
from securescan.source.enums import (
    AnalysisCapability,
    FileContentKind,
    SourceFileRole,
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
)
from securescan.workspaces.models import RepositoryManifestEntry, repository_content_digest

_RUN_ID = UUID("11111111-1111-4111-8111-111111111111")
_SECOND_RUN_ID = UUID("22222222-2222-4222-8222-222222222222")
_NOW = datetime(2026, 9, 7, 12, 0, tzinfo=UTC)
_DEADLINE = datetime(2026, 9, 7, 12, 30, tzinfo=UTC)
_PRIVATE_SOURCE = b"RAW_PRIVATE_SOURCE_TOKEN must never enter orchestration JSON\n"

_ANALYZERS = {
    AnalysisCapability.CONFIGURATION_SECURITY: "checkov-source-v1",
    AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING: "osv-dependency-advisory-v1",
    AnalysisCapability.PACKAGE_INVENTORY: "syft-source-v1",
    AnalysisCapability.PYTHON_SAST: "python-semgrep-v1",
    AnalysisCapability.SECRET_DETECTION: "gitleaks-source-v1",
}


def _manifest_entry(path: str, content: bytes) -> RepositoryManifestEntry:
    return RepositoryManifestEntry(path, len(content), hashlib.sha256(content).hexdigest())


def _capabilities(*values: AnalysisCapability) -> tuple[AnalysisCapability, ...]:
    return tuple(sorted(values, key=lambda value: value.value))


def _fixture_profile() -> RepositoryProfile:
    files = (
        SourceFileRecord(
            entry=_manifest_entry("app.py", _PRIVATE_SOURCE),
            content_kind=FileContentKind.TEXT,
            role=SourceFileRole.SOURCE,
            language="Python",
            component_id="application",
            eligible_capabilities=_capabilities(
                AnalysisCapability.PYTHON_SAST,
                AnalysisCapability.REPOSITORY_PROFILING,
                AnalysisCapability.SECRET_DETECTION,
            ),
        ),
        SourceFileRecord(
            entry=_manifest_entry("infra/main.tf", b'resource "x" "y" {}\n'),
            content_kind=FileContentKind.TEXT,
            role=SourceFileRole.TERRAFORM,
            eligible_capabilities=_capabilities(
                AnalysisCapability.CONFIGURATION_SECURITY,
                AnalysisCapability.REPOSITORY_PROFILING,
                AnalysisCapability.SECRET_DETECTION,
            ),
        ),
        SourceFileRecord(
            entry=_manifest_entry("requirements.lock", b"requests==2.31.0\n"),
            content_kind=FileContentKind.TEXT,
            role=SourceFileRole.LOCKFILE,
            component_id="application",
            eligible_capabilities=_capabilities(
                AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING,
                AnalysisCapability.PACKAGE_INVENTORY,
                AnalysisCapability.REPOSITORY_PROFILING,
                AnalysisCapability.SECRET_DETECTION,
            ),
        ),
    )
    surfaces = (
        AnalysisSurface(
            capability=AnalysisCapability.CONFIGURATION_SECURITY,
            support_state=SourceSupportState.SCANNABLE,
            eligible_paths=("infra/main.tf",),
        ),
        AnalysisSurface(
            capability=AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING,
            component_id="application",
            support_state=SourceSupportState.SCANNABLE,
            eligible_paths=("requirements.lock",),
        ),
        AnalysisSurface(
            capability=AnalysisCapability.PACKAGE_INVENTORY,
            support_state=SourceSupportState.SCANNABLE,
            eligible_paths=("requirements.lock",),
        ),
        AnalysisSurface(
            capability=AnalysisCapability.PYTHON_SAST,
            component_id="application",
            support_state=SourceSupportState.SCANNABLE,
            eligible_paths=("app.py",),
        ),
        AnalysisSurface(
            capability=AnalysisCapability.REPOSITORY_PROFILING,
            support_state=SourceSupportState.DETECTED,
            eligible_paths=("app.py", "infra/main.tf", "requirements.lock"),
        ),
        AnalysisSurface(
            capability=AnalysisCapability.SECRET_DETECTION,
            support_state=SourceSupportState.SCANNABLE,
            eligible_paths=("app.py", "infra/main.tf", "requirements.lock"),
        ),
    )
    return RepositoryProfile(
        repository_digest=repository_content_digest(tuple(file.entry for file in files)),
        files=files,
        components=(
            RepositoryComponent(
                component_id="application",
                display_name="Application",
                root_path=".",
                lockfile_paths=("requirements.lock",),
            ),
        ),
        languages=(
            LanguageSupport(
                language="Python",
                file_count=1,
                eligible_file_count=1,
                support_state=SourceSupportState.SCANNABLE,
            ),
        ),
        surfaces=surfaces,
    )


def _fixture_plan(profile: RepositoryProfile) -> SourceAnalysisPlan:
    entries = []
    for surface in profile.surfaces:
        profiling = surface.capability is AnalysisCapability.REPOSITORY_PROFILING
        entries.append(
            SourceAnalysisPlanEntry(
                capability=surface.capability,
                component_id=surface.component_id,
                support_state=surface.support_state,
                action=(SourcePlanAction.SATISFIED if profiling else SourcePlanAction.RUN),
                reason_code=("UPSTREAM_CAPABILITY_SATISFIED" if profiling else "PLANNED"),
                analyzer_id=None if profiling else _ANALYZERS[surface.capability],
                surface_paths=surface.eligible_paths,
                selected_paths=() if profiling else surface.eligible_paths,
                excluded_paths=(),
            )
        )
    return SourceAnalysisPlan(
        repository_digest=profile.repository_digest,
        profile_digest=profile.profile_digest(),
        analyzer_registry_digest="a" * 64,
        planning_policy_digest="b" * 64,
        entries=tuple(entries),
    )


@dataclass
class _Context:
    engine: object
    factory: sessionmaker[Session]
    artifact_root: Path
    service: SourceOrchestrationService
    request: SourceOrchestrationCreateRequest
    profile: RepositoryProfile
    plan: SourceAnalysisPlan


@pytest.fixture
def orchestration_context(tmp_path: Path) -> _Context:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'orchestration.db'}",
        artifact_root=tmp_path / "artifacts",
    )
    initialize_database(settings)
    engine, factory = create_session_factory(settings)
    profile = _fixture_profile()
    plan = _fixture_plan(profile)
    with factory.begin() as session:
        project = ProjectRow(name="S6A fixture")
        target = TargetRow(
            project=project,
            target_type=TargetType.SOURCE_REPOSITORY.value,
            content_digest=profile.repository_digest,
            source_path="/outside/durable/orchestration/snapshot",
        )
        session.add(target)
        session.flush()
        target_id = target.id
    service = SourceOrchestrationService(
        factory,
        ContentAddressedArtifactStore(settings.artifact_root),
        frozen_source_v1_authority_roster(),
        clock=lambda: _NOW,
        run_id_factory=lambda: _RUN_ID,
    )
    request = SourceOrchestrationCreateRequest(
        target_id=target_id,
        idempotency_key="c" * 64,
        profile=profile,
        plan=plan,
        deadline_at=_DEADLINE,
    )
    try:
        yield _Context(engine, factory, settings.artifact_root, service, request, profile, plan)
    finally:
        engine.dispose()


def test_frozen_roster_is_exact_and_deterministic() -> None:
    first = frozen_source_v1_authority_roster()
    second = frozen_source_v1_authority_roster()

    assert tuple(item.authority.value for item in first.authorities) == (
        "checkov",
        "gitleaks",
        "osv.dev",
        "semgrep-ce",
        "syft",
    )
    assert len(first.authorities) == 5
    assert first == second
    assert first.roster_digest() == second.roster_digest()
    assert first.roster_digest() == SOURCE_V1_AUTHORITY_ROSTER_DIGEST


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "extra", "reordered"])
def test_malformed_roster_fails_closed(mutation: str) -> None:
    roster = frozen_source_v1_authority_roster()
    if mutation == "missing":
        authorities = roster.authorities[:-1]
    elif mutation == "duplicate":
        authorities = (*roster.authorities[:-1], roster.authorities[0])
    elif mutation == "extra":
        authorities = (*roster.authorities, roster.authorities[0])
    else:
        authorities = tuple(reversed(roster.authorities))

    with pytest.raises(SourceOrchestrationIntegrityError):
        TrustedSourceAuthorityRoster(authorities)


@pytest.mark.parametrize("field", ["authority", "capability", "analyzer_id", "contract_digest"])
def test_wrong_trusted_authority_identity_fails_closed(field: str) -> None:
    authority = frozen_source_v1_authority_roster().authorities[0]
    replacements: dict[str, object] = {
        "authority": SourceAuthority.GITLEAKS,
        "capability": AnalysisCapability.SECRET_DETECTION,
        "analyzer_id": "wrong-analyzer",
        "contract_digest": "0" * 64,
    }

    with pytest.raises(SourceOrchestrationIntegrityError):
        replace(authority, **{field: replacements[field]})


def test_create_persists_exact_topology_without_execution_rows(
    orchestration_context: _Context,
) -> None:
    context = orchestration_context
    record = context.service.create(context.request)

    assert record.created is True
    assert record.run_id == str(_RUN_ID)
    assert record.lifecycle_state is OrchestrationLifecycleState.PREPARED
    assert record.deadline_at == _DEADLINE
    assert len(record.snapshot.nodes) == 5
    assert {node.authority for node in record.snapshot.nodes} == set(SourceAuthority)
    assert (
        sum(
            node.initial_state is OrchestrationNodeLifecycleState.READY
            for node in record.snapshot.nodes
        )
        == 4
    )
    osv = next(node for node in record.snapshot.nodes if node.authority is SourceAuthority.OSV)
    syft = next(node for node in record.snapshot.nodes if node.authority is SourceAuthority.SYFT)
    assert osv.initial_state is OrchestrationNodeLifecycleState.WAITING_DEPENDENCY
    assert record.snapshot.dependencies == (PlannedSourceDependency(osv.node_id, syft.node_id),)

    with context.factory() as session:
        assert session.scalar(select(func.count()).select_from(JobRow)) == 0
        assert session.scalar(select(func.count()).select_from(ToolExecutionRow)) == 0
        run = session.get(AnalysisRunRow, record.run_id)
        assert run is not None
        assert run.report_json is None


def test_identical_retry_returns_same_run_snapshot_and_topology(
    orchestration_context: _Context,
) -> None:
    first = orchestration_context.service.create(orchestration_context.request)
    second = orchestration_context.service.create(orchestration_context.request)

    assert first.created is True
    assert second.created is False
    assert first.run_id == second.run_id
    assert first.planning_snapshot_sha256 == second.planning_snapshot_sha256
    assert first.snapshot == second.snapshot
    with orchestration_context.factory() as session:
        assert session.scalar(select(func.count()).select_from(AnalysisRunRow)) == 1
        assert session.scalar(select(func.count()).select_from(SourceOrchestrationRow)) == 1
        assert session.scalar(select(func.count()).select_from(SourceOrchestrationNodeRow)) == 5
        assert (
            session.scalar(select(func.count()).select_from(SourceOrchestrationDependencyRow)) == 1
        )


@pytest.mark.parametrize("change", ["plan", "deadline"])
def test_conflicting_retry_is_rejected(
    orchestration_context: _Context,
    change: str,
) -> None:
    context = orchestration_context
    context.service.create(context.request)
    if change == "plan":
        request = replace(
            context.request,
            plan=replace(context.plan, planning_policy_digest="d" * 64),
        )
    else:
        request = replace(
            context.request,
            deadline_at=datetime(2026, 9, 7, 13, 0, tzinfo=UTC),
        )

    with pytest.raises(SourceOrchestrationConflictError):
        context.service.create(request)


def test_roster_digest_participates_in_idempotency_identity() -> None:
    common = dict(
        target_id="00000000-0000-4000-8000-000000000001",
        idempotency_key="a" * 64,
        deadline_iso=_DEADLINE.isoformat(),
        profile_digest="b" * 64,
        plan_digest="c" * 64,
    )
    assert orchestration_request_digest(**common, roster_digest="d" * 64) != (
        orchestration_request_digest(**common, roster_digest="e" * 64)
    )


def test_changed_trusted_roster_under_same_key_is_rejected(
    orchestration_context: _Context,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = orchestration_context
    context.service.create(context.request)
    identities = [dict(item) for item in orchestration_models._TRUSTED_AUTHORITY_IDENTITIES]
    identities[0]["contract_digest"] = "f" * 64
    monkeypatch.setattr(
        orchestration_models,
        "_TRUSTED_AUTHORITY_IDENTITIES",
        tuple(identities),
    )
    changed_service = SourceOrchestrationService(
        context.factory,
        ContentAddressedArtifactStore(context.artifact_root),
        frozen_source_v1_authority_roster(),
        clock=lambda: _NOW,
        run_id_factory=lambda: _SECOND_RUN_ID,
    )

    with pytest.raises(SourceOrchestrationConflictError):
        changed_service.create(context.request)


def test_node_id_uses_only_frozen_identity_material(orchestration_context: _Context) -> None:
    snapshot = SourcePlanningSnapshot.create(
        str(_RUN_ID),
        orchestration_context.profile,
        orchestration_context.plan,
        frozen_source_v1_authority_roster(),
    )
    semgrep = next(node for node in snapshot.nodes if node.authority is SourceAuthority.SEMGREP)
    assert semgrep.node_id == source_node_id(
        str(_RUN_ID),
        SourceAuthority.SEMGREP,
        AnalysisCapability.PYTHON_SAST,
        "application",
    )
    assert (
        source_node_id(
            str(_SECOND_RUN_ID),
            SourceAuthority.SEMGREP,
            AnalysisCapability.PYTHON_SAST,
            "application",
        )
        != semgrep.node_id
    )


def test_deadline_does_not_change_snapshot_or_node_identity(
    orchestration_context: _Context,
) -> None:
    context = orchestration_context
    first = SourcePlanningSnapshot.create(
        str(_RUN_ID), context.profile, context.plan, frozen_source_v1_authority_roster()
    )
    later_deadline = replace(
        context.request,
        deadline_at=datetime(2030, 1, 1, tzinfo=UTC),
    )
    second = SourcePlanningSnapshot.create(
        str(_RUN_ID),
        later_deadline.profile,
        later_deadline.plan,
        frozen_source_v1_authority_roster(),
    )
    assert first == second
    assert first.snapshot_digest() == second.snapshot_digest()


def test_snapshot_is_canonical_and_round_trips(orchestration_context: _Context) -> None:
    snapshot = SourcePlanningSnapshot.create(
        str(_RUN_ID),
        orchestration_context.profile,
        orchestration_context.plan,
        frozen_source_v1_authority_roster(),
    )
    payload = snapshot.canonical_json()

    assert payload.endswith(b"\n")
    assert SourcePlanningSnapshot.from_json(payload) == snapshot
    assert hashlib.sha256(payload).hexdigest() == snapshot.snapshot_digest()
    assert (
        SourcePlanningSnapshot.create(
            str(_RUN_ID),
            orchestration_context.profile,
            orchestration_context.plan,
            frozen_source_v1_authority_roster(),
        ).canonical_json()
        == payload
    )


def test_noncanonical_collection_order_is_rejected(
    orchestration_context: _Context,
) -> None:
    with pytest.raises(ValueError):
        replace(
            orchestration_context.profile,
            files=tuple(reversed(orchestration_context.profile.files)),
        )


@pytest.mark.parametrize(
    "mutation",
    ["unknown-schema", "unknown-field", "duplicate-key", "nan", "absolute", "traversal"],
)
def test_hostile_snapshot_json_fails_closed(
    orchestration_context: _Context,
    mutation: str,
) -> None:
    snapshot = SourcePlanningSnapshot.create(
        str(_RUN_ID),
        orchestration_context.profile,
        orchestration_context.plan,
        frozen_source_v1_authority_roster(),
    )
    raw = snapshot.canonical_data()
    if mutation == "unknown-schema":
        raw["schema_version"] = "future"
        payload = json.dumps(raw, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()
    elif mutation == "unknown-field":
        raw["unexpected"] = True
        payload = json.dumps(raw, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()
    elif mutation == "duplicate-key":
        payload = b'{"schema_version":"duplicate",' + snapshot.canonical_json()[1:]
    else:
        if mutation == "nan":
            raw["profile"]["files"][0]["size_bytes"] = float("nan")
        elif mutation == "absolute":
            raw["profile"]["files"][0]["relative_path"] = "/host/private.py"
        else:
            raw["profile"]["files"][0]["relative_path"] = "../private.py"
        payload = json.dumps(raw, allow_nan=True, sort_keys=True, separators=(",", ":")).encode()

    with pytest.raises(SourceOrchestrationIntegrityError):
        SourcePlanningSnapshot.from_json(payload)


@pytest.mark.parametrize("mutation", ["missing-selected", "unknown-analyzer", "surface-drift"])
def test_plan_profile_scope_tampering_fails_closed(
    orchestration_context: _Context,
    mutation: str,
) -> None:
    context = orchestration_context
    entries = list(context.plan.entries)
    index = next(
        index
        for index, entry in enumerate(entries)
        if entry.capability is AnalysisCapability.PYTHON_SAST
    )
    if mutation == "missing-selected":
        with pytest.raises(ValueError):
            replace(entries[index], selected_paths=("missing.py",))
        return
    if mutation == "unknown-analyzer":
        entries[index] = replace(entries[index], analyzer_id="unknown-analyzer")
        plan = replace(context.plan, entries=tuple(entries))
    else:
        entries[index] = replace(
            entries[index], surface_paths=("infra/main.tf",), selected_paths=("infra/main.tf",)
        )
        plan = replace(context.plan, entries=tuple(entries))

    with pytest.raises(SourceOrchestrationIntegrityError):
        SourcePlanningSnapshot.create(
            str(_RUN_ID), context.profile, plan, frozen_source_v1_authority_roster()
        )


@pytest.mark.parametrize("mutation", ["duplicate-node", "component", "self-edge", "cycle"])
def test_noncanonical_topology_fails_closed(
    orchestration_context: _Context,
    mutation: str,
) -> None:
    snapshot = SourcePlanningSnapshot.create(
        str(_RUN_ID),
        orchestration_context.profile,
        orchestration_context.plan,
        frozen_source_v1_authority_roster(),
    )
    with pytest.raises(SourceOrchestrationIntegrityError):
        if mutation == "duplicate-node":
            replace(snapshot, nodes=(*snapshot.nodes, snapshot.nodes[0]))
        elif mutation == "component":
            changed_node = replace(snapshot.nodes[0], component_id="application")
            replace(snapshot, nodes=(changed_node, *snapshot.nodes[1:]))
        elif mutation == "self-edge":
            replace(
                snapshot,
                dependencies=(
                    PlannedSourceDependency(
                        snapshot.nodes[0].node_id,
                        snapshot.nodes[0].node_id,
                    ),
                ),
            )
        else:
            edge = snapshot.dependencies[0]
            replace(
                snapshot,
                dependencies=(
                    *snapshot.dependencies,
                    PlannedSourceDependency(edge.prerequisite_node_id, edge.node_id),
                ),
            )


def test_osv_without_syft_fails_closed(orchestration_context: _Context) -> None:
    profile = replace(
        orchestration_context.profile,
        surfaces=tuple(
            surface
            for surface in orchestration_context.profile.surfaces
            if surface.capability is not AnalysisCapability.PACKAGE_INVENTORY
        ),
    )
    plan = SourceAnalysisPlan(
        repository_digest=profile.repository_digest,
        profile_digest=profile.profile_digest(),
        analyzer_registry_digest=orchestration_context.plan.analyzer_registry_digest,
        planning_policy_digest=orchestration_context.plan.planning_policy_digest,
        entries=tuple(
            entry
            for entry in orchestration_context.plan.entries
            if entry.capability is not AnalysisCapability.PACKAGE_INVENTORY
        ),
    )
    with pytest.raises(SourceOrchestrationIntegrityError, match="OSV requires"):
        SourcePlanningSnapshot.create(
            str(_RUN_ID), profile, plan, frozen_source_v1_authority_roster()
        )


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("selected_paths_json", ["different.py"]),
        ("component_id", "wrong-component"),
        ("analyzer_id", "wrong-analyzer"),
        ("contract_digest", "0" * 64),
        ("scope_digest", "0" * 64),
    ],
)
def test_durable_node_scope_mutation_is_rejected(
    orchestration_context: _Context,
    column: str,
    value: object,
) -> None:
    context = orchestration_context
    record = context.service.create(context.request)
    with context.factory.begin() as session:
        node = session.scalar(
            select(SourceOrchestrationNodeRow).where(
                SourceOrchestrationNodeRow.run_id == record.run_id,
                SourceOrchestrationNodeRow.authority == SourceAuthority.SEMGREP.value,
            )
        )
        assert node is not None
        setattr(node, column, value)
        if column == "component_id":
            node.component_key = str(value)

    with pytest.raises(SourceOrchestrationIntegrityError):
        context.service.load(record.run_id)


@pytest.mark.parametrize("tamper", ["bytes", "digest", "size", "locator"])
def test_cas_snapshot_tampering_is_rejected(
    orchestration_context: _Context,
    tamper: str,
) -> None:
    context = orchestration_context
    record = context.service.create(context.request)
    with context.factory.begin() as session:
        row = session.get(SourceOrchestrationRow, record.run_id)
        assert row is not None
        if tamper == "bytes":
            (context.artifact_root / row.snapshot_storage_path).write_bytes(b"tampered\n")
        elif tamper == "digest":
            row.planning_snapshot_sha256 = "f" * 64
        elif tamper == "size":
            row.snapshot_size_bytes += 1
        else:
            row.snapshot_storage_path = "../snapshot"

    with pytest.raises(SourceOrchestrationIntegrityError):
        context.service.load(record.run_id)


@pytest.mark.parametrize("tamper", ["missing-roster", "extra-roster", "wrong-roster"])
def test_durable_roster_mutation_is_rejected(
    orchestration_context: _Context,
    tamper: str,
) -> None:
    context = orchestration_context
    record = context.service.create(context.request)
    with context.factory.begin() as session:
        if tamper == "missing-roster":
            session.execute(
                delete(SourceOrchestrationAuthorityRow).where(
                    SourceOrchestrationAuthorityRow.run_id == record.run_id,
                    SourceOrchestrationAuthorityRow.authority == SourceAuthority.OSV.value,
                )
            )
        elif tamper == "extra-roster":
            session.add(
                SourceOrchestrationAuthorityRow(
                    run_id=record.run_id,
                    authority="unexpected",
                    capability="unexpected",
                    analyzer_id="unexpected",
                    contract_kind="trusted-binding",
                    contract_digest="0" * 64,
                    implementation_version="1",
                )
            )
        else:
            session.execute(
                update(SourceOrchestrationAuthorityRow)
                .where(
                    SourceOrchestrationAuthorityRow.run_id == record.run_id,
                    SourceOrchestrationAuthorityRow.authority == SourceAuthority.GITLEAKS.value,
                )
                .values(analyzer_id="wrong-analyzer")
            )

    with pytest.raises(SourceOrchestrationIntegrityError):
        context.service.load(record.run_id)


def test_unexpected_dependency_mutation_is_rejected(
    orchestration_context: _Context,
) -> None:
    context = orchestration_context
    record = context.service.create(context.request)
    nodes = record.snapshot.nodes
    with context.factory.begin() as session:
        session.add(
            SourceOrchestrationDependencyRow(
                run_id=record.run_id,
                node_id=nodes[0].node_id,
                prerequisite_node_id=nodes[1].node_id,
            )
        )

    with pytest.raises(SourceOrchestrationIntegrityError):
        context.service.load(record.run_id)


def test_database_rejects_self_dependency(orchestration_context: _Context) -> None:
    context = orchestration_context
    record = context.service.create(context.request)
    node_id = record.snapshot.nodes[0].node_id
    with pytest.raises(IntegrityError), context.factory.begin() as session:
        session.add(
            SourceOrchestrationDependencyRow(
                run_id=record.run_id,
                node_id=node_id,
                prerequisite_node_id=node_id,
            )
        )


def test_database_rejects_cross_run_dependency(orchestration_context: _Context) -> None:
    context = orchestration_context
    first = context.service.create(context.request)
    second_service = SourceOrchestrationService(
        context.factory,
        ContentAddressedArtifactStore(context.artifact_root),
        frozen_source_v1_authority_roster(),
        clock=lambda: _NOW,
        run_id_factory=lambda: _SECOND_RUN_ID,
    )
    second = second_service.create(replace(context.request, idempotency_key="d" * 64))
    with pytest.raises(IntegrityError), context.factory.begin() as session:
        session.add(
            SourceOrchestrationDependencyRow(
                run_id=second.run_id,
                node_id=first.snapshot.nodes[0].node_id,
                prerequisite_node_id=first.snapshot.nodes[1].node_id,
            )
        )


def test_cancellation_advances_monotonic_version_and_stale_transition_fails(
    orchestration_context: _Context,
) -> None:
    context = orchestration_context
    created = context.service.create(context.request)
    active = context.service.activate(created.run_id, created.state_version)
    cancelled = context.service.request_cancellation(active.run_id, active.state_version)

    assert active.state_version == 2
    assert cancelled.state_version == 3
    assert cancelled.cancel_requested is True
    assert cancelled.lifecycle_state is OrchestrationLifecycleState.CANCELLATION_REQUESTED
    with pytest.raises(SourceOrchestrationStaleVersionError):
        context.service.request_cancellation(active.run_id, active.state_version)


def test_competing_coordinator_uses_same_version_linearization(
    orchestration_context: _Context,
) -> None:
    context = orchestration_context
    created = context.service.create(context.request)
    active = context.service.activate(created.run_id, created.state_version)
    other = SourceOrchestrationService(
        context.factory,
        ContentAddressedArtifactStore(context.artifact_root),
        frozen_source_v1_authority_roster(),
        clock=lambda: datetime(2035, 1, 1, tzinfo=UTC),
        run_id_factory=lambda: _SECOND_RUN_ID,
    )
    observed_by_other = other.load(active.run_id)

    winner = context.service.request_cancellation(active.run_id, active.state_version)
    with pytest.raises(SourceOrchestrationStaleVersionError):
        other.request_cancellation(active.run_id, observed_by_other.state_version)
    assert winner.state_version == 3
    assert other.load(active.run_id).state_version == winner.state_version


def test_restart_reconstructs_identical_durable_truth(
    orchestration_context: _Context,
) -> None:
    context = orchestration_context
    original = context.service.create(context.request)
    del context.service
    fresh_service = SourceOrchestrationService(
        context.factory,
        ContentAddressedArtifactStore(context.artifact_root),
        frozen_source_v1_authority_roster(),
        clock=lambda: _NOW,
        run_id_factory=lambda: _SECOND_RUN_ID,
    )

    reconstructed = fresh_service.load(original.run_id)
    assert reconstructed.snapshot == original.snapshot
    assert reconstructed.planning_snapshot_sha256 == original.planning_snapshot_sha256
    assert reconstructed.roster_digest == original.roster_digest
    assert reconstructed.created is False


def test_snapshot_contains_only_safe_structural_planning_data(
    orchestration_context: _Context,
) -> None:
    payload = SourcePlanningSnapshot.create(
        str(_RUN_ID),
        orchestration_context.profile,
        orchestration_context.plan,
        frozen_source_v1_authority_roster(),
    ).canonical_json()

    assert _PRIVATE_SOURCE not in payload
    assert b"/outside/durable" not in payload
    assert b"RAW_PRIVATE_SOURCE_TOKEN" not in payload
    assert b"stdout" not in payload
    assert b"stderr" not in payload
    assert b"environment" not in payload
    assert b"credentials" not in payload


def test_creation_does_not_invoke_process_or_network(
    orchestration_context: _Context,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("execution boundary crossed")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)

    record = orchestration_context.service.create(orchestration_context.request)
    assert record.created is True


def test_legacy_run_without_orchestration_remains_valid(
    orchestration_context: _Context,
) -> None:
    context = orchestration_context
    with context.factory.begin() as session:
        legacy = AnalysisRunRow(
            id=str(_SECOND_RUN_ID),
            target_id=context.request.target_id,
            status="completed",
            report_json={"schema_version": "legacy", "finding_count": 0},
        )
        session.add(legacy)
    with context.factory() as session:
        reloaded = session.get(AnalysisRunRow, str(_SECOND_RUN_ID))
        assert reloaded is not None
        assert reloaded.report_json == {"schema_version": "legacy", "finding_count": 0}
        assert session.get(SourceOrchestrationRow, str(_SECOND_RUN_ID)) is None
    with pytest.raises(SourceOrchestrationNotFoundError):
        context.service.load(str(_SECOND_RUN_ID))


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_ALEMBIC_INI = _REPOSITORY_ROOT / "alembic.ini"
_MIGRATIONS = _REPOSITORY_ROOT / "migrations"
_S6A_REVISION = "3a6f1c8e2d90"
_PRE_S6A_REVISION = "f4a8c2d17b65"
_S6A_TABLES = {
    "source_orchestrations",
    "source_orchestration_authorities",
    "source_orchestration_nodes",
    "source_orchestration_dependencies",
}


@dataclass
class _PostgresS6AContext:
    database_url: str
    engine: Engine
    factory: sessionmaker[Session]
    artifact_root: Path
    request: SourceOrchestrationCreateRequest
    alternate_target_request: SourceOrchestrationCreateRequest

    def service(
        self,
        *,
        run_id_factory: Callable[[], UUID] = uuid4,
    ) -> SourceOrchestrationService:
        independent_factory = sessionmaker(bind=self.engine, expire_on_commit=False)
        return SourceOrchestrationService(
            independent_factory,
            ContentAddressedArtifactStore(self.artifact_root),
            frozen_source_v1_authority_roster(),
            clock=lambda: _NOW,
            run_id_factory=run_id_factory,
        )


def _reset_postgres_schema(database_url: str) -> None:
    engine = create_engine(database_url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
    finally:
        engine.dispose()


def _alembic_config() -> Config:
    config = Config(str(_ALEMBIC_INI))
    config.set_main_option("script_location", str(_MIGRATIONS))
    return config


@pytest.fixture
def postgres_s6a_database(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[str, Config, Engine]]:
    database_url = validated_postgres_test_url()
    config = _alembic_config()
    engine: Engine | None = None
    monkeypatch.setenv("SECURESCAN_DATABASE_URL", database_url)
    get_settings.cache_clear()
    try:
        _reset_postgres_schema(database_url)
        command.upgrade(config, "head")
        engine = create_engine(database_url)
        assert engine.dialect.name == "postgresql"
        assert {
            "projects",
            "targets",
            "analysis_runs",
            *_S6A_TABLES,
        } <= set(inspect(engine).get_table_names())
        yield database_url, config, engine
    finally:
        if engine is not None:
            engine.dispose()
        try:
            _reset_postgres_schema(database_url)
        finally:
            get_settings.cache_clear()


@pytest.fixture
def postgres_s6a_context(
    postgres_s6a_database: tuple[str, Config, Engine],
    tmp_path: Path,
) -> _PostgresS6AContext:
    database_url, _config, engine = postgres_s6a_database
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    profile = _fixture_profile()
    with factory.begin() as session:
        project = ProjectRow(name="S6A PostgreSQL freeze gate")
        primary = TargetRow(
            project=project,
            target_type=TargetType.SOURCE_REPOSITORY.value,
            content_digest=profile.repository_digest,
            source_path="/tmp/s6a-postgres-primary",
        )
        alternate = TargetRow(
            project=project,
            target_type=TargetType.SOURCE_REPOSITORY.value,
            content_digest=profile.repository_digest,
            source_path="/tmp/s6a-postgres-alternate",
        )
        session.add_all((primary, alternate))
        session.flush()
        primary_id = primary.id
        alternate_id = alternate.id
    request = SourceOrchestrationCreateRequest(
        target_id=primary_id,
        idempotency_key="a" * 64,
        profile=profile,
        plan=_fixture_plan(profile),
        deadline_at=_DEADLINE,
    )
    return _PostgresS6AContext(
        database_url=database_url,
        engine=engine,
        factory=factory,
        artifact_root=tmp_path / "postgres-cas",
        request=request,
        alternate_target_request=replace(request, target_id=alternate_id),
    )


def _current_postgres_revision(engine: Engine) -> str | None:
    with engine.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()


def _s6a_schema_signature(engine: Engine) -> dict[str, object]:
    inspector = inspect(engine)
    return {
        table: {
            "columns": tuple(
                (column["name"], str(column["type"]), column["nullable"])
                for column in inspector.get_columns(table)
            ),
            "primary_key": tuple(inspector.get_pk_constraint(table)["constrained_columns"]),
            "foreign_keys": tuple(
                sorted(
                    (
                        tuple(item["constrained_columns"]),
                        item["referred_table"],
                        tuple(item["referred_columns"]),
                        item.get("options", {}).get("ondelete"),
                    )
                    for item in inspector.get_foreign_keys(table)
                )
            ),
            "unique_constraints": tuple(
                sorted(
                    (item["name"], tuple(item["column_names"]))
                    for item in inspector.get_unique_constraints(table)
                )
            ),
            "checks": tuple(
                sorted(item["name"] for item in inspector.get_check_constraints(table))
            ),
            "indexes": tuple(
                sorted(
                    (item["name"], tuple(item["column_names"]), item["unique"])
                    for item in inspector.get_indexes(table)
                )
            ),
        }
        for table in sorted(_S6A_TABLES)
    }


def _assert_s6a_schema_contract(signature: dict[str, object]) -> None:
    orchestrations = signature["source_orchestrations"]
    authorities = signature["source_orchestration_authorities"]
    nodes = signature["source_orchestration_nodes"]
    dependencies = signature["source_orchestration_dependencies"]

    assert orchestrations["primary_key"] == ("run_id",)
    assert authorities["primary_key"] == ("run_id", "authority")
    assert nodes["primary_key"] == ("node_id",)
    assert dependencies["primary_key"] == (
        "run_id",
        "node_id",
        "prerequisite_node_id",
    )
    assert {name for name, _type, nullable in orchestrations["columns"] if nullable} == {
        "terminal_outcome",
        "cancel_requested_at",
    }
    assert not any(nullable for _name, _type, nullable in authorities["columns"])
    assert {name for name, _type, nullable in nodes["columns"] if nullable} == {
        "component_id",
        "terminal_disposition",
    }
    assert not any(nullable for _name, _type, nullable in dependencies["columns"])
    assert orchestrations["foreign_keys"] == (
        (("run_id",), "analysis_runs", ("id",), "CASCADE"),
    )
    assert authorities["foreign_keys"] == (
        (("run_id",), "source_orchestrations", ("run_id",), "CASCADE"),
    )
    assert set(nodes["foreign_keys"]) == {
        (("run_id",), "source_orchestrations", ("run_id",), "CASCADE"),
        (
            ("run_id", "authority", "capability"),
            "source_orchestration_authorities",
            ("run_id", "authority", "capability"),
            "CASCADE",
        ),
    }
    assert set(dependencies["foreign_keys"]) == {
        (("run_id",), "source_orchestrations", ("run_id",), "CASCADE"),
        (
            ("node_id", "run_id"),
            "source_orchestration_nodes",
            ("node_id", "run_id"),
            "CASCADE",
        ),
        (
            ("prerequisite_node_id", "run_id"),
            "source_orchestration_nodes",
            ("node_id", "run_id"),
            "CASCADE",
        ),
    }
    assert orchestrations["unique_constraints"] == (
        ("uq_source_orchestrations_idempotency", ("idempotency_key",)),
    )
    assert set(authorities["unique_constraints"]) == {
        (
            "uq_source_orchestration_authority_contract",
            ("run_id", "authority", "capability"),
        ),
        ("uq_source_orchestration_authority_capability", ("run_id", "capability")),
    }
    assert set(nodes["unique_constraints"]) == {
        ("uq_source_node_id_run", ("node_id", "run_id")),
        (
            "uq_source_node_logical_identity",
            ("run_id", "authority", "capability", "component_key"),
        ),
    }
    assert dependencies["unique_constraints"] == ()
    assert set(orchestrations["checks"]) == {
        "ck_source_orchestrations_cancel_timestamp",
        "ck_source_orchestrations_lifecycle",
        "ck_source_orchestrations_snapshot_size",
        "ck_source_orchestrations_terminal_outcome",
        "ck_source_orchestrations_terminal_pair",
        "ck_source_orchestrations_version",
    }
    assert authorities["checks"] == ()
    assert set(nodes["checks"]) == {
        "ck_source_node_component_key",
        "ck_source_node_containment",
        "ck_source_node_disposition",
        "ck_source_node_lifecycle",
        "ck_source_node_terminal_pair",
        "ck_source_node_version",
    }
    assert dependencies["checks"] == ("ck_source_dependency_not_self",)
    assert (
        "ix_source_orchestration_nodes_run_id",
        ("run_id",),
        False,
    ) in nodes["indexes"]


@pytest.mark.postgres
def test_postgres_s6a_migration_upgrade_downgrade_upgrade_is_identical(
    postgres_s6a_database: tuple[str, Config, Engine],
) -> None:
    _database_url, config, engine = postgres_s6a_database
    command.downgrade(config, _PRE_S6A_REVISION)
    assert _current_postgres_revision(engine) == _PRE_S6A_REVISION
    legacy_tables = set(inspect(engine).get_table_names())
    assert legacy_tables.isdisjoint(_S6A_TABLES)
    assert {"projects", "targets", "analysis_runs", "jobs", "tool_executions"} <= legacy_tables

    command.upgrade(config, _S6A_REVISION)
    assert _current_postgres_revision(engine) == _S6A_REVISION
    assert set(inspect(engine).get_table_names()) >= _S6A_TABLES
    first_signature = _s6a_schema_signature(engine)
    _assert_s6a_schema_contract(first_signature)

    command.downgrade(config, _PRE_S6A_REVISION)
    assert _current_postgres_revision(engine) == _PRE_S6A_REVISION
    downgraded_tables = set(inspect(engine).get_table_names())
    assert downgraded_tables.isdisjoint(_S6A_TABLES)
    assert legacy_tables == downgraded_tables

    command.upgrade(config, _S6A_REVISION)
    assert _current_postgres_revision(engine) == _S6A_REVISION
    assert _s6a_schema_signature(engine) == first_signature


def _race_call(barrier: threading.Barrier, operation: Callable[[], object]) -> object:
    barrier.wait(timeout=10)
    try:
        return operation()
    except Exception as exc:
        return exc


def _race_operations(
    first: Callable[[], object],
    second: Callable[[], object],
) -> tuple[object, object]:
    barrier = threading.Barrier(3)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(_race_call, barrier, first)
        second_future = executor.submit(_race_call, barrier, second)
        barrier.wait(timeout=10)
        return first_future.result(timeout=20), second_future.result(timeout=20)


def _race_creations(
    context: _PostgresS6AContext,
    first_request: SourceOrchestrationCreateRequest,
    second_request: SourceOrchestrationCreateRequest,
) -> tuple[object, object]:
    insert_barrier = threading.Barrier(2)

    def synchronize_after_both_initial_reads(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        if statement.lstrip().lower().startswith("insert into analysis_runs"):
            insert_barrier.wait(timeout=10)

    event.listen(context.engine, "before_cursor_execute", synchronize_after_both_initial_reads)
    try:
        first_service = context.service(
            run_id_factory=lambda: UUID("31111111-1111-4111-8111-111111111111")
        )
        second_service = context.service(
            run_id_factory=lambda: UUID("32222222-2222-4222-8222-222222222222")
        )
        return _race_operations(
            lambda: first_service.create(first_request),
            lambda: second_service.create(second_request),
        )
    finally:
        event.remove(context.engine, "before_cursor_execute", synchronize_after_both_initial_reads)


def _assert_complete_single_topology(context: _PostgresS6AContext, run_id: str) -> None:
    with context.factory() as session:
        assert session.scalar(select(func.count()).select_from(AnalysisRunRow)) == 1
        assert session.scalar(select(func.count()).select_from(SourceOrchestrationRow)) == 1
        assert (
            session.scalar(select(func.count()).select_from(SourceOrchestrationAuthorityRow)) == 5
        )
        nodes = tuple(
            session.scalars(
                select(SourceOrchestrationNodeRow).where(
                    SourceOrchestrationNodeRow.run_id == run_id
                )
            )
        )
        assert {node.node_id for node in nodes} == {
            node.node_id for node in context.service().load(run_id).snapshot.nodes
        }
        dependencies = tuple(
            session.scalars(
                select(SourceOrchestrationDependencyRow).where(
                    SourceOrchestrationDependencyRow.run_id == run_id
                )
            )
        )
        assert len(dependencies) == 1
        dependency = dependencies[0]
        by_id = {node.node_id: node for node in nodes}
        assert by_id[dependency.node_id].authority == SourceAuthority.OSV.value
        assert by_id[dependency.prerequisite_node_id].authority == SourceAuthority.SYFT.value


@pytest.mark.postgres
def test_postgres_concurrent_state_version_transition_has_exactly_one_winner(
    postgres_s6a_context: _PostgresS6AContext,
) -> None:
    context = postgres_s6a_context
    for iteration in range(8):
        request = replace(
            context.request,
            idempotency_key=hashlib.sha256(f"state-race-{iteration}".encode()).hexdigest(),
        )
        service = context.service()
        created = service.create(request)
        active = service.activate(created.run_id, created.state_version)
        first_service = context.service()
        second_service = context.service()
        first_observed = first_service.load(active.run_id)
        second_observed = second_service.load(active.run_id)
        assert first_observed.state_version == second_observed.state_version
        first, second = _race_operations(
            lambda observed=first_observed, service=first_service: (
                service.request_cancellation(observed.run_id, observed.state_version)
            ),
            lambda observed=second_observed, service=second_service: (
                service.request_cancellation(observed.run_id, observed.state_version)
            ),
        )
        outcomes = (first, second)
        assert sum(not isinstance(item, Exception) for item in outcomes) == 1
        assert sum(isinstance(item, SourceOrchestrationStaleVersionError) for item in outcomes) == 1
        final = context.service().load(active.run_id)
        assert final.state_version == active.state_version + 1
        assert final.lifecycle_state is OrchestrationLifecycleState.CANCELLATION_REQUESTED
        assert final.cancel_requested is True


@pytest.mark.postgres
def test_postgres_activation_vs_cancellation_has_one_legal_database_ordering(
    postgres_s6a_context: _PostgresS6AContext,
) -> None:
    context = postgres_s6a_context
    for iteration in range(8):
        request = replace(
            context.request,
            idempotency_key=hashlib.sha256(f"activation-race-{iteration}".encode()).hexdigest(),
        )
        created = context.service().create(request)
        activation_service = context.service()
        cancellation_service = context.service()
        activation_observed = activation_service.load(created.run_id)
        cancellation_observed = cancellation_service.load(created.run_id)
        assert activation_observed.state_version == cancellation_observed.state_version
        activated, cancelled = _race_operations(
            lambda observed=activation_observed, service=activation_service: (
                service.activate(observed.run_id, observed.state_version)
            ),
            lambda observed=cancellation_observed, service=cancellation_service: (
                service.request_cancellation(observed.run_id, observed.state_version)
            ),
        )
        outcomes = (activated, cancelled)
        assert sum(not isinstance(item, Exception) for item in outcomes) == 1
        assert sum(isinstance(item, SourceOrchestrationStaleVersionError) for item in outcomes) == 1
        final = context.service().load(created.run_id)
        assert final.state_version == created.state_version + 1
        assert (
            final.lifecycle_state,
            final.cancel_requested,
        ) in {
            (OrchestrationLifecycleState.ACTIVE, False),
            (OrchestrationLifecycleState.CANCELLATION_REQUESTED, True),
        }


@pytest.mark.postgres
def test_postgres_concurrent_identical_creation_reconciles_losing_insert(
    postgres_s6a_context: _PostgresS6AContext,
) -> None:
    context = postgres_s6a_context
    first, second = _race_creations(context, context.request, context.request)
    assert not isinstance(first, Exception)
    assert not isinstance(second, Exception)
    assert isinstance(first, SourceOrchestrationRecord)
    assert isinstance(second, SourceOrchestrationRecord)
    assert first.run_id == second.run_id
    assert {first.created, second.created} == {True, False}
    _assert_complete_single_topology(context, first.run_id)


@pytest.mark.postgres
@pytest.mark.parametrize("conflict", ["deadline", "plan", "request-target"])
def test_postgres_concurrent_conflicting_creation_has_one_winner(
    postgres_s6a_context: _PostgresS6AContext,
    conflict: str,
) -> None:
    context = postgres_s6a_context
    if conflict == "deadline":
        changed = replace(
            context.request,
            deadline_at=datetime(2026, 9, 7, 13, 0, tzinfo=UTC),
        )
    elif conflict == "plan":
        changed = replace(
            context.request,
            plan=replace(context.request.plan, planning_policy_digest="d" * 64),
        )
    else:
        changed = context.alternate_target_request

    first, second = _race_creations(context, context.request, changed)
    outcomes = (first, second)
    assert sum(isinstance(item, SourceOrchestrationRecord) for item in outcomes) == 1
    assert sum(isinstance(item, SourceOrchestrationConflictError) for item in outcomes) == 1
    winner = next(item for item in outcomes if isinstance(item, SourceOrchestrationRecord))
    _assert_complete_single_topology(context, winner.run_id)


def _new_node_row(
    node: SourceOrchestrationNodeRow,
    *,
    node_id: str,
    run_id: str | None = None,
) -> SourceOrchestrationNodeRow:
    return SourceOrchestrationNodeRow(
        node_id=node_id,
        run_id=run_id or node.run_id,
        authority=node.authority,
        capability=node.capability,
        component_id=node.component_id,
        component_key=node.component_key,
        analyzer_id=node.analyzer_id,
        contract_digest=node.contract_digest,
        plan_entry_keys_json=node.plan_entry_keys_json,
        selected_paths_json=node.selected_paths_json,
        scope_digest=node.scope_digest,
        lifecycle_state=node.lifecycle_state,
        terminal_disposition=node.terminal_disposition,
        containment_state=node.containment_state,
        state_version=node.state_version,
    )


@pytest.mark.postgres
@pytest.mark.parametrize(
    "hostile_write",
    [
        "duplicate-authority",
        "duplicate-node-logical-identity",
        "wrong-node-run",
        "self-dependency",
        "cross-run-dependency",
        "duplicate-dependency",
        "dangling-dependency",
        "orchestration-without-run",
        "immutable-component-key",
    ],
)
def test_postgres_rejects_hostile_topology_writes(
    postgres_s6a_context: _PostgresS6AContext,
    hostile_write: str,
) -> None:
    context = postgres_s6a_context
    record = context.service().create(context.request)
    with context.factory() as session:
        authority = session.scalar(
            select(SourceOrchestrationAuthorityRow).where(
                SourceOrchestrationAuthorityRow.run_id == record.run_id
            )
        )
        node = session.scalar(
            select(SourceOrchestrationNodeRow).where(
                SourceOrchestrationNodeRow.run_id == record.run_id
            )
        )
        dependency = session.scalar(
            select(SourceOrchestrationDependencyRow).where(
                SourceOrchestrationDependencyRow.run_id == record.run_id
            )
        )
        orchestration = session.get(SourceOrchestrationRow, record.run_id)
        assert authority is not None
        assert node is not None
        assert dependency is not None
        assert orchestration is not None
        session.expunge_all()

    second = None
    if hostile_write == "cross-run-dependency":
        second = context.service().create(
            replace(context.request, idempotency_key="b" * 64)
        )

    with pytest.raises(IntegrityError), context.factory.begin() as session:
        if hostile_write == "duplicate-authority":
            session.add(
                SourceOrchestrationAuthorityRow(
                    run_id=authority.run_id,
                    authority=authority.authority,
                    capability=authority.capability,
                    analyzer_id=authority.analyzer_id,
                    contract_kind=authority.contract_kind,
                    contract_digest=authority.contract_digest,
                    implementation_version=authority.implementation_version,
                )
            )
        elif hostile_write == "duplicate-node-logical-identity":
            session.add(_new_node_row(node, node_id="f" * 64))
        elif hostile_write == "wrong-node-run":
            session.add(
                _new_node_row(
                    node,
                    node_id="e" * 64,
                    run_id="40000000-0000-4000-8000-000000000004",
                )
            )
        elif hostile_write == "self-dependency":
            session.add(
                SourceOrchestrationDependencyRow(
                    run_id=record.run_id,
                    node_id=node.node_id,
                    prerequisite_node_id=node.node_id,
                )
            )
        elif hostile_write == "cross-run-dependency":
            assert second is not None
            session.add(
                SourceOrchestrationDependencyRow(
                    run_id=second.run_id,
                    node_id=dependency.node_id,
                    prerequisite_node_id=dependency.prerequisite_node_id,
                )
            )
        elif hostile_write == "duplicate-dependency":
            session.add(
                SourceOrchestrationDependencyRow(
                    run_id=dependency.run_id,
                    node_id=dependency.node_id,
                    prerequisite_node_id=dependency.prerequisite_node_id,
                )
            )
        elif hostile_write == "dangling-dependency":
            session.add(
                SourceOrchestrationDependencyRow(
                    run_id=record.run_id,
                    node_id="c" * 64,
                    prerequisite_node_id="d" * 64,
                )
            )
        elif hostile_write == "orchestration-without-run":
            session.add(
                SourceOrchestrationRow(
                    run_id="50000000-0000-4000-8000-000000000005",
                    idempotency_key="c" * 64,
                    creation_request_digest=orchestration.creation_request_digest,
                    repository_digest=orchestration.repository_digest,
                    profile_digest=orchestration.profile_digest,
                    plan_digest=orchestration.plan_digest,
                    roster_digest=orchestration.roster_digest,
                    planning_snapshot_sha256=orchestration.planning_snapshot_sha256,
                    snapshot_size_bytes=orchestration.snapshot_size_bytes,
                    snapshot_media_type=orchestration.snapshot_media_type,
                    snapshot_schema_version=orchestration.snapshot_schema_version,
                    snapshot_storage_path=orchestration.snapshot_storage_path,
                    lifecycle_state=orchestration.lifecycle_state,
                    terminal_outcome=orchestration.terminal_outcome,
                    cancel_requested=orchestration.cancel_requested,
                    cancel_requested_at=orchestration.cancel_requested_at,
                    state_version=orchestration.state_version,
                    deadline_at=orchestration.deadline_at,
                    created_at=orchestration.created_at,
                    updated_at=orchestration.updated_at,
                )
            )
        else:
            session.execute(
                update(SourceOrchestrationNodeRow)
                .where(SourceOrchestrationNodeRow.node_id == node.node_id)
                .values(component_key="not-the-component")
            )
        session.flush()


@pytest.mark.postgres
def test_postgres_typed_reload_rejects_semantic_topology_mutation(
    postgres_s6a_context: _PostgresS6AContext,
) -> None:
    context = postgres_s6a_context
    record = context.service().create(context.request)
    with context.factory.begin() as session:
        session.execute(
            update(SourceOrchestrationNodeRow)
            .where(
                SourceOrchestrationNodeRow.run_id == record.run_id,
                SourceOrchestrationNodeRow.authority == SourceAuthority.GITLEAKS.value,
            )
            .values(selected_paths_json=["different.py"])
        )
    with pytest.raises(SourceOrchestrationIntegrityError):
        context.service().load(record.run_id)


@pytest.mark.postgres
def test_postgres_losing_create_transaction_leaves_only_complete_database_topology(
    postgres_s6a_context: _PostgresS6AContext,
) -> None:
    context = postgres_s6a_context
    first, second = _race_creations(context, context.request, context.request)
    assert isinstance(first, SourceOrchestrationRecord)
    assert isinstance(second, SourceOrchestrationRecord)
    winner = first if first.created else second
    loser = second if first.created else first
    assert winner.run_id == loser.run_id
    _assert_complete_single_topology(context, winner.run_id)

    committed = context.service().load(winner.run_id)
    payload = ContentAddressedArtifactStore(context.artifact_root).read_by_sha256(
        committed.planning_snapshot_sha256,
        expected_size_bytes=len(committed.snapshot.canonical_json()),
    )
    assert payload == committed.snapshot.canonical_json()
    cas_objects = tuple(
        path
        for path in (context.artifact_root / "sha256").glob("*/*")
        if path.is_file()
    )
    assert len(cas_objects) == 2


@pytest.mark.postgres
def test_postgres_restart_reconstructs_exact_canonical_orchestration(
    postgres_s6a_context: _PostgresS6AContext,
) -> None:
    context = postgres_s6a_context
    service = context.service()
    original = service.create(context.request)
    active = service.activate(original.run_id, original.state_version)
    del service
    context.engine.dispose()

    fresh_engine = create_engine(context.database_url)
    fresh_factory = sessionmaker(bind=fresh_engine, expire_on_commit=False)
    fresh_service = SourceOrchestrationService(
        fresh_factory,
        ContentAddressedArtifactStore(context.artifact_root),
        frozen_source_v1_authority_roster(),
        clock=lambda: datetime(2035, 1, 1, tzinfo=UTC),
    )
    try:
        reloaded = fresh_service.load(active.run_id)
        assert reloaded == replace(active, created=False)
        assert reloaded.snapshot.canonical_json() == active.snapshot.canonical_json()
        assert reloaded.snapshot.roster == active.snapshot.roster
        assert reloaded.snapshot.nodes == active.snapshot.nodes
        assert reloaded.snapshot.dependencies == active.snapshot.dependencies
        assert reloaded.deadline_at == active.deadline_at
        assert reloaded.state_version == active.state_version
        assert reloaded.idempotency_key == active.idempotency_key
        assert (
            reloaded.snapshot.profile.profile_digest()
            == active.snapshot.profile.profile_digest()
        )
        assert reloaded.snapshot.plan.plan_digest() == active.snapshot.plan.plan_digest()
    finally:
        fresh_engine.dispose()
