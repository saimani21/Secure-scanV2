from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy.orm import Session, sessionmaker

import securescan.jobs.submission as job_submission_module
from securescan.adapters.sandbox_policy import (
    SandboxExecutionBackend,
    SandboxExecutionPolicy,
)
from securescan.adapters.trusted_registry import TrustedAdapterDefinition
from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.config import Settings
from securescan.domain.enums import ArtifactKind, JobStatus, TargetType
from securescan.execution.docker_sandbox import DockerSandboxExecutor
from securescan.jobs import (
    IdempotencyConflictError,
    JobRepository,
    JobSubmissionService,
    TargetContentDigestMismatchError,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    ProjectRow,
    TargetRow,
    create_session_factory,
    initialize_database,
)
from securescan.scanners.semgrep import (
    SOURCE_EXECUTION_PAYLOAD_KEY,
    InvalidSourceSemgrepExecutionRequestError,
    SemgrepScannerAdapter,
    SourceExecutionBindingMismatchError,
    SourceExecutionContextArtifactError,
    SourceExecutionContextIdentityError,
    SourceExecutionEnvelope,
    SourceSemgrepExecutionContextResolver,
    SourceSemgrepSubmissionRequest,
    SourceSemgrepSubmissionService,
    TrustedSemgrepSourceBinding,
    build_semgrep_source_execution_context,
    load_baseline_ruleset,
)
from securescan.source import (
    AnalysisCapability,
    AnalysisSurface,
    FileContentKind,
    InvalidSourceExecutionContextError,
    RepositoryComponent,
    RepositoryProfile,
    SourceExecutionContext,
    SourceExecutionSelectedFile,
    SourceFileRecord,
    SourceFileRole,
    SourcePlanningPolicy,
    SourceSupportState,
    TrustedSourceAnalyzer,
    TrustedSourceAnalyzerRegistry,
    build_source_analysis_plan,
)
from securescan.workspaces import RepositoryManifestEntry
from securescan.workspaces.models import repository_content_digest

IMAGE = "registry.example/securescan/semgrep@sha256:" + "5" * 64
RUN_ID = str(UUID("00000000-0000-4000-8000-000000003c01"))
JOB_ID = str(UUID("00000000-0000-4000-8000-000000003c02"))
GOLDEN_CONTEXT_DIGEST = (
    "90c04120da9262de94bb0e5861df974c6a4f8a8f3fb91b3ed057c7f62b37f06c"
)


def _definition(*, tool_version: str = "1.171.0") -> TrustedAdapterDefinition:
    return TrustedAdapterDefinition(
        adapter_id="semgrep-ce",
        display_name="Semgrep Community Edition",
        tool_name="semgrep",
        tool_version=tool_version,
        backend=SandboxExecutionBackend.DOCKER_SANDBOX,
        policy=SandboxExecutionPolicy(allowed_environment_names=("HOME",)),
        factory=lambda: object(),
        image_reference=IMAGE,
        command_prefix=("semgrep",),
    )


def _binding(*, tool_version: str = "1.171.0") -> TrustedSemgrepSourceBinding:
    return TrustedSemgrepSourceBinding(
        definition=_definition(tool_version=tool_version),
        ruleset=load_baseline_ruleset(),
    )


def _trusted_inputs():
    entries = (
        RepositoryManifestEntry(
            relative_path="app.py",
            size_bytes=12,
            sha256=hashlib.sha256(b"app content\n").hexdigest(),
        ),
        RepositoryManifestEntry(
            relative_path="pkg/mod.py",
            size_bytes=15,
            sha256=hashlib.sha256(b"module content\n").hexdigest(),
        ),
    )
    component_id = "component-python"
    files = (
        SourceFileRecord(
            entry=entries[0],
            content_kind=FileContentKind.TEXT,
            role=SourceFileRole.SOURCE,
            eligible_capabilities=(
                AnalysisCapability.PYTHON_SAST,
                AnalysisCapability.REPOSITORY_PROFILING,
            ),
        ),
        SourceFileRecord(
            entry=entries[1],
            content_kind=FileContentKind.TEXT,
            role=SourceFileRole.SOURCE,
            component_id=component_id,
            eligible_capabilities=(
                AnalysisCapability.PYTHON_SAST,
                AnalysisCapability.REPOSITORY_PROFILING,
            ),
        ),
    )
    paths = tuple(file.relative_path for file in files)
    profile = RepositoryProfile(
        repository_digest=repository_content_digest(entries),
        files=files,
        components=(
            RepositoryComponent(
                component_id=component_id,
                display_name="Python package",
                root_path="pkg",
            ),
        ),
        surfaces=tuple(
            sorted(
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
                key=lambda surface: surface.capability.value,
            )
        ),
    )
    registry = TrustedSourceAnalyzerRegistry(
        analyzers=(
            TrustedSourceAnalyzer(
                analyzer_id="python-semgrep-v1",
                capabilities=(AnalysisCapability.PYTHON_SAST,),
                available=True,
            ),
        )
    )
    plan = build_source_analysis_plan(profile, registry, SourcePlanningPolicy())
    entry = next(
        candidate
        for candidate in plan.entries
        if candidate.capability is AnalysisCapability.PYTHON_SAST
    )
    return profile, plan, entry, _binding()


def _context() -> SourceExecutionContext:
    profile, plan, entry, binding = _trusted_inputs()
    return build_semgrep_source_execution_context(
        source_run_id=RUN_ID,
        job_id=JOB_ID,
        profile=profile,
        plan=plan,
        entry=entry,
        binding=binding,
    )


@pytest.fixture
def durable_services(
    tmp_path: Path,
) -> Iterator[tuple[
    sessionmaker[Session],
    ContentAddressedArtifactStore,
    str,
]]:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'source-context.db'}",
        artifact_root=tmp_path / "artifacts",
    )
    initialize_database(settings)
    engine, session_factory = create_session_factory(settings)
    profile, _, _, _ = _trusted_inputs()
    with session_factory.begin() as session:
        project = ProjectRow(name="Source context test")
        target = TargetRow(
            project=project,
            target_type=TargetType.SOURCE_REPOSITORY.value,
            content_digest=profile.repository_digest,
            source_path="/mutable/original/not-used",
        )
        session.add(target)
        session.flush()
        target_id = target.id
    store = ContentAddressedArtifactStore(tmp_path / "artifacts")
    try:
        yield session_factory, store, target_id
    finally:
        engine.dispose()


def test_context_retains_trusted_identities_and_selected_file_facts() -> None:
    profile, plan, entry, binding = _trusted_inputs()
    context = _context()

    assert context.source_run_id == RUN_ID
    assert context.job_id == JOB_ID
    assert context.repository_digest == profile.repository_digest
    assert context.profile_digest == profile.profile_digest()
    assert context.plan_digest == plan.plan_digest()
    assert context.source_analyzer_id == entry.analyzer_id == binding.source_analyzer_id
    assert context.capability is AnalysisCapability.PYTHON_SAST
    assert context.core_adapter_id == binding.core_adapter_id == "semgrep-ce"
    assert context.binding_digest == binding.binding_digest()
    assert tuple(file.relative_path for file in context.selected_files) == entry.selected_paths
    assert context.selected_files == tuple(
        SourceExecutionSelectedFile(entry=file.entry, component_id=file.component_id)
        for file in profile.files
    )
    with pytest.raises(FrozenInstanceError):
        context.core_adapter_id = "other"  # type: ignore[misc]


def test_context_canonical_json_and_literal_digest_are_deterministic() -> None:
    first = _context()
    second = _context()

    assert first.canonical_json() == second.canonical_json()
    assert first.context_digest() == second.context_digest()
    assert first.context_digest() == GOLDEN_CONTEXT_DIGEST
    assert SourceExecutionContext.from_json(first.canonical_json()) == first


def test_builder_requires_run_python_binding_and_plan_membership() -> None:
    profile, plan, entry, binding = _trusted_inputs()

    non_member = replace(
        entry,
        component_id="component-python",
        surface_paths=("pkg/mod.py",),
        selected_paths=("pkg/mod.py",),
    )
    with pytest.raises(InvalidSourceSemgrepExecutionRequestError):
        build_semgrep_source_execution_context(
            source_run_id=RUN_ID,
            job_id=JOB_ID,
            profile=profile,
            plan=plan,
            entry=non_member,
            binding=binding,
        )

    bad_entry = replace(entry, analyzer_id="other-analyzer")
    with pytest.raises(InvalidSourceSemgrepExecutionRequestError):
        build_semgrep_source_execution_context(
            source_run_id=RUN_ID,
            job_id=JOB_ID,
            profile=profile,
            plan=plan,
            entry=bad_entry,
            binding=binding,
        )

    object.__setattr__(entry, "selected_paths", ())
    with pytest.raises(InvalidSourceSemgrepExecutionRequestError):
        build_semgrep_source_execution_context(
            source_run_id=RUN_ID,
            job_id=JOB_ID,
            profile=profile,
            plan=plan,
            entry=entry,
            binding=binding,
        )


def test_builder_rejects_nonrun_and_non_python_entries() -> None:
    profile, _, _, binding = _trusted_inputs()
    unavailable = TrustedSourceAnalyzerRegistry(
        analyzers=(
            TrustedSourceAnalyzer(
                analyzer_id="python-semgrep-v1",
                capabilities=(AnalysisCapability.PYTHON_SAST,),
                available=False,
                unavailable_reason_code="SEMGREP_UNAVAILABLE",
            ),
        )
    )
    skipped_plan = build_source_analysis_plan(
        profile,
        unavailable,
        SourcePlanningPolicy(),
    )
    skipped_entry = next(
        entry
        for entry in skipped_plan.entries
        if entry.capability is AnalysisCapability.PYTHON_SAST
    )
    with pytest.raises(InvalidSourceSemgrepExecutionRequestError):
        build_semgrep_source_execution_context(
            source_run_id=RUN_ID,
            job_id=JOB_ID,
            profile=profile,
            plan=skipped_plan,
            entry=skipped_entry,
            binding=binding,
        )

    secret_surface = AnalysisSurface(
        capability=AnalysisCapability.SECRET_DETECTION,
        support_state=SourceSupportState.SCANNABLE,
        eligible_paths=tuple(file.relative_path for file in profile.files),
    )
    secret_profile = replace(
        profile,
        files=tuple(
            replace(
                file,
                eligible_capabilities=tuple(
                    sorted(
                        {
                            *file.eligible_capabilities,
                            AnalysisCapability.SECRET_DETECTION,
                        },
                        key=lambda capability: capability.value,
                    )
                ),
            )
            for file in profile.files
        ),
        surfaces=tuple(
            sorted(
                (*profile.surfaces, secret_surface),
                key=lambda surface: surface.capability.value,
            )
        ),
    )
    secret_plan = build_source_analysis_plan(
        secret_profile,
        TrustedSourceAnalyzerRegistry(
            analyzers=(
                TrustedSourceAnalyzer(
                    analyzer_id="secret-analyzer",
                    capabilities=(AnalysisCapability.SECRET_DETECTION,),
                    available=True,
                ),
            )
        ),
        SourcePlanningPolicy(),
    )
    secret_entry = next(
        entry
        for entry in secret_plan.entries
        if entry.capability is AnalysisCapability.SECRET_DETECTION
    )
    with pytest.raises(InvalidSourceSemgrepExecutionRequestError):
        build_semgrep_source_execution_context(
            source_run_id=RUN_ID,
            job_id=JOB_ID,
            profile=secret_profile,
            plan=secret_plan,
            entry=secret_entry,
            binding=binding,
        )


def test_context_rejects_duplicate_or_unsorted_selected_files() -> None:
    context = _context()
    with pytest.raises(InvalidSourceExecutionContextError):
        replace(context, selected_files=(context.selected_files[0],) * 2)
    with pytest.raises(InvalidSourceExecutionContextError):
        replace(context, selected_files=tuple(reversed(context.selected_files)))


@pytest.mark.parametrize("constant", ("NaN", "Infinity", "-Infinity"))
def test_context_json_rejects_duplicate_keys_and_nonfinite_numbers(
    constant: str,
) -> None:
    payload = _context().canonical_json()
    duplicate = payload.replace(b'{"binding_digest":', b'{"job_id":"duplicate","binding_digest":')
    with pytest.raises(InvalidSourceExecutionContextError):
        SourceExecutionContext.from_json(duplicate)

    nonfinite = payload.replace(b'"size_bytes":12', f'"size_bytes":{constant}'.encode())
    with pytest.raises(InvalidSourceExecutionContextError):
        SourceExecutionContext.from_json(nonfinite)


def test_context_json_rejects_unknown_fields_and_noncanonical_encoding() -> None:
    context = _context()
    document = context.canonical_data()
    document["unknown"] = "field"
    with pytest.raises(InvalidSourceExecutionContextError):
        SourceExecutionContext.from_json(json.dumps(document).encode())
    with pytest.raises(InvalidSourceExecutionContextError):
        SourceExecutionContext.from_json(b" " + context.canonical_json())


def _submit(
    services: tuple[sessionmaker[Session], ContentAddressedArtifactStore, str],
):
    session_factory, store, target_id = services
    profile, plan, entry, binding = _trusted_inputs()
    service = SourceSemgrepSubmissionService(
        JobSubmissionService(session_factory),
        store,
        run_id_factory=lambda: UUID(RUN_ID),
        job_id_factory=lambda: UUID(JOB_ID),
    )
    result = service.submit(
        SourceSemgrepSubmissionRequest(
            target_id=target_id,
            idempotency_key="c" * 64,
            profile=profile,
            plan=plan,
            entry=entry,
            binding=binding,
        )
    )
    return result, binding


def _submission_request(
    target_id: str,
    *,
    priority: int = 100,
    max_attempts: int = 3,
) -> tuple[SourceSemgrepSubmissionRequest, TrustedSemgrepSourceBinding]:
    profile, plan, entry, binding = _trusted_inputs()
    return (
        SourceSemgrepSubmissionRequest(
            target_id=target_id,
            idempotency_key="d" * 64,
            profile=profile,
            plan=plan,
            entry=entry,
            binding=binding,
            priority=priority,
            max_attempts=max_attempts,
        ),
        binding,
    )


def _artifact_files(store: ContentAddressedArtifactStore) -> set[Path]:
    return {
        path.relative_to(store.root)
        for path in store.root.rglob("*")
        if path.is_file()
    }


def test_identical_retry_returns_existing_job_and_stable_context(
    durable_services,
) -> None:
    session_factory, store, target_id = durable_services
    request, binding = _submission_request(target_id)
    service = SourceSemgrepSubmissionService(
        JobSubmissionService(session_factory),
        store,
    )

    first = service.submit(request)
    first_job = JobRepository(session_factory).get_job(first.job_id)
    assert first_job is not None
    first_context = SourceSemgrepExecutionContextResolver(store, binding).resolve(
        first_job
    )
    first_envelope = first_job.payload_json
    first_artifacts = _artifact_files(store)

    second = service.submit(request)
    second_job = JobRepository(session_factory).get_job(second.job_id)
    assert second_job is not None
    second_context = SourceSemgrepExecutionContextResolver(store, binding).resolve(
        second_job
    )

    assert first.created is True
    assert second.created is False
    assert second.run_id == first.run_id
    assert second.job_id == first.job_id
    assert second_job.payload_json == first_envelope
    assert second_context == first_context
    assert _artifact_files(store) == first_artifacts
    assert len(first_artifacts) == 1
    with session_factory() as session:
        assert session.query(AnalysisRunRow).count() == 1
        assert session.query(JobRow).count() == 1


def test_identical_retry_with_fresh_services_uses_durable_identity(
    durable_services,
) -> None:
    session_factory, store, target_id = durable_services
    first_request, _ = _submission_request(target_id)
    first_service = SourceSemgrepSubmissionService(
        JobSubmissionService(session_factory),
        store,
    )
    first = first_service.submit(first_request)
    artifact_root = store.root
    del first_service, first_request, store

    fresh_store = ContentAddressedArtifactStore(artifact_root)
    second_request, binding = _submission_request(target_id)
    second_service = SourceSemgrepSubmissionService(
        JobSubmissionService(session_factory),
        fresh_store,
    )
    second = second_service.submit(second_request)
    durable_job = JobRepository(session_factory).get_job(second.job_id)

    assert second.created is False
    assert second.run_id == first.run_id
    assert second.job_id == first.job_id
    assert durable_job is not None
    context = SourceSemgrepExecutionContextResolver(
        fresh_store,
        binding,
    ).resolve(durable_job)
    assert context.source_run_id == first.run_id
    assert context.job_id == first.job_id
    assert len(_artifact_files(fresh_store)) == 1


def test_same_key_with_different_source_semantics_remains_a_conflict(
    durable_services,
) -> None:
    session_factory, store, target_id = durable_services
    request, _ = _submission_request(target_id)
    service = SourceSemgrepSubmissionService(
        JobSubmissionService(session_factory),
        store,
    )
    first = service.submit(request)

    with pytest.raises(IdempotencyConflictError):
        service.submit(replace(request, priority=request.priority + 1))

    with session_factory() as session:
        runs = list(session.query(AnalysisRunRow))
        jobs = list(session.query(JobRow))
        assert len(runs) == 1
        assert len(jobs) == 1
        assert runs[0].id == first.run_id
        assert jobs[0].id == first.job_id
        assert jobs[0].priority == request.priority


def test_server_owned_integrity_error_recovery_returns_existing_submission(
    durable_services,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_factory, store, target_id = durable_services
    request, _ = _submission_request(target_id)
    first_service = SourceSemgrepSubmissionService(
        JobSubmissionService(session_factory),
        store,
    )
    first = first_service.submit(request)
    original_find = job_submission_module._find_submission
    find_calls = 0

    def stale_once(session: Session, idempotency_key: str):
        nonlocal find_calls
        find_calls += 1
        if find_calls == 1:
            return None
        return original_find(session, idempotency_key)

    monkeypatch.setattr(job_submission_module, "_find_submission", stale_once)
    recovery_service = SourceSemgrepSubmissionService(
        JobSubmissionService(session_factory),
        ContentAddressedArtifactStore(store.root),
    )
    recovered = recovery_service.submit(_submission_request(target_id)[0])

    assert find_calls == 2
    assert recovered.created is False
    assert recovered.run_id == first.run_id
    assert recovered.job_id == first.job_id
    with session_factory() as session:
        assert session.query(AnalysisRunRow).count() == 1
        assert session.query(JobRow).count() == 1


def test_server_submission_derives_adapter_and_persists_tiny_envelope(
    durable_services,
) -> None:
    session_factory, _, _ = durable_services
    result, _ = _submit(durable_services)
    job = JobRepository(session_factory).get_job(result.job_id)

    assert result.created is True
    assert result.status is JobStatus.QUEUED
    assert result.run_id == RUN_ID
    assert result.job_id == JOB_ID
    assert job is not None
    assert job.adapter_id == "semgrep-ce"
    assert set(job.payload_json) == {SOURCE_EXECUTION_PAYLOAD_KEY}
    envelope = job.payload_json[SOURCE_EXECUTION_PAYLOAD_KEY]
    assert envelope["artifact_kind"] == ArtifactKind.SOURCE_EXECUTION_CONTEXT.value
    assert envelope["artifact_media_type"] == "application/json"
    assert envelope["artifact_sanitized"] is False
    assert "selected_files" not in envelope
    assert "image" not in envelope
    assert "command" not in envelope
    assert "adapter_id" not in {
        field.name for field in fields(SourceSemgrepSubmissionRequest)
    }


def test_server_submission_correlates_target_digest_before_creating_rows(
    durable_services,
) -> None:
    session_factory, _, target_id = durable_services
    with session_factory.begin() as session:
        target = session.get(TargetRow, target_id)
        assert target is not None
        target.content_digest = "f" * 64

    with pytest.raises(TargetContentDigestMismatchError):
        _submit(durable_services)

    with session_factory() as session:
        assert session.query(AnalysisRunRow).count() == 0
        assert session.query(JobRow).count() == 0


def test_fresh_repository_store_and_resolver_reconstruct_exact_context(
    durable_services,
) -> None:
    session_factory, store, _ = durable_services
    result, binding = _submit(durable_services)

    artifact_root = store.root
    del store
    fresh_repository = JobRepository(session_factory)
    fresh_store = ContentAddressedArtifactStore(artifact_root)
    fresh_resolver = SourceSemgrepExecutionContextResolver(fresh_store, _binding())
    durable_job = fresh_repository.get_job(result.job_id)

    assert durable_job is not None
    recovered = fresh_resolver.resolve(durable_job)
    assert recovered == _context()
    assert recovered.binding_digest == binding.binding_digest()


def test_artifact_corruption_is_rejected(durable_services) -> None:
    session_factory, store, _ = durable_services
    result, binding = _submit(durable_services)
    job = JobRepository(session_factory).get_job(result.job_id)
    assert job is not None
    envelope = SourceExecutionEnvelope.from_payload_json(job.payload_json)
    artifact_path = (
        store.root
        / "sha256"
        / envelope.artifact_sha256[:2]
        / envelope.artifact_sha256
    )
    original = artifact_path.read_bytes()
    artifact_path.write_bytes(bytes((original[0] ^ 1,)) + original[1:])

    with pytest.raises(SourceExecutionContextArtifactError):
        SourceSemgrepExecutionContextResolver(store, binding).resolve(job)


def test_context_digest_mismatch_is_rejected(durable_services) -> None:
    session_factory, store, _ = durable_services
    result, binding = _submit(durable_services)
    job = JobRepository(session_factory).get_job(result.job_id)
    assert job is not None
    envelope = SourceExecutionEnvelope.from_payload_json(job.payload_json)
    tampered_job = replace(
        job,
        payload_json=SourceExecutionEnvelope(
            artifact_sha256=envelope.artifact_sha256,
            artifact_size_bytes=envelope.artifact_size_bytes,
            context_digest="0" * 64,
        ).payload_json(),
    )

    with pytest.raises(InvalidSourceExecutionContextError):
        SourceSemgrepExecutionContextResolver(store, binding).resolve(tampered_job)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("repository_digest", "1" * 64),
        ("profile_digest", "2" * 64),
        ("plan_digest", "3" * 64),
        ("source_analyzer_id", "other-analyzer"),
        ("capability", AnalysisCapability.SECRET_DETECTION.value),
        ("binding_digest", "4" * 64),
    ),
)
def test_context_content_tampering_is_rejected(
    durable_services,
    field: str,
    value: object,
) -> None:
    session_factory, store, _ = durable_services
    result, binding = _submit(durable_services)
    job = JobRepository(session_factory).get_job(result.job_id)
    assert job is not None
    envelope = SourceExecutionEnvelope.from_payload_json(job.payload_json)
    payload = store.read_by_sha256(
        envelope.artifact_sha256,
        expected_size_bytes=envelope.artifact_size_bytes,
    )
    document = json.loads(payload)
    document[field] = value
    modified = json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    artifact = store.put(
        modified,
        kind=ArtifactKind.SOURCE_EXECUTION_CONTEXT,
        media_type="application/json",
        sanitized=False,
    )
    changed_envelope = SourceExecutionEnvelope(
        artifact_sha256=artifact.sha256,
        artifact_size_bytes=artifact.size_bytes,
        context_digest=envelope.context_digest,
    )
    tampered_job = replace(job, payload_json=changed_envelope.payload_json())

    with pytest.raises(
        (InvalidSourceExecutionContextError, SourceExecutionBindingMismatchError)
    ):
        SourceSemgrepExecutionContextResolver(store, binding).resolve(tampered_job)


@pytest.mark.parametrize("tamper", ("selected_file", "schema_version"))
def test_selected_file_and_schema_tampering_is_rejected(
    durable_services,
    tamper: str,
) -> None:
    session_factory, store, _ = durable_services
    result, binding = _submit(durable_services)
    job = JobRepository(session_factory).get_job(result.job_id)
    assert job is not None
    envelope = SourceExecutionEnvelope.from_payload_json(job.payload_json)
    document = json.loads(
        store.read_by_sha256(
            envelope.artifact_sha256,
            expected_size_bytes=envelope.artifact_size_bytes,
        )
    )
    if tamper == "selected_file":
        document["selected_files"][0]["sha256"] = "e" * 64
    else:
        document["schema_version"] = "0.3C2"
    modified = json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    artifact = store.put(
        modified,
        kind=ArtifactKind.SOURCE_EXECUTION_CONTEXT,
        media_type="application/json",
        sanitized=False,
    )
    tampered_job = replace(
        job,
        payload_json=SourceExecutionEnvelope(
            artifact_sha256=artifact.sha256,
            artifact_size_bytes=artifact.size_bytes,
            context_digest=envelope.context_digest,
        ).payload_json(),
    )

    with pytest.raises(InvalidSourceExecutionContextError):
        SourceSemgrepExecutionContextResolver(store, binding).resolve(tampered_job)


@pytest.mark.parametrize(
    ("field", "value", "error"),
    (
        (
            "id",
            str(UUID("00000000-0000-4000-8000-000000003c11")),
            SourceExecutionContextIdentityError,
        ),
        (
            "run_id",
            str(UUID("00000000-0000-4000-8000-000000003c12")),
            SourceExecutionContextIdentityError,
        ),
        ("adapter_id", "other-adapter", SourceExecutionContextIdentityError),
    ),
)
def test_job_identity_tampering_is_rejected(
    durable_services,
    field: str,
    value: str,
    error: type[Exception],
) -> None:
    session_factory, store, _ = durable_services
    result, binding = _submit(durable_services)
    job = JobRepository(session_factory).get_job(result.job_id)
    assert job is not None

    with pytest.raises(error):
        SourceSemgrepExecutionContextResolver(store, binding).resolve(
            replace(job, **{field: value})
        )


def test_current_binding_mismatch_is_rejected(durable_services) -> None:
    session_factory, store, _ = durable_services
    result, _ = _submit(durable_services)
    job = JobRepository(session_factory).get_job(result.job_id)
    assert job is not None

    with pytest.raises(SourceExecutionBindingMismatchError):
        SourceSemgrepExecutionContextResolver(
            store,
            _binding(tool_version="1.172.0"),
        ).resolve(job)


def test_context_boundary_never_discovers_or_executes_tools(
    durable_services,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("v0.3C1 attempted discovery or execution")

    monkeypatch.setattr(shutil, "which", fail)
    monkeypatch.setattr(subprocess, "run", fail)
    monkeypatch.setattr(os, "system", fail)
    monkeypatch.setattr(DockerSandboxExecutor, "execute", fail)
    monkeypatch.setattr(SemgrepScannerAdapter, "execute", fail)

    session_factory, store, _ = durable_services
    result, binding = _submit(durable_services)
    job = JobRepository(session_factory).get_job(result.job_id)
    assert job is not None
    assert SourceSemgrepExecutionContextResolver(store, binding).resolve(job)
