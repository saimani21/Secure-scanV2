from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from contextlib import suppress
from dataclasses import replace
from pathlib import Path
from textwrap import dedent
from uuid import UUID

import pytest
from sqlalchemy import func, select
from test_source_orchestration_s6a import (
    _DEADLINE,
    _NOW,
    _PRIVATE_SOURCE,
    _RUN_ID,
    _fixture_plan,
    _fixture_profile,
)

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.config import Settings
from securescan.domain.enums import (
    ExecutionOutcome,
    JobFailureCategory,
    JobStatus,
    TargetType,
)
from securescan.execution.cancellable_process import (
    CancellableProcessRequest,
    CancellableProcessResult,
    CancellableProcessStateError,
)
from securescan.execution.docker_sandbox import (
    DockerContainerInspectionError,
    DockerControlCommandResult,
    DockerSandboxExecutionRequest,
)
from securescan.execution.supervisor import (
    AttemptBoundProcessExecutor,
    SupervisorAttemptIdentity,
    TrustedLocalProcessSupervisor,
)
from securescan.orchestration.execution import (
    SourceScannerAttemptBlockedError,
    SourceScannerAttemptService,
    SourceScannerExecutionConflictError,
    SourceScannerJobService,
    SourceScannerLeaseReconciliationService,
    SourceScannerResultRejectedError,
)
from securescan.orchestration.execution_models import (
    AttemptContainmentOutcome,
    SafeSourceNativeResult,
    SourceAttemptCleanupReceipt,
    SourceSandboxCleanupReceipt,
    SourceScannerExecutionIntegrityError,
    SourceScannerFailureCode,
    source_sandbox_execution_identity,
)
from securescan.orchestration.local_execution import SourceLocalBridgeExecutionService
from securescan.orchestration.models import (
    OrchestrationContainmentState,
    SourceAuthority,
    frozen_source_v1_authority_roster,
)
from securescan.orchestration.sandbox_execution import (
    AttemptBoundDockerExecutor,
    SourceSandboxReconciliationService,
)
from securescan.orchestration.service import (
    SourceOrchestrationCreateRequest,
    SourceOrchestrationService,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    ProjectRow,
    SourceOrchestrationAttemptRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationScannerJobRow,
    TargetRow,
    ToolExecutionRow,
    create_session_factory,
    initialize_database,
)
from securescan.scanners.checkov import (
    CHECKOV_FRAMEWORKS,
    CHECKOV_SCANNER_ID,
    CHECKOV_VERSION,
    CheckovFrameworkOutcome,
    CheckovFrameworkState,
    CheckovParseResult,
    create_default_checkov_binding,
)
from securescan.scanners.checkov.source_execution import (
    CheckovExecutionResultEnvelope,
    CheckovExecutionStatus,
)
from securescan.scanners.gitleaks.binding import (
    GITLEAKS_SCANNER_ID,
    GITLEAKS_VERSION,
    create_default_gitleaks_binding,
)
from securescan.scanners.gitleaks.parser import GitleaksParseResult
from securescan.scanners.gitleaks.source_execution import (
    GitleaksExecutionResultEnvelope,
    GitleaksExecutionStatus,
)
from securescan.scanners.semgrep import (
    PRODUCTION_SEMGREP_IMAGE_REFERENCE,
    SourceExecutionEnvelope,
    SourceSemgrepExecutionContextResolver,
    TrustedSemgrepSourceBinding,
    create_production_semgrep_source_binding,
    create_semgrep_trusted_definition,
    create_source_aware_semgrep_trusted_definition,
    load_baseline_ruleset,
)
from securescan.scanners.syft import (
    SYFT_JSON_SCHEMA_VERSION,
    SYFT_SCANNER_ID,
    SYFT_VERSION,
    SyftParseResult,
    create_default_syft_binding,
)
from securescan.scanners.syft.source_execution import (
    SyftExecutionResultEnvelope,
    SyftExecutionStatus,
)
from securescan.source.execution_context import (
    SourceExecutionContext,
    SourceExecutionSelectedFile,
)
from securescan.source.projection import SourceProjectionManager
from securescan.worker.models import WorkerSuccessfulExecution
from securescan.workspaces import RepositoryWorkspaceManager
from securescan.workspaces.models import repository_content_digest

_LEASE_TOKEN = "33333333-3333-4333-8333-333333333333"
_ATTEMPT_TOKEN = UUID("44444444-4444-4444-8444-444444444444")
_SEMGREP_IMAGE = PRODUCTION_SEMGREP_IMAGE_REFERENCE
_SEMGREP_FIXTURE = (
    Path(__file__).parent / "fixtures" / "semgrep" / "output" / "valid-findings.json"
)
_GITLEAKS_EXECUTABLE = (
    Path.home() / ".local/securescan-tools/gitleaks/8.30.1/gitleaks"
)
_CHECKOV_EXECUTABLE = Path(".venv-checkov-3.3.16/bin/checkov")
_CONTROLLED_SECRET = b"ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


class _Environment:
    def __init__(
        self,
        tmp_path: Path,
        *,
        database_url: str | None = None,
        app_source: bytes = _PRIVATE_SOURCE,
        infra_source: bytes = b'resource "x" "y" {}\n',
    ) -> None:
        settings = Settings(
            database_url=database_url or f"sqlite:///{tmp_path / 's6b.db'}",
            artifact_root=tmp_path / "artifacts",
        )
        initialize_database(settings)
        self.engine, self.factory = create_session_factory(settings)
        self.store = ContentAddressedArtifactStore(settings.artifact_root)
        profile = _fixture_profile()
        fixture_sources = {
            "app.py": app_source,
            "infra/main.tf": infra_source,
            "requirements.lock": b"requests==2.31.0\n",
        }
        if app_source != _PRIVATE_SOURCE or infra_source != b'resource "x" "y" {}\n':
            files = tuple(
                replace(
                    item,
                    entry=replace(
                        item.entry,
                        size_bytes=len(fixture_sources[item.relative_path]),
                        sha256=hashlib.sha256(
                            fixture_sources[item.relative_path]
                        ).hexdigest(),
                    ),
                )
                for item in profile.files
            )
            profile = replace(
                profile,
                repository_digest=repository_content_digest(
                    tuple(item.entry for item in files)
                ),
                files=files,
            )
        self.profile = profile
        self.plan = _fixture_plan(self.profile)
        source = tmp_path / "source"
        source.mkdir()
        (source / "app.py").write_bytes(app_source)
        (source / "infra").mkdir()
        (source / "infra" / "main.tf").write_bytes(infra_source)
        (source / "requirements.lock").write_bytes(b"requests==2.31.0\n")
        self.workspace_manager = RepositoryWorkspaceManager(tmp_path / "workspaces")
        self.workspace = self.workspace_manager.prepare_repository(source)
        self.projections = SourceProjectionManager(tmp_path / "projections")
        with self.factory.begin() as session:
            project = ProjectRow(name="S6B fixture")
            target = TargetRow(
                project=project,
                target_type=TargetType.SOURCE_REPOSITORY.value,
                content_digest=self.profile.repository_digest,
                source_path="/not-persisted-in-native-result",
            )
            session.add(target)
            session.flush()
            target_id = target.id
        self.orchestrations = SourceOrchestrationService(
            self.factory,
            self.store,
            frozen_source_v1_authority_roster(),
            clock=lambda: _NOW,
            run_id_factory=lambda: _RUN_ID,
        )
        created = self.orchestrations.create(
            SourceOrchestrationCreateRequest(
                target_id=target_id,
                idempotency_key="8" * 64,
                profile=self.profile,
                plan=self.plan,
                deadline_at=_DEADLINE,
            )
        )
        self.orchestrations.activate(created.run_id, created.state_version)
        self.snapshot = created.snapshot
        self.jobs = SourceScannerJobService(
            self.factory,
            self.store,
            self.orchestrations,
            self.projections,
            clock=lambda: _NOW,
        )
        self.attempts = SourceScannerAttemptService(
            self.factory,
            self.store,
            self.projections,
            clock=lambda: _NOW,
            token_factory=lambda: _ATTEMPT_TOKEN,
        )

    def close(self) -> None:
        self.workspace_manager.cleanup_workspace(self.workspace)
        self.engine.dispose()

    def create(self, authority: SourceAuthority = SourceAuthority.GITLEAKS):
        node = next(item for item in self.snapshot.nodes if item.authority is authority)
        job = self.jobs.create_job(
            run_id=str(_RUN_ID), node_id=node.node_id, workspace=self.workspace
        )
        return node, job

    def start_attempt(
        self,
        authority: SourceAuthority = SourceAuthority.GITLEAKS,
        *,
        clean: bool = True,
    ):
        node, created = self.create(authority)
        with self.factory.begin() as session:
            job = session.get(JobRow, created.job_id)
            assert job is not None
            job.status = JobStatus.RUNNING.value
            job.attempt_count = 1
            job.leased_by = "worker-s6b"
            job.lease_token = _LEASE_TOKEN
            job.lease_expires_at = _DEADLINE
            job.started_at = _NOW
        attempt = self.attempts.register_attempt(
            job_id=created.job_id,
            worker_id="worker-s6b",
            lease_token=_LEASE_TOKEN,
        )
        self.attempts.register_supervisor(
            job_id=created.job_id,
            attempt_number=1,
            attempt_token=attempt.attempt_token,
            supervisor_identity="a" * 64,
            supervisor_pid=999_991,
            supervisor_start_ticks=101,
            scanner_pid=999_992,
            scanner_pgid=999_992,
            scanner_start_ticks=102,
        )
        if not clean:
            return node, created, attempt
        receipt = SourceAttemptCleanupReceipt(
            job_id=created.job_id,
            attempt_number=1,
            attempt_token=attempt.attempt_token,
            supervisor_identity="a" * 64,
            supervisor_pid=999_991,
            supervisor_start_ticks=101,
            scanner_pid=999_992,
            scanner_pgid=999_992,
            scanner_start_ticks=102,
            cleanup_outcome=AttemptContainmentOutcome.CLEAN,
            process_tree_empty=True,
        )
        self.attempts.record_cleanup(receipt)
        return node, created, attempt

    def native_result(self, node, job) -> SafeSourceNativeResult:
        with self.factory() as session:
            mapping = session.get(SourceOrchestrationScannerJobRow, job.job_id)
            assert mapping is not None
            payload = self.store.read_by_sha256(
                mapping.context_artifact_sha256,
                expected_size_bytes=mapping.context_artifact_size_bytes,
            )
        context = SourceExecutionContext.from_json(payload)
        common = {
            "node_id": node.node_id,
            "job_id": job.job_id,
            "attempt_number": 1,
            "analyzer_id": node.analyzer_id,
            "context": context,
        }
        projection = self.projections.reopen_projection(
            job.projection_id,
            expected_context_digest=context.context_digest(),
            expected_projection_digest=job.projection_digest,
        )
        if node.authority is SourceAuthority.GITLEAKS:
            envelope = GitleaksExecutionResultEnvelope(
                scanner_id=GITLEAKS_SCANNER_ID,
                scanner_version=GITLEAKS_VERSION,
                binding_digest=context.binding_digest,
                execution_status=GitleaksExecutionStatus.COMPLETED_NO_FINDINGS,
                failure_code=None,
                return_code=0,
                stdout_bytes=b"[]",
                stderr_bytes=b"",
                duration_ms=1,
                timed_out=False,
                output_limit_exceeded=False,
                termination_requested=False,
                force_killed=False,
                cancellation_requested=False,
                projection_id=projection.projection_id,
                context_digest=projection.context_digest,
                projection_digest=projection.projection_digest,
            )
            return SafeSourceNativeResult.from_gitleaks_execution(
                envelope=envelope, projection=projection, **common
            )
        if node.authority is SourceAuthority.SYFT:
            document = {
                "artifacts": [],
                "artifactRelationships": [],
                "source": {
                    "name": str(projection.source_directory),
                    "type": "directory",
                    "metadata": {"path": str(projection.source_directory)},
                },
                "descriptor": {
                    "name": "syft",
                    "version": SYFT_VERSION,
                    "configuration": {
                        "catalogers": {
                            "requested": {"default": ["directory", "file"]},
                            "used": [],
                        }
                    },
                },
                "schema": {
                    "version": SYFT_JSON_SCHEMA_VERSION,
                    "url": (
                        "https://raw.githubusercontent.com/anchore/syft/main/"
                        "schema/json/schema-16.1.10.json"
                    ),
                },
            }
            envelope = SyftExecutionResultEnvelope(
                scanner_id=SYFT_SCANNER_ID,
                scanner_version=SYFT_VERSION,
                binding_digest=context.binding_digest,
                execution_status=SyftExecutionStatus.COMPLETED,
                failure_code=None,
                return_code=0,
                stdout_bytes=json.dumps(document).encode(),
                stderr_bytes=b"",
                duration_ms=1,
                timed_out=False,
                output_limit_exceeded=False,
                termination_requested=False,
                force_killed=False,
                cancellation_requested=False,
                projection_id=projection.projection_id,
                context_digest=projection.context_digest,
                projection_digest=projection.projection_digest,
            )
            return SafeSourceNativeResult.from_syft_execution(
                envelope=envelope, projection=projection, **common
            )
        if node.authority is SourceAuthority.CHECKOV:
            document = {
                "check_type": "terraform",
                "results": {
                    "failed_checks": [],
                    "passed_checks": [
                        {
                            "check_id": "CKV_AWS_18",
                            "check_name": "Controlled check",
                            "resource": "x.y",
                            "file_path": "/infra/main.tf",
                            "file_line_range": [1, 1],
                            "check_result": {"result": "PASSED"},
                            "severity": None,
                        }
                    ],
                    "skipped_checks": [],
                    "parsing_errors": [],
                },
                "summary": {
                    "passed": 1,
                    "failed": 0,
                    "skipped": 0,
                    "parsing_errors": 0,
                    "resource_count": 1,
                    "checkov_version": CHECKOV_VERSION,
                },
                "url": "controlled",
            }
            envelope = CheckovExecutionResultEnvelope(
                scanner_id=CHECKOV_SCANNER_ID,
                scanner_version=CHECKOV_VERSION,
                binding_digest=context.binding_digest,
                execution_status=CheckovExecutionStatus.COMPLETED,
                failure_code=None,
                return_code=0,
                stdout_bytes=json.dumps(document).encode(),
                stderr_bytes=b"",
                duration_ms=1,
                timed_out=False,
                output_limit_exceeded=False,
                termination_requested=False,
                force_killed=False,
                cancellation_requested=False,
                projection_id=projection.projection_id,
                context_digest=projection.context_digest,
                projection_digest=projection.projection_digest,
            )
            return SafeSourceNativeResult.from_checkov_execution(
                envelope=envelope, projection=projection, **common
            )
        if node.authority is SourceAuthority.SEMGREP:
            payload = json.dumps(
                {
                    "results": [],
                    "ruleset": {
                        "id": "securescan-python-baseline-v2",
                        "version": "2",
                    },
                    "scanner_id": "semgrep-ce",
                    "schema_version": "securescan-semgrep-sanitized-v1",
                    "summary": {
                        "accepted_findings": 0,
                        "analysis_gaps": 0,
                        "duplicate_findings": 0,
                        "rejected_findings": 0,
                    },
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
            return SafeSourceNativeResult.from_semgrep_sanitized(
                payload=payload,
                scanner_version="1.171.0",
                projection_id=job.projection_id,
                projection_digest=job.projection_digest,
                **common,
            )
        raise AssertionError("OSV is not an S6B local authority")


@pytest.fixture
def s6b(tmp_path: Path):
    environment = _Environment(tmp_path)
    try:
        yield environment
    finally:
        environment.close()


def test_node_creates_exactly_one_bound_job(s6b: _Environment) -> None:
    node, first = s6b.create()
    _, second = s6b.create()

    assert first.created is True
    assert second.created is False
    assert first == replace(second, created=True)
    with s6b.factory() as session:
        assert session.scalar(select(func.count()).select_from(JobRow)) == 1
        mapping = session.get(SourceOrchestrationScannerJobRow, first.job_id)
        assert mapping is not None
        assert mapping.node_id == node.node_id
        assert mapping.run_id == str(_RUN_ID)
        assert mapping.contract_digest == node.contract_digest


def test_current_semgrep_native_identity_rejects_old_placeholder_binding(
    s6b: _Environment,
) -> None:
    node, job = s6b.create(SourceAuthority.SEMGREP)
    native = s6b.native_result(node, job)
    old_binding_digest = (
        "90876e4088e2b397bc37d310a0eba5eb4d61b7263fbdb72136c73557a100e59a"
    )

    with pytest.raises(SourceScannerExecutionIntegrityError):
        replace(native, binding_digest=old_binding_digest)


def test_attempt_requires_every_prior_attempt_to_be_clean(s6b: _Environment) -> None:
    _node, job, attempt = s6b.start_attempt()
    with s6b.factory.begin() as session:
        row = session.get(SourceOrchestrationAttemptRow, (job.job_id, 1))
        durable_job = session.get(JobRow, job.job_id)
        assert row is not None and durable_job is not None
        row.containment_state = OrchestrationContainmentState.RECONCILIATION_REQUIRED.value
        row.acceptance_state = "REJECTED"
        durable_job.attempt_count = 2
        durable_job.lease_token = "55555555-5555-4555-8555-555555555555"
    with pytest.raises(SourceScannerAttemptBlockedError):
        s6b.attempts.register_attempt(
            job_id=job.job_id,
            worker_id="worker-s6b",
            lease_token="55555555-5555-4555-8555-555555555555",
        )
    assert attempt.containment_state is OrchestrationContainmentState.ACTIVE


def test_failed_attempt_history_is_retained_and_clean_attempt_allows_successor(
    s6b: _Environment,
) -> None:
    _node, job, attempt = s6b.start_attempt()
    s6b.attempts.record_failure(
        job_id=job.job_id,
        attempt_number=1,
        attempt_token=attempt.attempt_token,
        lease_token=_LEASE_TOKEN,
        failure_code=SourceScannerFailureCode.EXECUTION_FAILURE,
        failure_category=JobFailureCategory.RETRYABLE_INFRASTRUCTURE,
        execution_outcome=ExecutionOutcome.INTERNAL_ERROR,
        return_code=2,
        duration_ms=8,
        retryable=True,
    )
    second_lease = "55555555-5555-4555-8555-555555555555"
    with s6b.factory.begin() as session:
        durable = session.get(JobRow, job.job_id)
        assert durable is not None
        durable.status = JobStatus.RUNNING.value
        durable.attempt_count = 2
        durable.leased_by = "worker-s6b"
        durable.lease_token = second_lease
        durable.lease_expires_at = _DEADLINE
    successor_service = SourceScannerAttemptService(
        s6b.factory,
        s6b.store,
        s6b.projections,
        clock=lambda: _NOW,
        token_factory=lambda: UUID("66666666-6666-4666-8666-666666666666"),
    )
    successor = successor_service.register_attempt(
        job_id=job.job_id,
        worker_id="worker-s6b",
        lease_token=second_lease,
    )
    assert successor.attempt_number == 2
    with s6b.factory() as session:
        attempts = tuple(
            session.scalars(
                select(SourceOrchestrationAttemptRow)
                .where(SourceOrchestrationAttemptRow.job_id == job.job_id)
                .order_by(SourceOrchestrationAttemptRow.attempt_number)
            )
        )
        assert [item.acceptance_state for item in attempts] == ["REJECTED", "PENDING"]
        assert session.scalar(select(func.count()).select_from(ToolExecutionRow)) == 1


def test_safe_native_result_acceptance_is_atomic_idempotent_and_reloadable(
    s6b: _Environment,
) -> None:
    node, job, _attempt = s6b.start_attempt()
    native = s6b.native_result(node, job)

    first = s6b.attempts.accept_result(
        native,
        lease_token=_LEASE_TOKEN,
        execution_outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
        return_code=0,
        duration_ms=12,
    )
    second = s6b.attempts.accept_result(
        native,
        lease_token=_LEASE_TOKEN,
        execution_outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
        return_code=0,
        duration_ms=12,
    )

    assert first.created is True
    assert second == replace(first, created=False)
    fresh = SourceScannerAttemptService(s6b.factory, s6b.store, s6b.projections, clock=lambda: _NOW)
    assert fresh.load_accepted_result(run_id=str(_RUN_ID), node_id=node.node_id) == native
    with s6b.factory() as session:
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        durable_job = session.get(JobRow, job.job_id)
        durable_node = session.get(SourceOrchestrationNodeRow, node.node_id)
        assert run is not None and run.report_json is None
        assert durable_job is not None and durable_job.status == JobStatus.SUCCEEDED.value
        assert durable_node is not None and durable_node.terminal_disposition == "COMPLETE"
        assert session.scalar(select(func.count()).select_from(ToolExecutionRow)) == 1


def test_conflicting_or_cross_node_result_is_rejected(s6b: _Environment) -> None:
    node, job, _attempt = s6b.start_attempt()
    native = s6b.native_result(node, job)
    cross_node = replace(native, node_id="f" * 64)
    with pytest.raises(SourceScannerResultRejectedError):
        s6b.attempts.accept_result(
            cross_node,
            lease_token=_LEASE_TOKEN,
            execution_outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
            return_code=0,
            duration_ms=11,
        )
    s6b.attempts.accept_result(
        native,
        lease_token=_LEASE_TOKEN,
        execution_outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
        return_code=0,
        duration_ms=12,
    )
    conflicting_data = dict(native.canonical_data()["native_data"])
    conflicting_data["finding_count"] = 1
    conflicting = replace(native, native_data=conflicting_data)
    with pytest.raises(SourceScannerResultRejectedError):
        s6b.attempts.accept_result(
            conflicting,
            lease_token=_LEASE_TOKEN,
            execution_outcome=ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS,
            return_code=1,
            duration_ms=13,
        )


def test_parent_cancellation_wins_by_database_lock_order(s6b: _Environment) -> None:
    node, job, _attempt = s6b.start_attempt()
    native = s6b.native_result(node, job)
    s6b.orchestrations.request_cancellation(str(_RUN_ID), 2)

    with pytest.raises(SourceScannerResultRejectedError):
        s6b.attempts.accept_result(
            native,
            lease_token=_LEASE_TOKEN,
            execution_outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
            return_code=0,
            duration_ms=12,
        )
    with s6b.factory() as session:
        assert session.scalar(select(func.count()).select_from(ToolExecutionRow)) == 0


def test_projection_or_cas_tampering_fails_closed(s6b: _Environment) -> None:
    node, job, _attempt = s6b.start_attempt()
    native = s6b.native_result(node, job)
    projection_file = s6b.projections.base_directory / job.projection_id / "source" / "app.py"
    projection_file.chmod(0o600)
    projection_file.write_bytes(b"tampered\n")
    with pytest.raises(SourceScannerResultRejectedError):
        s6b.attempts.accept_result(
            native,
            lease_token=_LEASE_TOKEN,
            execution_outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
            return_code=0,
            duration_ms=1,
        )


def test_native_cas_readback_tampering_fails_before_acceptance(
    s6b: _Environment, monkeypatch: pytest.MonkeyPatch
) -> None:
    node, job, _attempt = s6b.start_attempt()
    native = s6b.native_result(node, job)
    original_read = s6b.store.read_by_sha256

    def tampered_read(digest: str, *, expected_size_bytes: int) -> bytes:
        payload = original_read(digest, expected_size_bytes=expected_size_bytes)
        return payload + b" " if digest == native.sha256() else payload

    monkeypatch.setattr(s6b.store, "read_by_sha256", tampered_read)
    with pytest.raises(SourceScannerResultRejectedError):
        s6b.attempts.accept_result(
            native,
            lease_token=_LEASE_TOKEN,
            execution_outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
            return_code=0,
            duration_ms=1,
        )
    with s6b.factory() as session:
        attempt = session.get(SourceOrchestrationAttemptRow, (job.job_id, 1))
        assert attempt is not None and attempt.acceptance_state == "PENDING"
        assert session.scalar(select(func.count()).select_from(ToolExecutionRow)) == 0


def test_tampered_durable_cleanup_receipt_cannot_authorize_result(
    s6b: _Environment,
) -> None:
    node, job, _attempt = s6b.start_attempt()
    native = s6b.native_result(node, job)
    with s6b.factory.begin() as session:
        attempt = session.get(SourceOrchestrationAttemptRow, (job.job_id, 1))
        assert attempt is not None and attempt.cleanup_receipt_json is not None
        attempt.cleanup_receipt_json = {
            **attempt.cleanup_receipt_json,
            "scanner_start_ticks": 999,
        }
    with pytest.raises(SourceScannerResultRejectedError):
        s6b.attempts.accept_result(
            native,
            lease_token=_LEASE_TOKEN,
            execution_outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
            return_code=0,
            duration_ms=1,
        )


def test_stale_failed_attempt_cannot_replace_current_attempt(s6b: _Environment) -> None:
    node, job, first = s6b.start_attempt()
    stale_result = s6b.native_result(node, job)
    s6b.attempts.record_failure(
        job_id=job.job_id,
        attempt_number=1,
        attempt_token=first.attempt_token,
        lease_token=_LEASE_TOKEN,
        failure_code=SourceScannerFailureCode.EXECUTION_FAILURE,
        failure_category=JobFailureCategory.RETRYABLE_INFRASTRUCTURE,
        execution_outcome=ExecutionOutcome.INTERNAL_ERROR,
        return_code=2,
        duration_ms=1,
        retryable=True,
    )
    second_lease = "55555555-5555-4555-8555-555555555555"
    with s6b.factory.begin() as session:
        durable = session.get(JobRow, job.job_id)
        assert durable is not None
        durable.status = JobStatus.RUNNING.value
        durable.attempt_count = 2
        durable.leased_by = "worker-s6b"
        durable.lease_token = second_lease
        durable.lease_expires_at = _DEADLINE
    successor_service = SourceScannerAttemptService(
        s6b.factory,
        s6b.store,
        s6b.projections,
        clock=lambda: _NOW,
        token_factory=lambda: UUID("66666666-6666-4666-8666-666666666666"),
    )
    successor_service.register_attempt(
        job_id=job.job_id,
        worker_id="worker-s6b",
        lease_token=second_lease,
    )
    with pytest.raises(SourceScannerResultRejectedError):
        successor_service.accept_result(
            stale_result,
            lease_token=second_lease,
            execution_outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
            return_code=0,
            duration_ms=1,
        )


def test_raw_secret_and_workspace_path_never_enter_safe_native_artifact(
    s6b: _Environment,
) -> None:
    node, job, _attempt = s6b.start_attempt()
    with s6b.factory() as session:
        mapping = session.get(SourceOrchestrationScannerJobRow, job.job_id)
        assert mapping is not None
        context = SourceExecutionContext.from_json(
            s6b.store.read_by_sha256(
                mapping.context_artifact_sha256,
                expected_size_bytes=mapping.context_artifact_size_bytes,
            )
        )
    projection = s6b.projections.reopen_projection(
        job.projection_id,
        expected_context_digest=context.context_digest(),
        expected_projection_digest=job.projection_digest,
    )
    raw_finding = json.dumps(
        [
            {
                "RuleID": "github-pat",
                "Description": "controlled",
                "StartLine": 1,
                "EndLine": 1,
                "StartColumn": 1,
                "EndColumn": len(_PRIVATE_SOURCE.rstrip(b"\n")),
                "Match": _PRIVATE_SOURCE.decode().rstrip("\n"),
                "Secret": "REDACTED",
                "File": "app.py",
                "SymlinkFile": "",
                "Commit": "",
                "Entropy": 4.5,
                "Author": "",
                "Email": "",
                "Date": "",
                "Message": "",
                "Tags": ["controlled"],
                "Fingerprint": "unsafe-upstream-fingerprint",
            }
        ]
    ).encode()
    envelope = GitleaksExecutionResultEnvelope(
        scanner_id=GITLEAKS_SCANNER_ID,
        scanner_version=GITLEAKS_VERSION,
        binding_digest=context.binding_digest,
        execution_status=GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS,
        failure_code=None,
        return_code=1,
        stdout_bytes=raw_finding,
        stderr_bytes=_PRIVATE_SOURCE,
        duration_ms=1,
        timed_out=False,
        output_limit_exceeded=False,
        termination_requested=False,
        force_killed=False,
        cancellation_requested=False,
        projection_id=projection.projection_id,
        context_digest=projection.context_digest,
        projection_digest=projection.projection_digest,
    )
    native = SafeSourceNativeResult.from_gitleaks_execution(
        envelope=envelope,
        projection=projection,
        node_id=node.node_id,
        job_id=job.job_id,
        attempt_number=1,
        analyzer_id=node.analyzer_id,
        context=context,
    )
    payload = native.canonical_json()
    assert b"RAW_PRIVATE_SOURCE_TOKEN" not in payload
    assert str(s6b.workspace.source_directory).encode() not in payload
    assert b"environment" not in payload
    s6b.attempts.accept_result(
        native,
        lease_token=_LEASE_TOKEN,
        execution_outcome=ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS,
        return_code=1,
        duration_ms=1,
    )
    assert all(
        _PRIVATE_SOURCE.rstrip(b"\n") not in path.read_bytes()
        for path in s6b.store.root.rglob("*")
        if path.is_file()
    )
    assert _PRIVATE_SOURCE.rstrip(b"\n") not in Path(
        str(s6b.engine.url.database)
    ).read_bytes()


def test_all_four_local_authorities_have_canonical_safe_native_schemas(
    s6b: _Environment,
) -> None:
    results: list[SafeSourceNativeResult] = []
    projection_id = "securescan-source-projection-" + "9" * 32
    projection_digest = "c" * 64
    for authority in (
        SourceAuthority.GITLEAKS,
        SourceAuthority.SYFT,
        SourceAuthority.CHECKOV,
        SourceAuthority.SEMGREP,
    ):
        node = next(item for item in s6b.snapshot.nodes if item.authority is authority)
        job_id = str(UUID(int=len(results) + 10))
        files = {item.relative_path: item for item in s6b.profile.files}
        context = SourceExecutionContext(
            source_run_id=str(_RUN_ID),
            job_id=job_id,
            repository_digest=s6b.profile.repository_digest,
            profile_digest=s6b.profile.profile_digest(),
            plan_digest=s6b.plan.plan_digest(),
            source_analyzer_id=node.analyzer_id,
            capability=node.capability,
            component_id=node.component_id,
            selected_files=tuple(
                SourceExecutionSelectedFile(
                    entry=replace(files[path].entry),
                    component_id=files[path].component_id,
                )
                for path in node.selected_paths
            ),
            binding_digest=node.contract_digest,
            core_adapter_id=authority.value,
        )
        common = {
            "node_id": node.node_id,
            "job_id": job_id,
            "attempt_number": 1,
            "analyzer_id": node.analyzer_id,
            "context": context,
        }
        if authority is SourceAuthority.GITLEAKS:
            parsed = GitleaksParseResult(
                scanner_id=GITLEAKS_SCANNER_ID,
                scanner_version=GITLEAKS_VERSION,
                binding_digest=node.contract_digest,
                projection_id=projection_id,
                context_digest=context.context_digest(),
                projection_digest=projection_digest,
                findings=(),
                finding_count=0,
            )
            native = SafeSourceNativeResult.from_parse_result(
                result=parsed, authority=authority.value, **common
            )
        elif authority is SourceAuthority.SYFT:
            parsed = SyftParseResult(
                scanner_id=SYFT_SCANNER_ID,
                scanner_version=SYFT_VERSION,
                binding_digest=node.contract_digest,
                projection_id=projection_id,
                snapshot_digest=projection_digest,
                syft_schema_version=SYFT_JSON_SCHEMA_VERSION,
                requested_cataloger_strategy=("directory", "file"),
                used_catalogers=(),
                observations=(),
                package_count=0,
            )
            native = SafeSourceNativeResult.from_parse_result(
                result=parsed, authority=authority.value, **common
            )
        elif authority is SourceAuthority.CHECKOV:
            outcomes = tuple(
                CheckovFrameworkOutcome(
                    framework=framework,
                    state=CheckovFrameworkState.NOT_APPLICABLE,
                    failed_count=0,
                    passed_count=0,
                    suppressed_count=0,
                    parsing_gap_count=0,
                    resource_count=0,
                )
                for framework in CHECKOV_FRAMEWORKS
            )
            parsed = CheckovParseResult(
                scanner_id=CHECKOV_SCANNER_ID,
                scanner_version=CHECKOV_VERSION,
                binding_digest=node.contract_digest,
                projection_id=projection_id,
                snapshot_digest=projection_digest,
                observations=(),
                findings=(),
                suppressions=(),
                gaps=(),
                framework_outcomes=outcomes,
                passed_observations=(),
            )
            native = SafeSourceNativeResult.from_parse_result(
                result=parsed, authority=authority.value, **common
            )
        else:
            semgrep_payload = json.dumps(
                {
                    "results": [],
                    "ruleset": {
                        "id": "securescan-python-baseline-v2",
                        "version": "2",
                    },
                    "scanner_id": "semgrep-ce",
                    "schema_version": "securescan-semgrep-sanitized-v1",
                    "summary": {
                        "accepted_findings": 0,
                        "analysis_gaps": 0,
                        "duplicate_findings": 0,
                        "rejected_findings": 0,
                    },
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
            native = SafeSourceNativeResult.from_semgrep_sanitized(
                payload=semgrep_payload,
                scanner_version="1.171.0",
                projection_id=projection_id,
                projection_digest=projection_digest,
                **common,
            )
        assert SafeSourceNativeResult.from_json(native.canonical_json()) == native
        results.append(native)
    assert {item.authority for item in results} == {
        "semgrep-ce",
        "gitleaks",
        "syft",
        "checkov",
    }


def test_controlled_four_scanner_path_persists_four_results_without_publication(
    s6b: _Environment,
) -> None:
    authorities = (
        SourceAuthority.SEMGREP,
        SourceAuthority.GITLEAKS,
        SourceAuthority.SYFT,
        SourceAuthority.CHECKOV,
    )
    accepted = []
    for index, authority in enumerate(authorities, start=1):
        node, job = s6b.create(authority)
        lease_token = str(UUID(int=100 + index))
        attempt_token = UUID(int=200 + index)
        with s6b.factory.begin() as session:
            durable = session.get(JobRow, job.job_id)
            assert durable is not None
            durable.status = JobStatus.RUNNING.value
            durable.attempt_count = 1
            durable.leased_by = f"controlled-worker-{index}"
            durable.lease_token = lease_token
            durable.lease_expires_at = _DEADLINE
            durable.started_at = _NOW
        service = SourceScannerAttemptService(
            s6b.factory,
            s6b.store,
            s6b.projections,
            clock=lambda: _NOW,
            token_factory=lambda token=attempt_token: token,
        )
        attempt = service.register_attempt(
            job_id=job.job_id,
            worker_id=f"controlled-worker-{index}",
            lease_token=lease_token,
        )
        if authority is SourceAuthority.SEMGREP:
            service.record_sandbox_cleanup(
                SourceSandboxCleanupReceipt(
                    job_id=job.job_id,
                    attempt_number=1,
                    attempt_token=attempt.attempt_token,
                    execution_backend="docker-sandbox",
                    execution_id=job.job_id,
                    sandbox_identity=source_sandbox_execution_identity(
                        job.job_id, 1, attempt.attempt_token
                    ),
                    cleanup_outcome=AttemptContainmentOutcome.CLEAN,
                    execution_removed=True,
                )
            )
        else:
            scanner_pid = 999_900 + index
            service.register_supervisor(
                job_id=job.job_id,
                attempt_number=1,
                attempt_token=attempt.attempt_token,
                supervisor_identity=f"{index:x}" * 64,
                supervisor_pid=999_800 + index,
                supervisor_start_ticks=100 + index,
                scanner_pid=scanner_pid,
                scanner_pgid=scanner_pid,
                scanner_start_ticks=200 + index,
            )
            service.record_cleanup(
                SourceAttemptCleanupReceipt(
                    job_id=job.job_id,
                    attempt_number=1,
                    attempt_token=attempt.attempt_token,
                    supervisor_identity=f"{index:x}" * 64,
                    supervisor_pid=999_800 + index,
                    supervisor_start_ticks=100 + index,
                    scanner_pid=scanner_pid,
                    scanner_pgid=scanner_pid,
                    scanner_start_ticks=200 + index,
                    cleanup_outcome=AttemptContainmentOutcome.CLEAN,
                    process_tree_empty=True,
                )
            )
        native = s6b.native_result(node, job)
        accepted.append(
            service.accept_result(
                native,
                lease_token=lease_token,
                execution_outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
                return_code=0,
                duration_ms=index,
            )
        )

    assert len(accepted) == 4
    fresh = SourceScannerAttemptService(s6b.factory, s6b.store, s6b.projections, clock=lambda: _NOW)
    for authority in authorities:
        node = next(item for item in s6b.snapshot.nodes if item.authority is authority)
        assert (
            fresh.load_accepted_result(run_id=str(_RUN_ID), node_id=node.node_id).authority
            == authority.value
        )
    with s6b.factory() as session:
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        assert run is not None and run.report_json is None
        assert session.scalar(select(func.count()).select_from(JobRow)) == 4
        assert session.scalar(select(func.count()).select_from(ToolExecutionRow)) == 4
        assert session.scalar(select(func.count()).select_from(SourceOrchestrationNodeRow)) == 5
        assert (
            session.scalar(
                select(func.count())
                .select_from(SourceOrchestrationScannerJobRow)
                .where(SourceOrchestrationScannerJobRow.authority == "osv.dev")
            )
            == 0
        )


def test_expired_attempt_is_quarantined_not_retried(s6b: _Environment) -> None:
    _node, job, _attempt = s6b.start_attempt(clean=False)
    with s6b.factory.begin() as session:
        durable = session.get(JobRow, job.job_id)
        assert durable is not None
        durable.lease_expires_at = _NOW
    service = SourceScannerLeaseReconciliationService(s6b.factory, clock=lambda: _DEADLINE)
    records = service.quarantine_expired()
    assert len(records) == 1
    assert records[0].containment_state is OrchestrationContainmentState.RECONCILIATION_REQUIRED
    with s6b.factory() as session:
        durable = session.get(JobRow, job.job_id)
        assert durable is not None and durable.status == JobStatus.RUNNING.value


def _request(argv: tuple[str, ...]) -> CancellableProcessRequest:
    return CancellableProcessRequest(
        argv=argv,
        cwd=None,
        environment=None,
        timeout_seconds=10,
        stdout_limit_bytes=1024 * 1024,
        stderr_limit_bytes=1024 * 1024,
    )


def _register_running_attempt(
    s6b: _Environment,
    authority: SourceAuthority = SourceAuthority.GITLEAKS,
):
    node, job = s6b.create(authority)
    with s6b.factory.begin() as session:
        durable = session.get(JobRow, job.job_id)
        assert durable is not None
        durable.status = JobStatus.RUNNING.value
        durable.attempt_count = 1
        durable.leased_by = "worker-s6b"
        durable.lease_token = _LEASE_TOKEN
        durable.lease_expires_at = _DEADLINE
    attempt = s6b.attempts.register_attempt(
        job_id=job.job_id,
        worker_id="worker-s6b",
        lease_token=_LEASE_TOKEN,
    )
    return node, job, attempt


class _CompletedDockerHandle:
    def poll(self) -> CancellableProcessResult:
        return CancellableProcessResult(
            return_code=0,
            stdout=b"",
            stderr=b"",
            duration_ms=1,
            timed_out=False,
            output_limit_exceeded=False,
            termination_requested=False,
            force_killed=False,
        )

    def wait(
        self, timeout_seconds: float | None = None
    ) -> CancellableProcessResult:
        del timeout_seconds
        return self.poll()

    def terminate(self) -> None:
        pass

    def kill(self) -> None:
        pass

    def close(self) -> None:
        pass


class _SandboxRunner:
    def __init__(
        self,
        *,
        inspected_identity: str | None = None,
        semgrep_result: bytes | None = None,
    ) -> None:
        self.inspected_identity = inspected_identity
        self.semgrep_result = semgrep_result
        self.output_directory: Path | None = None
        self.commands: list[tuple[str, ...]] = []

    def run_control_command(
        self, argv: tuple[str, ...], timeout_seconds: float
    ) -> DockerControlCommandResult:
        del timeout_seconds
        self.commands.append(argv)
        operation = argv[1]
        if operation == "create":
            output_mount = next(
                (
                    argument
                    for argument in argv
                    if argument.endswith(",dst=/workspace/output")
                ),
                None,
            )
            if output_mount is not None:
                source = output_mount.removeprefix("type=bind,src=").removesuffix(
                    ",dst=/workspace/output"
                )
                self.output_directory = Path(source)
        if operation == "inspect" and "{{.State.Running}}|{{.State.ExitCode}}" in argv:
            return DockerControlCommandResult(0, b"false|0\n", b"")
        if operation == "inspect" and any(
            "securescan.managed" in argument for argument in argv
        ):
            if self.inspected_identity is None:
                return DockerControlCommandResult(1, b"", b"missing")
            return DockerControlCommandResult(
                0, self.inspected_identity.encode("ascii") + b"\n", b""
            )
        if operation == "inspect" and len(argv) == 3:
            return DockerControlCommandResult(1, b"", b"missing")
        if operation == "ps":
            return DockerControlCommandResult(0, b"", b"")
        return DockerControlCommandResult(0, b"ok\n", b"")

    def start_attached(
        self,
        argv: tuple[str, ...],
        stdout_limit: int,
        stderr_limit: int,
        timeout_seconds: float,
    ) -> _CompletedDockerHandle:
        del stdout_limit, stderr_limit, timeout_seconds
        self.commands.append(argv)
        if self.semgrep_result is not None:
            assert self.output_directory is not None
            (self.output_directory / "semgrep-results.json").write_bytes(
                self.semgrep_result
            )
        return _CompletedDockerHandle()


def _semgrep_docker_contract(
    s6b: _Environment,
    tmp_path: Path,
    *,
    image_reference: str = _SEMGREP_IMAGE,
) -> tuple[object, TrustedSemgrepSourceBinding]:
    ruleset = load_baseline_ruleset()
    definition = create_semgrep_trusted_definition(
        image_reference=image_reference,
        tool_version="1.171.0",
        docker_executor=object(),
        workspace_manager=RepositoryWorkspaceManager(tmp_path / "semgrep-workspaces"),
        ruleset=ruleset,
        artifact_store=s6b.store,
        source_resolver=lambda _run_id: tmp_path,
    )
    binding_factory = (
        create_production_semgrep_source_binding
        if image_reference == PRODUCTION_SEMGREP_IMAGE_REFERENCE
        else TrustedSemgrepSourceBinding
    )
    return definition, binding_factory(definition=definition, ruleset=ruleset)


def _semgrep_docker_request(
    s6b: _Environment,
    tmp_path: Path,
    job_id: str,
) -> tuple[DockerSandboxExecutionRequest, TrustedSemgrepSourceBinding]:
    definition, binding = _semgrep_docker_contract(s6b, tmp_path)
    source = tmp_path / "docker-source"
    output = tmp_path / "docker-output"
    source.mkdir()
    output.mkdir()
    return (
        DockerSandboxExecutionRequest(
            definition=definition,
            source_directory=source,
            output_directory=output,
            execution_id=job_id,
        ),
        binding,
    )


def test_semgrep_uses_docker_cleanup_proof_without_fabricated_process_identity(
    s6b: _Environment,
) -> None:
    _node, job, attempt = _register_running_attempt(s6b, SourceAuthority.SEMGREP)
    receipt = SourceSandboxCleanupReceipt(
        job_id=job.job_id,
        attempt_number=attempt.attempt_number,
        attempt_token=attempt.attempt_token,
        execution_backend="docker-sandbox",
        execution_id=job.job_id,
        sandbox_identity=source_sandbox_execution_identity(
            job.job_id, attempt.attempt_number, attempt.attempt_token
        ),
        cleanup_outcome=AttemptContainmentOutcome.CLEAN,
        execution_removed=True,
    )

    clean = s6b.attempts.record_sandbox_cleanup(receipt)
    assert clean.containment_state is OrchestrationContainmentState.CLEAN
    with s6b.factory() as session:
        durable = session.get(
            SourceOrchestrationAttemptRow,
            (job.job_id, attempt.attempt_number),
        )
        assert durable is not None
        assert durable.supervisor_identity is None
        assert durable.scanner_pid is None
        assert durable.cleanup_receipt_sha256 == receipt.sha256()


def test_attempt_bound_semgrep_docker_records_cleanup_only_after_removal(
    s6b: _Environment,
    tmp_path: Path,
) -> None:
    _node, job, attempt = _register_running_attempt(s6b, SourceAuthority.SEMGREP)
    request, binding = _semgrep_docker_request(s6b, tmp_path, job.job_id)
    runner = _SandboxRunner()
    executor = AttemptBoundDockerExecutor(
        attempt=attempt,
        attempt_persistence=s6b.attempts,
        binding=binding,
        runner=runner,
    )

    handle = executor.start(request)
    with s6b.factory() as session:
        durable = session.get(
            SourceOrchestrationAttemptRow, (job.job_id, attempt.attempt_number)
        )
        assert durable is not None
        assert durable.containment_state == OrchestrationContainmentState.ACTIVE.value
        assert durable.cleanup_receipt_sha256 is None

    assert handle.poll() is not None

    operations = [command[1] for command in runner.commands]
    assert operations == [
        "version",
        "image",
        "create",
        "start",
        "inspect",
        "rm",
        "inspect",
    ]
    with s6b.factory() as session:
        durable = session.get(
            SourceOrchestrationAttemptRow, (job.job_id, attempt.attempt_number)
        )
        assert durable is not None
        assert durable.containment_state == OrchestrationContainmentState.CLEAN.value
        assert durable.cleanup_receipt_sha256 is not None
        assert durable.supervisor_identity is None
        assert durable.scanner_pid is None


def test_frozen_semgrep_adapter_runs_through_attempt_bound_docker_and_acceptance(
    s6b: _Environment,
    tmp_path: Path,
) -> None:
    node, created, attempt = _register_running_attempt(s6b, SourceAuthority.SEMGREP)
    _definition, binding = _semgrep_docker_contract(s6b, tmp_path)
    runner = _SandboxRunner(semgrep_result=_SEMGREP_FIXTURE.read_bytes())
    docker_executor = AttemptBoundDockerExecutor(
        attempt=attempt,
        attempt_persistence=s6b.attempts,
        binding=binding,
        runner=runner,
    )
    definition = create_source_aware_semgrep_trusted_definition(
        image_reference=_SEMGREP_IMAGE,
        tool_version="1.171.0",
        docker_executor=docker_executor,
        workspace_manager=RepositoryWorkspaceManager(tmp_path / "adapter-workspaces"),
        ruleset=load_baseline_ruleset(),
        artifact_store=s6b.store,
        source_resolver=lambda _run_id: tmp_path,
        projection_manager=s6b.projections,
        binding=binding,
        clock=lambda: _NOW,
    )
    with s6b.factory() as session:
        from securescan.jobs.mappers import job_record_from_row

        row = session.get(JobRow, created.job_id)
        assert row is not None
        job = job_record_from_row(row)

    handle = definition.factory().start(job)
    outcome = handle.poll()
    handle.close()

    assert isinstance(outcome, WorkerSuccessfulExecution)
    report_execution = outcome.report_json["executions"][0]
    artifact_reference = report_execution["artifacts"][0]
    payload = s6b.store.read_by_sha256(
        artifact_reference["sha256"],
        expected_size_bytes=artifact_reference["size_bytes"],
    )
    context = SourceSemgrepExecutionContextResolver(s6b.store, binding).resolve(job)
    envelope = SourceExecutionEnvelope.from_payload_json(job.payload_json)
    native = SafeSourceNativeResult.from_semgrep_sanitized(
        payload=payload,
        node_id=node.node_id,
        job_id=created.job_id,
        attempt_number=attempt.attempt_number,
        scanner_version="1.171.0",
        analyzer_id=node.analyzer_id,
        context=context,
        projection_id=envelope.projection_reference.projection_id,
        projection_digest=envelope.projection_reference.projection_digest,
    )
    accepted = s6b.attempts.accept_result(
        native,
        lease_token=_LEASE_TOKEN,
        execution_outcome=ExecutionOutcome(report_execution["outcome"]),
        return_code=report_execution["exit_code"],
        duration_ms=report_execution["duration_ms"],
    )

    assert accepted.created is True
    with s6b.factory() as session:
        durable = session.get(
            SourceOrchestrationAttemptRow, (created.job_id, attempt.attempt_number)
        )
        assert durable is not None
        assert durable.containment_state == OrchestrationContainmentState.CLEAN.value
        assert durable.acceptance_state == "ACCEPTED"
        assert durable.supervisor_identity is None
        assert durable.cleanup_receipt_sha256 is not None


def test_semgrep_docker_reconciliation_removes_only_matching_attempt_sandbox(
    s6b: _Environment,
    tmp_path: Path,
) -> None:
    _node, job, attempt = _register_running_attempt(s6b, SourceAuthority.SEMGREP)
    with s6b.factory.begin() as session:
        durable = session.get(
            SourceOrchestrationAttemptRow, (job.job_id, attempt.attempt_number)
        )
        node = session.get(SourceOrchestrationNodeRow, attempt.node_id)
        assert durable is not None and node is not None
        durable.containment_state = OrchestrationContainmentState.RECONCILIATION_REQUIRED.value
        node.containment_state = OrchestrationContainmentState.RECONCILIATION_REQUIRED.value
    name = source_sandbox_execution_identity(
        attempt.job_id, attempt.attempt_number, attempt.attempt_token
    )
    runner = _SandboxRunner(
        inspected_identity=f"/{name}|true|{attempt.job_id}|true"
    )
    definition, binding = _semgrep_docker_contract(s6b, tmp_path)

    recovered = SourceSandboxReconciliationService(
        attempt_persistence=s6b.attempts,
        binding=binding,
        definition=definition,
        runner=runner,
    ).reconcile(attempt)

    assert recovered.containment_state is OrchestrationContainmentState.CLEAN
    assert [command[1] for command in runner.commands] == [
        "inspect",
        "stop",
        "rm",
        "ps",
    ]


def test_semgrep_docker_reconciliation_rejects_foreign_identity_without_removal(
    s6b: _Environment,
    tmp_path: Path,
) -> None:
    _node, job, attempt = _register_running_attempt(s6b, SourceAuthority.SEMGREP)
    with s6b.factory.begin() as session:
        durable = session.get(
            SourceOrchestrationAttemptRow, (job.job_id, attempt.attempt_number)
        )
        node = session.get(SourceOrchestrationNodeRow, attempt.node_id)
        assert durable is not None and node is not None
        durable.containment_state = OrchestrationContainmentState.RECONCILIATION_REQUIRED.value
        node.containment_state = OrchestrationContainmentState.RECONCILIATION_REQUIRED.value
    name = source_sandbox_execution_identity(
        attempt.job_id, attempt.attempt_number, attempt.attempt_token
    )
    runner = _SandboxRunner(
        inspected_identity=f"/{name}|false|{attempt.job_id}|true"
    )
    definition, binding = _semgrep_docker_contract(s6b, tmp_path)

    with pytest.raises(DockerContainerInspectionError):
        SourceSandboxReconciliationService(
            attempt_persistence=s6b.attempts,
            binding=binding,
            definition=definition,
            runner=runner,
        ).reconcile(attempt)

    assert [command[1] for command in runner.commands] == ["inspect"]
    with s6b.factory() as session:
        durable = session.get(
            SourceOrchestrationAttemptRow, (job.job_id, attempt.attempt_number)
        )
        assert durable is not None
        assert (
            durable.containment_state
            == OrchestrationContainmentState.RECONCILIATION_REQUIRED.value
        )


def test_sandbox_cleanup_proof_is_rejected_for_local_scanner(s6b: _Environment) -> None:
    _node, job, attempt = _register_running_attempt(s6b)
    with pytest.raises(SourceScannerExecutionConflictError):
        s6b.attempts.record_sandbox_cleanup(
            SourceSandboxCleanupReceipt(
                job_id=job.job_id,
                attempt_number=attempt.attempt_number,
                attempt_token=attempt.attempt_token,
                execution_backend="docker-sandbox",
                execution_id=job.job_id,
                sandbox_identity=source_sandbox_execution_identity(
                    job.job_id, attempt.attempt_number, attempt.attempt_token
                ),
                cleanup_outcome=AttemptContainmentOutcome.CLEAN,
                execution_removed=True,
            )
        )


def test_frozen_syft_bridge_runs_through_attempt_bound_supervisor(
    s6b: _Environment,
    tmp_path: Path,
) -> None:
    executable = Path(".venv-syft-1.51/bin/syft").resolve(strict=True)
    binding = create_default_syft_binding(executable)
    node, created, attempt = _register_running_attempt(s6b, SourceAuthority.SYFT)
    with s6b.factory() as session:
        from securescan.jobs.mappers import job_record_from_row

        row = session.get(JobRow, created.job_id)
        assert row is not None
        job = job_record_from_row(row)
    service = SourceLocalBridgeExecutionService(
        s6b.store,
        s6b.projections,
        s6b.attempts,
        tmp_path / "bridge-receipts",
    )

    handle = service.start_syft(job=job, attempt=attempt, binding=binding)
    native = handle.wait(60)
    handle.close()

    assert native is not None
    assert native.authority == SourceAuthority.SYFT.value
    assert native.node_id == node.node_id
    assert native.job_id == created.job_id
    assert native.attempt_number == attempt.attempt_number
    accepted = s6b.attempts.accept_result(
        native,
        lease_token=_LEASE_TOKEN,
        execution_outcome=ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS,
        return_code=0,
        duration_ms=1,
    )
    assert accepted.created is True
    with s6b.factory() as session:
        durable = session.get(
            SourceOrchestrationAttemptRow,
            (created.job_id, attempt.attempt_number),
        )
        assert durable is not None
        assert durable.containment_state == OrchestrationContainmentState.CLEAN.value
        assert durable.acceptance_state == "ACCEPTED"
        assert durable.supervisor_identity is not None
        assert durable.cleanup_receipt_sha256 is not None


def test_frozen_gitleaks_bridge_runs_through_supervisor_and_persists_only_safe_result(
    tmp_path: Path,
) -> None:
    environment = _Environment(
        tmp_path,
        app_source=b'CONTROLLED = "' + _CONTROLLED_SECRET + b'"\n',
    )
    try:
        binding = create_default_gitleaks_binding(
            _GITLEAKS_EXECUTABLE.resolve(strict=True)
        )
        node, created, attempt = _register_running_attempt(
            environment, SourceAuthority.GITLEAKS
        )
        with environment.factory() as session:
            from securescan.jobs.mappers import job_record_from_row

            row = session.get(JobRow, created.job_id)
            assert row is not None
            job = job_record_from_row(row)
        service = SourceLocalBridgeExecutionService(
            environment.store,
            environment.projections,
            environment.attempts,
            tmp_path / "gitleaks-bridge-receipts",
        )

        handle = service.start_gitleaks(job=job, attempt=attempt, binding=binding)
        native = handle.wait(60)
        handle.close()

        assert native is not None
        assert native.authority == SourceAuthority.GITLEAKS.value
        assert native.node_id == node.node_id
        assert native.job_id == created.job_id
        assert native.attempt_number == attempt.attempt_number
        assert native.binding_digest == node.contract_digest == binding.binding_digest()
        assert native.context_digest == created.context_digest
        assert native.projection_id == created.projection_id
        assert native.projection_digest == created.projection_digest
        assert len(native.native_data["findings"]) == 1
        assert native.native_data["findings"][0]["rule_id"] == "github-pat"
        safe_payload = native.canonical_json()
        assert _CONTROLLED_SECRET not in safe_payload

        accepted = environment.attempts.accept_result(
            native,
            lease_token=_LEASE_TOKEN,
            execution_outcome=ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS,
            return_code=1,
            duration_ms=1,
        )
        assert accepted.created is True
        assert environment.store.read_by_sha256(
            accepted.artifact_sha256,
            expected_size_bytes=accepted.artifact_size_bytes,
        ) == safe_payload

        fresh_service = SourceScannerAttemptService(
            environment.factory,
            environment.store,
            environment.projections,
            clock=lambda: _NOW,
        )
        assert fresh_service.load_accepted_result(
            run_id=str(_RUN_ID), node_id=node.node_id
        ) == native

        with environment.factory() as session:
            mapping = session.get(
                SourceOrchestrationScannerJobRow, created.job_id
            )
            durable_attempt = session.get(
                SourceOrchestrationAttemptRow,
                (created.job_id, attempt.attempt_number),
            )
            run = session.get(AnalysisRunRow, str(_RUN_ID))
            tools = session.scalars(
                select(ToolExecutionRow).where(
                    ToolExecutionRow.job_id == created.job_id
                )
            ).all()
            mappings = session.scalars(
                select(SourceOrchestrationScannerJobRow)
            ).all()
            assert mapping is not None and durable_attempt is not None
            assert run is not None and run.report_json is None
            assert mapping.selected_attempt_number == attempt.attempt_number
            assert durable_attempt.acceptance_state == "ACCEPTED"
            assert durable_attempt.containment_state == "CLEAN"
            assert len(tools) == 1
            assert len(mappings) == 1
            assert all(item.authority != SourceAuthority.OSV.value for item in mappings)
            durable_values = {
                "cleanup_receipt": durable_attempt.cleanup_receipt_json,
                "mapping": {
                    column.name: getattr(mapping, column.name)
                    for column in mapping.__table__.columns
                },
                "attempt": {
                    column.name: getattr(durable_attempt, column.name)
                    for column in durable_attempt.__table__.columns
                },
                "tool_execution": {
                    column.name: getattr(tools[0], column.name)
                    for column in tools[0].__table__.columns
                },
            }
            assert _CONTROLLED_SECRET.decode() not in json.dumps(
                durable_values, default=str, sort_keys=True
            )
    finally:
        environment.close()


def test_frozen_checkov_bridge_runs_through_attempt_bound_supervisor_and_reloads(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    environment = _Environment(
        tmp_path,
        infra_source=dedent(
            """
            resource "aws_s3_bucket" "controlled" {
              bucket = "securescan-controlled-fixture"
            }
            """
        ).lstrip().encode(),
    )
    request.addfinalizer(environment.close)
    binding = create_default_checkov_binding(_CHECKOV_EXECUTABLE.resolve(strict=True))
    node, created, attempt = _register_running_attempt(
        environment, SourceAuthority.CHECKOV
    )
    with environment.factory() as session:
        from securescan.jobs.mappers import job_record_from_row

        row = session.get(JobRow, created.job_id)
        assert row is not None
        job = job_record_from_row(row)
    service = SourceLocalBridgeExecutionService(
        environment.store,
        environment.projections,
        environment.attempts,
        tmp_path / "checkov-bridge-receipts",
    )

    handle = service.start_checkov(job=job, attempt=attempt, binding=binding)
    native = handle.wait(90)
    handle.close()

    assert native is not None
    assert native.authority == SourceAuthority.CHECKOV.value
    assert native.node_id == node.node_id
    assert native.job_id == created.job_id
    assert native.attempt_number == attempt.attempt_number
    assert native.binding_digest == node.contract_digest == binding.binding_digest()
    assert native.context_digest == created.context_digest
    assert native.projection_id == created.projection_id
    assert native.projection_digest == created.projection_digest
    outcomes = native.native_data["framework_outcomes"]
    assert tuple(item["framework"] for item in outcomes) == CHECKOV_FRAMEWORKS
    assert all(item["parsing_gap_count"] == 0 for item in outcomes)
    assert sum(item["suppressed_count"] for item in outcomes) == len(
        native.native_data["suppressions"]
    )

    accepted = environment.attempts.accept_result(
        native,
        lease_token=_LEASE_TOKEN,
        execution_outcome=ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS,
        return_code=0,
        duration_ms=1,
    )
    assert accepted.created is True
    fresh_service = SourceScannerAttemptService(
        environment.factory,
        environment.store,
        environment.projections,
        clock=lambda: _NOW,
    )
    assert fresh_service.load_accepted_result(
        run_id=str(_RUN_ID), node_id=node.node_id
    ) == native
    with environment.factory() as session:
        mapping = session.get(SourceOrchestrationScannerJobRow, created.job_id)
        durable_attempt = session.get(
            SourceOrchestrationAttemptRow,
            (created.job_id, attempt.attempt_number),
        )
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        tools = session.scalars(
            select(ToolExecutionRow).where(ToolExecutionRow.job_id == created.job_id)
        ).all()
        mappings = session.scalars(select(SourceOrchestrationScannerJobRow)).all()
        assert mapping is not None and durable_attempt is not None
        assert run is not None and run.report_json is None
        assert mapping.selected_attempt_number == attempt.attempt_number
        assert durable_attempt.acceptance_state == "ACCEPTED"
        assert durable_attempt.containment_state == "CLEAN"
        assert len(tools) == 1
        assert len(mappings) == 1
        assert all(item.authority != SourceAuthority.OSV.value for item in mappings)


def test_supervisor_normal_completion_and_receipt(tmp_path: Path) -> None:
    supervisor = TrustedLocalProcessSupervisor(
        SupervisorAttemptIdentity(
            job_id="11111111-1111-4111-8111-111111111111",
            attempt_number=1,
            attempt_token="22222222-2222-4222-8222-222222222222",
        ),
        tmp_path / "receipts",
    )
    handle = supervisor.start(_request(("/bin/sh", "-c", "printf controlled")))
    result = handle.wait(15)
    assert result is not None and result.stdout == b"controlled"
    receipt = handle.cleanup_receipt
    assert receipt is not None
    assert receipt.cleanup_outcome is AttemptContainmentOutcome.CLEAN
    assert receipt.process_tree_empty is True
    handle.close()


def test_attempt_bound_executor_supervises_probes_and_binds_only_exact_scan(
    s6b: _Environment, tmp_path: Path
) -> None:
    _node, job, attempt = _register_running_attempt(s6b)
    final_request = _request(("/bin/sh", "-c", "printf scan"))
    executor = AttemptBoundProcessExecutor(
        attempt=SupervisorAttemptIdentity(
            job_id=job.job_id,
            attempt_number=attempt.attempt_number,
            attempt_token=attempt.attempt_token,
        ),
        final_request=final_request,
        attempt_persistence=s6b.attempts,
        receipt_directory=tmp_path / "receipts",
    )

    probe = executor.start(_request(("/bin/sh", "-c", "printf 1.0")))
    probe_result = probe.wait(15)
    assert probe_result is not None and probe_result.stdout == b"1.0"
    probe.close()
    with s6b.factory() as session:
        durable = session.get(
            SourceOrchestrationAttemptRow,
            (job.job_id, attempt.attempt_number),
        )
        assert durable is not None
        assert durable.containment_state == OrchestrationContainmentState.ACTIVE.value
        assert durable.supervisor_identity is None
        assert durable.cleanup_receipt_sha256 is None

    scan = executor.start(final_request)
    scan_result = scan.wait(15)
    assert scan_result is not None and scan_result.stdout == b"scan"
    scan.close()
    with s6b.factory() as session:
        durable = session.get(
            SourceOrchestrationAttemptRow,
            (job.job_id, attempt.attempt_number),
        )
        assert durable is not None
        assert durable.containment_state == OrchestrationContainmentState.CLEAN.value
        assert durable.supervisor_identity is not None
        assert durable.cleanup_receipt_sha256 is not None

    with pytest.raises(CancellableProcessStateError):
        executor.start(final_request)


def test_fresh_service_recovers_receipt_when_worker_dies_after_scanner_spawn(
    s6b: _Environment, tmp_path: Path
) -> None:
    _node, job, attempt = _register_running_attempt(s6b)
    receipt_directory = tmp_path / "receipts"
    supervisor = TrustedLocalProcessSupervisor(
        SupervisorAttemptIdentity(
            job_id=job.job_id,
            attempt_number=attempt.attempt_number,
            attempt_token=attempt.attempt_token,
        ),
        receipt_directory,
    )
    handle = supervisor.start(_request(("/bin/sh", "-c", "printf controlled")))
    # Simulate worker death after scanner spawn but before the DB handshake write.
    assert handle.wait(15) is not None
    handle.close()

    fresh_service = SourceScannerAttemptService(
        s6b.factory,
        s6b.store,
        s6b.projections,
        clock=lambda: _NOW,
    )
    recovered = fresh_service.recover_cleanup_receipt(
        job_id=job.job_id,
        attempt_number=attempt.attempt_number,
        receipt_directory=receipt_directory,
    )
    assert recovered.containment_state is OrchestrationContainmentState.CLEAN


def test_missing_durable_cleanup_receipt_requires_reconciliation(
    s6b: _Environment, tmp_path: Path
) -> None:
    _node, job, attempt = _register_running_attempt(s6b)
    receipt_directory = tmp_path / "receipts"
    receipt_directory.mkdir(mode=0o700)
    recovered = s6b.attempts.recover_cleanup_receipt(
        job_id=job.job_id,
        attempt_number=attempt.attempt_number,
        receipt_directory=receipt_directory,
    )
    assert (
        recovered.containment_state
        is OrchestrationContainmentState.RECONCILIATION_REQUIRED
    )


def test_wrong_durable_receipt_requires_reconciliation(
    s6b: _Environment, tmp_path: Path
) -> None:
    _node, job, attempt = _register_running_attempt(s6b)
    receipt_directory = tmp_path / "receipts"
    receipt_directory.mkdir(mode=0o700)
    path = receipt_directory / f"{job.job_id}-1-{attempt.attempt_token}.json"
    path.write_bytes(
        SourceAttemptCleanupReceipt(
            job_id="11111111-1111-4111-8111-111111111112",
            attempt_number=1,
            attempt_token=attempt.attempt_token,
            supervisor_identity="a" * 64,
            supervisor_pid=999_991,
            supervisor_start_ticks=101,
            scanner_pid=999_992,
            scanner_pgid=999_992,
            scanner_start_ticks=102,
            cleanup_outcome=AttemptContainmentOutcome.CLEAN,
            process_tree_empty=True,
        ).canonical_json()
    )
    path.chmod(0o600)
    recovered = s6b.attempts.recover_cleanup_receipt(
        job_id=job.job_id,
        attempt_number=1,
        receipt_directory=receipt_directory,
    )
    assert (
        recovered.containment_state
        is OrchestrationContainmentState.RECONCILIATION_REQUIRED
    )


def test_supervisor_kills_term_resistant_descendant(tmp_path: Path) -> None:
    child_file = tmp_path / "child.pid"
    script = f"trap '' TERM; sh -c 'trap \"\" TERM; echo $$ > {child_file}; sleep 60' & wait"
    supervisor = TrustedLocalProcessSupervisor(
        SupervisorAttemptIdentity(
            job_id="11111111-1111-4111-8111-111111111111",
            attempt_number=1,
            attempt_token="22222222-2222-4222-8222-222222222222",
        ),
        tmp_path / "receipts",
    )
    handle = supervisor.start(_request(("/bin/sh", "-c", script)))
    deadline = time.monotonic() + 3
    while not child_file.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    child_pid = int(child_file.read_text())
    handle.terminate()
    result = handle.wait(15)
    assert result is not None and result.force_killed is True
    receipt = handle.cleanup_receipt
    assert receipt is not None and receipt.process_tree_empty is True
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)
    handle.close()


def test_supervisor_cleans_multiple_descendants(tmp_path: Path) -> None:
    child_file = tmp_path / "children.txt"
    script = f"sleep 60 & a=$!; sleep 60 & b=$!; echo $a $b > {child_file}; wait"
    supervisor = TrustedLocalProcessSupervisor(
        SupervisorAttemptIdentity(
            job_id="11111111-1111-4111-8111-111111111111",
            attempt_number=1,
            attempt_token="22222222-2222-4222-8222-222222222222",
        ),
        tmp_path / "receipts",
    )
    handle = supervisor.start(_request(("/bin/sh", "-c", script)))
    deadline = time.monotonic() + 3
    while not child_file.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    child_pids = tuple(int(value) for value in child_file.read_text().split())
    assert len(child_pids) == 2
    handle.terminate()
    result = handle.wait(15)
    assert result is not None and result.termination_requested is True
    receipt = handle.cleanup_receipt
    assert receipt is not None and receipt.process_tree_empty is True
    for child_pid in child_pids:
        with pytest.raises(ProcessLookupError):
            os.kill(child_pid, 0)
    handle.close()


@pytest.mark.parametrize("worker_signal", [signal.SIGTERM, signal.SIGKILL])
def test_hard_worker_death_triggers_supervisor_cleanup(
    tmp_path: Path, worker_signal: signal.Signals
) -> None:
    receipt_dir = tmp_path / "receipts"
    ready = tmp_path / "ready.json"
    worker_script = dedent(
        """
        import json, time
        from pathlib import Path
        from securescan.execution.cancellable_process import CancellableProcessRequest
        from securescan.execution.supervisor import (
            SupervisorAttemptIdentity,
            TrustedLocalProcessSupervisor,
        )
        root=Path(__import__('sys').argv[1])
        ready=Path(__import__('sys').argv[2])
        identity=SupervisorAttemptIdentity(
            job_id='11111111-1111-4111-8111-111111111111',
            attempt_number=1,
            attempt_token='22222222-2222-4222-8222-222222222222',
        )
        sup=TrustedLocalProcessSupervisor(identity,root)
        request=CancellableProcessRequest(
            argv=('/bin/sh','-c','trap "" TERM; sleep 60'),
            cwd=None,
            environment=None,
            timeout_seconds=120,
            stdout_limit_bytes=1024,
            stderr_limit_bytes=1024,
        )
        h=sup.start(request)
        ready.write_text(json.dumps({'scanner_pid':h.handshake.scanner_pid}))
        time.sleep(120)
        """
    )
    worker = subprocess.Popen(  # noqa: S603 - fixed ephemeral hostile-test child
        (sys.executable, "-c", worker_script, str(receipt_dir), str(ready)),
        cwd=Path(__file__).resolve().parents[1],
    )
    deadline = time.monotonic() + 10
    while not ready.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    scanner_pid = json.loads(ready.read_text())["scanner_pid"]
    os.kill(worker.pid, worker_signal)
    worker.wait(timeout=5)
    deadline = time.monotonic() + 10
    receipt_files: list[Path] = []
    while time.monotonic() < deadline:
        receipt_files = list(receipt_dir.glob("*.json"))
        if receipt_files:
            break
        time.sleep(0.02)
    assert len(receipt_files) == 1
    receipt = SourceAttemptCleanupReceipt.from_json(receipt_files[0].read_bytes())
    assert receipt.cleanup_outcome is AttemptContainmentOutcome.CLEAN
    with pytest.raises(ProcessLookupError):
        os.kill(scanner_pid, 0)


def test_worker_death_during_supervisor_startup_leaves_no_helper_or_receipt(
    tmp_path: Path,
) -> None:
    receipt_dir = tmp_path / "receipts"
    ready = tmp_path / "supervisor.pid"
    worker_script = dedent(
        """
        import subprocess, time
        from pathlib import Path
        from securescan.execution.cancellable_process import CancellableProcessRequest
        from securescan.execution.supervisor import (
            SupervisorAttemptIdentity,
            TrustedLocalProcessSupervisor,
        )
        root=Path(__import__('sys').argv[1])
        ready=Path(__import__('sys').argv[2])
        def delayed_popen(*args, **kwargs):
            process=subprocess.Popen(*args, **kwargs)
            ready.write_text(str(process.pid))
            time.sleep(60)
            return process
        supervisor=TrustedLocalProcessSupervisor(
            SupervisorAttemptIdentity(
                job_id='11111111-1111-4111-8111-111111111111',
                attempt_number=1,
                attempt_token='22222222-2222-4222-8222-222222222222',
            ),
            root,
            popen=delayed_popen,
        )
        supervisor.start(CancellableProcessRequest(
            argv=('/bin/sh','-c','sleep 60'),
            cwd=None,
            environment=None,
            timeout_seconds=120,
            stdout_limit_bytes=1024,
            stderr_limit_bytes=1024,
        ))
        """
    )
    worker = subprocess.Popen(  # noqa: S603 - fixed ephemeral hostile-test child
        (sys.executable, "-c", worker_script, str(receipt_dir), str(ready)),
        cwd=Path(__file__).resolve().parents[1],
    )
    deadline = time.monotonic() + 10
    while not ready.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    supervisor_pid = int(ready.read_text())
    os.kill(worker.pid, signal.SIGKILL)
    worker.wait(timeout=5)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(supervisor_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.02)
    else:
        pytest.fail("startup supervisor survived its worker")
    assert list(receipt_dir.glob("*.json")) == []


def test_cleanup_receipt_tamper_and_wrong_attempt_fail_closed(s6b: _Environment) -> None:
    _node, job, attempt = s6b.start_attempt()
    wrong = SourceAttemptCleanupReceipt(
        job_id=job.job_id,
        attempt_number=2,
        attempt_token=attempt.attempt_token,
        supervisor_identity="a" * 64,
        supervisor_pid=999_991,
        supervisor_start_ticks=101,
        scanner_pid=999_992,
        scanner_pgid=999_992,
        scanner_start_ticks=102,
        cleanup_outcome=AttemptContainmentOutcome.CLEAN,
        process_tree_empty=True,
    )
    with pytest.raises(SourceScannerExecutionConflictError):
        s6b.attempts.record_cleanup(wrong)
    payload = attempt.attempt_token.encode()
    assert payload not in repr(wrong).encode()
    tampered = wrong.canonical_json().replace(b'"attempt_number":2', b'"attempt_number":1')
    with pytest.raises(SourceScannerExecutionIntegrityError, match="invalid"):
        SourceAttemptCleanupReceipt.from_json(tampered + b" ")


def test_cleanup_receipt_cannot_claim_a_live_process_tree_is_clean(
    s6b: _Environment,
) -> None:
    _node, job = s6b.create()
    with s6b.factory.begin() as session:
        durable = session.get(JobRow, job.job_id)
        assert durable is not None
        durable.status = JobStatus.RUNNING.value
        durable.attempt_count = 1
        durable.leased_by = "worker-s6b"
        durable.lease_token = _LEASE_TOKEN
        durable.lease_expires_at = _DEADLINE
    attempt = s6b.attempts.register_attempt(
        job_id=job.job_id,
        worker_id="worker-s6b",
        lease_token=_LEASE_TOKEN,
    )
    process_payload = Path(f"/proc/{os.getpid()}/stat").read_text(encoding="ascii")
    fields = process_payload[process_payload.rfind(")") + 2 :].split()
    start_ticks = int(fields[19])
    process_group = os.getpgid(0)
    s6b.attempts.register_supervisor(
        job_id=job.job_id,
        attempt_number=1,
        attempt_token=attempt.attempt_token,
        supervisor_identity="b" * 64,
        supervisor_pid=os.getpid(),
        supervisor_start_ticks=start_ticks,
        scanner_pid=os.getpid(),
        scanner_pgid=process_group,
        scanner_start_ticks=start_ticks,
    )
    receipt = SourceAttemptCleanupReceipt(
        job_id=job.job_id,
        attempt_number=1,
        attempt_token=attempt.attempt_token,
        supervisor_identity="b" * 64,
        supervisor_pid=os.getpid(),
        supervisor_start_ticks=start_ticks,
        scanner_pid=os.getpid(),
        scanner_pgid=process_group,
        scanner_start_ticks=start_ticks,
        cleanup_outcome=AttemptContainmentOutcome.CLEAN,
        process_tree_empty=True,
    )
    with pytest.raises(SourceScannerExecutionConflictError):
        s6b.attempts.record_cleanup(receipt)


def test_supervisor_death_produces_no_forged_clean_receipt(tmp_path: Path) -> None:
    receipt_dir = tmp_path / "receipts"
    supervisor = TrustedLocalProcessSupervisor(
        SupervisorAttemptIdentity(
            job_id="11111111-1111-4111-8111-111111111111",
            attempt_number=1,
            attempt_token="22222222-2222-4222-8222-222222222222",
        ),
        receipt_dir,
    )
    handle = supervisor.start(_request(("/bin/sh", "-c", "sleep 60")))
    os.kill(handle.handshake.supervisor_pid, signal.SIGKILL)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            process_payload = Path(f"/proc/{handle.handshake.scanner_pid}/stat").read_text()
            state = process_payload[process_payload.rfind(")") + 2]
        except OSError:
            break
        if state == "Z":
            break
        time.sleep(0.02)
    assert list(receipt_dir.glob("*.json")) == []
    with suppress(Exception):
        handle.close()
