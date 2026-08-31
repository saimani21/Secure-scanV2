from __future__ import annotations

import json
import os
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from test_source_semgrep_execution_bridge import (
    NOW,
    WORKER_ID,
    _DockerExecutor,
    _environment,
    _LeasePublishedJob,
)

from securescan.adapters.trusted_registry import (
    TrustedAdapterRegistry,
    TrustedAdapterResolver,
)
from securescan.domain.enums import JobStatus
from securescan.jobs import (
    JobCancellationService,
    JobExecutionService,
    JobFailureCommitService,
    JobHeartbeatService,
    JobLeaseExpiredError,
    JobRepository,
    JobResultCommitService,
)
from securescan.persistence.database import AnalysisRunRow, JobRow, ToolExecutionRow
from securescan.scanners.semgrep import (
    SOURCE_EXECUTION_PAYLOAD_KEY,
    SourceExecutionEnvelope,
    SourceProjectionLifecycleDisposition,
    SourceProjectionLifecycleService,
    SourceProjectionTerminalObserver,
    SourceSemgrepExecutionContextResolver,
)
from securescan.source import SourceProjectionCleanupError, SourceProjectionManager
from securescan.worker import SingleJobWorkerCycle, WorkerCycleDisposition


def _projection_path(environment) -> Path:
    envelope = SourceExecutionEnvelope.from_payload_json(environment.job.payload_json)
    return (
        environment.projection_manager.base_directory
        / envelope.projection_reference.projection_id
    )


def _lifecycle(
    environment,
    manager: SourceProjectionManager | None = None,
) -> SourceProjectionLifecycleService:
    return SourceProjectionLifecycleService(
        JobRepository(environment.session_factory),
        SourceSemgrepExecutionContextResolver(
            environment.store,
            environment.binding,
        ),
        manager or SourceProjectionManager(
            environment.projection_manager.base_directory
        ),
    )


def _persist_job(
    environment,
    *,
    status: JobStatus,
    payload_json=None,
):
    with environment.session_factory.begin() as session:
        row = session.get(JobRow, environment.job.id)
        assert row is not None
        row.status = status.value
        if payload_json is not None:
            row.payload_json = payload_json
        if status in {
            JobStatus.SUCCEEDED,
            JobStatus.PARTIAL,
            JobStatus.FAILED,
            JobStatus.CANCELLED,
        }:
            row.finished_at = NOW
            row.leased_by = None
            row.lease_token = None
            row.lease_expires_at = None
        else:
            row.finished_at = None
    job = JobRepository(environment.session_factory).get_job(environment.job.id)
    assert job is not None
    return job


def _cycle(
    environment,
    tmp_path: Path,
    executor,
    *,
    terminal_observer=None,
    result_commit_service=None,
) -> SingleJobWorkerCycle:
    definition = environment.definition(tmp_path, executor)
    return SingleJobWorkerCycle(
        _LeasePublishedJob(environment.session_factory, environment.submission.job_id),
        JobExecutionService(environment.session_factory, clock=lambda: NOW),
        result_commit_service
        or JobResultCommitService(environment.session_factory, clock=lambda: NOW),
        JobFailureCommitService(environment.session_factory, clock=lambda: NOW),
        TrustedAdapterResolver(TrustedAdapterRegistry((definition,))),
        JobRepository(environment.session_factory),
        JobCancellationService(environment.session_factory, clock=lambda: NOW),
        JobHeartbeatService(environment.session_factory, clock=lambda: NOW),
        worker_id=WORKER_ID,
        lease_seconds=30,
        execution_poll_interval_seconds=0.01,
        terminal_observer=terminal_observer,
    )


def test_terminal_success_commits_before_projection_cleanup(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    observed = []
    observer = SourceProjectionTerminalObserver(
        _lifecycle(environment),
        observed.append,
    )

    result = _cycle(
        environment,
        tmp_path / "success",
        _DockerExecutor(),
        terminal_observer=observer,
    ).run_one_job()
    committed = JobRepository(environment.session_factory).get_job(environment.job.id)

    assert result.disposition is WorkerCycleDisposition.SUCCEEDED
    assert committed is not None and committed.status is JobStatus.SUCCEEDED
    assert observed[0].disposition is SourceProjectionLifecycleDisposition.CLEANED
    assert not _projection_path(environment).exists()
    with environment.session_factory() as session:
        run = session.get(AnalysisRunRow, environment.job.run_id)
        assert run is not None and run.report_json is not None
        assert session.query(ToolExecutionRow).count() == 1


def test_terminal_policy_failure_commits_before_projection_cleanup(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path, select_ignore=True)
    observed = []

    result = _cycle(
        environment,
        tmp_path / "policy-failure",
        _DockerExecutor(),
        terminal_observer=SourceProjectionTerminalObserver(
            _lifecycle(environment),
            observed.append,
        ),
    ).run_one_job()
    committed = JobRepository(environment.session_factory).get_job(environment.job.id)

    assert result.disposition is WorkerCycleDisposition.FAILED
    assert committed is not None and committed.status is JobStatus.FAILED
    assert observed[0].disposition is SourceProjectionLifecycleDisposition.CLEANED
    assert not _projection_path(environment).exists()
    with environment.session_factory() as session:
        assert session.query(ToolExecutionRow).count() == 1


class _UnavailableDockerExecutor(_DockerExecutor):
    def start(self, request):
        raise RuntimeError("runtime unavailable")


def test_retryable_failure_retains_projection_for_verified_second_attempt(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    first_observed = []
    first = _cycle(
        environment,
        tmp_path / "first",
        _UnavailableDockerExecutor(),
        terminal_observer=SourceProjectionTerminalObserver(
            _lifecycle(environment),
            first_observed.append,
        ),
    ).run_one_job()
    after_first = JobRepository(environment.session_factory).get_job(environment.job.id)

    assert first.disposition is WorkerCycleDisposition.RETRY_PENDING
    assert after_first is not None and after_first.status is JobStatus.RETRY_PENDING
    assert first_observed == []
    assert _projection_path(environment).is_dir()

    second_observed = []
    executor = _DockerExecutor(b'{"results": [], "errors": []}')
    second = _cycle(
        environment,
        tmp_path / "second",
        executor,
        terminal_observer=SourceProjectionTerminalObserver(
            _lifecycle(environment),
            second_observed.append,
        ),
    ).run_one_job()

    assert second.disposition is WorkerCycleDisposition.SUCCEEDED
    assert executor.visible_files == [("app.py", "pkg/auth.py")]
    assert second_observed[0].disposition is SourceProjectionLifecycleDisposition.CLEANED
    assert not _projection_path(environment).exists()


class _LeaseLostResultCommit:
    def commit_result(self, request):
        raise JobLeaseExpiredError(
            request.job_id,
            NOW,
            NOW + timedelta(seconds=1),
        )


def test_lease_loss_after_scanner_completion_retains_projection(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    observed = []

    result = _cycle(
        environment,
        tmp_path / "lease-loss",
        _DockerExecutor(),
        result_commit_service=_LeaseLostResultCommit(),
        terminal_observer=SourceProjectionTerminalObserver(
            _lifecycle(environment),
            observed.append,
        ),
    ).run_one_job()

    assert result.disposition is WorkerCycleDisposition.LEASE_LOST
    assert observed == []
    assert _projection_path(environment).is_dir()


class _CleanupFailingProjectionManager(SourceProjectionManager):
    def cleanup_projection(self, projection) -> None:
        raise SourceProjectionCleanupError


@pytest.mark.parametrize("select_ignore", (False, True))
def test_cleanup_failure_cannot_change_committed_terminal_result(
    tmp_path: Path,
    select_ignore: bool,
) -> None:
    environment = _environment(tmp_path, select_ignore=select_ignore)
    manager = _CleanupFailingProjectionManager(
        environment.projection_manager.base_directory
    )
    observed = []

    result = _cycle(
        environment,
        tmp_path / "cleanup-failure",
        _DockerExecutor(),
        terminal_observer=SourceProjectionTerminalObserver(
            _lifecycle(environment, manager),
            observed.append,
        ),
    ).run_one_job()
    committed = JobRepository(environment.session_factory).get_job(environment.job.id)

    expected = (
        WorkerCycleDisposition.FAILED
        if select_ignore
        else WorkerCycleDisposition.SUCCEEDED
    )
    expected_status = JobStatus.FAILED if select_ignore else JobStatus.SUCCEEDED
    assert result.disposition is expected
    assert committed is not None and committed.status is expected_status
    assert observed[0].disposition is SourceProjectionLifecycleDisposition.CLEANUP_FAILED
    assert _projection_path(environment).is_dir()
    with environment.session_factory() as session:
        run = session.get(AnalysisRunRow, environment.job.run_id)
        assert run is not None
        assert (run.report_json is not None) is (not select_ignore)
        assert session.query(ToolExecutionRow).count() == 1


@pytest.mark.parametrize(
    "status",
    (
        JobStatus.QUEUED,
        JobStatus.LEASED,
        JobStatus.RUNNING,
        JobStatus.RETRY_PENDING,
    ),
)
def test_non_terminal_jobs_are_never_cleanup_authority(
    tmp_path: Path,
    status: JobStatus,
) -> None:
    environment = _environment(tmp_path)
    durable_job = _persist_job(environment, status=status)

    result = _lifecycle(environment).reconcile_job(durable_job.id)

    assert (
        result.disposition
        is SourceProjectionLifecycleDisposition.RETAINED_NON_TERMINAL
    )
    assert _projection_path(environment).is_dir()


@pytest.mark.parametrize(
    "forged_status",
    (
        JobStatus.SUCCEEDED,
        JobStatus.PARTIAL,
        JobStatus.FAILED,
        JobStatus.CANCELLED,
    ),
)
def test_caller_supplied_terminal_status_cannot_authorize_cleanup(
    tmp_path: Path,
    forged_status: JobStatus,
) -> None:
    environment = _environment(tmp_path)
    fake_terminal = replace(environment.job, status=forged_status)

    result = SourceProjectionTerminalObserver(_lifecycle(environment))(fake_terminal)

    durable = JobRepository(environment.session_factory).get_job(environment.job.id)
    assert durable is not None and durable.status is JobStatus.QUEUED
    assert (
        result.disposition
        is SourceProjectionLifecycleDisposition.RETAINED_NON_TERMINAL
    )
    assert _projection_path(environment).is_dir()


def test_caller_supplied_payload_cannot_select_cleanup_target(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    fake_payload = json.loads(json.dumps(environment.job.payload_json))
    fake_payload[SOURCE_EXECUTION_PAYLOAD_KEY]["projection_reference"][
        "projection_id"
    ] = "securescan-source-projection-" + "0" * 32
    fake = replace(
        environment.job,
        run_id="00000000-0000-4000-8000-00000000eeee",
        adapter_id="caller-controlled-adapter",
        status=JobStatus.SUCCEEDED,
        payload_json=fake_payload,
    )

    retained = SourceProjectionTerminalObserver(_lifecycle(environment))(fake)

    assert (
        retained.disposition
        is SourceProjectionLifecycleDisposition.RETAINED_NON_TERMINAL
    )
    assert _projection_path(environment).is_dir()

    _persist_job(environment, status=JobStatus.SUCCEEDED)
    cleaned = SourceProjectionTerminalObserver(_lifecycle(environment))(fake)

    assert cleaned.disposition is SourceProjectionLifecycleDisposition.CLEANED
    assert not _projection_path(environment).exists()


def test_terminal_cleanup_is_idempotent_and_missing_is_safe(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    cancellation = JobCancellationService(
        environment.session_factory,
        clock=lambda: NOW,
    ).request_cancellation(environment.job.id)
    assert cancellation.immediate is True
    assert cancellation.job.status is JobStatus.CANCELLED
    lifecycle = _lifecycle(environment)

    first = lifecycle.reconcile_job(environment.job.id)
    second = lifecycle.reconcile_job(environment.job.id)

    assert first.disposition is SourceProjectionLifecycleDisposition.CLEANED
    assert second.disposition is SourceProjectionLifecycleDisposition.ALREADY_ABSENT


def test_restart_reconciliation_cleans_crash_after_terminal_commit(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    worker_result = _cycle(
        environment,
        tmp_path / "crashed-worker",
        _DockerExecutor(),
    ).run_one_job()
    durable_job = JobRepository(environment.session_factory).get_job(environment.job.id)

    assert worker_result.disposition is WorkerCycleDisposition.SUCCEEDED
    assert durable_job is not None and durable_job.status is JobStatus.SUCCEEDED
    assert _projection_path(environment).is_dir()

    fresh_repository = JobRepository(environment.session_factory)
    fresh_lifecycle = SourceProjectionLifecycleService(
        fresh_repository,
        SourceSemgrepExecutionContextResolver(
            environment.store,
            environment.binding,
        ),
        SourceProjectionManager(environment.projection_manager.base_directory),
    )
    reconciled = fresh_lifecycle.reconcile_job(environment.job.id)

    assert reconciled.disposition is SourceProjectionLifecycleDisposition.CLEANED
    assert not _projection_path(environment).exists()


def test_corrupt_terminal_projection_is_not_deleted(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    projection_path = _projection_path(environment)
    marker = projection_path / ".securescan-source-projection.json"
    os.chmod(marker, 0o600)
    marker.write_text("{}", encoding="utf-8")
    durable_job = _persist_job(environment, status=JobStatus.FAILED)

    result = _lifecycle(environment).reconcile_job(durable_job.id)

    assert result.disposition is SourceProjectionLifecycleDisposition.UNSAFE_TO_CLEAN
    assert projection_path.is_dir()


def test_foreign_terminal_tree_is_not_deleted(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    projection_path = _projection_path(environment)
    saved_projection = tmp_path / "saved-projection"
    projection_path.rename(saved_projection)
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    sentinel = foreign / "must-remain.txt"
    sentinel.write_text("foreign\n", encoding="utf-8")
    projection_path.symlink_to(foreign, target_is_directory=True)
    durable_job = _persist_job(environment, status=JobStatus.FAILED)

    result = _lifecycle(environment).reconcile_job(durable_job.id)

    assert result.disposition is SourceProjectionLifecycleDisposition.UNSAFE_TO_CLEAN
    assert projection_path.is_symlink()
    assert sentinel.read_text(encoding="utf-8") == "foreign\n"


@pytest.mark.parametrize(
    "field",
    ("projection_id", "context_digest", "projection_digest"),
)
def test_wrong_terminal_reference_is_rejected_without_deletion(
    tmp_path: Path,
    field: str,
) -> None:
    environment = _environment(tmp_path)
    payload = json.loads(json.dumps(environment.job.payload_json))
    value = payload[SOURCE_EXECUTION_PAYLOAD_KEY]
    if field == "projection_id":
        value["projection_reference"]["projection_id"] = "../../outside"
    elif field == "context_digest":
        value["context_digest"] = "0" * 64
        value["projection_reference"]["context_digest"] = "0" * 64
    else:
        value["projection_reference"]["projection_digest"] = "0" * 64

    durable_job = _persist_job(
        environment,
        status=JobStatus.SUCCEEDED,
        payload_json=payload,
    )
    result = _lifecycle(environment).reconcile_job(durable_job.id)

    assert result.disposition is SourceProjectionLifecycleDisposition.UNSAFE_TO_CLEAN
    assert _projection_path(environment).is_dir()


def test_ordinary_terminal_job_is_ignored_without_filesystem_effect(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    durable_job = _persist_job(
        environment,
        status=JobStatus.SUCCEEDED,
        payload_json={"ordinary": True},
    )

    result = _lifecycle(environment).reconcile_job(durable_job.id)

    assert result.disposition is SourceProjectionLifecycleDisposition.IGNORED_NON_SOURCE
    assert result.projection_id is None
    assert _projection_path(environment).is_dir()


def test_missing_durable_job_never_authorizes_cleanup(tmp_path: Path) -> None:
    environment = _environment(tmp_path)

    result = _lifecycle(environment).reconcile_job(
        "00000000-0000-4000-8000-00000000ffff"
    )

    assert (
        result.disposition
        is SourceProjectionLifecycleDisposition.DURABLE_JOB_MISSING
    )
    assert result.projection_id is None
    assert _projection_path(environment).is_dir()
