from __future__ import annotations

import json
import os
import shutil
import subprocess
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest
from sqlalchemy import delete
from test_source_projection_lifecycle import (
    _cycle,
    _lifecycle,
    _projection_path,
    _UnavailableDockerExecutor,
)
from test_source_semgrep_execution_bridge import FIXTURE, NOW, _DockerExecutor, _environment

from securescan.domain.enums import (
    ArtifactKind,
    ExecutionOutcome,
    JobFailureCategory,
    JobStatus,
    ObservationType,
)
from securescan.jobs import JobCancellationService, JobRepository, JobRepositoryError
from securescan.persistence.database import AnalysisRunRow, JobRow, ToolExecutionRow
from securescan.runs.query import RunQueryService
from securescan.scanners.semgrep import (
    SOURCE_EXECUTION_PAYLOAD_KEY,
    SourceExecutionAssessmentIntegrityError,
    SourceExecutionAssessmentPersistenceError,
    SourceExecutionBindingMismatchError,
    SourceExecutionJobNotFoundError,
    SourceExecutionNotSourceJobError,
    SourceExecutionNotTerminalError,
    SourceProjectionTerminalObserver,
    SourceSemgrepExecutionAssessmentService,
    SourceSemgrepExecutionContextIntegrityResolver,
    SourceSemgrepExecutionContextResolver,
    TrustedSemgrepSourceBinding,
    load_baseline_ruleset,
)
from securescan.source import (
    AnalysisCapability,
    AssessmentStatus,
    CoverageStatus,
    SourceCapabilityExecutionAssessment,
    SourceExecutionStatus,
    SourceSecurityObservation,
)
from securescan.source.execution_context import SourceExecutionContext
from securescan.worker import WorkerCycleDisposition
from securescan.workspaces import RepositoryWorkspaceManager


def _service(environment) -> SourceSemgrepExecutionAssessmentService:
    return SourceSemgrepExecutionAssessmentService(
        JobRepository(environment.session_factory),
        SourceSemgrepExecutionContextIntegrityResolver(environment.store),
        RunQueryService(environment.session_factory),
        environment.store,
    )


def _run_terminal(
    environment,
    output_root: Path,
    executor,
    *,
    cleanup: bool = False,
):
    observer = (
        SourceProjectionTerminalObserver(_lifecycle(environment))
        if cleanup
        else None
    )
    return _cycle(
        environment,
        output_root,
        executor,
        terminal_observer=observer,
    ).run_one_job()


def _set_max_attempts(environment, value: int) -> None:
    with environment.session_factory.begin() as session:
        row = session.get(JobRow, environment.job.id)
        assert row is not None
        row.max_attempts = value


def _partial_output() -> bytes:
    value = json.loads(FIXTURE.read_text(encoding="utf-8"))
    value["errors"] = [{"type": "ParseError", "message": "/host/secret"}]
    return json.dumps(value).encode("utf-8")


def _replace_durable_context(environment, **changes) -> None:
    payload = deepcopy(environment.job.payload_json)
    envelope = payload[SOURCE_EXECUTION_PAYLOAD_KEY]
    original = environment.store.read_by_sha256(
        envelope["artifact_sha256"],
        expected_size_bytes=envelope["artifact_size_bytes"],
    )
    context = replace(SourceExecutionContext.from_json(original), **changes)
    artifact = environment.store.put(
        context.canonical_json(),
        kind=ArtifactKind.SOURCE_EXECUTION_CONTEXT,
        media_type="application/json",
        sanitized=False,
    )
    envelope["artifact_sha256"] = artifact.sha256
    envelope["artifact_size_bytes"] = artifact.size_bytes
    envelope["context_digest"] = context.context_digest()
    envelope["projection_reference"]["context_digest"] = context.context_digest()
    with environment.session_factory.begin() as session:
        job = session.get(JobRow, environment.job.id)
        assert job is not None
        job.payload_json = payload


def _fixed_assessment() -> SourceCapabilityExecutionAssessment:
    fingerprint = (
        "496693dc786c75757e5978a1c32b1d4108bb81564078b87e41a04bbc7f47e912"
    )
    observation = SourceSecurityObservation(
        observation_id="496693dc-786c-7575-7e59-78a1c32b1d41",
        producer="semgrep-ce",
        observation_type=ObservationType.SOURCE_RULE_MATCH,
        rule_id="python.fixed-rule",
        message="Semgrep security rule matched",
        native_severity="high",
        relative_path="app.py",
        start_line=1,
        start_column=1,
        end_line=1,
        end_column=4,
        cwe_ids=("CWE-95",),
        fingerprint=fingerprint,
    )
    return SourceCapabilityExecutionAssessment(
        source_run_id="00000000-0000-4000-8000-000000000301",
        job_id="00000000-0000-4000-8000-000000000302",
        repository_digest="1" * 64,
        profile_digest="2" * 64,
        plan_digest="3" * 64,
        source_analyzer_id="python-semgrep-v1",
        capability=AnalysisCapability.PYTHON_SAST,
        component_id=None,
        binding_digest="4" * 64,
        core_adapter_id="semgrep-ce",
        execution_status=SourceExecutionStatus.COMPLETE,
        coverage_status=CoverageStatus.FULL_FOR_DECLARED_SCOPE,
        assessment_status=AssessmentStatus.OBSERVATIONS_ONLY,
        declared_paths=("app.py",),
        declared_file_count=1,
        declared_total_bytes=24,
        observations=(observation,),
        gaps=(),
        attempt_count=1,
        terminal_job_status=JobStatus.SUCCEEDED,
        final_tool_execution_id="00000000-0000-4000-8000-000000000303",
        tool_version="1.171.0",
    )


def test_success_assessment_survives_cleanup_and_fresh_restart(tmp_path: Path) -> None:
    environment = _environment(tmp_path)

    result = _run_terminal(
        environment,
        tmp_path / "attempt",
        _DockerExecutor(),
        cleanup=True,
    )
    first = _service(environment).assess_job(environment.job.id)
    first_digest = first.assessment_digest()

    assert result.disposition is WorkerCycleDisposition.SUCCEEDED
    assert not _projection_path(environment).exists()
    assert first.execution_status is SourceExecutionStatus.COMPLETE
    assert first.coverage_status is CoverageStatus.FULL_FOR_DECLARED_SCOPE
    assert first.assessment_status is AssessmentStatus.OBSERVATIONS_ONLY
    assert first.declared_paths == ("app.py", "pkg/auth.py")
    assert first.declared_file_count == 2
    assert first.declared_total_bytes > 0
    assert first.observation_count == 1
    assert first.gap_count == 0
    assert first.attempt_count == 1
    assert first.final_tool_execution_id is not None
    assert first.observations[0].relative_path == "app.py"

    del first
    restarted = _service(environment).assess_job(environment.job.id)
    assert restarted.assessment_digest() == first_digest
    assert restarted.canonical_json() == _service(environment).assess_job(
        environment.job.id
    ).canonical_json()


def test_zero_observations_is_complete_without_a_security_claim(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    _run_terminal(
        environment,
        tmp_path / "attempt",
        _DockerExecutor(b'{"version":"1.171.0","results":[],"errors":[]}'),
    )

    assessment = _service(environment).assess_job(environment.job.id)

    assert assessment.execution_status is SourceExecutionStatus.COMPLETE
    assert assessment.coverage_status is CoverageStatus.FULL_FOR_DECLARED_SCOPE
    assert assessment.observation_count == 0
    assert assessment.gap_count == 0
    serialized = assessment.canonical_json().lower()
    assert b"secure repository" not in serialized
    assert b"clean repository" not in serialized
    assert b"vulnerability-free" not in serialized


def test_partial_observations_and_safe_gaps_are_preserved(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    _run_terminal(
        environment,
        tmp_path / "attempt",
        _DockerExecutor(_partial_output()),
    )

    assessment = _service(environment).assess_job(environment.job.id)

    assert assessment.execution_status is SourceExecutionStatus.PARTIAL
    assert assessment.coverage_status is CoverageStatus.PARTIAL
    assert assessment.observation_count == 1
    assert assessment.gap_count == 1
    assert assessment.gaps[0].code == "SEMGREP_PARSE_ERROR"
    assert assessment.gaps[0].stage == "parsing"
    assert "/host/secret" not in assessment.gaps[0].message


@pytest.mark.parametrize(
    ("kind", "expected_code"),
    (
        ("authorization", "EXECUTION_AUTHORIZATION_FAILED"),
        ("infrastructure", "EXECUTION_INFRASTRUCTURE_FAILED"),
        ("tool", "EXECUTION_TOOL_FAILED"),
    ),
)
def test_terminal_failures_map_to_unknown_safe_gaps(
    tmp_path: Path,
    kind: str,
    expected_code: str,
) -> None:
    environment = _environment(tmp_path, select_ignore=kind == "authorization")
    if kind == "infrastructure":
        _set_max_attempts(environment, 1)
        executor = _UnavailableDockerExecutor()
    elif kind == "tool":
        executor = _DockerExecutor(b"not-json")
    else:
        executor = _DockerExecutor()
    result = _run_terminal(environment, tmp_path / "attempt", executor)

    assessment = _service(environment).assess_job(environment.job.id)

    assert result.disposition is WorkerCycleDisposition.FAILED
    assert assessment.execution_status is SourceExecutionStatus.FAILED
    assert assessment.coverage_status is CoverageStatus.UNKNOWN
    assert assessment.observation_count == 0
    assert assessment.gap_count == 1
    assert assessment.gaps[0].code == expected_code
    assert assessment.final_tool_execution_id is not None


def test_immediate_cancellation_is_failed_unknown_with_safe_gap(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    result = JobCancellationService(
        environment.session_factory,
        clock=lambda: NOW,
    ).request_cancellation(environment.job.id)

    assessment = _service(environment).assess_job(environment.job.id)

    assert result.immediate is True
    assert assessment.terminal_job_status is JobStatus.CANCELLED
    assert assessment.execution_status is SourceExecutionStatus.FAILED
    assert assessment.coverage_status is CoverageStatus.UNKNOWN
    assert assessment.gaps[0].code == "EXECUTION_CANCELLED"
    assert assessment.attempt_count == 0
    assert assessment.final_tool_execution_id is None


def test_cancellation_after_retry_preserves_attempt_provenance(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    first = _run_terminal(
        environment,
        tmp_path / "first",
        _UnavailableDockerExecutor(),
    )
    cancelled = JobCancellationService(
        environment.session_factory,
        clock=lambda: NOW,
    ).request_cancellation(environment.job.id)

    assessment = _service(environment).assess_job(environment.job.id)

    assert first.disposition is WorkerCycleDisposition.RETRY_PENDING
    assert cancelled.immediate is True
    assert assessment.terminal_job_status is JobStatus.CANCELLED
    assert assessment.execution_status is SourceExecutionStatus.FAILED
    assert assessment.coverage_status is CoverageStatus.UNKNOWN
    assert assessment.attempt_count == 1
    assert assessment.final_tool_execution_id is not None
    assert assessment.gaps[0].code == "EXECUTION_CANCELLED"


def test_retry_then_success_uses_only_final_attempt_truth(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    first = _run_terminal(
        environment,
        tmp_path / "first",
        _UnavailableDockerExecutor(),
    )
    second = _run_terminal(
        environment,
        tmp_path / "second",
        _DockerExecutor(b'{"results":[],"errors":[]}'),
    )

    assessment = _service(environment).assess_job(environment.job.id)

    assert first.disposition is WorkerCycleDisposition.RETRY_PENDING
    assert second.disposition is WorkerCycleDisposition.SUCCEEDED
    assert assessment.execution_status is SourceExecutionStatus.COMPLETE
    assert assessment.coverage_status is CoverageStatus.FULL_FOR_DECLARED_SCOPE
    assert assessment.attempt_count == 2
    assert assessment.gaps == ()
    with environment.session_factory() as session:
        rows = session.query(ToolExecutionRow).order_by(
            ToolExecutionRow.attempt_number
        ).all()
        assert [row.attempt_number for row in rows] == [1, 2]
        assert assessment.final_tool_execution_id == rows[1].id


def test_retry_then_terminal_failure_uses_final_failure(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    _set_max_attempts(environment, 2)
    first = _run_terminal(
        environment,
        tmp_path / "first",
        _UnavailableDockerExecutor(),
    )
    second = _run_terminal(
        environment,
        tmp_path / "second",
        _UnavailableDockerExecutor(),
    )

    assessment = _service(environment).assess_job(environment.job.id)

    assert first.disposition is WorkerCycleDisposition.RETRY_PENDING
    assert second.disposition is WorkerCycleDisposition.FAILED
    assert assessment.execution_status is SourceExecutionStatus.FAILED
    assert assessment.coverage_status is CoverageStatus.UNKNOWN
    assert assessment.attempt_count == 2
    assert assessment.gaps[0].code == "EXECUTION_INFRASTRUCTURE_FAILED"
    with environment.session_factory() as session:
        rows = session.query(ToolExecutionRow).order_by(
            ToolExecutionRow.attempt_number
        ).all()
        assert assessment.final_tool_execution_id == rows[1].id


def test_historical_assessment_does_not_require_current_binding(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    _run_terminal(environment, tmp_path / "attempt", _DockerExecutor())
    original = _service(environment).assess_job(environment.job.id)

    changed_binding = TrustedSemgrepSourceBinding(
        definition=replace(
            environment.definition(tmp_path / "changed", _DockerExecutor()),
            tool_version="9.9.9",
        ),
        ruleset=load_baseline_ruleset(),
    )
    durable_job = JobRepository(environment.session_factory).get_job(environment.job.id)
    assert durable_job is not None

    with pytest.raises(SourceExecutionBindingMismatchError):
        SourceSemgrepExecutionContextResolver(
            environment.store,
            changed_binding,
        ).resolve(durable_job)

    historical = _service(environment).assess_job(environment.job.id)
    assert historical.binding_digest == original.binding_digest
    assert historical.tool_version == original.tool_version == "1.171.0"
    assert historical.assessment_digest() == original.assessment_digest()


@pytest.mark.parametrize(
    "changes",
    (
        {"job_id": "00000000-0000-4000-8000-00000000eeee"},
        {"source_run_id": "00000000-0000-4000-8000-00000000eeee"},
        {"source_analyzer_id": "other-analyzer"},
        {"capability": AnalysisCapability.REPOSITORY_PROFILING},
    ),
)
def test_context_identity_analyzer_and_capability_tampering_fails_closed(
    tmp_path: Path,
    changes: dict[str, object],
) -> None:
    environment = _environment(tmp_path)
    _run_terminal(environment, tmp_path / "attempt", _DockerExecutor())
    _replace_durable_context(environment, **changes)

    with pytest.raises(SourceExecutionAssessmentIntegrityError):
        _service(environment).assess_job(environment.job.id)


@pytest.mark.parametrize(
    "field",
    (
        "job_id",
        "source_run_id",
        "core_adapter_id",
        "source_analyzer_id",
        "capability",
        "repository_digest",
        "profile_digest",
        "plan_digest",
        "selected_files",
        "binding_digest",
        "schema_version",
    ),
)
def test_any_unauthenticated_context_artifact_tampering_fails_closed(
    tmp_path: Path,
    field: str,
) -> None:
    environment = _environment(tmp_path)
    _run_terminal(environment, tmp_path / "attempt", _DockerExecutor())
    envelope = environment.job.payload_json[SOURCE_EXECUTION_PAYLOAD_KEY]
    artifact = (
        environment.store.root
        / "sha256"
        / envelope["artifact_sha256"][:2]
        / envelope["artifact_sha256"]
    )
    document = json.loads(artifact.read_text(encoding="utf-8"))
    if field in {"job_id", "source_run_id"}:
        document[field] = "00000000-0000-4000-8000-00000000eeee"
    elif field in {"repository_digest", "profile_digest", "plan_digest"}:
        document[field] = "0" * 64
    elif field == "selected_files":
        document[field] = document[field][:-1]
    elif field == "binding_digest":
        document[field] = "corrupt"
    elif field == "capability":
        document[field] = AnalysisCapability.REPOSITORY_PROFILING.value
    else:
        document[field] = "corrupt"
    artifact.write_text(
        json.dumps(document, separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )

    with pytest.raises(SourceExecutionAssessmentIntegrityError):
        _service(environment).assess_job(environment.job.id)


def test_coordinated_repository_digest_rewrite_conflicts_with_durable_target(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    _run_terminal(environment, tmp_path / "attempt", _DockerExecutor())
    _replace_durable_context(environment, repository_digest="0" * 64)

    with pytest.raises(SourceExecutionAssessmentIntegrityError):
        _service(environment).assess_job(environment.job.id)


def test_assessment_never_executes_or_reopens_source_filesystem(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment(tmp_path)
    _run_terminal(
        environment,
        tmp_path / "attempt",
        _DockerExecutor(),
        cleanup=True,
    )

    def forbidden(*_args, **_kwargs):
        raise AssertionError("assessment attempted execution or Source filesystem work")

    from securescan.execution.docker_sandbox import DockerSandboxExecutor
    from securescan.scanners.semgrep.adapter import SemgrepScannerAdapter
    from securescan.source.projection import SourceProjectionManager

    monkeypatch.setattr(DockerSandboxExecutor, "start", forbidden)
    monkeypatch.setattr(DockerSandboxExecutor, "execute", forbidden)
    monkeypatch.setattr(SemgrepScannerAdapter, "start", forbidden)
    monkeypatch.setattr(SemgrepScannerAdapter, "execute", forbidden)
    monkeypatch.setattr(RepositoryWorkspaceManager, "prepare_repository", forbidden)
    monkeypatch.setattr(SourceProjectionManager, "build_projection", forbidden)
    monkeypatch.setattr(SourceProjectionManager, "reopen_projection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)

    assessment = _service(environment).assess_job(environment.job.id)
    assert assessment.execution_status is SourceExecutionStatus.COMPLETE


@pytest.mark.parametrize(
    "status",
    (
        JobStatus.QUEUED,
        JobStatus.LEASED,
        JobStatus.RUNNING,
        JobStatus.RETRY_PENDING,
    ),
)
def test_nonterminal_jobs_are_rejected(tmp_path: Path, status: JobStatus) -> None:
    environment = _environment(tmp_path)
    with environment.session_factory.begin() as session:
        row = session.get(JobRow, environment.job.id)
        assert row is not None
        row.status = status.value

    with pytest.raises(SourceExecutionNotTerminalError):
        _service(environment).assess_job(environment.job.id)


@pytest.mark.parametrize(
    "mutation",
    (
        "wrong_run_status",
        "active_job",
        "extra_succeeded",
        "extra_partial",
        "extra_failed",
        "extra_cancelled",
    ),
)
def test_inconsistent_single_job_run_aggregate_fails_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    environment = _environment(tmp_path)
    _run_terminal(environment, tmp_path / "attempt", _DockerExecutor())
    with environment.session_factory.begin() as session:
        run = session.get(AnalysisRunRow, environment.job.run_id)
        assert run is not None
        if mutation == "wrong_run_status":
            run.status = "failed"
        else:
            extra_status = {
                "active_job": JobStatus.QUEUED,
                "extra_succeeded": JobStatus.SUCCEEDED,
                "extra_partial": JobStatus.PARTIAL,
                "extra_failed": JobStatus.FAILED,
                "extra_cancelled": JobStatus.CANCELLED,
            }[mutation]
            session.add(
                JobRow(
                    id="00000000-0000-4000-8000-00000000eeee",
                    run_id=environment.job.run_id,
                    adapter_id="semgrep-ce",
                    status=extra_status.value,
                    idempotency_key="e" * 64,
                    payload_json={},
                    attempt_count=0,
                )
            )

    with pytest.raises(SourceExecutionAssessmentIntegrityError):
        _service(environment).assess_job(environment.job.id)


def test_missing_and_ordinary_jobs_are_typed(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    with pytest.raises(SourceExecutionJobNotFoundError):
        _service(environment).assess_job("00000000-0000-4000-8000-00000000ffff")

    with environment.session_factory.begin() as session:
        row = session.get(JobRow, environment.job.id)
        assert row is not None
        row.payload_json = {"caller": "ordinary"}
    with pytest.raises(SourceExecutionNotSourceJobError):
        _service(environment).assess_job(environment.job.id)


def test_cross_version_report_ruleset_tamper_fails_artifact_correlation(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    _run_terminal(environment, tmp_path / "attempt", _DockerExecutor())

    with environment.session_factory.begin() as session:
        run = session.get(AnalysisRunRow, environment.job.run_id)
        assert run is not None and run.report_json is not None
        report = deepcopy(run.report_json)
        assert report["target"]["metadata"]["ruleset_id"] == (
            "securescan-python-baseline-v2"
        )
        assert report["target"]["metadata"]["ruleset_version"] == "2"
        report["target"]["metadata"]["ruleset_id"] = (
            "securescan-python-baseline-v1"
        )
        report["target"]["metadata"]["ruleset_version"] = "1"
        run.report_json = report

    with pytest.raises(SourceExecutionAssessmentIntegrityError):
        _service(environment).assess_job(environment.job.id)


def test_matching_historical_v1_report_and_artifact_remain_assessable(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    _run_terminal(environment, tmp_path / "attempt", _DockerExecutor())

    with environment.session_factory.begin() as session:
        run = session.get(AnalysisRunRow, environment.job.run_id)
        assert run is not None and run.report_json is not None
        report = deepcopy(run.report_json)
        artifact_record = report["executions"][0]["artifacts"][0]
        evidence = json.loads(
            environment.store.read_by_sha256(
                artifact_record["sha256"],
                expected_size_bytes=artifact_record["size_bytes"],
            )
        )
        evidence["ruleset"] = {
            "id": "securescan-python-baseline-v1",
            "version": "1",
        }
        historical_artifact = environment.store.put(
            json.dumps(
                evidence,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8"),
            kind=ArtifactKind.SANITIZED_NATIVE_REPORT,
            media_type="application/json",
            sanitized=True,
        )
        report["target"]["metadata"]["ruleset_id"] = (
            "securescan-python-baseline-v1"
        )
        report["target"]["metadata"]["ruleset_version"] = "1"
        report["executions"][0]["artifacts"][0] = (
            historical_artifact.model_dump(mode="json")
        )
        run.report_json = report

    assessment = _service(environment).assess_job(environment.job.id)

    assert assessment.execution_status is SourceExecutionStatus.COMPLETE
    assert assessment.coverage_status is CoverageStatus.FULL_FOR_DECLARED_SCOPE


@pytest.mark.parametrize(
    "mutation",
    (
        "missing_report",
        "malformed_report",
        "unknown_report_field",
        "missing_tool",
        "contradictory_tool",
        "wrong_tool_adapter",
        "wrong_adapter_version",
        "wrong_tool_version",
        "unexpected_failure_category",
        "unexpected_retryability",
        "wrong_target_type",
        "wrong_target_path",
        "wrong_target_digest",
        "wrong_ruleset_id",
        "wrong_ruleset_version",
        "wrong_file_count",
        "wrong_execution_adapter",
        "wrong_report_adapter_version",
        "wrong_report_tool_version",
        "wrong_execution_status",
        "wrong_execution_outcome",
        "unexpected_execution_error",
        "wrong_artifact_kind",
        "wrong_sanitized_flag",
        "wrong_artifact_media_type",
        "malformed_artifact_sha",
        "wrong_artifact_storage_path",
        "duplicate_observation",
        "outside_path",
        "noncanonical_path",
        "wrong_observation_producer",
        "wrong_observation_type",
        "wrong_observation_message",
        "invalid_rule_id",
        "invalid_severity",
        "invalid_line",
        "noncanonical_cwe",
        "wrong_fingerprint",
        "wrong_observation_id",
        "wrong_scanner_version",
        "success_with_gap",
        "run_id_mismatch",
        "job_adapter",
    ),
)
def test_inconsistent_success_evidence_fails_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    environment = _environment(tmp_path)
    _run_terminal(environment, tmp_path / "attempt", _DockerExecutor())
    with environment.session_factory.begin() as session:
        run = session.get(AnalysisRunRow, environment.job.run_id)
        job = session.get(JobRow, environment.job.id)
        tool = session.query(ToolExecutionRow).one()
        assert run is not None and job is not None and run.report_json is not None
        report = deepcopy(run.report_json)
        if mutation == "missing_report":
            run.report_json = None
        elif mutation == "malformed_report":
            run.report_json = {"unknown": True}
        elif mutation == "unknown_report_field":
            report["unknown"] = True
            run.report_json = report
        elif mutation == "missing_tool":
            session.execute(delete(ToolExecutionRow))
        elif mutation == "contradictory_tool":
            tool.outcome = ExecutionOutcome.INTERNAL_ERROR.value
            tool.failure_category = JobFailureCategory.RETRYABLE_INFRASTRUCTURE.value
            tool.retryable = True
        elif mutation == "wrong_tool_adapter":
            tool.adapter_id = "other-adapter"
        elif mutation == "wrong_adapter_version":
            tool.adapter_version = "9.9.9"
        elif mutation == "wrong_tool_version":
            tool.tool_version = "9.9.9"
        elif mutation == "unexpected_failure_category":
            tool.failure_category = JobFailureCategory.NON_RETRYABLE_POLICY.value
        elif mutation == "unexpected_retryability":
            tool.retryable = False
        elif mutation == "wrong_target_type":
            report["target"]["target_type"] = "live_web_application"
            run.report_json = report
        elif mutation == "wrong_target_path":
            report["target"]["path"] = "/host/source"
            run.report_json = report
        elif mutation == "wrong_target_digest":
            report["target"]["content_digest"] = "0" * 64
            run.report_json = report
        elif mutation == "wrong_ruleset_id":
            report["target"]["metadata"]["ruleset_id"] = "other"
            run.report_json = report
        elif mutation == "wrong_ruleset_version":
            report["target"]["metadata"]["ruleset_version"] = "999"
            run.report_json = report
        elif mutation == "wrong_file_count":
            report["target"]["metadata"]["file_count"] = 99
            run.report_json = report
        elif mutation == "wrong_execution_adapter":
            report["executions"][0]["adapter_id"] = "other-adapter"
            run.report_json = report
        elif mutation == "wrong_report_adapter_version":
            report["executions"][0]["adapter_version"] = "9.9.9"
            run.report_json = report
        elif mutation == "wrong_report_tool_version":
            report["executions"][0]["tool_version"] = "9.9.9"
            run.report_json = report
        elif mutation == "wrong_execution_status":
            report["executions"][0]["status"] = "partial"
            run.report_json = report
        elif mutation == "wrong_execution_outcome":
            report["executions"][0]["outcome"] = "partial_analysis"
            run.report_json = report
        elif mutation == "unexpected_execution_error":
            report["executions"][0]["error"] = "/host/secret"
            run.report_json = report
        elif mutation.startswith("wrong_artifact") or mutation in {
            "wrong_sanitized_flag",
            "malformed_artifact_sha",
        }:
            artifact = report["executions"][0]["artifacts"][0]
            if mutation == "wrong_artifact_kind":
                artifact["kind"] = "stdout"
            elif mutation == "wrong_sanitized_flag":
                artifact["sanitized"] = False
            elif mutation == "wrong_artifact_media_type":
                artifact["media_type"] = "text/plain"
            elif mutation == "malformed_artifact_sha":
                artifact["sha256"] = "not-a-digest"
            else:
                artifact["storage_path"] = "/host/native.json"
            run.report_json = report
        elif mutation == "duplicate_observation":
            report["observations"].append(deepcopy(report["observations"][0]))
            report["executions"][0]["observations"].append(
                deepcopy(report["executions"][0]["observations"][0])
            )
            run.report_json = report
        elif mutation in {"outside_path", "noncanonical_path"}:
            path = "outside.py" if mutation == "outside_path" else "pkg/../app.py"
            report["observations"][0]["path"] = path
            report["executions"][0]["observations"][0]["path"] = path
            run.report_json = report
        elif mutation.startswith("wrong_observation") or mutation in {
            "invalid_rule_id",
            "invalid_severity",
            "invalid_line",
            "noncanonical_cwe",
            "wrong_fingerprint",
            "wrong_scanner_version",
        }:
            observations = (
                report["observations"][0],
                report["executions"][0]["observations"][0],
            )
            for observation in observations:
                if mutation == "wrong_observation_producer":
                    observation["producer"] = "other-adapter"
                elif mutation == "wrong_observation_type":
                    observation["observation_type"] = "test_observation"
                elif mutation == "wrong_observation_message":
                    observation["message"] = "native scanner detail"
                elif mutation == "invalid_rule_id":
                    observation["rule_id"] = ""
                elif mutation == "invalid_severity":
                    observation["native_severity"] = "critical"
                    observation["properties"]["severity"] = "critical"
                elif mutation == "invalid_line":
                    observation["start_line"] = 0
                elif mutation == "noncanonical_cwe":
                    observation["cwe_ids"] = ["CWE-invalid"]
                    observation["properties"]["metadata"] = {
                        "cwe": ["CWE-invalid"]
                    }
                elif mutation == "wrong_fingerprint":
                    observation["fingerprint"] = "0" * 64
                elif mutation == "wrong_observation_id":
                    observation["observation_id"] = (
                        "00000000-0000-4000-8000-00000000eeee"
                    )
                else:
                    observation["properties"]["scanner_version"] = "9.9.9"
            run.report_json = report
        elif mutation == "success_with_gap":
            gap = {
                "code": "SEMGREP_PARSE_ERROR",
                "message": "Semgrep could not parse part of the repository",
                "adapter_id": "semgrep-ce",
            }
            report["analysis_gaps"] = [gap]
            report["executions"][0]["warnings"] = [gap["message"]]
            run.report_json = report
        elif mutation == "run_id_mismatch":
            report["run_id"] = "00000000-0000-4000-8000-00000000eeee"
            report["executions"][0]["run_id"] = report["run_id"]
            run.report_json = report
        else:
            job.adapter_id = "other-adapter"

    with pytest.raises(SourceExecutionAssessmentIntegrityError):
        _service(environment).assess_job(environment.job.id)


@pytest.mark.parametrize("mutation", ("missing_report", "zero_gaps"))
def test_inconsistent_partial_evidence_fails_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    environment = _environment(tmp_path)
    _run_terminal(
        environment,
        tmp_path / "attempt",
        _DockerExecutor(_partial_output()),
    )
    with environment.session_factory.begin() as session:
        run = session.get(AnalysisRunRow, environment.job.run_id)
        assert run is not None and run.report_json is not None
        if mutation == "missing_report":
            run.report_json = None
        else:
            report = deepcopy(run.report_json)
            report["analysis_gaps"] = []
            report["executions"][0]["warnings"] = []
            run.report_json = report

    with pytest.raises(SourceExecutionAssessmentIntegrityError):
        _service(environment).assess_job(environment.job.id)


@pytest.mark.parametrize("mutation", ("code", "message", "adapter"))
def test_unknown_or_mismatched_parser_gap_fails_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    environment = _environment(tmp_path)
    _run_terminal(
        environment,
        tmp_path / "attempt",
        _DockerExecutor(_partial_output()),
    )
    with environment.session_factory.begin() as session:
        run = session.get(AnalysisRunRow, environment.job.run_id)
        assert run is not None and run.report_json is not None
        report = deepcopy(run.report_json)
        gap = report["analysis_gaps"][0]
        if mutation == "code":
            gap["code"] = "SEMGREP_NATIVE_SECRET"
        elif mutation == "message":
            gap["message"] = "/host/private diagnostic"
            report["executions"][0]["warnings"] = [gap["message"]]
        else:
            gap["adapter_id"] = "other-adapter"
        run.report_json = report

    with pytest.raises(SourceExecutionAssessmentIntegrityError):
        _service(environment).assess_job(environment.job.id)


def test_gap_order_does_not_change_assessment_identity(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    raw["errors"] = [{"type": "Timeout"}, {"type": "ParseError"}]
    _run_terminal(
        environment,
        tmp_path / "attempt",
        _DockerExecutor(json.dumps(raw).encode("utf-8")),
    )
    original = _service(environment).assess_job(environment.job.id)
    with environment.session_factory.begin() as session:
        run = session.get(AnalysisRunRow, environment.job.run_id)
        assert run is not None and run.report_json is not None
        report = deepcopy(run.report_json)
        report["analysis_gaps"].reverse()
        report["executions"][0]["warnings"].reverse()
        run.report_json = report

    reordered = _service(environment).assess_job(environment.job.id)
    assert reordered.canonical_json() == original.canonical_json()
    assert reordered.assessment_digest() == original.assessment_digest()


def test_failed_job_with_successful_execution_is_rejected(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    _set_max_attempts(environment, 1)
    _run_terminal(environment, tmp_path / "attempt", _UnavailableDockerExecutor())
    with environment.session_factory.begin() as session:
        tool = session.query(ToolExecutionRow).one()
        tool.outcome = ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS.value
        tool.failure_category = None
        tool.retryable = None

    with pytest.raises(SourceExecutionAssessmentIntegrityError):
        _service(environment).assess_job(environment.job.id)


@pytest.mark.parametrize(
    ("outcome", "category", "retryable"),
    (
        (
            ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
            JobFailureCategory.RETRYABLE_INFRASTRUCTURE,
            True,
        ),
        (ExecutionOutcome.TIMEOUT, JobFailureCategory.OUTPUT_LIMIT, True),
        (
            ExecutionOutcome.OUTPUT_LIMIT_EXCEEDED,
            JobFailureCategory.TIMEOUT,
            True,
        ),
        (
            ExecutionOutcome.INVALID_OUTPUT,
            JobFailureCategory.NON_RETRYABLE_POLICY,
            False,
        ),
        (
            ExecutionOutcome.INTERNAL_ERROR,
            JobFailureCategory.NON_RETRYABLE_POLICY,
            True,
        ),
        (
            ExecutionOutcome.INTERNAL_ERROR,
            JobFailureCategory.RETRYABLE_INFRASTRUCTURE,
            False,
        ),
    ),
)
def test_failed_outcome_category_and_retryability_must_agree(
    tmp_path: Path,
    outcome: ExecutionOutcome,
    category: JobFailureCategory,
    retryable: bool,
) -> None:
    environment = _environment(tmp_path)
    _set_max_attempts(environment, 1)
    _run_terminal(environment, tmp_path / "attempt", _UnavailableDockerExecutor())
    with environment.session_factory.begin() as session:
        tool = session.query(ToolExecutionRow).one()
        tool.outcome = outcome.value
        tool.failure_category = category.value
        tool.retryable = retryable

    with pytest.raises(SourceExecutionAssessmentIntegrityError):
        _service(environment).assess_job(environment.job.id)


def test_report_order_does_not_change_assessment_identity(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    second = deepcopy(raw["results"][0])
    second["check_id"] = "python.second-rule"
    second["path"] = "/workspace/source/pkg/auth.py"
    raw["results"].append(second)
    _run_terminal(
        environment,
        tmp_path / "attempt",
        _DockerExecutor(json.dumps(raw).encode("utf-8")),
    )
    original = _service(environment).assess_job(environment.job.id)
    with environment.session_factory.begin() as session:
        run = session.get(AnalysisRunRow, environment.job.run_id)
        assert run is not None and run.report_json is not None
        report = deepcopy(run.report_json)
        report["observations"].reverse()
        report["executions"][0]["observations"].reverse()
        run.report_json = report

    reordered = _service(environment).assess_job(environment.job.id)
    assert reordered.canonical_json() == original.canonical_json()
    assert reordered.assessment_digest() == original.assessment_digest()


@pytest.mark.parametrize("mutation", ("missing", "corrupt"))
def test_context_artifact_missing_or_corrupt_fails_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    environment = _environment(tmp_path)
    _run_terminal(environment, tmp_path / "attempt", _DockerExecutor())
    envelope = environment.job.payload_json[SOURCE_EXECUTION_PAYLOAD_KEY]
    artifact = (
        environment.store.root
        / "sha256"
        / envelope["artifact_sha256"][:2]
        / envelope["artifact_sha256"]
    )
    if mutation == "missing":
        artifact.unlink()
    else:
        artifact.write_bytes(b"corrupt")
    with pytest.raises(SourceExecutionAssessmentIntegrityError):
        _service(environment).assess_job(environment.job.id)


def test_assessment_api_accepts_only_durable_job_identity(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    _run_terminal(environment, tmp_path / "attempt", _DockerExecutor())
    service = _service(environment)

    with pytest.raises(TypeError):
        service.assess_job(  # type: ignore[call-arg]
            environment.job.id,
            report={"forged": True},
            status=JobStatus.SUCCEEDED,
        )
    assert service.assess_job(environment.job.id).terminal_job_status is JobStatus.SUCCEEDED


def test_persistence_failures_are_distinct_and_sanitized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment(tmp_path)
    repository = JobRepository(environment.session_factory)
    query = RunQueryService(environment.session_factory)
    service = SourceSemgrepExecutionAssessmentService(
        repository,
        SourceSemgrepExecutionContextIntegrityResolver(environment.store),
        query,
        environment.store,
    )

    def repository_unavailable(_job_id: str):
        raise JobRepositoryError("/host/private/database")

    monkeypatch.setattr(repository, "get_job", repository_unavailable)
    with pytest.raises(SourceExecutionAssessmentPersistenceError) as captured:
        service.assess_job(environment.job.id)
    assert str(captured.value) == "Durable Source execution evidence is unavailable"

    monkeypatch.undo()
    _run_terminal(environment, tmp_path / "attempt", _DockerExecutor())
    service = _service(environment)

    def query_unavailable(_run_id: str):
        from securescan.runs import RunQueryPersistenceError

        raise RunQueryPersistenceError

    monkeypatch.setattr(service._run_query_service, "get_run", query_unavailable)
    with pytest.raises(SourceExecutionAssessmentPersistenceError) as captured:
        service.assess_job(environment.job.id)
    assert str(captured.value) == "Durable Source execution evidence is unavailable"


def test_fixed_assessment_contract_is_frozen_canonical_and_duplicate_safe() -> None:
    assessment = _fixed_assessment()
    reordered = dict(reversed(tuple(assessment.canonical_data().items())))

    assert assessment.canonical_json() == json.dumps(
        reordered,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    with pytest.raises(FrozenInstanceError):
        assessment.attempt_count = 2  # type: ignore[misc]
    with pytest.raises(ValueError):
        replace(
            assessment,
            observations=(assessment.observations[0], assessment.observations[0]),
        )


@pytest.mark.parametrize(
    "changes",
    (
        {"coverage_status": CoverageStatus.UNKNOWN},
        {"terminal_job_status": JobStatus.PARTIAL},
        {"assessment_status": AssessmentStatus.VALIDATED},
        {"gaps": ()},
        {"final_tool_execution_id": None},
        {"tool_version": None},
    ),
)
def test_assessment_contract_rejects_invalid_complete_combinations(
    changes: dict[str, object],
) -> None:
    assessment = _fixed_assessment()
    if changes == {"gaps": ()}:
        changes = {
            "execution_status": SourceExecutionStatus.PARTIAL,
            "coverage_status": CoverageStatus.PARTIAL,
            "terminal_job_status": JobStatus.PARTIAL,
        }
    with pytest.raises(ValueError):
        replace(assessment, **changes)


def test_fixed_assessment_has_literal_golden_digest() -> None:
    assert (
        _fixed_assessment().assessment_digest()
        == "49d45ad4c1b78ffcbcdfc596558488ac981f504a0eb960b9a7c5024a5432e7c2"
    )
