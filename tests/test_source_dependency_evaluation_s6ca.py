from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from sqlalchemy import func, select
from test_source_orchestration_s6a import _NOW, _RUN_ID
from test_source_orchestration_s6b import _Environment

from securescan.domain.enums import ExecutionOutcome
from securescan.orchestration.dependency_evaluation import (
    DependencyEvaluationDecision,
    PackageScopeClassification,
    SourceDependencyEvaluationError,
    SourceDependencyEvaluationService,
)
from securescan.orchestration.execution_models import SafeSourceNativeResult
from securescan.orchestration.models import SourceAuthority
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    SourceOrchestrationAttemptRow,
    SourceOrchestrationDependencyEvaluationRow,
    SourceOrchestrationDependencyRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationScannerJobRow,
    ToolExecutionRow,
)
from securescan.scanners.syft import (
    SYFT_JSON_SCHEMA_VERSION,
    SYFT_PARSER_SCHEMA_VERSION,
    SYFT_SCANNER_ID,
    SYFT_VERSION,
    PackageObservation,
    SyftParseResult,
)
from securescan.source.execution_context import SourceExecutionContext

_LEASE_TOKEN = "33333333-3333-4333-8333-333333333333"


@pytest.fixture
def s6ca(tmp_path: Path):
    environment = _Environment(tmp_path)
    try:
        yield environment
    finally:
        environment.close()


def _nodes(environment: _Environment):
    syft = next(
        item for item in environment.snapshot.nodes if item.authority is SourceAuthority.SYFT
    )
    osv = next(item for item in environment.snapshot.nodes if item.authority is SourceAuthority.OSV)
    return syft, osv


def _observation(job, node, locations: tuple[str, ...], *, supported: bool = True):
    return PackageObservation.create(
        package_name="requests" if supported else "openssl",
        package_version="2.31.0" if supported else "3.0.0",
        package_type="python" if supported else "binary",
        language="python" if supported else None,
        purl="pkg:pypi/requests@2.31.0" if supported else "pkg:generic/openssl@3.0.0",
        found_by="python-package-cataloger",
        locations=locations,
        projection_id=job.projection_id,
        snapshot_digest=job.projection_digest,
        binding_digest=node.contract_digest,
    )


def _accept_syft(
    environment: _Environment,
    observations: tuple[PackageObservation, ...],
    *,
    partial: bool = False,
):
    node, job, _attempt = environment.start_attempt(SourceAuthority.SYFT)
    with environment.factory() as session:
        mapping = session.get(SourceOrchestrationScannerJobRow, job.job_id)
        assert mapping is not None
        context = SourceExecutionContext.from_json(
            environment.store.read_by_sha256(
                mapping.context_artifact_sha256,
                expected_size_bytes=mapping.context_artifact_size_bytes,
            )
        )
    result = SyftParseResult(
        scanner_id=SYFT_SCANNER_ID,
        scanner_version=SYFT_VERSION,
        binding_digest=node.contract_digest,
        projection_id=job.projection_id,
        snapshot_digest=job.projection_digest,
        syft_schema_version=SYFT_JSON_SCHEMA_VERSION,
        requested_cataloger_strategy=("directory", "file"),
        used_catalogers=("python-package-cataloger",) if observations else (),
        observations=tuple(sorted(observations, key=lambda item: item.package_observation_id)),
        package_count=len(observations),
        schema_version=SYFT_PARSER_SCHEMA_VERSION,
    )
    native = SafeSourceNativeResult.from_parse_result(
        result=result,
        node_id=node.node_id,
        job_id=job.job_id,
        attempt_number=1,
        authority=SourceAuthority.SYFT.value,
        analyzer_id=node.analyzer_id,
        context=context,
    )
    accepted = environment.attempts.accept_result(
        native,
        lease_token=_LEASE_TOKEN,
        execution_outcome=(
            ExecutionOutcome.PARTIAL_ANALYSIS
            if partial
            else ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS
            if observations
            else ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS
        ),
        return_code=0,
        duration_ms=1,
    )
    return node, job, native, accepted


def _evaluate(environment: _Environment):
    _syft, osv = _nodes(environment)
    service = SourceDependencyEvaluationService(
        environment.factory, environment.store, clock=lambda: _NOW
    )
    return service, osv, service.evaluate(run_id=str(_RUN_ID), osv_node_id=osv.node_id)


def test_clean_process_osv_and_application_imports() -> None:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import securescan.advisories.osv; import securescan.api",
        ],
        check=False,
        capture_output=True,
        env=environment,
        timeout=15,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")


def test_zero_packages_is_not_applicable_without_osv_job_or_tool_execution(
    s6ca: _Environment,
) -> None:
    _accept_syft(s6ca, ())
    _service, osv, record = _evaluate(s6ca)

    assert record.evaluation.decision is DependencyEvaluationDecision.NOT_APPLICABLE_NO_PACKAGES
    assert record.evaluation.coverage_limited is False
    with s6ca.factory() as session:
        node = session.get(SourceOrchestrationNodeRow, osv.node_id)
        assert node is not None
        assert (node.lifecycle_state, node.terminal_disposition, node.terminal_reason_code) == (
            "TERMINAL",
            "NOT_APPLICABLE",
            "NO_PACKAGES_OBSERVED",
        )
        assert session.scalar(select(func.count()).select_from(JobRow)) == 1
        assert session.scalar(select(func.count()).select_from(ToolExecutionRow)) == 1
        assert (
            session.scalar(
                select(func.count())
                .select_from(JobRow)
                .where(JobRow.adapter_id == SourceAuthority.OSV.value)
            )
            == 0
        )
        assert (
            session.scalar(
                select(func.count())
                .select_from(ToolExecutionRow)
                .where(ToolExecutionRow.adapter_id == SourceAuthority.OSV.value)
            )
            == 0
        )


def test_outside_scope_only_is_not_applicable(s6ca: _Environment) -> None:
    syft, _osv = _nodes(s6ca)
    _node, job, _attempt = s6ca.start_attempt(SourceAuthority.SYFT)
    observation = _observation(job, syft, ("app.py",))
    # Reuse the already-created attempt by completing it with the requested observation.
    with s6ca.factory() as session:
        mapping = session.get(SourceOrchestrationScannerJobRow, job.job_id)
        assert mapping is not None
        context = SourceExecutionContext.from_json(
            s6ca.store.read_by_sha256(
                mapping.context_artifact_sha256,
                expected_size_bytes=mapping.context_artifact_size_bytes,
            )
        )
    parse = SyftParseResult(
        scanner_id=SYFT_SCANNER_ID,
        scanner_version=SYFT_VERSION,
        binding_digest=syft.contract_digest,
        projection_id=job.projection_id,
        snapshot_digest=job.projection_digest,
        syft_schema_version=SYFT_JSON_SCHEMA_VERSION,
        requested_cataloger_strategy=("directory", "file"),
        used_catalogers=("python-package-cataloger",),
        observations=(observation,),
        package_count=1,
    )
    native = SafeSourceNativeResult.from_parse_result(
        result=parse,
        node_id=syft.node_id,
        job_id=job.job_id,
        attempt_number=1,
        authority="syft",
        analyzer_id=syft.analyzer_id,
        context=context,
    )
    s6ca.attempts.accept_result(
        native,
        lease_token=_LEASE_TOKEN,
        execution_outcome=ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS,
        return_code=0,
        duration_ms=1,
    )
    _service, osv, record = _evaluate(s6ca)
    evidence = record.evaluation.observations[0]
    assert evidence.classification is PackageScopeClassification.OUTSIDE_SCOPE
    assert record.evaluation.decision is (
        DependencyEvaluationDecision.NOT_APPLICABLE_NO_PACKAGES_IN_SCOPE
    )
    with s6ca.factory() as session:
        node = session.get(SourceOrchestrationNodeRow, osv.node_id)
        assert node is not None and node.terminal_reason_code == "NO_PACKAGES_IN_ADVISORY_SCOPE"


def test_unsupported_only_is_partial_and_preserves_frozen_s2_gap(s6ca: _Environment) -> None:
    syft, _osv = _nodes(s6ca)
    _node, job, _attempt = s6ca.start_attempt(SourceAuthority.SYFT)
    observation = _observation(job, syft, ("requirements.lock",), supported=False)
    _finish_existing_syft(s6ca, syft, job, (observation,))
    _service, osv, record = _evaluate(s6ca)

    assert record.evaluation.decision is (
        DependencyEvaluationDecision.PARTIAL_NO_SUPPORTED_COORDINATES
    )
    assert [item.reason_code for item in record.evaluation.coordinate_gaps] == [
        "OSV_UNSUPPORTED_PURL_TYPE"
    ]
    with s6ca.factory() as session:
        node = session.get(SourceOrchestrationNodeRow, osv.node_id)
        assert node is not None
        assert (node.terminal_disposition, node.terminal_reason_code) == (
            "PARTIAL",
            "NO_SUPPORTED_OSV_COORDINATES",
        )


def test_supported_candidate_releases_ready_and_reuses_frozen_s2_identity(
    s6ca: _Environment,
) -> None:
    syft, _osv = _nodes(s6ca)
    _node, job, _attempt = s6ca.start_attempt(SourceAuthority.SYFT)
    observation = _observation(job, syft, ("requirements.lock",))
    _finish_existing_syft(s6ca, syft, job, (observation,))
    _service, osv, record = _evaluate(s6ca)

    from securescan.advisories.osv.models import build_osv_query_candidates

    candidates, gaps = build_osv_query_candidates((observation,))
    assert gaps == ()
    assert record.evaluation.candidate_ids == (candidates[0].candidate_id,)
    assert record.evaluation.decision is DependencyEvaluationDecision.OSV_RUN_REQUIRED
    assert record.evaluation.scope.selected_paths == osv.selected_paths
    assert record.evaluation.scope.scope_digest == osv.scope_digest
    with s6ca.factory() as session:
        node = session.get(SourceOrchestrationNodeRow, osv.node_id)
        assert node is not None
        assert (node.lifecycle_state, node.terminal_disposition, node.terminal_reason_code) == (
            "READY",
            None,
            None,
        )
        assert session.scalar(select(func.count()).select_from(JobRow)) == 1
        assert (
            session.scalar(
                select(func.count())
                .select_from(JobRow)
                .where(JobRow.adapter_id == SourceAuthority.OSV.value)
            )
            == 0
        )


def test_supported_plus_unsupported_is_runnable_but_coverage_limited(
    s6ca: _Environment,
) -> None:
    syft, _osv = _nodes(s6ca)
    _node, job, _attempt = s6ca.start_attempt(SourceAuthority.SYFT)
    observations = (
        _observation(job, syft, ("requirements.lock",)),
        _observation(job, syft, ("requirements.lock",), supported=False),
    )
    _finish_existing_syft(s6ca, syft, job, observations)
    _service, _osv, record = _evaluate(s6ca)
    assert record.evaluation.decision is DependencyEvaluationDecision.OSV_RUN_REQUIRED
    assert record.evaluation.coverage_limited is True
    assert len(record.evaluation.coordinate_gaps) == 1


def test_mixed_scope_is_excluded_without_mutating_observation_identity(
    s6ca: _Environment,
) -> None:
    syft, _osv = _nodes(s6ca)
    _node, job, _attempt = s6ca.start_attempt(SourceAuthority.SYFT)
    observation = _observation(job, syft, ("app.py", "requirements.lock"))
    before = json.dumps(
        observation.canonical_data(), separators=(",", ":"), sort_keys=True
    ).encode()
    identity = observation.package_observation_id
    _finish_existing_syft(s6ca, syft, job, (observation,))
    _service, osv, record = _evaluate(s6ca)

    assert (
        json.dumps(observation.canonical_data(), separators=(",", ":"), sort_keys=True).encode()
        == before
    )
    assert observation.package_observation_id == identity
    assert record.evaluation.observations[0].classification is (
        PackageScopeClassification.MIXED_SCOPE
    )
    assert record.evaluation.eligible_package_observation_ids == ()
    assert record.evaluation.candidate_ids == ()
    assert record.evaluation.mixed_scope_gaps[0].package_observation_ids == (
        observation.package_observation_id,
    )
    with s6ca.factory() as session:
        node = session.get(SourceOrchestrationNodeRow, osv.node_id)
        assert node is not None
        assert (node.terminal_disposition, node.terminal_reason_code) == (
            "PARTIAL",
            "MIXED_SCOPE_PACKAGE_OBSERVATION",
        )


def test_supported_plus_mixed_is_runnable_and_coverage_limited(s6ca: _Environment) -> None:
    syft, _osv = _nodes(s6ca)
    _node, job, _attempt = s6ca.start_attempt(SourceAuthority.SYFT)
    observations = (
        _observation(job, syft, ("requirements.lock",)),
        _observation(job, syft, ("app.py", "requirements.lock"), supported=False),
    )
    _finish_existing_syft(s6ca, syft, job, observations)
    _service, _osv, record = _evaluate(s6ca)
    assert record.evaluation.decision is DependencyEvaluationDecision.OSV_RUN_REQUIRED
    assert record.evaluation.coverage_limited is True
    assert len(record.evaluation.mixed_scope_gaps) == 1


def test_partial_syft_is_explicit_and_cannot_look_complete(s6ca: _Environment) -> None:
    syft, _osv = _nodes(s6ca)
    _node, job, _attempt = s6ca.start_attempt(SourceAuthority.SYFT)
    observation = _observation(job, syft, ("requirements.lock",))
    _finish_existing_syft(s6ca, syft, job, (observation,), partial=True)
    _service, _osv, record = _evaluate(s6ca)
    assert record.evaluation.syft_prerequisite.prerequisite_complete is False
    assert record.evaluation.coverage_limited is True
    assert record.evaluation.decision is DependencyEvaluationDecision.OSV_RUN_REQUIRED


def test_evaluation_is_idempotent_and_reloadable_by_fresh_service(s6ca: _Environment) -> None:
    _accept_syft(s6ca, ())
    service, osv, first = _evaluate(s6ca)
    second = service.evaluate(run_id=str(_RUN_ID), osv_node_id=osv.node_id)
    fresh_service = SourceDependencyEvaluationService(s6ca.factory, s6ca.store, clock=lambda: _NOW)
    reconstructed = fresh_service.evaluate(run_id=str(_RUN_ID), osv_node_id=osv.node_id)
    loaded = fresh_service.load(run_id=str(_RUN_ID), osv_node_id=osv.node_id)

    assert first.created is True
    assert second == replace(first, created=False)
    assert reconstructed == replace(first, created=False)
    assert loaded == replace(first, created=False)
    with s6ca.factory() as session:
        assert (
            session.scalar(
                select(func.count()).select_from(SourceOrchestrationDependencyEvaluationRow)
            )
            == 1
        )
        node = session.get(SourceOrchestrationNodeRow, osv.node_id)
        assert node is not None
        assert (node.lifecycle_state, node.terminal_disposition, node.terminal_reason_code) == (
            "TERMINAL",
            "NOT_APPLICABLE",
            "NO_PACKAGES_OBSERVED",
        )


@pytest.mark.parametrize(
    "tamper",
    [
        "edge",
        "scope_digest",
        "selected_paths",
        "containment",
        "selected_attempt",
        "storage_path",
        "tool_adapter",
    ],
)
def test_prerequisite_or_scope_tampering_fails_closed(s6ca: _Environment, tamper: str) -> None:
    _accept_syft(s6ca, ())
    syft, osv = _nodes(s6ca)
    with s6ca.factory.begin() as session:
        if tamper == "edge":
            edge = session.get(
                SourceOrchestrationDependencyRow, (str(_RUN_ID), osv.node_id, syft.node_id)
            )
            assert edge is not None
            session.delete(edge)
        elif tamper == "scope_digest":
            node = session.get(SourceOrchestrationNodeRow, osv.node_id)
            assert node is not None
            node.scope_digest = "f" * 64
        elif tamper == "selected_paths":
            node = session.get(SourceOrchestrationNodeRow, osv.node_id)
            assert node is not None
            node.selected_paths_json = ["app.py"]
        elif tamper == "containment":
            node = session.get(SourceOrchestrationNodeRow, syft.node_id)
            assert node is not None
            node.containment_state = "RECONCILIATION_REQUIRED"
        elif tamper == "selected_attempt":
            mapping = session.scalar(
                select(SourceOrchestrationScannerJobRow).where(
                    SourceOrchestrationScannerJobRow.node_id == syft.node_id
                )
            )
            assert mapping is not None
            mapping.selected_attempt_number = None
        else:
            mapping = session.scalar(
                select(SourceOrchestrationScannerJobRow).where(
                    SourceOrchestrationScannerJobRow.node_id == syft.node_id
                )
            )
            assert mapping is not None and mapping.selected_attempt_number is not None
            attempt = session.get(
                SourceOrchestrationAttemptRow,
                (mapping.job_id, mapping.selected_attempt_number),
            )
            assert attempt is not None and attempt.tool_execution_id is not None
            if tamper == "storage_path":
                attempt.native_result_storage_path = "/host/private/result.json"
            else:
                tool = session.get(ToolExecutionRow, attempt.tool_execution_id)
                assert tool is not None
                tool.adapter_id = "gitleaks"
    service = SourceDependencyEvaluationService(s6ca.factory, s6ca.store, clock=lambda: _NOW)
    with pytest.raises(SourceDependencyEvaluationError):
        service.evaluate(run_id=str(_RUN_ID), osv_node_id=osv.node_id)


def test_wrong_run_and_wrong_osv_node_fail_closed(s6ca: _Environment) -> None:
    _accept_syft(s6ca, ())
    service, osv, _record = _evaluate(s6ca)
    with pytest.raises(SourceDependencyEvaluationError):
        service.evaluate(run_id="99999999-9999-4999-8999-999999999999", osv_node_id=osv.node_id)
    with pytest.raises(SourceDependencyEvaluationError):
        service.evaluate(run_id=str(_RUN_ID), osv_node_id="f" * 64)


def test_unaccepted_result_fails_closed(s6ca: _Environment) -> None:
    syft, osv = _nodes(s6ca)
    _node, job, _attempt = s6ca.start_attempt(SourceAuthority.SYFT)
    service = SourceDependencyEvaluationService(s6ca.factory, s6ca.store, clock=lambda: _NOW)
    with pytest.raises(SourceDependencyEvaluationError):
        service.evaluate(run_id=str(_RUN_ID), osv_node_id=osv.node_id)

    assert syft.node_id == _node.node_id and job.job_id


def test_tampered_accepted_native_cas_fails_closed(tmp_path: Path) -> None:
    environment = _Environment(tmp_path)
    try:
        _syft, osv = _nodes(environment)
        _node, _job, _native, accepted = _accept_syft(environment, ())
        artifact = (
            environment.store.root
            / "sha256"
            / accepted.artifact_sha256[:2]
            / accepted.artifact_sha256
        )
        artifact.write_bytes(artifact.read_bytes() + b" ")
        service = SourceDependencyEvaluationService(
            environment.factory, environment.store, clock=lambda: _NOW
        )
        with pytest.raises(SourceDependencyEvaluationError):
            service.evaluate(run_id=str(_RUN_ID), osv_node_id=osv.node_id)
    finally:
        environment.close()


def test_conflicting_selected_result_after_evaluation_fails_closed(s6ca: _Environment) -> None:
    _accept_syft(s6ca, ())
    service, osv, _record = _evaluate(s6ca)
    syft, _osv = _nodes(s6ca)
    with s6ca.factory.begin() as session:
        mapping = session.scalar(
            select(SourceOrchestrationScannerJobRow).where(
                SourceOrchestrationScannerJobRow.node_id == syft.node_id
            )
        )
        assert mapping is not None
        mapping.selected_attempt_number = None
    with pytest.raises(SourceDependencyEvaluationError):
        service.evaluate(run_id=str(_RUN_ID), osv_node_id=osv.node_id)


def test_no_osv_http_capability_is_used(
    s6ca: _Environment, monkeypatch: pytest.MonkeyPatch
) -> None:
    from securescan.advisories.osv.client import TrustedOsvClient

    _accept_syft(s6ca, ())
    monkeypatch.setattr(
        TrustedOsvClient,
        "query",
        lambda *_args, **_kwargs: pytest.fail("OSV query must not be called in S6C-A"),
    )
    monkeypatch.setattr(
        socket,
        "socket",
        lambda *_args, **_kwargs: pytest.fail("network socket must not be created in S6C-A"),
    )
    _evaluate(s6ca)


def test_cancellation_prevents_release(s6ca: _Environment) -> None:
    _accept_syft(s6ca, ())
    _syft, osv = _nodes(s6ca)
    s6ca.orchestrations.request_cancellation(str(_RUN_ID), 2)
    service = SourceDependencyEvaluationService(s6ca.factory, s6ca.store, clock=lambda: _NOW)
    with pytest.raises(SourceDependencyEvaluationError):
        service.evaluate(run_id=str(_RUN_ID), osv_node_id=osv.node_id)


def test_expired_deadline_prevents_release(s6ca: _Environment) -> None:
    from test_source_orchestration_s6a import _DEADLINE

    _accept_syft(s6ca, ())
    _syft, osv = _nodes(s6ca)
    service = SourceDependencyEvaluationService(
        s6ca.factory,
        s6ca.store,
        clock=lambda: _DEADLINE.replace(year=_DEADLINE.year + 1),
    )
    with pytest.raises(SourceDependencyEvaluationError):
        service.evaluate(run_id=str(_RUN_ID), osv_node_id=osv.node_id)


def test_committed_evaluation_remains_idempotently_readable_after_cancellation(
    s6ca: _Environment,
) -> None:
    _accept_syft(s6ca, ())
    service, osv, first = _evaluate(s6ca)
    s6ca.orchestrations.request_cancellation(str(_RUN_ID), 2)

    second = service.evaluate(run_id=str(_RUN_ID), osv_node_id=osv.node_id)
    assert second == replace(first, created=False)


def test_dependency_artifact_is_canonical_confidential_and_does_not_publish(
    tmp_path: Path,
) -> None:
    secret = "S6CA_RAW_SECRET_SENTINEL"
    environment = _Environment(tmp_path, app_source=f"{secret} = 1\n".encode())
    try:
        workspace = str(environment.workspace.root_directory)
        _accept_syft(environment, ())
        _service, _osv, record = _evaluate(environment)
        payload = environment.store.read_by_sha256(
            record.artifact_sha256, expected_size_bytes=record.artifact_size_bytes
        )

        assert hashlib.sha256(payload).hexdigest() == record.artifact_sha256
        assert json.loads(payload) == record.evaluation.canonical_data()
        assert secret.encode() not in payload
        assert workspace.encode() not in payload
        with environment.factory() as session:
            run = session.get(AnalysisRunRow, str(_RUN_ID))
            durable = session.get(
                SourceOrchestrationDependencyEvaluationRow,
                (str(_RUN_ID), record.evaluation.osv_node_id),
            )
            assert run is not None and run.report_json is None
            assert durable is not None
            assert durable.evaluation_schema_version == (
                "securescan-source-dependency-evaluation-s6c-v1"
            )
            assert durable.evaluation_artifact_media_type == (
                "application/vnd.securescan.source-dependency-evaluation+json"
            )
            assert session.scalar(select(func.count()).select_from(JobRow)) == 1
            assert session.scalar(select(func.count()).select_from(ToolExecutionRow)) == 1
    finally:
        environment.close()


def _finish_existing_syft(
    environment: _Environment,
    node,
    job,
    observations: tuple[PackageObservation, ...],
    *,
    partial: bool = False,
) -> None:
    with environment.factory() as session:
        mapping = session.get(SourceOrchestrationScannerJobRow, job.job_id)
        assert mapping is not None
        context = SourceExecutionContext.from_json(
            environment.store.read_by_sha256(
                mapping.context_artifact_sha256,
                expected_size_bytes=mapping.context_artifact_size_bytes,
            )
        )
    result = SyftParseResult(
        scanner_id=SYFT_SCANNER_ID,
        scanner_version=SYFT_VERSION,
        binding_digest=node.contract_digest,
        projection_id=job.projection_id,
        snapshot_digest=job.projection_digest,
        syft_schema_version=SYFT_JSON_SCHEMA_VERSION,
        requested_cataloger_strategy=("directory", "file"),
        used_catalogers=("python-package-cataloger",),
        observations=tuple(sorted(observations, key=lambda item: item.package_observation_id)),
        package_count=len(observations),
    )
    native = SafeSourceNativeResult.from_parse_result(
        result=result,
        node_id=node.node_id,
        job_id=job.job_id,
        attempt_number=1,
        authority="syft",
        analyzer_id=node.analyzer_id,
        context=context,
    )
    environment.attempts.accept_result(
        native,
        lease_token=_LEASE_TOKEN,
        execution_outcome=(
            ExecutionOutcome.PARTIAL_ANALYSIS
            if partial
            else ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS
        ),
        return_code=0,
        duration_ms=1,
    )
