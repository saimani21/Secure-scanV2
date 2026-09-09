from __future__ import annotations

import json
import time
from contextlib import suppress
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Event, Thread
from uuid import UUID

import pytest
from sqlalchemy import func, select
from test_source_dependency_evaluation_s6ca import (
    _finish_existing_syft,
    _nodes,
    _observation,
)
from test_source_orchestration_s6a import _RUN_ID
from test_source_orchestration_s6b import _Environment

from securescan.advisories.osv import OsvCandidateMatch, OsvDependencyAnalysis
from securescan.orchestration.dependency_evaluation import SourceDependencyEvaluationService
from securescan.orchestration.execution import SourceScannerAttemptService
from securescan.orchestration.execution_models import (
    AttemptContainmentOutcome,
    SourceAttemptCleanupReceipt,
)
from securescan.orchestration.models import SourceAuthority
from securescan.orchestration.osv_execution import (
    OsvRequestOperation,
    SafeSourceOsvResult,
    SourceOsvAttemptService,
    SourceOsvExecutionConflictError,
    SourceOsvFailureCode,
    SourceOsvJobService,
    SourceOsvRequestPermitService,
)
from securescan.orchestration.osv_runtime import SourceOsvHelperExecutionService
from securescan.orchestration.service import orchestration_request_digest
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    SourceOrchestrationAttemptRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationRow,
    SourceOrchestrationScannerJobRow,
    SourceOsvRequestPermitRow,
    ToolExecutionRow,
)

_LEASE = "33333333-3333-4333-8333-333333333333"
_DEADLINE = datetime(2099, 1, 1, tzinfo=UTC)


@pytest.fixture
def environment(tmp_path: Path):
    value = _Environment(tmp_path)
    with value.factory.begin() as session:
        parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        assert parent is not None and run is not None
        parent.deadline_at = _DEADLINE
        parent.creation_request_digest = orchestration_request_digest(
            target_id=run.target_id,
            idempotency_key=parent.idempotency_key,
            deadline_iso=_DEADLINE.isoformat(),
            profile_digest=parent.profile_digest,
            plan_digest=parent.plan_digest,
            roster_digest=parent.roster_digest,
        )
    try:
        yield value
    finally:
        value.close()


def _runnable(environment: _Environment, *, partial: bool = False):
    syft, osv = _nodes(environment)
    _node, syft_job, _attempt = environment.start_attempt(SourceAuthority.SYFT)
    observation = _observation(syft_job, syft, ("requirements.lock",))
    _finish_existing_syft(environment, syft, syft_job, (observation,), partial=partial)
    evaluations = SourceDependencyEvaluationService(environment.factory, environment.store)
    evaluation = evaluations.evaluate(run_id=str(_RUN_ID), osv_node_id=osv.node_id)
    jobs = SourceOsvJobService(environment.factory, environment.store, evaluations)
    created = jobs.create_job(run_id=str(_RUN_ID), node_id=osv.node_id)
    return osv, evaluation, jobs, created


def _start_osv_attempt(environment: _Environment, created):
    with environment.factory.begin() as session:
        job = session.get(JobRow, created.job_id)
        assert job is not None
        job.status = "running"
        job.attempt_count = 1
        job.leased_by = "worker-osv"
        job.lease_token = _LEASE
        job.lease_expires_at = _DEADLINE
    service = _osv_attempts(environment)
    attempt = service.register_attempt(
        job_id=created.job_id,
        worker_id="worker-osv",
        lease_token=_LEASE,
    )
    service.register_supervisor(
        job_id=created.job_id,
        attempt_number=1,
        attempt_token=attempt.attempt_token,
        supervisor_identity="b" * 64,
        supervisor_pid=999_981,
        supervisor_start_ticks=201,
        scanner_pid=999_982,
        scanner_pgid=999_982,
        scanner_start_ticks=202,
    )
    return attempt


def _lease_osv_attempt(environment: _Environment, created):
    with environment.factory.begin() as session:
        job = session.get(JobRow, created.job_id)
        assert job is not None
        job.status = "running"
        job.attempt_count = 1
        job.leased_by = "worker-osv"
        job.lease_token = _LEASE
        job.lease_expires_at = _DEADLINE
    return _osv_attempts(environment).register_attempt(
        job_id=created.job_id,
        worker_id="worker-osv",
        lease_token=_LEASE,
    )


def _clean(environment: _Environment, attempt) -> None:
    _osv_attempts(environment).record_cleanup(
        SourceAttemptCleanupReceipt(
            job_id=attempt.job_id,
            attempt_number=attempt.attempt_number,
            attempt_token=attempt.attempt_token,
            supervisor_identity="b" * 64,
            supervisor_pid=999_981,
            supervisor_start_ticks=201,
            scanner_pid=999_982,
            scanner_pgid=999_982,
            scanner_start_ticks=202,
            cleanup_outcome=AttemptContainmentOutcome.CLEAN,
            process_tree_empty=True,
        )
    )


def _osv_attempts(environment: _Environment) -> SourceScannerAttemptService:
    return SourceScannerAttemptService(
        environment.factory,
        environment.store,
        environment.projections,
        token_factory=lambda: UUID("55555555-5555-4555-8555-555555555555"),
    )


def _zero_analysis(execution_input):
    matches = tuple(OsvCandidateMatch(item, (), ()) for item in execution_input.candidates)
    ids = tuple(item.candidate_id for item in execution_input.candidates)
    return OsvDependencyAnalysis(
        candidates=execution_input.candidates,
        gaps=(),
        candidate_matches=matches,
        findings=(),
        completed_candidate_ids=ids,
        zero_advisory_candidate_ids=ids,
    )


def test_osv_job_is_deterministic_and_has_no_projection(environment: _Environment) -> None:
    osv, evaluation, jobs, first = _runnable(environment)
    second = jobs.create_job(run_id=str(_RUN_ID), node_id=osv.node_id)
    execution_input = jobs.load_input(job_id=first.job_id)

    assert first.created is True
    assert second.created is False
    assert second.job_id == first.job_id
    assert execution_input.dependency_evaluation_sha256 == evaluation.artifact_sha256
    assert tuple(
        observation_id
        for item in execution_input.candidates
        for observation_id in item.package_observation_ids
    ) == tuple(sorted(evaluation.evaluation.eligible_package_observation_ids))
    with environment.factory() as session:
        mapping = session.get(SourceOrchestrationScannerJobRow, first.job_id)
        assert mapping is not None
        assert mapping.input_kind == "OSV_DEPENDENCY_INPUT"
        assert mapping.context_digest is None
        assert mapping.projection_id is None
        assert mapping.projection_digest is None


def test_one_permit_authorizes_one_transport_operation(environment: _Environment) -> None:
    _osv, _evaluation, _jobs, created = _runnable(environment)
    attempt = _start_osv_attempt(environment, created)
    permits = SourceOsvRequestPermitService(environment.factory)
    first = permits.authorize(
        job_id=created.job_id,
        attempt_number=1,
        attempt_token=attempt.attempt_token,
        helper_identity="b" * 64,
        request_sequence=1,
        operation_kind=OsvRequestOperation.QUERY_BATCH,
        logical_request_digest="c" * 64,
        transport_attempt_number=1,
    )
    second = permits.authorize(
        job_id=created.job_id,
        attempt_number=1,
        attempt_token=attempt.attempt_token,
        helper_identity="b" * 64,
        request_sequence=2,
        operation_kind=OsvRequestOperation.QUERY_BATCH,
        logical_request_digest="c" * 64,
        transport_attempt_number=2,
    )
    assert (first.request_sequence, second.request_sequence) == (1, 2)
    with environment.factory() as session:
        assert session.scalar(select(func.count()).select_from(SourceOsvRequestPermitRow)) == 2


@pytest.mark.parametrize("boundary", ["cancel", "deadline", "wrong_sequence"])
def test_permit_fails_closed_at_lifecycle_boundary(
    environment: _Environment, boundary: str
) -> None:
    _osv, _evaluation, _jobs, created = _runnable(environment)
    attempt = _start_osv_attempt(environment, created)
    with environment.factory.begin() as session:
        parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        assert parent is not None
        if boundary == "cancel":
            parent.cancel_requested = True
            parent.cancel_requested_at = datetime.now(UTC)
            parent.lifecycle_state = "CANCELLATION_REQUESTED"
        elif boundary == "deadline":
            parent.deadline_at = datetime(2000, 1, 1, tzinfo=UTC)
    with pytest.raises(SourceOsvExecutionConflictError):
        SourceOsvRequestPermitService(environment.factory).authorize(
            job_id=created.job_id,
            attempt_number=1,
            attempt_token=attempt.attempt_token,
            helper_identity="b" * 64,
            request_sequence=2 if boundary == "wrong_sequence" else 1,
            operation_kind=OsvRequestOperation.QUERY_BATCH,
            logical_request_digest="c" * 64,
            transport_attempt_number=1,
        )


def test_zero_advisories_is_complete_not_not_applicable(environment: _Environment) -> None:
    osv, _evaluation, jobs, created = _runnable(environment)
    attempt = _start_osv_attempt(environment, created)
    _clean(environment, attempt)
    execution_input = jobs.load_input(job_id=created.job_id)
    result = SafeSourceOsvResult.from_analysis(
        execution_input,
        attempt_number=1,
        analysis=_zero_analysis(execution_input),
    )
    parsed = SafeSourceOsvResult.from_json(result.canonical_json())
    accepted = SourceOsvAttemptService(
        environment.factory, environment.store, jobs
    ).accept_result(parsed, lease_token=_LEASE, duration_ms=3)
    assert accepted is True
    with environment.factory() as session:
        node = session.get(SourceOrchestrationNodeRow, osv.node_id)
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        mapping = session.get(SourceOrchestrationScannerJobRow, created.job_id)
        attempt_row = session.get(SourceOrchestrationAttemptRow, (created.job_id, 1))
        assert node is not None and node.terminal_disposition == "COMPLETE"
        assert run is not None and run.report_json is None
        assert mapping is not None and mapping.selected_attempt_number == 1
        assert attempt_row is not None and attempt_row.dependency_input_revalidated is True
        assert attempt_row.projection_revalidated is None
        assert (
            session.scalar(
                select(func.count())
                .select_from(ToolExecutionRow)
                .where(ToolExecutionRow.adapter_id == "osv.dev")
            )
            == 1
        )


def test_partial_prerequisite_remains_partial_after_osv_success(
    environment: _Environment,
) -> None:
    osv, _evaluation, jobs, created = _runnable(environment, partial=True)
    attempt = _start_osv_attempt(environment, created)
    _clean(environment, attempt)
    execution_input = jobs.load_input(job_id=created.job_id)
    result = SafeSourceOsvResult.from_analysis(
        execution_input,
        attempt_number=1,
        analysis=_zero_analysis(execution_input),
    )
    SourceOsvAttemptService(environment.factory, environment.store, jobs).accept_result(
        result, lease_token=_LEASE, duration_ms=3
    )
    with environment.factory() as session:
        node = session.get(SourceOrchestrationNodeRow, osv.node_id)
        assert node is not None
        assert (node.terminal_disposition, node.terminal_reason_code) == (
            "PARTIAL",
            "DEPENDENCY_COVERAGE_LIMITED",
        )


def test_conflicting_second_result_is_rejected(environment: _Environment) -> None:
    _osv, _evaluation, jobs, created = _runnable(environment)
    attempt = _start_osv_attempt(environment, created)
    _clean(environment, attempt)
    execution_input = jobs.load_input(job_id=created.job_id)
    result = SafeSourceOsvResult.from_analysis(
        execution_input,
        attempt_number=1,
        analysis=_zero_analysis(execution_input),
    )
    service = SourceOsvAttemptService(environment.factory, environment.store, jobs)
    assert service.accept_result(result, lease_token=_LEASE, duration_ms=1) is True
    assert service.accept_result(result, lease_token=_LEASE, duration_ms=1) is False
    tampered = SafeSourceOsvResult.from_json(result.canonical_json())
    with environment.factory.begin() as session:
        row = session.get(SourceOrchestrationAttemptRow, (created.job_id, 1))
        assert row is not None
        row.native_result_sha256 = "f" * 64
    with pytest.raises(SourceOsvExecutionConflictError):
        service.accept_result(tampered, lease_token=_LEASE, duration_ms=1)


def test_contained_helper_uses_local_http_and_one_durable_permit(
    environment: _Environment, tmp_path: Path
) -> None:
    class Handler(BaseHTTPRequestHandler):
        requests = 0

        def do_POST(self) -> None:  # noqa: N802
            assert self.path == "/v1/querybatch"
            length = int(self.headers["Content-Length"])
            self.rfile.read(length)
            type(self).requests += 1
            time.sleep(0.05)
            payload = b'{"results":[{}]}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server_thread = Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        _osv, _evaluation, jobs, created = _runnable(environment)
        attempt = _lease_osv_attempt(environment, created)
        attempts = _osv_attempts(environment)
        outcome = SourceOsvHelperExecutionService(
            environment.factory,
            jobs,
            attempts,
            SourceOsvAttemptService(environment.factory, environment.store, jobs),
            SourceOsvRequestPermitService(environment.factory),
            tmp_path / "receipts",
            loopback_test_base_url=f"http://127.0.0.1:{server.server_port}",
            heartbeat_interval_seconds=0.01,
        ).execute(
            job=_load_job(environment, created.job_id),
            attempt=attempt,
            lease_token=_LEASE,
        )
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)
    assert outcome.accepted is True
    assert outcome.failure_code is None
    assert Handler.requests == 1
    with environment.factory() as session:
        assert session.scalar(select(func.count()).select_from(SourceOsvRequestPermitRow)) == 1
        job = session.get(JobRow, created.job_id)
        assert job is not None and job.heartbeat_at is not None


@pytest.mark.parametrize(
    ("status", "failure_code"),
    [
        pytest.param(429, SourceOsvFailureCode.HTTP_RATE_LIMIT, id="rate-limit"),
        pytest.param(
            503,
            SourceOsvFailureCode.HTTP_RETRYABLE_SERVER_ERROR,
            id="retryable-server-error",
        ),
    ],
)
def test_transient_http_retries_each_require_a_permit_and_remain_job_retryable(
    environment: _Environment,
    tmp_path: Path,
    status: int,
    failure_code: SourceOsvFailureCode,
) -> None:
    class Handler(BaseHTTPRequestHandler):
        requests = 0

        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            type(self).requests += 1
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server_thread = Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        _osv, _evaluation, jobs, created = _runnable(environment)
        attempt = _lease_osv_attempt(environment, created)
        outcome = SourceOsvHelperExecutionService(
            environment.factory,
            jobs,
            _osv_attempts(environment),
            SourceOsvAttemptService(environment.factory, environment.store, jobs),
            SourceOsvRequestPermitService(environment.factory),
            tmp_path / "receipts-rate-limit",
            loopback_test_base_url=f"http://127.0.0.1:{server.server_port}",
        ).execute(
            job=_load_job(environment, created.job_id),
            attempt=attempt,
            lease_token=_LEASE,
        )
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)

    assert outcome.accepted is False
    assert outcome.failure_code is failure_code
    assert Handler.requests == 3
    with environment.factory() as session:
        assert (
            session.scalar(select(func.count()).select_from(SourceOsvRequestPermitRow))
            == 3
        )
        job = session.get(JobRow, created.job_id)
        assert job is not None
        assert job.status == "retry_pending"
        assert job.last_error == failure_code.value


def test_each_pagination_request_requires_its_own_durable_permit(
    environment: _Environment, tmp_path: Path
) -> None:
    class Handler(BaseHTTPRequestHandler):
        bodies: list[dict[str, object]] = []

        def do_POST(self) -> None:  # noqa: N802
            payload = self.rfile.read(int(self.headers["Content-Length"]))
            body = json.loads(payload)
            type(self).bodies.append(body)
            document = (
                {"results": [{"next_page_token": "page-2"}]}
                if len(type(self).bodies) == 1
                else {"results": [{}]}
            )
            response = json.dumps(document, separators=(",", ":")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server_thread = Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        _osv, _evaluation, jobs, created = _runnable(environment)
        attempt = _lease_osv_attempt(environment, created)
        outcome = SourceOsvHelperExecutionService(
            environment.factory,
            jobs,
            _osv_attempts(environment),
            SourceOsvAttemptService(environment.factory, environment.store, jobs),
            SourceOsvRequestPermitService(environment.factory),
            tmp_path / "receipts-pagination",
            loopback_test_base_url=f"http://127.0.0.1:{server.server_port}",
        ).execute(
            job=_load_job(environment, created.job_id),
            attempt=attempt,
            lease_token=_LEASE,
        )
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)

    assert outcome.accepted is True
    assert len(Handler.bodies) == 2
    assert "page_token" not in Handler.bodies[0]["queries"][0]
    assert Handler.bodies[1]["queries"][0]["page_token"] == "page-2"
    with environment.factory() as session:
        permits = tuple(
            session.scalars(
                select(SourceOsvRequestPermitRow).order_by(
                    SourceOsvRequestPermitRow.request_sequence
                )
            )
        )
        assert tuple(item.request_sequence for item in permits) == (1, 2)
        assert all(item.operation_kind == "QUERY_BATCH" for item in permits)


def test_contained_helper_accepts_vulnerability_with_query_and_advisory_permits(
    environment: _Environment, tmp_path: Path
) -> None:
    modified = "2026-08-06T00:00:00Z"

    class Handler(BaseHTTPRequestHandler):
        paths: list[str] = []

        def _send(self, document: object) -> None:
            payload = json.dumps(document, separators=(",", ":")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            type(self).paths.append(self.path)
            self._send(
                {
                    "results": [
                        {"vulns": [{"id": "PYSEC-2026-1", "modified": modified}]}
                    ]
                }
            )

        def do_GET(self) -> None:  # noqa: N802
            type(self).paths.append(self.path)
            self._send(
                {
                    "schema_version": "1.9.0",
                    "id": "PYSEC-2026-1",
                    "modified": modified,
                    "aliases": ["CVE-2026-10001"],
                    "summary": "controlled advisory",
                    "affected": [
                        {
                            "package": {
                                "ecosystem": "PyPI",
                                "name": "requests",
                                "purl": "pkg:pypi/requests",
                            },
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "2.32.0"},
                                    ],
                                }
                            ],
                        }
                    ],
                }
            )

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server_thread = Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        _osv, _evaluation, jobs, created = _runnable(environment)
        attempt = _lease_osv_attempt(environment, created)
        result_service = SourceOsvAttemptService(
            environment.factory, environment.store, jobs
        )
        outcome = SourceOsvHelperExecutionService(
            environment.factory,
            jobs,
            _osv_attempts(environment),
            result_service,
            SourceOsvRequestPermitService(environment.factory),
            tmp_path / "receipts-vulnerability",
            loopback_test_base_url=f"http://127.0.0.1:{server.server_port}",
        ).execute(
            job=_load_job(environment, created.job_id),
            attempt=attempt,
            lease_token=_LEASE,
        )
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)

    assert outcome.accepted is True
    assert Handler.paths == ["/v1/querybatch", "/v1/vulns/PYSEC-2026-1"]
    accepted = result_service.load_accepted_result(
        run_id=str(_RUN_ID), node_id=_osv.node_id
    )
    assert len(accepted.analysis.findings) == 1
    assert accepted.analysis.findings[0].canonical_advisory_id == "CVE-2026-10001"
    assert accepted.analysis.findings[0].osv_record_ids == ("PYSEC-2026-1",)
    with environment.factory() as session:
        assert (
            session.scalar(select(func.count()).select_from(SourceOsvRequestPermitRow))
            == 2
        )


def test_active_osv_request_is_cancelled_within_controlled_stop_sla(
    environment: _Environment, tmp_path: Path
) -> None:
    request_started = Event()
    release = Event()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            request_started.set()
            release.wait(5)
            with suppress(BrokenPipeError, ConnectionResetError):
                self.send_response(200)
                self.send_header("Content-Length", "14")
                self.end_headers()
                self.wfile.write(b'{"results":[{}]}')

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server_thread = Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    _osv, _evaluation, jobs, created = _runnable(environment)
    attempt = _lease_osv_attempt(environment, created)

    def cancel() -> None:
        assert request_started.wait(3)
        with environment.factory.begin() as session:
            parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
            assert parent is not None
            parent.cancel_requested = True
            parent.cancel_requested_at = datetime.now(UTC)
            parent.lifecycle_state = "CANCELLATION_REQUESTED"

    canceller = Thread(target=cancel)
    canceller.start()
    started = time.monotonic()
    try:
        outcome = SourceOsvHelperExecutionService(
            environment.factory,
            jobs,
            _osv_attempts(environment),
            SourceOsvAttemptService(environment.factory, environment.store, jobs),
            SourceOsvRequestPermitService(environment.factory),
            tmp_path / "receipts-cancel",
            loopback_test_base_url=f"http://127.0.0.1:{server.server_port}",
        ).execute(
            job=_load_job(environment, created.job_id),
            attempt=attempt,
            lease_token=_LEASE,
        )
    finally:
        release.set()
        canceller.join(timeout=3)
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)
    elapsed = time.monotonic() - started

    assert outcome.accepted is False
    assert outcome.failure_code is SourceOsvFailureCode.CANCELLED
    assert elapsed < 3.0
    with environment.factory() as session:
        assert (
            session.scalar(select(func.count()).select_from(SourceOsvRequestPermitRow))
            == 1
        )
        assert session.get(AnalysisRunRow, str(_RUN_ID)).report_json is None


def _load_job(environment: _Environment, job_id: str):
    with environment.factory() as session:
        job = session.get(JobRow, job_id)
        assert job is not None
        session.expunge(job)
        return job
