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
    _observation,
)
from test_source_orchestration_s6a import _PRIVATE_SOURCE, _RUN_ID
from test_source_orchestration_s6b import _LEASE_TOKEN, _Environment

from securescan.domain.enums import ExecutionOutcome, RunStatus
from securescan.orchestration.assembly import SourceResultAssemblyService
from securescan.orchestration.coordinator import SourceOrchestrationCoordinatorService
from securescan.orchestration.dependency_evaluation import (
    SourceDependencyEvaluationService,
)
from securescan.orchestration.execution import SourceScannerAttemptService
from securescan.orchestration.execution_models import (
    AttemptContainmentOutcome,
    SourceAttemptCleanupReceipt,
    SourceSandboxCleanupReceipt,
    source_sandbox_execution_identity,
)
from securescan.orchestration.models import (
    OrchestrationLifecycleState,
    SourceAuthority,
    frozen_source_v1_authority_roster,
    orchestration_request_digest,
)
from securescan.orchestration.osv_execution import (
    SourceOsvAttemptService,
    SourceOsvJobService,
    SourceOsvRequestPermitService,
)
from securescan.orchestration.osv_runtime import SourceOsvHelperExecutionService
from securescan.orchestration.worker import (
    SourceAuthorityDispatcher,
    SourceMappedJobLeasingService,
    SourceOrchestrationWorkerCycle,
    SourceWorkerDisposition,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    SourceOrchestrationRow,
    SourceOsvRequestPermitRow,
    ToolExecutionRow,
)


@pytest.fixture
def engine(tmp_path: Path):
    environment = _Environment(tmp_path)
    deadline = datetime(2099, 1, 1, tzinfo=UTC)
    with environment.factory.begin() as session:
        parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        assert parent is not None and run is not None
        parent.deadline_at = deadline
        parent.creation_request_digest = orchestration_request_digest(
            target_id=run.target_id,
            idempotency_key=parent.idempotency_key,
            deadline_iso=deadline.isoformat(),
            profile_digest=parent.profile_digest,
            plan_digest=parent.plan_digest,
            roster_digest=parent.roster_digest,
        )
    tokens = iter(
        UUID(f"88888888-8888-4888-8888-{value:012d}") for value in range(1, 20)
    )
    environment.attempts = SourceScannerAttemptService(
        environment.factory,
        environment.store,
        environment.projections,
        token_factory=lambda: next(tokens),
    )
    try:
        yield environment
    finally:
        environment.close()


def _record_local_cleanup(environment: _Environment, authority, attempt) -> None:
    if authority is SourceAuthority.SEMGREP:
        environment.attempts.record_sandbox_cleanup(
            SourceSandboxCleanupReceipt(
                job_id=attempt.job_id,
                attempt_number=attempt.attempt_number,
                attempt_token=attempt.attempt_token,
                execution_backend="docker-sandbox",
                execution_id=attempt.job_id,
                sandbox_identity=source_sandbox_execution_identity(
                    attempt.job_id, attempt.attempt_number, attempt.attempt_token
                ),
                cleanup_outcome=AttemptContainmentOutcome.CLEAN,
                execution_removed=True,
            )
        )
        return
    environment.attempts.register_supervisor(
        job_id=attempt.job_id,
        attempt_number=attempt.attempt_number,
        attempt_token=attempt.attempt_token,
        supervisor_identity="d" * 64,
        supervisor_pid=999_971,
        supervisor_start_ticks=301,
        scanner_pid=999_972,
        scanner_pgid=999_972,
        scanner_start_ticks=302,
    )
    environment.attempts.record_cleanup(
        SourceAttemptCleanupReceipt(
            job_id=attempt.job_id,
            attempt_number=attempt.attempt_number,
            attempt_token=attempt.attempt_token,
            supervisor_identity="d" * 64,
            supervisor_pid=999_971,
            supervisor_start_ticks=301,
            scanner_pid=999_972,
            scanner_pgid=999_972,
            scanner_start_ticks=302,
            cleanup_outcome=AttemptContainmentOutcome.CLEAN,
            process_tree_empty=True,
        )
    )


def _with_controlled_finding(result, authority: SourceAuthority):
    document = result.canonical_data()
    native = document["native_data"]
    if authority is SourceAuthority.GITLEAKS:
        native["findings"] = [
            {
                "context_digest": result.context_digest,
                "detection_kind": "CONTENT",
                "end_column": 12,
                "end_line": 1,
                "file_path": "app.py",
                "projection_digest": result.projection_digest,
                "projection_id": result.projection_id,
                "rule_id": "github-pat",
                "scanner_id": result.scanner_id,
                "scanner_version": result.scanner_version,
                "start_column": 1,
                "start_line": 1,
            }
        ]
        native["finding_count"] = 1
    elif authority is SourceAuthority.CHECKOV:
        identity = "a" * 64
        native["findings"] = [
            {
                "check_id": "CKV_AWS_18",
                "check_name": "Controlled failed check",
                "checkov_binding_digest": result.binding_digest,
                "finding_id": identity,
                "framework": "terraform",
                "line_end": 1,
                "line_start": 1,
                "normalized_path": "infra/main.tf",
                "projection_id": result.projection_id,
                "resource": "x.y",
                "scanner_id": result.scanner_id,
                "scanner_version": result.scanner_version,
                "severity": "HIGH",
                "snapshot_digest": result.projection_digest,
                "source": "checkov",
            }
        ]
        native["observation_count"] = 1
        terraform = next(
            item
            for item in native["framework_outcomes"]
            if item["framework"] == "terraform"
        )
        terraform["failed_count"] = 1
        terraform["state"] = "completed_with_findings"
    elif authority is SourceAuthority.SEMGREP:
        native["results"] = [
            {
                "end": {"column": 12, "line": 1},
                "fingerprint": "b" * 64,
                "metadata": {"cwe": ["CWE-95"]},
                "path": "app.py",
                "rule_id": "securescan.python.dangerous-eval",
                "severity": "high",
                "start": {"column": 1, "line": 1},
            }
        ]
        native["summary"]["accepted_findings"] = 1
    else:
        return result
    payload = (
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        + b"\n"
    )
    return type(result).from_json(payload)


@pytest.mark.parametrize(
    ("response_status", "expected_osv_coverage", "expected_run_status"),
    [
        pytest.param(
            200,
            "COMPLETE_WITH_FINDINGS",
            RunStatus.COMPLETED,
            id="vulnerability-success",
        ),
        pytest.param(400, "FAILED", RunStatus.PARTIAL, id="permanent-osv-failure"),
    ],
)
def test_controlled_engine_closure_runs_full_graph_failure_path_and_restarts(
    engine: _Environment,
    tmp_path: Path,
    response_status: int,
    expected_osv_coverage: str,
    expected_run_status: RunStatus,
) -> None:
    class Handler(BaseHTTPRequestHandler):
        requests = 0
        modified = "2026-08-06T00:00:00Z"

        def _send(self, status: int, document: object) -> None:
            payload = json.dumps(document, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            type(self).requests += 1
            document = (
                {
                    "results": [
                        {
                            "vulns": [
                                {
                                    "id": "PYSEC-2026-1",
                                    "modified": type(self).modified,
                                }
                            ]
                        }
                    ]
                }
                if response_status == 200
                else {"error": "controlled permanent failure"}
            )
            self._send(response_status, document)

        def do_GET(self) -> None:  # noqa: N802
            type(self).requests += 1
            self._send(
                200,
                {
                    "schema_version": "1.9.0",
                    "id": "PYSEC-2026-1",
                    "modified": type(self).modified,
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
                },
            )

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server_thread = Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    coordinator = SourceOrchestrationCoordinatorService(
        engine.factory,
        engine.store,
        frozen_source_v1_authority_roster(),
        engine.projections,
    )
    coordinator.advance(run_id=str(_RUN_ID), workspace=engine.workspace)

    def local_runner(authority: SourceAuthority):
        def run(_job, attempt) -> None:
            node = next(
                item for item in engine.snapshot.nodes if item.authority is authority
            )
            bound = engine.jobs.create_job(
                run_id=str(_RUN_ID), node_id=node.node_id, workspace=engine.workspace
            )
            _record_local_cleanup(engine, authority, attempt)
            if authority is SourceAuthority.SYFT:
                observation = _observation(bound, node, ("requirements.lock",))
                _finish_existing_syft(engine, node, bound, (observation,))
                return
            native = _with_controlled_finding(
                engine.native_result(node, bound), authority
            )
            engine.attempts.accept_result(
                native,
                lease_token=_LEASE_TOKEN,
                execution_outcome=ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS,
                return_code=0,
                duration_ms=1,
            )

        return run

    evaluations = SourceDependencyEvaluationService(engine.factory, engine.store)
    osv_jobs = SourceOsvJobService(engine.factory, engine.store, evaluations)

    def osv_runner(job, attempt) -> None:
        assert job.lease_token is not None
        SourceOsvHelperExecutionService(
            engine.factory,
            osv_jobs,
            engine.attempts,
            SourceOsvAttemptService(engine.factory, engine.store, osv_jobs),
            SourceOsvRequestPermitService(engine.factory),
            tmp_path / "osv-receipts",
            loopback_test_base_url=f"http://127.0.0.1:{server.server_port}",
        ).execute(job=job, attempt=attempt, lease_token=job.lease_token)

    dispatcher = SourceAuthorityDispatcher(
        {
            SourceAuthority.SEMGREP: local_runner(SourceAuthority.SEMGREP),
            SourceAuthority.GITLEAKS: local_runner(SourceAuthority.GITLEAKS),
            SourceAuthority.SYFT: local_runner(SourceAuthority.SYFT),
            SourceAuthority.CHECKOV: local_runner(SourceAuthority.CHECKOV),
            SourceAuthority.OSV: osv_runner,
        }
    )
    leasing = SourceMappedJobLeasingService(
        engine.factory,
        token_factory=lambda: UUID(_LEASE_TOKEN),
    )
    worker = SourceOrchestrationWorkerCycle(
        engine.factory,
        leasing,
        engine.attempts,
        dispatcher,
        worker_id="engine-closure-worker",
    )
    try:
        assert all(
            worker.run_one().disposition is SourceWorkerDisposition.DISPATCHED
            for _ in range(4)
        )
        coordinator = SourceOrchestrationCoordinatorService(
            engine.factory,
            engine.store,
            frozen_source_v1_authority_roster(),
            engine.projections,
        )
        coordinator.advance(run_id=str(_RUN_ID), workspace=engine.workspace)
        assert worker.run_one().authority is SourceAuthority.OSV
        coordinator = SourceOrchestrationCoordinatorService(
            engine.factory,
            engine.store,
            frozen_source_v1_authority_roster(),
            engine.projections,
        )
        ready = coordinator.advance(run_id=str(_RUN_ID), workspace=engine.workspace)
        assert ready.lifecycle_state is OrchestrationLifecycleState.ASSEMBLY_READY
        assembly = SourceResultAssemblyService(engine.factory, engine.store)
        published = assembly.assemble_and_publish(str(_RUN_ID))
        reloaded = SourceResultAssemblyService(engine.factory, engine.store).load(
            str(_RUN_ID)
        )
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)

    assert reloaded.artifact_sha256 == published.artifact_sha256
    assert Handler.requests == (2 if response_status == 200 else 1)
    with engine.factory() as session:
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        assert run is not None and run.report_json is not None
        serialized_report = json.dumps(run.report_json, sort_keys=True).encode()
        assert _PRIVATE_SOURCE not in serialized_report
        assert b"RAW_PRIVATE_SOURCE_TOKEN" not in serialized_report
        assert b"controlled permanent failure" not in serialized_report
        assert str(tmp_path).encode() not in serialized_report
        assert b'"stdout"' not in serialized_report
        assert b'"stderr"' not in serialized_report
        assert run.status == expected_run_status.value
        assert {item["authority"] for item in run.report_json["coverage_outcomes"]} == {
            "checkov",
            "gitleaks",
            "osv.dev",
            "semgrep-ce",
            "syft",
        }
        osv_coverage = next(
            item
            for item in run.report_json["coverage_outcomes"]
            if item["authority"] == "osv.dev"
        )
        assert osv_coverage["state"] == expected_osv_coverage
        assert osv_coverage["finding_count"] == int(response_status == 200)
        assert osv_coverage["gap_count"] == int(response_status != 200)
        categories = {item["category"] for item in run.report_json["findings"]}
        assert {
            "CODE_SECURITY",
            "CONFIGURATION_SECURITY",
            "SECRET_EXPOSURE",
        }.issubset(categories)
        if response_status == 200:
            assert "DEPENDENCY_VULNERABILITY" in categories
            osv_finding = next(
                item
                for item in run.report_json["findings"]
                if item["category"] == "DEPENDENCY_VULNERABILITY"
            )
            assert osv_finding["supporting_evidence_refs"]
        assert any(
            item["component_kind"] == "PACKAGE"
            for item in run.report_json["components"]
        )
        assert (
            session.scalar(select(func.count()).select_from(ToolExecutionRow)) == 5
        )
        assert (
            session.scalar(select(func.count()).select_from(SourceOsvRequestPermitRow))
            == (2 if response_status == 200 else 1)
        )


def test_controlled_engine_closure_cancellation_stops_active_osv_and_never_publishes(
    engine: _Environment, tmp_path: Path
) -> None:
    request_started = Event()
    release = Event()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            request_started.set()
            release.wait(5)
            with suppress(BrokenPipeError, ConnectionResetError):
                payload = b'{"results":[{}]}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server_thread = Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    coordinator = SourceOrchestrationCoordinatorService(
        engine.factory,
        engine.store,
        frozen_source_v1_authority_roster(),
        engine.projections,
    )
    coordinator.advance(run_id=str(_RUN_ID), workspace=engine.workspace)

    def local_runner(authority: SourceAuthority):
        def run(_job, attempt) -> None:
            node = next(
                item for item in engine.snapshot.nodes if item.authority is authority
            )
            bound = engine.jobs.create_job(
                run_id=str(_RUN_ID), node_id=node.node_id, workspace=engine.workspace
            )
            _record_local_cleanup(engine, authority, attempt)
            if authority is SourceAuthority.SYFT:
                observation = _observation(bound, node, ("requirements.lock",))
                _finish_existing_syft(engine, node, bound, (observation,))
                return
            engine.attempts.accept_result(
                engine.native_result(node, bound),
                lease_token=_LEASE_TOKEN,
                execution_outcome=ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
                return_code=0,
                duration_ms=1,
            )

        return run

    evaluations = SourceDependencyEvaluationService(engine.factory, engine.store)
    osv_jobs = SourceOsvJobService(engine.factory, engine.store, evaluations)

    def osv_runner(job, attempt) -> None:
        assert job.lease_token is not None
        SourceOsvHelperExecutionService(
            engine.factory,
            osv_jobs,
            engine.attempts,
            SourceOsvAttemptService(engine.factory, engine.store, osv_jobs),
            SourceOsvRequestPermitService(engine.factory),
            tmp_path / "osv-cancel-receipts",
            loopback_test_base_url=f"http://127.0.0.1:{server.server_port}",
        ).execute(job=job, attempt=attempt, lease_token=job.lease_token)

    dispatcher = SourceAuthorityDispatcher(
        {
            SourceAuthority.SEMGREP: local_runner(SourceAuthority.SEMGREP),
            SourceAuthority.GITLEAKS: local_runner(SourceAuthority.GITLEAKS),
            SourceAuthority.SYFT: local_runner(SourceAuthority.SYFT),
            SourceAuthority.CHECKOV: local_runner(SourceAuthority.CHECKOV),
            SourceAuthority.OSV: osv_runner,
        }
    )
    worker = SourceOrchestrationWorkerCycle(
        engine.factory,
        SourceMappedJobLeasingService(
            engine.factory, token_factory=lambda: UUID(_LEASE_TOKEN)
        ),
        engine.attempts,
        dispatcher,
        worker_id="engine-closure-cancellation-worker",
    )
    try:
        for _ in range(4):
            assert worker.run_one().disposition is SourceWorkerDisposition.DISPATCHED
        coordinator.advance(run_id=str(_RUN_ID), workspace=engine.workspace)

        def cancel_parent() -> None:
            assert request_started.wait(3)
            coordinator.request_cancellation(str(_RUN_ID))

        canceller = Thread(target=cancel_parent)
        canceller.start()
        started = time.monotonic()
        assert worker.run_one().authority is SourceAuthority.OSV
        elapsed = time.monotonic() - started
        canceller.join(timeout=3)
        assert not canceller.is_alive()
        final = coordinator.advance(run_id=str(_RUN_ID))
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)

    assert elapsed < 3.0
    assert final.lifecycle_state is OrchestrationLifecycleState.TERMINAL
    with engine.factory() as session:
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        assert run is not None and run.report_json is None
        assert run.status == RunStatus.CANCELLED.value
        assert parent is not None and parent.terminal_outcome == "CANCELLED"
        assert (
            session.scalar(select(func.count()).select_from(SourceOsvRequestPermitRow))
            == 1
        )
