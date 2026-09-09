from __future__ import annotations

import json
import os
import socket
import stat
import sys
import tempfile
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from securescan.advisories.osv import OSV_BASE_URL, OsvFailureCode
from securescan.execution import CancellableProcessRequest
from securescan.execution.supervisor import (
    AttemptBoundProcessExecutor,
    SupervisorAttemptIdentity,
)
from securescan.jobs.heartbeat import JobHeartbeatError, JobHeartbeatService
from securescan.persistence.database import (
    JobRow,
    SourceOrchestrationAttemptRow,
    SourceOrchestrationRow,
)

from .execution import SourceScannerAttemptRecord, SourceScannerAttemptService
from .osv_execution import (
    OSV_HELPER_PROTOCOL_VERSION,
    OsvRequestOperation,
    SafeSourceOsvResult,
    SourceOsvAttemptService,
    SourceOsvExecutionConflictError,
    SourceOsvExecutionError,
    SourceOsvFailureCode,
    SourceOsvJobService,
    SourceOsvRequestPermitService,
    analysis_from_document,
)

OSV_CONTROLLED_STOP_SLA_SECONDS = 3.0
_MAX_PERMIT_BYTES = 16 * 1024
_MAX_RESULT_BYTES = 100 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class SourceOsvExecutionOutcome:
    accepted: bool
    result_sha256: str | None
    failure_code: SourceOsvFailureCode | None
    duration_ms: int


class SourceOsvHelperExecutionService:
    """Execute one OSV attempt through the S6B supervisor and durable permits."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        jobs: SourceOsvJobService,
        attempts: SourceScannerAttemptService,
        osv_attempts: SourceOsvAttemptService,
        permits: SourceOsvRequestPermitService,
        receipt_root: Path,
        *,
        loopback_test_base_url: str | None = None,
        monotonic: Any = time.monotonic,
        heartbeat_interval_seconds: float = 5.0,
        lease_seconds: int = 30,
    ) -> None:
        if not isinstance(receipt_root, Path) or not receipt_root.is_absolute():
            raise SourceOsvExecutionError
        if (
            isinstance(heartbeat_interval_seconds, bool)
            or not isinstance(heartbeat_interval_seconds, (int, float))
            or heartbeat_interval_seconds <= 0
            or type(lease_seconds) is not int
            or lease_seconds < 1
            or heartbeat_interval_seconds >= lease_seconds
        ):
            raise SourceOsvExecutionError
        if loopback_test_base_url is not None and not loopback_test_base_url.startswith(
            ("http://127.0.0.1:", "http://localhost:", "http://[::1]:")
        ):
            raise SourceOsvExecutionError
        self._sessions = session_factory
        self._jobs = jobs
        self._attempts = attempts
        self._osv_attempts = osv_attempts
        self._permits = permits
        self._receipt_root = receipt_root
        self._loopback_test_base_url = loopback_test_base_url
        self._monotonic = monotonic
        self._heartbeats = JobHeartbeatService(session_factory)
        self._heartbeat_interval_seconds = float(heartbeat_interval_seconds)
        self._lease_seconds = lease_seconds

    def execute(
        self,
        *,
        job: Any,
        attempt: SourceScannerAttemptRecord,
        lease_token: str,
    ) -> SourceOsvExecutionOutcome:
        if (
            job.id != attempt.job_id
            or job.run_id != attempt.run_id
            or job.attempt_count != attempt.attempt_number
            or job.lease_token != lease_token
            or not isinstance(job.leased_by, str)
            or not job.leased_by
            or job.adapter_id != "osv.dev"
        ):
            raise SourceOsvExecutionConflictError
        execution_input = self._jobs.load_input(job_id=job.id)
        ipc_directory = self._prepare_ipc_directory(attempt)
        socket_path = ipc_directory / "permit.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.settimeout(0.05)
        server.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        server.listen(1)
        stop = threading.Event()
        failures: list[BaseException] = []
        permit_thread = threading.Thread(
            target=self._serve_permits,
            args=(server, stop, failures, attempt),
            daemon=True,
            name="securescan-osv-permits",
        )
        permit_thread.start()
        environment = {
            "PYTHONHASHSEED": "0",
            "PYTHONPATH": os.pathsep.join(sys.path),
            "SECURESCAN_OSV_BASE_URL": self._loopback_test_base_url or OSV_BASE_URL,
            "SECURESCAN_OSV_PERMIT_SOCKET": str(socket_path),
        }
        if self._loopback_test_base_url is not None:
            environment["SECURESCAN_OSV_ALLOW_LOOPBACK_TEST_TRANSPORT"] = "1"
        helper_input = _canonical_json(
            {
                "attempt_token": attempt.attempt_token,
                "execution_input": execution_input.canonical_data(),
                "protocol_version": OSV_HELPER_PROTOCOL_VERSION,
            }
        )
        remaining = self._remaining_seconds(job.run_id)
        request = CancellableProcessRequest(
            argv=(str(Path(sys.executable)), "-m", "securescan.orchestration.osv_helper"),
            cwd=None,
            environment=environment,
            timeout_seconds=max(0.1, min(remaining, 3600.0)),
            stdout_limit_bytes=_MAX_RESULT_BYTES,
            stderr_limit_bytes=64 * 1024,
            stdin_data=helper_input,
        )
        executor = AttemptBoundProcessExecutor(
            attempt=SupervisorAttemptIdentity(
                job_id=attempt.job_id,
                attempt_number=attempt.attempt_number,
                attempt_token=attempt.attempt_token,
            ),
            final_request=request,
            attempt_persistence=self._attempts,
            receipt_directory=self._receipt_root / attempt.job_id / str(attempt.attempt_number),
        )
        started = self._monotonic()
        next_heartbeat = started + self._heartbeat_interval_seconds
        try:
            handle = executor.start(request)
            try:
                while True:
                    process_result = handle.wait(0.02)
                    if process_result is not None:
                        break
                    stop_reason = self._stop_reason(job.run_id, job.id, lease_token)
                    current = self._monotonic()
                    if stop_reason is None and current >= next_heartbeat:
                        try:
                            self._heartbeats.renew_lease(
                                job.id,
                                job.leased_by,
                                lease_token,
                                self._lease_seconds,
                            )
                            next_heartbeat = current + self._heartbeat_interval_seconds
                        except JobHeartbeatError:
                            stop_reason = (
                                self._stop_reason(job.run_id, job.id, lease_token)
                                or SourceOsvFailureCode.HELPER_EXECUTION_FAILURE
                            )
                    if stop_reason is not None:
                        handle.terminate()
                        process_result = handle.wait(0.75)
                        if process_result is None:
                            handle.kill()
                            process_result = handle.wait(2.0)
                        if process_result is None:
                            raise SourceOsvExecutionError
                        duration = int((self._monotonic() - started) * 1000)
                        self._osv_attempts.record_failure(
                            job_id=job.id,
                            attempt_number=attempt.attempt_number,
                            attempt_token=attempt.attempt_token,
                            lease_token=lease_token,
                            failure_code=stop_reason,
                            duration_ms=duration,
                        )
                        return SourceOsvExecutionOutcome(False, None, stop_reason, duration)
            finally:
                handle.close()
        finally:
            stop.set()
            server.close()
            permit_thread.join(timeout=1.0)
            with suppress(OSError):
                socket_path.unlink()
            with suppress(OSError):
                ipc_directory.rmdir()
        duration = int((self._monotonic() - started) * 1000)
        if failures:
            failure = SourceOsvFailureCode.HELPER_EXECUTION_FAILURE
            self._osv_attempts.record_failure(
                job_id=job.id,
                attempt_number=attempt.attempt_number,
                attempt_token=attempt.attempt_token,
                lease_token=lease_token,
                failure_code=failure,
                duration_ms=duration,
            )
            return SourceOsvExecutionOutcome(False, None, failure, duration)
        failure = _process_failure(process_result)
        if failure is not None:
            self._osv_attempts.record_failure(
                job_id=job.id,
                attempt_number=attempt.attempt_number,
                attempt_token=attempt.attempt_token,
                lease_token=lease_token,
                failure_code=failure,
                duration_ms=duration,
            )
            return SourceOsvExecutionOutcome(False, None, failure, duration)
        try:
            root = _load_helper_result(process_result.stdout)
            analysis = analysis_from_document(root["analysis"])
            result = SafeSourceOsvResult.from_analysis(
                execution_input,
                attempt_number=attempt.attempt_number,
                analysis=analysis,
            )
            self._osv_attempts.accept_result(
                result, lease_token=lease_token, duration_ms=duration
            )
        except Exception:
            failure = SourceOsvFailureCode.RESULT_CANONICALIZATION_FAILURE
            self._osv_attempts.record_failure(
                job_id=job.id,
                attempt_number=attempt.attempt_number,
                attempt_token=attempt.attempt_token,
                lease_token=lease_token,
                failure_code=failure,
                duration_ms=duration,
            )
            return SourceOsvExecutionOutcome(False, None, failure, duration)
        return SourceOsvExecutionOutcome(True, result.sha256(), None, duration)

    def _serve_permits(
        self,
        server: socket.socket,
        stop: threading.Event,
        failures: list[BaseException],
        attempt: SourceScannerAttemptRecord,
    ) -> None:
        while not stop.is_set():
            try:
                channel, _ = server.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with channel:
                try:
                    root = _load_permit(channel)
                    helper_identity = self._helper_identity(attempt)
                    permit = self._permits.authorize(
                        job_id=attempt.job_id,
                        attempt_number=attempt.attempt_number,
                        attempt_token=root["attempt_token"],
                        helper_identity=helper_identity,
                        request_sequence=root["request_sequence"],
                        operation_kind=OsvRequestOperation(root["operation_kind"]),
                        logical_request_digest=root["logical_request_digest"],
                        transport_attempt_number=root["transport_attempt_number"],
                    )
                    channel.sendall(
                        _canonical_json(
                            {
                                "authorized": True,
                                "protocol_version": OSV_HELPER_PROTOCOL_VERSION,
                                "request_sequence": permit.request_sequence,
                            }
                        )
                    )
                except BaseException as exc:
                    failures.append(exc)
                    with suppress(OSError):
                        channel.sendall(
                            _canonical_json(
                                {
                                    "authorized": False,
                                    "protocol_version": OSV_HELPER_PROTOCOL_VERSION,
                                }
                            )
                        )
                    return

    def _helper_identity(self, attempt: SourceScannerAttemptRecord) -> str:
        with self._sessions() as session:
            row = session.get(
                SourceOrchestrationAttemptRow,
                (attempt.job_id, attempt.attempt_number),
            )
            if row is None or row.supervisor_identity is None:
                raise SourceOsvExecutionError
            return row.supervisor_identity

    def _stop_reason(
        self, run_id: str, job_id: str, lease_token: str
    ) -> SourceOsvFailureCode | None:
        with self._sessions() as session:
            parent = session.get(SourceOrchestrationRow, run_id)
            job = session.get(JobRow, job_id)
            if parent is None or job is None or job.lease_token != lease_token:
                return SourceOsvFailureCode.HELPER_EXECUTION_FAILURE
            if parent.cancel_requested or job.cancel_requested:
                return SourceOsvFailureCode.CANCELLED
            if self._database_now(session) >= _utc(parent.deadline_at):
                return SourceOsvFailureCode.DEADLINE_EXCEEDED
            return None

    def _remaining_seconds(self, run_id: str) -> float:
        with self._sessions() as session:
            parent = session.get(SourceOrchestrationRow, run_id)
            if parent is None:
                raise SourceOsvExecutionError
            return max(
                0.0,
                (_utc(parent.deadline_at) - self._database_now(session)).total_seconds(),
            )

    @staticmethod
    def _database_now(session: Session):
        from sqlalchemy import func

        value = session.scalar(select(func.now()))
        if value is None:
            raise SourceOsvExecutionError
        return _utc(value)

    def _prepare_ipc_directory(self, _attempt: SourceScannerAttemptRecord) -> Path:
        path = Path(tempfile.mkdtemp(prefix="securescan-osv-", dir="/tmp"))
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
        ):
            raise SourceOsvExecutionError
        os.chmod(path, 0o700)
        if len(str(path / "permit.sock").encode()) >= 104:
            raise SourceOsvExecutionError
        return path


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _strict_json(payload: bytes, *, maximum: int) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    if not payload or len(payload) > maximum:
        raise SourceOsvExecutionError
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (TypeError, ValueError, UnicodeError):
        raise SourceOsvExecutionError from None
    if not isinstance(value, dict) or _canonical_json(value) != payload:
        raise SourceOsvExecutionError
    return value


def _load_permit(channel: socket.socket) -> dict[str, Any]:
    data = bytearray()
    while len(data) <= _MAX_PERMIT_BYTES:
        chunk = channel.recv(min(4096, _MAX_PERMIT_BYTES + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk:
            break
    root = _strict_json(bytes(data), maximum=_MAX_PERMIT_BYTES)
    if (
        len(data) > _MAX_PERMIT_BYTES
        or data.count(b"\n") != 1
        or not data.endswith(b"\n")
        or set(root)
        != {
            "attempt_token",
            "logical_request_digest",
            "operation_kind",
            "protocol_version",
            "request_sequence",
            "transport_attempt_number",
        }
        or root["protocol_version"] != OSV_HELPER_PROTOCOL_VERSION
    ):
        raise SourceOsvExecutionError
    return root


def _load_helper_result(payload: bytes) -> dict[str, Any]:
    root = _strict_json(payload, maximum=_MAX_RESULT_BYTES)
    if (
        not isinstance(root, dict)
        or set(root) != {"analysis", "protocol_version", "status"}
        or root["protocol_version"] != OSV_HELPER_PROTOCOL_VERSION
        or root["status"] != "SUCCEEDED"
    ):
        raise SourceOsvExecutionError
    return root


def _process_failure(result: Any) -> SourceOsvFailureCode | None:
    if result.timed_out:
        return SourceOsvFailureCode.DEADLINE_EXCEEDED
    if result.output_limit_exceeded:
        return SourceOsvFailureCode.HELPER_EXECUTION_FAILURE
    if result.return_code == 0:
        return None
    try:
        root = _strict_json(result.stdout, maximum=_MAX_RESULT_BYTES)
        if root.get("status") != "FAILED":
            raise ValueError
        raw_code = root["failure_code"]
        try:
            return SourceOsvFailureCode(raw_code)
        except ValueError:
            code = OsvFailureCode(raw_code)
    except (KeyError, TypeError, ValueError, UnicodeError, SourceOsvExecutionError):
        return SourceOsvFailureCode.HELPER_EXECUTION_FAILURE
    return {
        OsvFailureCode.NETWORK_FAILURE: SourceOsvFailureCode.NETWORK_FAILURE,
        OsvFailureCode.TIMEOUT: SourceOsvFailureCode.READ_WRITE_TIMEOUT,
        OsvFailureCode.RESPONSE_LIMIT: SourceOsvFailureCode.INVALID_OSV_SCHEMA,
        OsvFailureCode.HTTP_ERROR: SourceOsvFailureCode.HTTP_PERMANENT_ERROR,
        OsvFailureCode.QUERY_RESPONSE_INVALID: SourceOsvFailureCode.INVALID_OSV_SCHEMA,
        OsvFailureCode.PAGINATION_INVALID: SourceOsvFailureCode.PAGINATION_INTEGRITY_FAILURE,
        OsvFailureCode.ADVISORY_FETCH_FAILED: SourceOsvFailureCode.HTTP_PERMANENT_ERROR,
        OsvFailureCode.ADVISORY_SCHEMA_INVALID: SourceOsvFailureCode.INVALID_OSV_SCHEMA,
        OsvFailureCode.DATA_CHANGED_DURING_QUERY: (
            SourceOsvFailureCode.OSV_DATA_CHANGED_DURING_QUERY
        ),
        OsvFailureCode.RUNTIME_DEPENDENCY_INVALID: (
            SourceOsvFailureCode.HELPER_EXECUTION_FAILURE
        ),
    }[code]


def _utc(value):
    from datetime import UTC

    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
