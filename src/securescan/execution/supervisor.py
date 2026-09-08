from __future__ import annotations

import base64
import hashlib
import json
import os
import select
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Protocol
from uuid import UUID, uuid5

from securescan.orchestration.execution_models import (
    SourceAttemptCleanupReceipt,
    SourceScannerExecutionIntegrityError,
)

from .cancellable_process import (
    CancellableProcessHandle,
    CancellableProcessRequest,
    CancellableProcessResult,
    CancellableProcessStartError,
    CancellableProcessStateError,
    InvalidCancellableProcessRequestError,
)

SUPERVISOR_PROTOCOL_VERSION = "securescan-local-supervisor-s6b-v1"
_MAX_CONTROL_BYTES = 24 * 1024 * 1024
_MAX_EVENT_BYTES = 300 * 1024 * 1024
_START_TIMEOUT_SECONDS = 10.0
_PREFLIGHT_NAMESPACE = UUID("65ba8f83-72a4-50d9-91eb-a7eb41bd64d2")


@dataclass(frozen=True, slots=True, kw_only=True)
class SupervisorAttemptIdentity:
    job_id: str
    attempt_number: int
    attempt_token: str = field(repr=False)

    def __post_init__(self) -> None:
        from uuid import UUID

        try:
            valid = (
                str(UUID(self.job_id)) == self.job_id
                and type(self.attempt_number) is int
                and self.attempt_number >= 1
                and str(UUID(self.attempt_token)) == self.attempt_token
            )
        except (TypeError, ValueError):
            valid = False
        if not valid:
            raise InvalidCancellableProcessRequestError(
                "Supervisor attempt identity is invalid"
            ) from None


@dataclass(frozen=True, slots=True)
class SupervisorHandshake:
    supervisor_identity: str
    supervisor_pid: int
    supervisor_start_ticks: int
    scanner_pid: int
    scanner_pgid: int
    scanner_start_ticks: int


class _SupervisedProcessHandle:
    def __init__(
        self,
        *,
        supervisor: subprocess.Popen[bytes],
        liveness_fd: int,
        control_fd: int,
        event_fd: int,
        handshake: SupervisorHandshake,
    ) -> None:
        self._supervisor = supervisor
        self._liveness_fd = liveness_fd
        self._control_fd = control_fd
        self._event_fd = event_fd
        self._handshake = handshake
        self._queue: Queue[dict[str, Any] | BaseException] = Queue()
        self._result: CancellableProcessResult | None = None
        self._receipt: SourceAttemptCleanupReceipt | None = None
        self._closed = False
        self._reader = threading.Thread(
            target=self._read_events,
            daemon=True,
            name="securescan-supervisor-events",
        )
        self._reader.start()

    @property
    def handshake(self) -> SupervisorHandshake:
        return self._handshake

    @property
    def cleanup_receipt(self) -> SourceAttemptCleanupReceipt | None:
        self.poll()
        return self._receipt

    def __enter__(self) -> _SupervisedProcessHandle:
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    def poll(self) -> CancellableProcessResult | None:
        self._consume_events(block=False)
        if self._result is not None:
            return self._result
        if self._supervisor.poll() is not None and not self._reader.is_alive():
            self._consume_events(block=False)
            if self._result is None:
                raise CancellableProcessStateError(
                    "Trusted process supervisor ended without a result"
                )
        return None

    def terminate(self) -> None:
        self._send_control(b"T")

    def kill(self) -> None:
        self._send_control(b"K")

    def wait(self, timeout_seconds: float | None = None) -> CancellableProcessResult | None:
        if timeout_seconds is not None and (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds < 0
        ):
            raise CancellableProcessStateError("Process wait duration must be zero or greater")
        deadline = None if timeout_seconds is None else time.monotonic() + timeout_seconds
        while True:
            result = self.poll()
            if result is not None:
                return result
            if deadline is not None and time.monotonic() >= deadline:
                return None
            self._consume_events(block=True, timeout=0.02)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self.poll() is None:
                self.terminate()
                if self.wait(1.0) is None:
                    self.kill()
                    if self.wait(2.0) is None:
                        raise CancellableProcessStateError(
                            "Trusted process supervisor could not clean up"
                        )
        finally:
            for descriptor in (self._liveness_fd, self._control_fd):
                if descriptor >= 0:
                    with suppress(OSError):
                        os.close(descriptor)
            self._liveness_fd = -1
            self._control_fd = -1
            self._reader.join(timeout=2.0)
            if self._reader.is_alive():
                raise CancellableProcessStateError(
                    "Trusted process supervisor event channel did not close"
                )

    def _send_control(self, value: bytes) -> None:
        if self._result is not None or self._control_fd < 0:
            return
        try:
            os.write(self._control_fd, value)
        except BrokenPipeError:
            return
        except OSError as exc:
            raise CancellableProcessStateError("Trusted process supervisor control failed") from exc

    def _read_events(self) -> None:
        data = bytearray()
        try:
            while len(data) <= _MAX_EVENT_BYTES:
                chunk = os.read(
                    self._event_fd,
                    min(64 * 1024, _MAX_EVENT_BYTES + 1 - len(data)),
                )
                if not chunk:
                    break
                data.extend(chunk)
            if len(data) > _MAX_EVENT_BYTES:
                raise CancellableProcessStateError(
                    "Trusted process supervisor response exceeded its limit"
                )
            for line in bytes(data).splitlines():
                value = json.loads(line.decode("utf-8"))
                if not isinstance(value, dict):
                    raise ValueError
                self._queue.put(value)
        except BaseException as exc:
            self._queue.put(exc)
        finally:
            with suppress(OSError):
                os.close(self._event_fd)

    def _consume_events(self, *, block: bool, timeout: float = 0.0) -> None:
        while True:
            try:
                event = self._queue.get(block=block, timeout=timeout if block else None)
            except Empty:
                return
            block = False
            if isinstance(event, BaseException):
                raise CancellableProcessStateError(
                    "Trusted process supervisor response was invalid"
                ) from event
            if event.get("type") != "result" or self._result is not None:
                raise CancellableProcessStateError(
                    "Trusted process supervisor response was invalid"
                )
            try:
                self._result = CancellableProcessResult(
                    return_code=event["return_code"],
                    stdout=base64.b64decode(event["stdout"], validate=True),
                    stderr=base64.b64decode(event["stderr"], validate=True),
                    duration_ms=event["duration_ms"],
                    timed_out=event["timed_out"],
                    output_limit_exceeded=event["output_limit_exceeded"],
                    termination_requested=event["termination_requested"],
                    force_killed=event["force_killed"],
                )
                receipt_payload = base64.b64decode(event["receipt"], validate=True)
                self._receipt = SourceAttemptCleanupReceipt.from_json(receipt_payload)
            except (KeyError, TypeError, ValueError, SourceScannerExecutionIntegrityError) as exc:
                raise CancellableProcessStateError(
                    "Trusted process supervisor response was invalid"
                ) from exc


class _AttemptPersistence(Protocol):
    def register_supervisor(
        self,
        *,
        job_id: str,
        attempt_number: int,
        attempt_token: str,
        supervisor_identity: str,
        supervisor_pid: int,
        supervisor_start_ticks: int,
        scanner_pid: int,
        scanner_pgid: int,
        scanner_start_ticks: int,
    ) -> object: ...

    def record_cleanup(self, receipt: SourceAttemptCleanupReceipt) -> object: ...


class _TrackedSupervisedProcessHandle:
    """Complete one supervised phase exactly once before another phase starts."""

    def __init__(
        self,
        handle: _SupervisedProcessHandle,
        on_complete: Callable[[SourceAttemptCleanupReceipt], None],
    ) -> None:
        self._handle = handle
        self._on_complete = on_complete
        self._completed = False

    @property
    def cleanup_receipt(self) -> SourceAttemptCleanupReceipt | None:
        return self._handle.cleanup_receipt

    def __enter__(self) -> _TrackedSupervisedProcessHandle:
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    def poll(self) -> CancellableProcessResult | None:
        result = self._handle.poll()
        if result is not None:
            self._complete()
        return result

    def wait(self, timeout_seconds: float | None = None) -> CancellableProcessResult | None:
        result = self._handle.wait(timeout_seconds)
        if result is not None:
            self._complete()
        return result

    def terminate(self) -> None:
        self._handle.terminate()

    def kill(self) -> None:
        self._handle.kill()

    def close(self) -> None:
        self._handle.close()
        self._complete()

    def _complete(self) -> None:
        if self._completed:
            return
        receipt = self._handle.cleanup_receipt
        if receipt is None:
            raise CancellableProcessStateError(
                "Trusted process supervisor ended without a cleanup receipt"
            )
        self._on_complete(receipt)
        self._completed = True


class AttemptBoundProcessExecutor:
    """Adapt frozen local bridges to one durable S6B scanner attempt.

    Frozen bindings perform one or more runtime probes before starting the scanner.
    Every probe is independently supervised, while only the exact predeclared scan
    request may bind the durable attempt. If a worker dies during a probe, the durable
    attempt remains ACTIVE and therefore cannot authorize a replacement.
    """

    def __init__(
        self,
        *,
        attempt: SupervisorAttemptIdentity,
        final_request: CancellableProcessRequest,
        attempt_persistence: _AttemptPersistence,
        receipt_directory: Path,
        helper_python: Path | None = None,
    ) -> None:
        if (
            not isinstance(attempt, SupervisorAttemptIdentity)
            or not isinstance(final_request, CancellableProcessRequest)
            or not callable(getattr(attempt_persistence, "register_supervisor", None))
            or not callable(getattr(attempt_persistence, "record_cleanup", None))
        ):
            raise InvalidCancellableProcessRequestError(
                "Attempt-bound process executor is invalid"
            )
        self._attempt = attempt
        self._final_request = final_request
        self._attempt_persistence = attempt_persistence
        self._receipt_directory = TrustedLocalProcessSupervisor._prepare_receipt_directory(
            receipt_directory
        )
        self._helper_python = helper_python
        self._preflight_count = 0
        self._final_started = False
        self._active = False
        self._lock = threading.Lock()

    def start(self, request: CancellableProcessRequest) -> CancellableProcessHandle:
        if not isinstance(request, CancellableProcessRequest):
            raise InvalidCancellableProcessRequestError(
                "A valid cancellable process request is required"
            )
        with self._lock:
            if self._active or self._final_started:
                raise CancellableProcessStateError(
                    "Attempt-bound process phases must be sequential"
                )
            is_final = request == self._final_request
            self._active = True
            if is_final:
                self._final_started = True
                identity = self._attempt
                directory = self._receipt_directory
            else:
                self._preflight_count += 1
                seed = (
                    f"{self._attempt.job_id}\0{self._attempt.attempt_number}\0"
                    f"{self._attempt.attempt_token}\0{self._preflight_count}"
                )
                identity = SupervisorAttemptIdentity(
                    job_id=str(uuid5(_PREFLIGHT_NAMESPACE, f"job\0{seed}")),
                    attempt_number=1,
                    attempt_token=str(uuid5(_PREFLIGHT_NAMESPACE, f"token\0{seed}")),
                )
                directory = self._receipt_directory / f"preflight-{self._preflight_count}"
        try:
            handle = TrustedLocalProcessSupervisor(
                identity,
                directory,
                helper_python=self._helper_python,
            ).start(request)
            if is_final:
                handshake = handle.handshake
                self._attempt_persistence.register_supervisor(
                    job_id=self._attempt.job_id,
                    attempt_number=self._attempt.attempt_number,
                    attempt_token=self._attempt.attempt_token,
                    supervisor_identity=handshake.supervisor_identity,
                    supervisor_pid=handshake.supervisor_pid,
                    supervisor_start_ticks=handshake.supervisor_start_ticks,
                    scanner_pid=handshake.scanner_pid,
                    scanner_pgid=handshake.scanner_pgid,
                    scanner_start_ticks=handshake.scanner_start_ticks,
                )
            return _TrackedSupervisedProcessHandle(
                handle,
                self._record_final_cleanup if is_final else self._complete_phase,
            )
        except Exception:
            with self._lock:
                self._active = False
            if "handle" in locals():
                with suppress(Exception):
                    handle.close()
            raise

    def _record_final_cleanup(self, receipt: SourceAttemptCleanupReceipt) -> None:
        try:
            self._attempt_persistence.record_cleanup(receipt)
        finally:
            self._complete_phase(receipt)

    def _complete_phase(self, _receipt: SourceAttemptCleanupReceipt) -> None:
        with self._lock:
            self._active = False


class TrustedLocalProcessSupervisor:
    """Launch a scanner under a worker-independent Linux cleanup helper."""

    def __init__(
        self,
        attempt: SupervisorAttemptIdentity,
        receipt_directory: Path,
        *,
        helper_python: Path | None = None,
        popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
    ) -> None:
        if not isinstance(attempt, SupervisorAttemptIdentity):
            raise InvalidCancellableProcessRequestError("Supervisor attempt identity is invalid")
        self._attempt = attempt
        self._receipt_directory = self._prepare_receipt_directory(receipt_directory)
        self._helper_python = Path(sys.executable) if helper_python is None else helper_python
        self._popen = popen

    def start(self, request: CancellableProcessRequest) -> CancellableProcessHandle:
        if not isinstance(request, CancellableProcessRequest):
            raise InvalidCancellableProcessRequestError(
                "A valid cancellable process request is required"
            )
        request_read, request_write = os.pipe()
        liveness_read, liveness_write = os.pipe()
        control_read, control_write = os.pipe()
        event_read, event_write = os.pipe()
        supervisor: subprocess.Popen[bytes] | None = None
        try:
            command = (
                str(self._helper_python),
                "-m",
                "securescan.execution.supervisor_helper",
                str(request_read),
                str(liveness_read),
                str(control_read),
                str(event_write),
                str(self._receipt_directory),
            )
            supervisor = self._popen(  # noqa: S603 - fixed trusted module invocation
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                pass_fds=(request_read, liveness_read, control_read, event_write),
                start_new_session=True,
            )
            for descriptor in (request_read, liveness_read, control_read, event_write):
                os.close(descriptor)
            request_document = {
                "argv": list(request.argv),
                "attempt_number": self._attempt.attempt_number,
                "attempt_token": self._attempt.attempt_token,
                "cwd": None if request.cwd is None else str(request.cwd),
                "environment": None if request.environment is None else dict(request.environment),
                "job_id": self._attempt.job_id,
                "protocol_version": SUPERVISOR_PROTOCOL_VERSION,
                "stderr_limit_bytes": request.stderr_limit_bytes,
                "stdin": None
                if request.stdin_data is None
                else base64.b64encode(request.stdin_data).decode("ascii"),
                "stdout_limit_bytes": request.stdout_limit_bytes,
                "timeout_seconds": request.timeout_seconds,
            }
            payload = json.dumps(
                request_document,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            if len(payload) > _MAX_CONTROL_BYTES:
                raise InvalidCancellableProcessRequestError("Supervisor request exceeded its limit")
            os.write(request_write, payload)
            os.close(request_write)
            request_write = -1
            handshake = self._read_handshake(event_read, supervisor)
            return _SupervisedProcessHandle(
                supervisor=supervisor,
                liveness_fd=liveness_write,
                control_fd=control_write,
                event_fd=event_read,
                handshake=handshake,
            )
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            if supervisor is not None and supervisor.poll() is None:
                supervisor.kill()
                supervisor.wait()
            raise CancellableProcessStartError(
                "The trusted process supervisor could not start"
            ) from exc
        finally:
            for descriptor in (request_read, liveness_read, control_read, event_write):
                with suppress(OSError):
                    os.close(descriptor)
            if request_write >= 0:
                with suppress(OSError):
                    os.close(request_write)

    @staticmethod
    def _read_handshake(event_fd: int, supervisor: subprocess.Popen[bytes]) -> SupervisorHandshake:
        deadline = time.monotonic() + _START_TIMEOUT_SECONDS
        data = bytearray()
        while time.monotonic() < deadline and len(data) < 16 * 1024:
            ready, _, _ = select.select([event_fd], [], [], 0.05)
            if ready:
                chunk = os.read(event_fd, 1)
                if not chunk:
                    break
                if chunk == b"\n":
                    try:
                        value = json.loads(data.decode("utf-8"))
                        if value.pop("type") != "handshake" or set(value) != {
                            "scanner_pgid",
                            "scanner_pid",
                            "scanner_start_ticks",
                            "supervisor_identity",
                            "supervisor_pid",
                            "supervisor_start_ticks",
                        }:
                            raise ValueError
                        handshake = SupervisorHandshake(**value)
                    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
                        raise CancellableProcessStartError(
                            "Trusted process supervisor handshake was invalid"
                        ) from exc
                    if len(handshake.supervisor_identity) != 64 or any(
                        type(item) is not int or item < 1
                        for item in (
                            handshake.supervisor_pid,
                            handshake.supervisor_start_ticks,
                            handshake.scanner_pid,
                            handshake.scanner_pgid,
                            handshake.scanner_start_ticks,
                        )
                    ):
                        raise CancellableProcessStartError(
                            "Trusted process supervisor handshake was invalid"
                        )
                    return handshake
                data.extend(chunk)
            if supervisor.poll() is not None:
                break
        raise CancellableProcessStartError("Trusted process supervisor handshake did not complete")

    @staticmethod
    def _prepare_receipt_directory(path: Path) -> Path:
        if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
            raise InvalidCancellableProcessRequestError("Supervisor receipt directory is invalid")
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = path.stat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise InvalidCancellableProcessRequestError("Supervisor receipt directory is invalid")
        return path.resolve(strict=True)


def supervisor_identity(pid: int, start_ticks: int) -> str:
    return hashlib.sha256(
        f"{SUPERVISOR_PROTOCOL_VERSION}\0{pid}\0{start_ticks}".encode("ascii")
    ).hexdigest()
