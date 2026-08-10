from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import time
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Lock, Thread
from types import MappingProxyType
from typing import IO, Protocol, runtime_checkable

_MAX_OUTPUT_BYTES = 100 * 1024 * 1024
_MAX_STDIN_BYTES = 16 * 1024 * 1024
_READ_SIZE = 64 * 1024
_WAIT_INTERVAL_SECONDS = 0.01
_CLOSE_TERMINATION_SECONDS = 0.1
_CLOSE_KILL_SECONDS = 1.0


class CancellableProcessExecutorError(RuntimeError):
    """Raised when cancellable local process execution fails."""


class InvalidCancellableProcessRequestError(CancellableProcessExecutorError):
    """Raised when a cancellable process request is invalid."""


class CancellableProcessStartError(CancellableProcessExecutorError):
    """Raised when the operating system cannot create the requested process."""


class CancellableProcessStateError(CancellableProcessExecutorError):
    """Raised when a process handle cannot satisfy its lifecycle contract."""


@dataclass(frozen=True, slots=True)
class CancellableProcessRequest:
    argv: tuple[str, ...]
    cwd: Path | None
    environment: Mapping[str, str] | None
    timeout_seconds: float
    stdout_limit_bytes: int
    stderr_limit_bytes: int
    stdin_data: bytes | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.argv, tuple)
            or not self.argv
            or any(not isinstance(item, str) or not item for item in self.argv)
        ):
            raise InvalidCancellableProcessRequestError(
                "Process arguments must be a non-empty tuple of non-empty strings"
            )
        if self.cwd is not None and (not isinstance(self.cwd, Path) or not self.cwd.is_absolute()):
            raise InvalidCancellableProcessRequestError(
                "Process working directory must be an absolute Path"
            )
        if self.environment is not None:
            if not isinstance(self.environment, Mapping):
                raise InvalidCancellableProcessRequestError(
                    "Process environment must be a string mapping"
                )
            copied_environment: dict[str, str] = {}
            for key, value in self.environment.items():
                if (
                    not isinstance(key, str)
                    or not isinstance(value, str)
                    or "=" in key
                    or "\0" in key
                    or "\0" in value
                ):
                    raise InvalidCancellableProcessRequestError(
                        "Process environment contains an invalid entry"
                    )
                copied_environment[key] = value
            object.__setattr__(
                self,
                "environment",
                MappingProxyType(copied_environment),
            )
        if self.stdin_data is not None and (
            not isinstance(self.stdin_data, bytes)
            or len(self.stdin_data) > _MAX_STDIN_BYTES
        ):
            raise InvalidCancellableProcessRequestError(
                "Process input must be immutable bytes no larger than 16 MiB"
            )
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not 0 < self.timeout_seconds <= 86_400
        ):
            raise InvalidCancellableProcessRequestError(
                "Process timeout must be greater than zero and at most 86400 seconds"
            )
        for field_name in ("stdout_limit_bytes", "stderr_limit_bytes"):
            value = getattr(self, field_name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 1 <= value <= _MAX_OUTPUT_BYTES
            ):
                raise InvalidCancellableProcessRequestError(
                    "Process output limits must be integers from 1 through 100 MiB"
                )


@dataclass(frozen=True, slots=True)
class CancellableProcessResult:
    return_code: int
    stdout: bytes
    stderr: bytes
    duration_ms: int
    timed_out: bool
    output_limit_exceeded: bool
    termination_requested: bool
    force_killed: bool


@runtime_checkable
class CancellableProcessHandle(Protocol):
    def __enter__(self) -> CancellableProcessHandle: ...

    def __exit__(self, *_exc_info: object) -> None: ...

    def poll(self) -> CancellableProcessResult | None: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...

    def wait(
        self,
        timeout_seconds: float | None = None,
    ) -> CancellableProcessResult | None: ...

    def close(self) -> None: ...


class _CancellableProcessHandle:
    def __init__(
        self,
        process: subprocess.Popen[bytes],
        request: CancellableProcessRequest,
        monotonic_clock: Callable[[], float],
    ) -> None:
        self._process = process
        self._request = request
        self._monotonic_clock = monotonic_clock
        self._started_at = monotonic_clock()
        self._lock = Lock()
        self._stdout = bytearray()
        self._stderr = bytearray()
        self._output_limit_event = Event()
        self._reader_failure_event = Event()
        self._termination_requested = False
        self._force_killed = False
        self._timed_out = False
        self._closed = False
        self._result: CancellableProcessResult | None = None
        assert process.stdout is not None
        assert process.stderr is not None
        self._reader_threads = (
            Thread(
                target=self._drain_stream,
                args=(process.stdout, self._stdout, request.stdout_limit_bytes),
                daemon=True,
                name="securescan-stdout-drain",
            ),
            Thread(
                target=self._drain_stream,
                args=(process.stderr, self._stderr, request.stderr_limit_bytes),
                daemon=True,
                name="securescan-stderr-drain",
            ),
        )
        for thread in self._reader_threads:
            thread.start()

    def __enter__(self) -> _CancellableProcessHandle:
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    def poll(self) -> CancellableProcessResult | None:
        with self._lock:
            if self._result is not None:
                return self._result
            elapsed = self._monotonic_clock() - self._started_at
            timeout_due = elapsed >= self._request.timeout_seconds
            if timeout_due:
                self._timed_out = True
            must_terminate = (
                timeout_due
                or self._output_limit_event.is_set()
                or self._reader_failure_event.is_set()
            )

        if must_terminate:
            self.terminate()

        return_code = self._process.poll()
        if return_code is None:
            return None
        if any(thread.is_alive() for thread in self._reader_threads):
            return None
        if self._reader_failure_event.is_set():
            raise CancellableProcessStateError("Process output could not be collected safely")

        with self._lock:
            if self._result is None:
                duration_ms = max(
                    0,
                    int((self._monotonic_clock() - self._started_at) * 1000),
                )
                self._result = CancellableProcessResult(
                    return_code=return_code,
                    stdout=bytes(self._stdout),
                    stderr=bytes(self._stderr),
                    duration_ms=duration_ms,
                    timed_out=self._timed_out,
                    output_limit_exceeded=self._output_limit_event.is_set(),
                    termination_requested=self._termination_requested,
                    force_killed=self._force_killed,
                )
            return self._result

    def terminate(self) -> None:
        with self._lock:
            if self._result is not None or self._process.poll() is not None:
                return
            if self._termination_requested:
                return
            self._termination_requested = True
        try:
            if os.name == "posix":
                os.killpg(self._process.pid, signal.SIGTERM)
            else:
                self._process.terminate()
        except ProcessLookupError:
            return
        except OSError as exc:
            raise CancellableProcessStateError(
                "Process termination could not be requested safely"
            ) from exc

    def kill(self) -> None:
        with self._lock:
            if self._result is not None or self._process.poll() is not None:
                return
            if self._force_killed:
                return
            self._force_killed = True
        try:
            if os.name == "posix":
                os.killpg(self._process.pid, signal.SIGKILL)
            else:
                self._process.kill()
        except ProcessLookupError:
            return
        except OSError as exc:
            raise CancellableProcessStateError(
                "Process forceful termination could not be requested safely"
            ) from exc

    def wait(
        self,
        timeout_seconds: float | None = None,
    ) -> CancellableProcessResult | None:
        if timeout_seconds is not None and (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds < 0
        ):
            raise CancellableProcessStateError("Process wait duration must be zero or greater")
        deadline = None if timeout_seconds is None else self._monotonic_clock() + timeout_seconds
        while True:
            result = self.poll()
            if result is not None:
                return result
            if deadline is not None and self._monotonic_clock() >= deadline:
                return None
            time.sleep(_WAIT_INTERVAL_SECONDS)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        try:
            if self.poll() is None:
                self.terminate()
                if self.wait(_CLOSE_TERMINATION_SECONDS) is None:
                    self.kill()
                    if self.wait(_CLOSE_KILL_SECONDS) is None:
                        raise CancellableProcessStateError(
                            "Process could not be reaped during handle cleanup"
                        )
        finally:
            for thread in self._reader_threads:
                thread.join(timeout=_CLOSE_KILL_SECONDS)
            for stream in (self._process.stdout, self._process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
            if any(thread.is_alive() for thread in self._reader_threads):
                raise CancellableProcessStateError(
                    "Process output resources could not be cleaned up"
                )

    def _drain_stream(
        self,
        stream: IO[bytes],
        destination: bytearray,
        limit: int,
    ) -> None:
        try:
            while True:
                chunk = stream.read(_READ_SIZE)
                if not chunk:
                    return
                limit_exceeded = False
                with self._lock:
                    remaining = limit - len(destination)
                    if remaining > 0:
                        destination.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        self._output_limit_event.set()
                        limit_exceeded = True
                if limit_exceeded:
                    try:
                        self.terminate()
                    except CancellableProcessStateError:
                        self._reader_failure_event.set()
        except Exception:
            self._reader_failure_event.set()


class CancellableProcessExecutor:
    def __init__(
        self,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._monotonic_clock = monotonic_clock

    def start(
        self,
        request: CancellableProcessRequest,
    ) -> CancellableProcessHandle:
        if not isinstance(request, CancellableProcessRequest):
            raise InvalidCancellableProcessRequestError(
                "A valid cancellable process request is required"
            )
        if request.cwd is not None and (not request.cwd.exists() or not request.cwd.is_dir()):
            raise CancellableProcessStartError(
                "The requested process working directory is unavailable"
            )
        environment = None if request.environment is None else dict(request.environment)
        try:
            with ExitStack() as resources:
                if request.stdin_data is None:
                    stdin_stream: int | IO[bytes] = subprocess.DEVNULL
                else:
                    stdin_file = resources.enter_context(
                        tempfile.TemporaryFile(mode="w+b")
                    )
                    stdin_file.write(request.stdin_data)
                    stdin_file.flush()
                    stdin_file.seek(0)
                    stdin_stream = stdin_file

                process = subprocess.Popen(  # noqa: S603 - argv is a validated sequence
                    request.argv,
                    cwd=request.cwd,
                    env=environment,
                    stdin=stdin_stream,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                    bufsize=0,
                    start_new_session=os.name == "posix",
                )
        except (OSError, ValueError) as exc:
            raise CancellableProcessStartError(
                "The requested local process could not be started"
            ) from exc
        return _CancellableProcessHandle(
            process,
            request,
            self._monotonic_clock,
        )
