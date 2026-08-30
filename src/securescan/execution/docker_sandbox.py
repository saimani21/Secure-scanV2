from __future__ import annotations

import os
import re
import secrets
import subprocess
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, replace
from pathlib import Path
from threading import RLock
from typing import NoReturn, Protocol

from securescan.adapters.sandbox_policy import SandboxExecutionBackend
from securescan.adapters.trusted_registry import TrustedAdapterDefinition
from securescan.execution.cancellable_process import (
    CancellableProcessExecutor,
    CancellableProcessHandle,
    CancellableProcessRequest,
    CancellableProcessResult,
)

_DOCKER_EXECUTABLE = "docker"
_CONTROL_OUTPUT_LIMIT = 64 * 1024
_CONTROL_TIMEOUT_SECONDS = 5.0
_IMAGE_PATTERN = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z", re.ASCII)
_CONTAINER_NAME_PATTERN = re.compile(r"securescan-[a-z0-9][a-z0-9_.-]{7,52}\Z", re.ASCII)
_EXECUTION_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}\Z", re.ASCII)
_PROTECTED_HOST_PATHS = (
    Path("/"),
    Path("/dev"),
    Path("/etc"),
    Path("/proc"),
    Path("/root"),
    Path("/run"),
    Path("/sys"),
    Path("/var/run"),
)


class DockerSandboxError(RuntimeError):
    """Base class for sanitized Docker sandbox failures."""


class InvalidDockerSandboxRequestError(DockerSandboxError, ValueError):
    def __init__(self) -> None:
        super().__init__("Docker sandbox request is invalid")


class DockerUnavailableError(DockerSandboxError):
    def __init__(self) -> None:
        super().__init__("Docker sandbox service is unavailable")


class DockerImageUnavailableError(DockerSandboxError):
    def __init__(self) -> None:
        super().__init__("Trusted Docker sandbox image is unavailable")


class DockerContainerCreationError(DockerSandboxError):
    def __init__(self) -> None:
        super().__init__("Docker sandbox container could not be created")


class DockerContainerStartError(DockerSandboxError):
    def __init__(self) -> None:
        super().__init__("Docker sandbox container could not be started")


class DockerContainerInspectionError(DockerSandboxError):
    def __init__(self) -> None:
        super().__init__("Docker sandbox container state could not be verified")


class DockerContainerTerminationError(DockerSandboxError):
    def __init__(self) -> None:
        super().__init__("Docker sandbox container could not be terminated")


class DockerContainerCleanupError(DockerSandboxError):
    def __init__(self) -> None:
        super().__init__("Docker sandbox container could not be removed")


class DockerSandboxTimeoutError(DockerSandboxError):
    def __init__(self) -> None:
        super().__init__("Docker sandbox execution timed out")


class _DockerCommandFailure(RuntimeError):
    pass


def _contains_control_characters(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _validated_directory(value: object) -> Path:
    if not isinstance(value, Path) or not value.is_absolute() or value.is_symlink():
        raise InvalidDockerSandboxRequestError
    try:
        resolved = value.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise InvalidDockerSandboxRequestError from exc
    if not resolved.is_dir() or resolved in _PROTECTED_HOST_PATHS:
        raise InvalidDockerSandboxRequestError
    if any(
        protected != Path("/") and resolved.is_relative_to(protected)
        for protected in _PROTECTED_HOST_PATHS
    ):
        raise InvalidDockerSandboxRequestError
    if resolved.name == "docker.sock" or "," in str(resolved):
        raise InvalidDockerSandboxRequestError
    return resolved


def _normalized_environment(
    value: object,
    allowed_names: tuple[str, ...],
) -> tuple[tuple[str, str], ...]:
    if isinstance(value, Mapping):
        entries: object = tuple(value.items())
    else:
        entries = value
    if not isinstance(entries, tuple):
        raise InvalidDockerSandboxRequestError

    normalized: list[tuple[str, str]] = []
    seen: set[str] = set()
    for entry in entries:
        if (
            not isinstance(entry, tuple)
            or len(entry) != 2
            or not isinstance(entry[0], str)
            or not isinstance(entry[1], str)
        ):
            raise InvalidDockerSandboxRequestError
        name, environment_value = entry
        if (
            name not in allowed_names
            or name in seen
            or _contains_control_characters(environment_value)
        ):
            raise InvalidDockerSandboxRequestError
        seen.add(name)
        normalized.append((name, environment_value))
    return tuple(sorted(normalized))


@dataclass(frozen=True, slots=True)
class DockerSandboxExecutionRequest:
    definition: TrustedAdapterDefinition
    source_directory: Path
    output_directory: Path
    arguments: tuple[str, ...] = ()
    environment: Mapping[str, str] | tuple[tuple[str, str], ...] = ()
    execution_id: str | None = None

    def __post_init__(self) -> None:
        definition = self.definition
        try:
            validated_resources = replace(definition.policy.resources)
            validated_policy = replace(
                definition.policy,
                resources=validated_resources,
            )
            validated_definition = replace(
                definition,
                policy=validated_policy,
            )
        except Exception as exc:
            raise InvalidDockerSandboxRequestError from exc
        if (
            not isinstance(definition, TrustedAdapterDefinition)
            or validated_definition != definition
            or definition.backend is not SandboxExecutionBackend.DOCKER_SANDBOX
            or definition.policy.backend is not SandboxExecutionBackend.DOCKER_SANDBOX
            or definition.test_only
            or not isinstance(definition.image_reference, str)
            or _IMAGE_PATTERN.fullmatch(definition.image_reference) is None
            or not definition.command_prefix
        ):
            raise InvalidDockerSandboxRequestError

        source = _validated_directory(self.source_directory)
        output = _validated_directory(self.output_directory)
        if (
            source == output
            or output.is_relative_to(source)
            or source.is_relative_to(output)
        ):
            raise InvalidDockerSandboxRequestError

        if (
            not isinstance(self.arguments, tuple)
            or any(
                not isinstance(argument, str)
                or _contains_control_characters(argument)
                for argument in self.arguments
            )
        ):
            raise InvalidDockerSandboxRequestError

        environment = _normalized_environment(
            self.environment,
            definition.policy.allowed_environment_names,
        )
        if self.execution_id is not None and (
            not isinstance(self.execution_id, str)
            or _EXECUTION_ID_PATTERN.fullmatch(self.execution_id) is None
        ):
            raise InvalidDockerSandboxRequestError

        object.__setattr__(self, "source_directory", source)
        object.__setattr__(self, "output_directory", output)
        object.__setattr__(self, "environment", environment)


@dataclass(frozen=True, slots=True)
class DockerControlCommandResult:
    return_code: int
    stdout: bytes
    stderr: bytes


class DockerCommandRunner(Protocol):
    def run_control_command(
        self,
        argv: tuple[str, ...],
        timeout_seconds: float,
    ) -> DockerControlCommandResult: ...

    def start_attached(
        self,
        argv: tuple[str, ...],
        stdout_limit: int,
        stderr_limit: int,
        timeout_seconds: float,
    ) -> CancellableProcessHandle: ...


class DockerCliCommandRunner:
    def __init__(
        self,
        process_executor: CancellableProcessExecutor | None = None,
    ) -> None:
        self._process_executor = process_executor or CancellableProcessExecutor()

    @staticmethod
    def _validate_argv(argv: tuple[str, ...]) -> None:
        if (
            not isinstance(argv, tuple)
            or len(argv) < 2
            or argv[0] != _DOCKER_EXECUTABLE
            or any(not isinstance(argument, str) or "\0" in argument for argument in argv)
        ):
            raise InvalidDockerSandboxRequestError

    def run_control_command(
        self,
        argv: tuple[str, ...],
        timeout_seconds: float,
    ) -> DockerControlCommandResult:
        self._validate_argv(argv)
        completed = subprocess.run(  # noqa: S603 - fixed executable and argv-only commands
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            shell=False,
            timeout=timeout_seconds,
            check=False,
            close_fds=os.name == "posix",
        )
        return DockerControlCommandResult(
            return_code=completed.returncode,
            stdout=completed.stdout[:_CONTROL_OUTPUT_LIMIT],
            stderr=completed.stderr[:_CONTROL_OUTPUT_LIMIT],
        )

    def start_attached(
        self,
        argv: tuple[str, ...],
        stdout_limit: int,
        stderr_limit: int,
        timeout_seconds: float,
    ) -> CancellableProcessHandle:
        self._validate_argv(argv)
        return self._process_executor.start(
            CancellableProcessRequest(
                argv=argv,
                cwd=None,
                environment=None,
                timeout_seconds=timeout_seconds,
                stdout_limit_bytes=stdout_limit,
                stderr_limit_bytes=stderr_limit,
            )
        )


class DockerSandboxCommandBuilder:
    def build_create_command(
        self,
        request: DockerSandboxExecutionRequest,
        container_name: str,
    ) -> tuple[str, ...]:
        if not isinstance(request, DockerSandboxExecutionRequest):
            raise InvalidDockerSandboxRequestError
        if (
            not isinstance(container_name, str)
            or _CONTAINER_NAME_PATTERN.fullmatch(container_name) is None
        ):
            raise InvalidDockerSandboxRequestError

        definition = request.definition
        policy = definition.policy
        resources = policy.resources
        execution_id = request.execution_id or container_name.removeprefix("securescan-")
        command = [
            _DOCKER_EXECUTABLE,
            "create",
            "--pull",
            "never",
            "--name",
            container_name,
            "--label",
            "securescan.managed=true",
            "--label",
            f"securescan.execution={execution_id}",
            "--network",
            "none",
            "--read-only",
            "--user",
            f"{policy.run_as_uid}:{policy.run_as_gid}",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--pids-limit",
            str(resources.pids_limit),
            "--memory",
            str(resources.memory_bytes),
            "--memory-swap",
            str(resources.memory_bytes),
            "--cpus",
            format(resources.cpu_count, "g"),
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,size={resources.tmpfs_bytes}",
            "--mount",
            f"type=bind,src={request.source_directory},dst=/workspace/source,readonly",
            "--mount",
            f"type=bind,src={request.output_directory},dst=/workspace/output",
            "--workdir",
            "/workspace/source",
            "--init",
        ]
        for name, value in request.environment:
            command.extend(("--env", f"{name}={value}"))
        assert definition.image_reference is not None
        command.append(definition.image_reference)
        command.extend(definition.command_prefix)
        command.extend(request.arguments)
        return tuple(command)


def _new_container_name() -> str:
    return f"securescan-{secrets.token_hex(16)}"


class DockerSandboxExecutionHandle:
    def __init__(
        self,
        runner: DockerCommandRunner,
        request: DockerSandboxExecutionRequest,
        container_name: str,
        attached_handle: CancellableProcessHandle,
        monotonic_clock: Callable[[], float],
        sleeper: Callable[[float], None],
    ) -> None:
        self._runner = runner
        self._request = request
        self._container_name = container_name
        self._attached_handle = attached_handle
        self._monotonic_clock = monotonic_clock
        self._sleeper = sleeper
        self._started_at = monotonic_clock()
        self._lock = RLock()
        self._result: CancellableProcessResult | None = None
        self._error: DockerSandboxError | None = None
        self._cleaned = False
        self._closed = False

    def __enter__(self) -> DockerSandboxExecutionHandle:
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    def _control(
        self,
        argv: tuple[str, ...],
        timeout_seconds: float = _CONTROL_TIMEOUT_SECONDS,
    ) -> DockerControlCommandResult:
        return self._runner.run_control_command(argv, timeout_seconds)

    def _is_running(self) -> bool:
        try:
            result = self._control(
                (
                    _DOCKER_EXECUTABLE,
                    "inspect",
                    "--format",
                    "{{.State.Running}}",
                    self._container_name,
                )
            )
        except Exception as exc:
            raise DockerContainerInspectionError from exc
        if result.return_code != 0:
            return False
        value = result.stdout.decode("ascii", errors="ignore").strip().lower()
        if value not in {"true", "false"}:
            raise DockerContainerInspectionError
        return value == "true"

    def _inspect_exit_code(self) -> int:
        try:
            result = self._control(
                (
                    _DOCKER_EXECUTABLE,
                    "inspect",
                    "--format",
                    "{{.State.Running}}|{{.State.ExitCode}}",
                    self._container_name,
                )
            )
        except Exception as exc:
            raise DockerContainerInspectionError from exc
        if result.return_code != 0:
            raise DockerContainerInspectionError
        try:
            running_text, exit_code_text = (
                result.stdout.decode("ascii", errors="strict").strip().split("|", 1)
            )
            if running_text not in {"true", "false"} or running_text == "true":
                raise ValueError
            return int(exit_code_text)
        except (UnicodeDecodeError, ValueError) as exc:
            raise DockerContainerInspectionError from exc

    def _kill_container(self) -> None:
        try:
            result = self._control(
                (_DOCKER_EXECUTABLE, "kill", self._container_name),
            )
            if result.return_code != 0 and self._is_running():
                raise _DockerCommandFailure
        except DockerSandboxError:
            raise
        except Exception as exc:
            raise DockerContainerTerminationError from exc

    def _stop_container(self) -> None:
        grace = self._request.definition.policy.resources.termination_grace_seconds
        try:
            result = self._control(
                (
                    _DOCKER_EXECUTABLE,
                    "stop",
                    "--time",
                    str(grace),
                    self._container_name,
                ),
                grace + _CONTROL_TIMEOUT_SECONDS,
            )
            if result.return_code != 0 or self._is_running():
                self._kill_container()
        except DockerSandboxError:
            raise
        except Exception as exc:
            raise DockerContainerTerminationError from exc

    def _cleanup(self) -> None:
        if self._cleaned:
            return
        try:
            self._control(
                (_DOCKER_EXECUTABLE, "rm", "--force", self._container_name),
            )
            inspect_result = self._control(
                (_DOCKER_EXECUTABLE, "inspect", self._container_name),
            )
            if inspect_result.return_code == 0:
                raise _DockerCommandFailure
        except Exception as exc:
            raise DockerContainerCleanupError from exc
        self._cleaned = True

    def _close_attached(self) -> None:
        try:
            self._attached_handle.close()
        except Exception as exc:
            raise DockerContainerCleanupError from exc

    @staticmethod
    def _controlled_result(
        result: CancellableProcessResult | None,
        *,
        force_killed: bool,
    ) -> CancellableProcessResult:
        if result is None:
            return CancellableProcessResult(
                return_code=-9 if force_killed else -15,
                stdout=b"",
                stderr=b"",
                duration_ms=0,
                timed_out=False,
                output_limit_exceeded=False,
                termination_requested=True,
                force_killed=force_killed,
            )
        return CancellableProcessResult(
            return_code=result.return_code,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_ms=result.duration_ms,
            timed_out=result.timed_out,
            output_limit_exceeded=result.output_limit_exceeded,
            termination_requested=True,
            force_killed=force_killed or result.force_killed,
        )

    def _finish_controlled_termination(self, *, force_killed: bool) -> None:
        try:
            if force_killed:
                self._attached_handle.kill()
            else:
                self._attached_handle.terminate()
            attached_result = self._attached_handle.wait(timeout_seconds=1)
            if attached_result is None:
                self._attached_handle.kill()
                force_killed = True
                attached_result = self._attached_handle.wait(timeout_seconds=1)
            self._result = self._controlled_result(
                attached_result,
                force_killed=force_killed,
            )
        except Exception as exc:
            raise DockerContainerTerminationError from exc
        finally:
            try:
                self._close_attached()
            finally:
                self._cleanup()

    def poll(self) -> CancellableProcessResult | None:
        with self._lock:
            if self._error is not None:
                raise self._error
            if self._result is not None:
                return self._result
            if self._closed:
                return self._result

            try:
                attached_result = self._attached_handle.poll()
            except Exception as exc:
                self._handle_start_failure(exc)

            timeout = self._request.definition.policy.resources.timeout_seconds
            if attached_result is None and self._monotonic_clock() - self._started_at >= timeout:
                self._handle_timeout()
            if attached_result is None:
                return None
            if attached_result.timed_out:
                self._handle_timeout()
            if attached_result.output_limit_exceeded:
                self._stop_container()
                self._finish_controlled_termination(force_killed=False)
                return self._result

            try:
                exit_code = self._inspect_exit_code()
            except DockerSandboxError as exc:
                self._handle_start_failure(exc)
            try:
                try:
                    self._close_attached()
                finally:
                    self._cleanup()
            except DockerSandboxError as exc:
                self._error = exc
                raise
            self._result = CancellableProcessResult(
                return_code=exit_code,
                stdout=attached_result.stdout,
                stderr=attached_result.stderr,
                duration_ms=attached_result.duration_ms,
                timed_out=False,
                output_limit_exceeded=False,
                termination_requested=attached_result.termination_requested,
                force_killed=attached_result.force_killed,
            )
            return self._result

    def _handle_start_failure(self, cause: Exception) -> NoReturn:
        lifecycle_error: DockerSandboxError | None = None
        try:
            if self._is_running():
                self._stop_container()
        except DockerSandboxError as exc:
            lifecycle_error = exc
        try:
            self._close_attached()
        except DockerSandboxError as exc:
            lifecycle_error = exc
        try:
            self._cleanup()
        except DockerSandboxError as exc:
            lifecycle_error = exc
        if lifecycle_error is not None:
            self._error = lifecycle_error
            raise lifecycle_error from cause
        error = DockerContainerStartError()
        error.__cause__ = cause
        self._error = error
        raise error

    def _handle_timeout(self) -> None:
        try:
            self._stop_container()
            self._finish_controlled_termination(force_killed=False)
        except DockerSandboxError as exc:
            self._error = exc
            raise
        error = DockerSandboxTimeoutError()
        self._error = error
        raise error

    def wait(
        self,
        timeout_seconds: float | None = None,
    ) -> CancellableProcessResult | None:
        if timeout_seconds is not None and (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds < 0
        ):
            raise InvalidDockerSandboxRequestError
        deadline = None if timeout_seconds is None else self._monotonic_clock() + timeout_seconds
        while True:
            result = self.poll()
            if result is not None:
                return result
            if deadline is not None and self._monotonic_clock() >= deadline:
                return None
            self._sleeper(0.01)

    def terminate(self) -> None:
        with self._lock:
            if self._result is not None or self._cleaned:
                return
            self._stop_container()
            self._finish_controlled_termination(force_killed=False)

    def kill(self) -> None:
        with self._lock:
            if self._result is not None or self._cleaned:
                return
            self._kill_container()
            self._finish_controlled_termination(force_killed=True)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                if self._result is None and not self._cleaned:
                    try:
                        self._stop_container()
                        self._finish_controlled_termination(force_killed=False)
                    finally:
                        if not self._cleaned:
                            self._cleanup()
                elif not self._cleaned:
                    self._cleanup()
            finally:
                self._closed = self._cleaned


class DockerSandboxExecutor:
    def __init__(
        self,
        runner: DockerCommandRunner | None = None,
        command_builder: DockerSandboxCommandBuilder | None = None,
        name_generator: Callable[[], str] = _new_container_name,
        monotonic_clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self._runner = runner or DockerCliCommandRunner()
        self._command_builder = command_builder or DockerSandboxCommandBuilder()
        self._name_generator = name_generator
        self._monotonic_clock = monotonic_clock
        self._sleeper = sleeper
        self._availability_verified = False

    def _verify_availability(self) -> None:
        if self._availability_verified:
            return
        try:
            result = self._runner.run_control_command(
                (
                    _DOCKER_EXECUTABLE,
                    "version",
                    "--format",
                    "{{.Server.Version}}",
                ),
                _CONTROL_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            raise DockerUnavailableError from exc
        if result.return_code != 0:
            raise DockerUnavailableError
        self._availability_verified = True

    def _verify_image(self, image_reference: str) -> None:
        try:
            result = self._runner.run_control_command(
                (
                    _DOCKER_EXECUTABLE,
                    "image",
                    "inspect",
                    "--format",
                    "{{.Id}}",
                    image_reference,
                ),
                _CONTROL_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            raise DockerImageUnavailableError from exc
        if result.return_code != 0:
            raise DockerImageUnavailableError

    def verify_runtime_prerequisites(
        self,
        definition: TrustedAdapterDefinition,
    ) -> None:
        """Verify Docker and a trusted pinned image without creating a container."""
        if (
            not isinstance(definition, TrustedAdapterDefinition)
            or definition.backend is not SandboxExecutionBackend.DOCKER_SANDBOX
            or definition.policy.backend
            is not SandboxExecutionBackend.DOCKER_SANDBOX
            or definition.test_only
            or not isinstance(definition.image_reference, str)
            or _IMAGE_PATTERN.fullmatch(definition.image_reference) is None
        ):
            raise InvalidDockerSandboxRequestError
        self._verify_availability()
        self._verify_image(definition.image_reference)

    def _best_effort_remove(self, container_name: str) -> None:
        with suppress(Exception):
            self._runner.run_control_command(
                (_DOCKER_EXECUTABLE, "rm", "--force", container_name),
                _CONTROL_TIMEOUT_SECONDS,
            )

    def _cleanup_after_failed_start(
        self,
        container_name: str,
        termination_grace_seconds: int,
    ) -> None:
        try:
            inspected = self._runner.run_control_command(
                (
                    _DOCKER_EXECUTABLE,
                    "inspect",
                    "--format",
                    "{{.State.Running}}",
                    container_name,
                ),
                _CONTROL_TIMEOUT_SECONDS,
            )
            running = inspected.return_code == 0 and inspected.stdout.strip() == b"true"
            if running:
                stopped = self._runner.run_control_command(
                    (
                        _DOCKER_EXECUTABLE,
                        "stop",
                        "--time",
                        str(termination_grace_seconds),
                        container_name,
                    ),
                    termination_grace_seconds + _CONTROL_TIMEOUT_SECONDS,
                )
                inspected = self._runner.run_control_command(
                    (
                        _DOCKER_EXECUTABLE,
                        "inspect",
                        "--format",
                        "{{.State.Running}}",
                        container_name,
                    ),
                    _CONTROL_TIMEOUT_SECONDS,
                )
                if stopped.return_code != 0 or (
                    inspected.return_code == 0 and inspected.stdout.strip() == b"true"
                ):
                    self._runner.run_control_command(
                        (_DOCKER_EXECUTABLE, "kill", container_name),
                        _CONTROL_TIMEOUT_SECONDS,
                    )
            self._runner.run_control_command(
                (_DOCKER_EXECUTABLE, "rm", "--force", container_name),
                _CONTROL_TIMEOUT_SECONDS,
            )
            confirmed = self._runner.run_control_command(
                (_DOCKER_EXECUTABLE, "inspect", container_name),
                _CONTROL_TIMEOUT_SECONDS,
            )
            if confirmed.return_code == 0:
                raise _DockerCommandFailure
        except DockerSandboxError:
            raise
        except Exception as exc:
            raise DockerContainerCleanupError from exc

    def start(
        self,
        request: DockerSandboxExecutionRequest,
    ) -> DockerSandboxExecutionHandle:
        if not isinstance(request, DockerSandboxExecutionRequest):
            raise InvalidDockerSandboxRequestError
        self._verify_availability()
        assert request.definition.image_reference is not None
        self._verify_image(request.definition.image_reference)
        try:
            container_name = self._name_generator()
            create_command = self._command_builder.build_create_command(
                request,
                container_name,
            )
        except Exception as exc:
            raise DockerContainerCreationError from exc
        try:
            create_result = self._runner.run_control_command(
                create_command,
                _CONTROL_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            self._best_effort_remove(container_name)
            raise DockerContainerCreationError from exc
        if create_result.return_code != 0:
            self._best_effort_remove(container_name)
            self._verify_image(request.definition.image_reference)
            raise DockerContainerCreationError

        resources = request.definition.policy.resources
        try:
            attached_handle = self._runner.start_attached(
                (_DOCKER_EXECUTABLE, "start", "--attach", container_name),
                resources.max_stdout_bytes,
                resources.max_stderr_bytes,
                resources.timeout_seconds,
            )
        except Exception as exc:
            try:
                self._cleanup_after_failed_start(
                    container_name,
                    resources.termination_grace_seconds,
                )
            except DockerSandboxError as cleanup_error:
                raise cleanup_error from exc
            raise DockerContainerStartError from exc
        return DockerSandboxExecutionHandle(
            self._runner,
            request,
            container_name,
            attached_handle,
            self._monotonic_clock,
            self._sleeper,
        )

    def execute(
        self,
        request: DockerSandboxExecutionRequest,
    ) -> CancellableProcessResult:
        handle = self.start(request)
        try:
            result = handle.wait()
            if result is None:
                raise DockerContainerStartError
            return result
        finally:
            handle.close()
