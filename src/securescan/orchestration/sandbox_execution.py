from __future__ import annotations

from securescan.adapters.trusted_registry import TrustedAdapterDefinition
from securescan.execution.cancellable_process import CancellableProcessResult
from securescan.execution.docker_sandbox import (
    DockerCliCommandRunner,
    DockerCommandRunner,
    DockerContainerInspectionError,
    DockerContainerTerminationError,
    DockerControlCommandResult,
    DockerSandboxExecutionHandle,
    DockerSandboxExecutionRequest,
    DockerSandboxExecutor,
    DockerSandboxTimeoutError,
)
from securescan.scanners.semgrep.source_binding import TrustedSemgrepSourceBinding

from .execution import (
    SourceScannerAttemptRecord,
    SourceScannerAttemptService,
    SourceScannerExecutionConflictError,
)
from .execution_models import (
    AttemptContainmentOutcome,
    SourceSandboxCleanupReceipt,
    source_sandbox_execution_identity,
)

_DOCKER_EXECUTABLE = "docker"
_CONTROL_TIMEOUT_SECONDS = 5.0
_INSPECTION_FORMAT = (
    '{{.Name}}|{{index .Config.Labels "securescan.managed"}}|'
    '{{index .Config.Labels "securescan.execution"}}|{{.State.Running}}'
)
_ABSENCE_FORMAT = "{{.Names}}"


class AttemptBoundDockerExecutionHandle:
    """Persist sandbox cleanup only after the frozen handle proves removal."""

    def __init__(
        self,
        *,
        handle: DockerSandboxExecutionHandle,
        attempt: SourceScannerAttemptRecord,
        attempt_persistence: SourceScannerAttemptService,
    ) -> None:
        self._handle = handle
        self._attempt = attempt
        self._attempt_persistence = attempt_persistence
        self._cleanup_recorded = False

    def poll(self) -> CancellableProcessResult | None:
        try:
            result = self._handle.poll()
        except DockerSandboxTimeoutError:
            self._record_clean()
            raise
        if result is not None:
            self._record_clean()
        return result

    def wait(
        self, timeout_seconds: float | None = None
    ) -> CancellableProcessResult | None:
        try:
            result = self._handle.wait(timeout_seconds)
        except DockerSandboxTimeoutError:
            self._record_clean()
            raise
        if result is not None:
            self._record_clean()
        return result

    def terminate(self) -> None:
        self._handle.terminate()
        self._record_clean()

    def kill(self) -> None:
        self._handle.kill()
        self._record_clean()

    def close(self) -> None:
        self._handle.close()
        self._record_clean()

    def _record_clean(self) -> None:
        if self._cleanup_recorded:
            return
        self._attempt_persistence.record_sandbox_cleanup(
            _clean_receipt(self._attempt)
        )
        self._cleanup_recorded = True


class AttemptBoundDockerExecutor:
    """Bind the frozen Semgrep Docker lifecycle to one durable S6B attempt."""

    def __init__(
        self,
        *,
        attempt: SourceScannerAttemptRecord,
        attempt_persistence: SourceScannerAttemptService,
        binding: TrustedSemgrepSourceBinding,
        runner: DockerCommandRunner | None = None,
    ) -> None:
        if (
            not isinstance(attempt, SourceScannerAttemptRecord)
            or not isinstance(attempt_persistence, SourceScannerAttemptService)
            or not isinstance(binding, TrustedSemgrepSourceBinding)
        ):
            raise SourceScannerExecutionConflictError
        binding._validate_state()
        self._attempt = attempt
        self._attempt_persistence = attempt_persistence
        self._binding = binding
        self._sandbox_identity = source_sandbox_execution_identity(
            attempt.job_id,
            attempt.attempt_number,
            attempt.attempt_token,
        )
        self._executor = DockerSandboxExecutor(
            runner=runner,
            name_generator=lambda: self._sandbox_identity,
        )
        self._started = False

    def start(
        self, request: DockerSandboxExecutionRequest
    ) -> AttemptBoundDockerExecutionHandle:
        if (
            not isinstance(request, DockerSandboxExecutionRequest)
            or request.execution_id != self._attempt.job_id
            or self._started
        ):
            raise SourceScannerExecutionConflictError
        try:
            definition_matches = self._binding.matches_definition(request.definition)
        except Exception as exc:
            raise SourceScannerExecutionConflictError from exc
        if not definition_matches:
            raise SourceScannerExecutionConflictError
        self._started = True
        handle = self._executor.start(request)
        return AttemptBoundDockerExecutionHandle(
            handle=handle,
            attempt=self._attempt,
            attempt_persistence=self._attempt_persistence,
        )

    def execute(
        self, request: DockerSandboxExecutionRequest
    ) -> CancellableProcessResult:
        handle = self.start(request)
        try:
            result = handle.wait()
            if result is None:
                raise SourceScannerExecutionConflictError
            return result
        finally:
            handle.close()


class SourceSandboxReconciliationService:
    """Reconcile only the deterministic Docker sandbox owned by one attempt."""

    def __init__(
        self,
        *,
        attempt_persistence: SourceScannerAttemptService,
        binding: TrustedSemgrepSourceBinding,
        definition: TrustedAdapterDefinition,
        runner: DockerCommandRunner | None = None,
    ) -> None:
        if (
            not isinstance(attempt_persistence, SourceScannerAttemptService)
            or not isinstance(binding, TrustedSemgrepSourceBinding)
            or not isinstance(definition, TrustedAdapterDefinition)
        ):
            raise SourceScannerExecutionConflictError
        try:
            definition_matches = binding.matches_definition(definition)
        except Exception as exc:
            raise SourceScannerExecutionConflictError from exc
        if not definition_matches:
            raise SourceScannerExecutionConflictError
        self._attempt_persistence = attempt_persistence
        self._runner = runner or DockerCliCommandRunner()
        self._termination_grace_seconds = (
            definition.policy.resources.termination_grace_seconds
        )

    def reconcile(
        self, attempt: SourceScannerAttemptRecord
    ) -> SourceScannerAttemptRecord:
        if not isinstance(attempt, SourceScannerAttemptRecord):
            raise SourceScannerExecutionConflictError
        name = source_sandbox_execution_identity(
            attempt.job_id,
            attempt.attempt_number,
            attempt.attempt_token,
        )
        inspected = self._control(
            (
                _DOCKER_EXECUTABLE,
                "inspect",
                "--format",
                _INSPECTION_FORMAT,
                name,
            )
        )
        if inspected.return_code == 0:
            expected_prefix = f"/{name}|true|{attempt.job_id}|"
            try:
                text = inspected.stdout.decode("ascii", errors="strict").strip()
            except UnicodeDecodeError as exc:
                raise DockerContainerInspectionError from exc
            if not text.startswith(expected_prefix):
                raise DockerContainerInspectionError
            running = text.removeprefix(expected_prefix)
            if running not in {"true", "false"}:
                raise DockerContainerInspectionError
            if running == "true":
                stopped = self._control(
                    (
                        _DOCKER_EXECUTABLE,
                        "stop",
                        "--time",
                        str(self._termination_grace_seconds),
                        name,
                    ),
                    timeout_seconds=(
                        self._termination_grace_seconds + _CONTROL_TIMEOUT_SECONDS
                    ),
                )
                if stopped.return_code != 0:
                    killed = self._control((_DOCKER_EXECUTABLE, "kill", name))
                    if killed.return_code != 0:
                        raise DockerContainerTerminationError
            removed = self._control((_DOCKER_EXECUTABLE, "rm", "--force", name))
            if removed.return_code != 0:
                raise DockerContainerTerminationError
        self._prove_absent(name)
        return self._attempt_persistence.record_sandbox_cleanup(
            _clean_receipt(attempt)
        )

    def _prove_absent(self, name: str) -> None:
        result = self._control(
            (
                _DOCKER_EXECUTABLE,
                "ps",
                "-a",
                "--no-trunc",
                "--filter",
                f"name=^/{name}$",
                "--format",
                _ABSENCE_FORMAT,
            )
        )
        if result.return_code != 0 or result.stdout.strip():
            raise DockerContainerInspectionError

    def _control(
        self,
        argv: tuple[str, ...],
        timeout_seconds: float = _CONTROL_TIMEOUT_SECONDS,
    ) -> DockerControlCommandResult:
        try:
            return self._runner.run_control_command(argv, timeout_seconds)
        except (DockerContainerInspectionError, DockerContainerTerminationError):
            raise
        except Exception as exc:
            raise DockerContainerInspectionError from exc


def _clean_receipt(attempt: SourceScannerAttemptRecord) -> SourceSandboxCleanupReceipt:
    return SourceSandboxCleanupReceipt(
        job_id=attempt.job_id,
        attempt_number=attempt.attempt_number,
        attempt_token=attempt.attempt_token,
        execution_backend="docker-sandbox",
        execution_id=attempt.job_id,
        sandbox_identity=source_sandbox_execution_identity(
            attempt.job_id,
            attempt.attempt_number,
            attempt.attempt_token,
        ),
        cleanup_outcome=AttemptContainmentOutcome.CLEAN,
        execution_removed=True,
    )
