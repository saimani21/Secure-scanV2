from importlib import import_module
from typing import Any

from .cancellable_process import (
    CancellableProcessExecutor,
    CancellableProcessExecutorError,
    CancellableProcessHandle,
    CancellableProcessRequest,
    CancellableProcessResult,
    CancellableProcessStartError,
    CancellableProcessStateError,
    InvalidCancellableProcessRequestError,
)

_SUPERVISOR_EXPORTS = {
    "AttemptBoundProcessExecutor",
    "SupervisorAttemptIdentity",
    "TrustedLocalProcessSupervisor",
}
_DOCKER_EXPORTS = {
    "DockerCliCommandRunner",
    "DockerCommandRunner",
    "DockerContainerCleanupError",
    "DockerContainerCreationError",
    "DockerContainerInspectionError",
    "DockerContainerStartError",
    "DockerContainerTerminationError",
    "DockerControlCommandResult",
    "DockerImageUnavailableError",
    "DockerSandboxCommandBuilder",
    "DockerSandboxError",
    "DockerSandboxExecutionHandle",
    "DockerSandboxExecutionRequest",
    "DockerSandboxExecutor",
    "DockerSandboxTimeoutError",
    "DockerUnavailableError",
    "InvalidDockerSandboxRequestError",
}


def __getattr__(name: str) -> Any:
    if name in _SUPERVISOR_EXPORTS:
        module = import_module("securescan.execution.supervisor")
    elif name in _DOCKER_EXPORTS:
        module = import_module("securescan.execution.docker_sandbox")
    else:
        raise AttributeError(name)
    value = getattr(module, name)
    globals()[name] = value
    return value


__all__ = [
    "CancellableProcessExecutor",
    "CancellableProcessExecutorError",
    "CancellableProcessHandle",
    "CancellableProcessRequest",
    "CancellableProcessResult",
    "CancellableProcessStartError",
    "CancellableProcessStateError",
    "InvalidCancellableProcessRequestError",
    "DockerCliCommandRunner",
    "DockerCommandRunner",
    "DockerContainerCleanupError",
    "DockerContainerCreationError",
    "DockerContainerInspectionError",
    "DockerContainerStartError",
    "DockerContainerTerminationError",
    "DockerControlCommandResult",
    "DockerImageUnavailableError",
    "DockerSandboxCommandBuilder",
    "DockerSandboxError",
    "DockerSandboxExecutionHandle",
    "DockerSandboxExecutionRequest",
    "DockerSandboxExecutor",
    "DockerSandboxTimeoutError",
    "DockerUnavailableError",
    "InvalidDockerSandboxRequestError",
    "AttemptBoundProcessExecutor",
    "SupervisorAttemptIdentity",
    "TrustedLocalProcessSupervisor",
]
