from importlib import import_module
from typing import TYPE_CHECKING, Any

from securescan.execution.cancellable_process import (
    CancellableProcessExecutor,
    CancellableProcessExecutorError,
    CancellableProcessHandle,
    CancellableProcessRequest,
    CancellableProcessResult,
    CancellableProcessStartError,
    CancellableProcessStateError,
    InvalidCancellableProcessRequestError,
)
from securescan.execution.docker_sandbox import (
    DockerCliCommandRunner,
    DockerCommandRunner,
    DockerContainerCleanupError,
    DockerContainerCreationError,
    DockerContainerInspectionError,
    DockerContainerStartError,
    DockerContainerTerminationError,
    DockerControlCommandResult,
    DockerImageUnavailableError,
    DockerSandboxCommandBuilder,
    DockerSandboxError,
    DockerSandboxExecutionHandle,
    DockerSandboxExecutionRequest,
    DockerSandboxExecutor,
    DockerSandboxTimeoutError,
    DockerUnavailableError,
    InvalidDockerSandboxRequestError,
)

if TYPE_CHECKING:
    from securescan.execution.supervisor import (
        AttemptBoundProcessExecutor,
        SupervisorAttemptIdentity,
        TrustedLocalProcessSupervisor,
    )


def __getattr__(name: str) -> Any:
    if name in {
        "AttemptBoundProcessExecutor",
        "SupervisorAttemptIdentity",
        "TrustedLocalProcessSupervisor",
    }:
        supervisor = import_module("securescan.execution.supervisor")
        return getattr(supervisor, name)
    raise AttributeError(name)

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
