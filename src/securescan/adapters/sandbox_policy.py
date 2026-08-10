from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any

_MEBIBYTE = 1024 * 1024
_GIBIBYTE = 1024 * _MEBIBYTE
_ENVIRONMENT_NAME_PATTERN = re.compile(r"[A-Z_][A-Z0-9_]*\Z", re.ASCII)
_PROTECTED_WRITABLE_PATHS = (
    "/",
    "/dev",
    "/etc",
    "/proc",
    "/root",
    "/run",
    "/sys",
    "/var/run",
)


class InvalidSandboxPolicyError(ValueError):
    """Raised when a sandbox policy would weaken an execution invariant."""

    def __init__(self) -> None:
        super().__init__("Sandbox policy is invalid")


class SandboxNetworkMode(StrEnum):
    DISABLED = "disabled"


class SandboxSourceMountMode(StrEnum):
    READ_ONLY = "read_only"


class SandboxOutputMountMode(StrEnum):
    READ_WRITE = "read_write"


class SandboxExecutionBackend(StrEnum):
    TEST_ONLY = "test_only"
    DOCKER_SANDBOX = "docker_sandbox"


def _is_bounded_integer(value: object, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


@dataclass(frozen=True, slots=True)
class SandboxResourceLimits:
    timeout_seconds: int = 300
    termination_grace_seconds: int = 5
    cpu_count: float = 1.0
    memory_bytes: int = 1_073_741_824
    pids_limit: int = 128
    max_stdout_bytes: int = 2_000_000
    max_stderr_bytes: int = 1_000_000
    tmpfs_bytes: int = 268_435_456

    def __post_init__(self) -> None:
        valid = (
            _is_bounded_integer(self.timeout_seconds, 1, 3600)
            and _is_bounded_integer(self.termination_grace_seconds, 1, 30)
            and isinstance(self.cpu_count, (int, float))
            and not isinstance(self.cpu_count, bool)
            and 0 < self.cpu_count <= 8
            and _is_bounded_integer(self.memory_bytes, 64 * _MEBIBYTE, 8 * _GIBIBYTE)
            and _is_bounded_integer(self.pids_limit, 16, 1024)
            and _is_bounded_integer(
                self.max_stdout_bytes,
                1024,
                16 * _MEBIBYTE,
            )
            and _is_bounded_integer(
                self.max_stderr_bytes,
                1024,
                16 * _MEBIBYTE,
            )
            and _is_bounded_integer(
                self.tmpfs_bytes,
                16 * _MEBIBYTE,
                2 * _GIBIBYTE,
            )
        )
        if not valid:
            raise InvalidSandboxPolicyError
        object.__setattr__(self, "cpu_count", float(self.cpu_count))

    def canonical_data(self) -> dict[str, int | float]:
        return {
            "cpu_count": self.cpu_count,
            "max_stderr_bytes": self.max_stderr_bytes,
            "max_stdout_bytes": self.max_stdout_bytes,
            "memory_bytes": self.memory_bytes,
            "pids_limit": self.pids_limit,
            "termination_grace_seconds": self.termination_grace_seconds,
            "timeout_seconds": self.timeout_seconds,
            "tmpfs_bytes": self.tmpfs_bytes,
        }


def _normalize_string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, tuple) or any(not isinstance(item, str) for item in value):
        raise InvalidSandboxPolicyError
    return tuple(sorted(value))


def _is_protected_path(path: str) -> bool:
    return any(
        path == protected
        or (protected != "/" and path.startswith(f"{protected}/"))
        for protected in _PROTECTED_WRITABLE_PATHS
    )


@dataclass(frozen=True, slots=True)
class SandboxExecutionPolicy:
    backend: SandboxExecutionBackend = SandboxExecutionBackend.DOCKER_SANDBOX
    network_mode: SandboxNetworkMode = SandboxNetworkMode.DISABLED
    source_mount_mode: SandboxSourceMountMode = SandboxSourceMountMode.READ_ONLY
    output_mount_mode: SandboxOutputMountMode = SandboxOutputMountMode.READ_WRITE
    read_only_root_filesystem: bool = True
    run_as_non_root: bool = True
    run_as_uid: int = 65532
    run_as_gid: int = 65532
    drop_all_capabilities: bool = True
    no_new_privileges: bool = True
    allow_privilege_escalation: bool = False
    resources: SandboxResourceLimits = field(default_factory=SandboxResourceLimits)
    allowed_environment_names: tuple[str, ...] = ()
    writable_tmp_paths: tuple[str, ...] = ("/tmp",)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.backend, SandboxExecutionBackend)
            or self.network_mode is not SandboxNetworkMode.DISABLED
            or self.source_mount_mode is not SandboxSourceMountMode.READ_ONLY
            or self.output_mount_mode is not SandboxOutputMountMode.READ_WRITE
            or self.read_only_root_filesystem is not True
            or self.run_as_non_root is not True
            or not _is_bounded_integer(self.run_as_uid, 1, 2_147_483_647)
            or not _is_bounded_integer(self.run_as_gid, 1, 2_147_483_647)
            or self.drop_all_capabilities is not True
            or self.no_new_privileges is not True
            or self.allow_privilege_escalation is not False
            or not isinstance(self.resources, SandboxResourceLimits)
        ):
            raise InvalidSandboxPolicyError

        environment_names = _normalize_string_tuple(self.allowed_environment_names)
        if (
            len(set(environment_names)) != len(environment_names)
            or any(
                _ENVIRONMENT_NAME_PATTERN.fullmatch(name) is None
                for name in environment_names
            )
        ):
            raise InvalidSandboxPolicyError

        writable_paths = _normalize_string_tuple(self.writable_tmp_paths)
        if len(set(writable_paths)) != len(writable_paths):
            raise InvalidSandboxPolicyError
        for path in writable_paths:
            pure_path = PurePosixPath(path)
            normalized = str(pure_path)
            if (
                not path.startswith("/")
                or path.startswith("//")
                or normalized != path
                or ".." in pure_path.parts
                or any(ord(character) < 32 or ord(character) == 127 for character in path)
                or _is_protected_path(path)
            ):
                raise InvalidSandboxPolicyError

        object.__setattr__(self, "allowed_environment_names", environment_names)
        object.__setattr__(self, "writable_tmp_paths", writable_paths)

    def canonical_data(self) -> dict[str, Any]:
        return {
            "allow_privilege_escalation": self.allow_privilege_escalation,
            "allowed_environment_names": list(self.allowed_environment_names),
            "backend": self.backend.value,
            "drop_all_capabilities": self.drop_all_capabilities,
            "network_mode": self.network_mode.value,
            "no_new_privileges": self.no_new_privileges,
            "output_mount_mode": self.output_mount_mode.value,
            "read_only_root_filesystem": self.read_only_root_filesystem,
            "resources": self.resources.canonical_data(),
            "run_as_gid": self.run_as_gid,
            "run_as_non_root": self.run_as_non_root,
            "run_as_uid": self.run_as_uid,
            "source_mount_mode": self.source_mount_mode.value,
            "writable_tmp_paths": list(self.writable_tmp_paths),
        }

    def fingerprint(self) -> str:
        serialized = json.dumps(
            self.canonical_data(),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
