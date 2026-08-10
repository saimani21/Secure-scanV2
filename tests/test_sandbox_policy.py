from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace

import pytest

from securescan.adapters.sandbox_policy import (
    InvalidSandboxPolicyError,
    SandboxExecutionPolicy,
    SandboxNetworkMode,
    SandboxResourceLimits,
    SandboxSourceMountMode,
)


def test_default_sandbox_policy_is_locked_down() -> None:
    policy = SandboxExecutionPolicy()

    assert policy.network_mode is SandboxNetworkMode.DISABLED
    assert policy.source_mount_mode is SandboxSourceMountMode.READ_ONLY
    assert policy.read_only_root_filesystem is True
    assert policy.run_as_non_root is True
    assert policy.run_as_uid > 0
    assert policy.run_as_gid > 0
    assert policy.drop_all_capabilities is True
    assert policy.no_new_privileges is True
    assert policy.allow_privilege_escalation is False
    assert 1 <= policy.resources.timeout_seconds <= 3600
    assert 64 * 1024 * 1024 <= policy.resources.memory_bytes <= 8 * 1024**3
    assert 16 <= policy.resources.pids_limit <= 1024


def test_sandbox_policy_is_immutable() -> None:
    policy = SandboxExecutionPolicy(
        allowed_environment_names=("LANG",),
        writable_tmp_paths=("/tmp", "/workspace-output"),
    )

    with pytest.raises(FrozenInstanceError):
        policy.run_as_uid = 1  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        policy.resources.timeout_seconds = 1  # type: ignore[misc]
    with pytest.raises(TypeError):
        policy.allowed_environment_names[0] = "PATH"  # type: ignore[index]
    with pytest.raises(TypeError):
        policy.writable_tmp_paths[0] = "/"  # type: ignore[index]


def test_sandbox_policy_rejects_unsafe_identity_and_privilege_values() -> None:
    unsafe_values = (
        {"run_as_uid": 0},
        {"run_as_gid": 0},
        {"run_as_non_root": False},
        {"read_only_root_filesystem": False},
        {"drop_all_capabilities": False},
        {"no_new_privileges": False},
        {"allow_privilege_escalation": True},
    )

    for changes in unsafe_values:
        with pytest.raises(InvalidSandboxPolicyError):
            SandboxExecutionPolicy(**changes)


def test_sandbox_policy_rejects_invalid_resource_limits() -> None:
    invalid_limits = (
        {"timeout_seconds": 0},
        {"timeout_seconds": 3601},
        {"termination_grace_seconds": 31},
        {"cpu_count": 0},
        {"cpu_count": 9},
        {"memory_bytes": 64 * 1024 * 1024 - 1},
        {"memory_bytes": 8 * 1024**3 + 1},
        {"pids_limit": 15},
        {"max_stdout_bytes": 1023},
        {"max_stderr_bytes": 16 * 1024 * 1024 + 1},
        {"tmpfs_bytes": 16 * 1024 * 1024 - 1},
        {"timeout_seconds": True},
        {"cpu_count": False},
    )

    for changes in invalid_limits:
        with pytest.raises(InvalidSandboxPolicyError):
            SandboxResourceLimits(**changes)


def test_sandbox_policy_rejects_unsafe_environment_and_paths() -> None:
    invalid_values = (
        {"allowed_environment_names": ("lowercase",)},
        {"allowed_environment_names": ("LANG", "LANG")},
        {"writable_tmp_paths": ("relative",)},
        {"writable_tmp_paths": ("/",)},
        {"writable_tmp_paths": ("/etc",)},
        {"writable_tmp_paths": ("/proc/child",)},
        {"writable_tmp_paths": ("/run",)},
        {"writable_tmp_paths": ("/tmp/../etc",)},
        {"writable_tmp_paths": ("/tmp/\0hidden",)},
        {"writable_tmp_paths": ("/tmp", "/tmp")},
    )

    for changes in invalid_values:
        with pytest.raises(InvalidSandboxPolicyError):
            SandboxExecutionPolicy(**changes)


def test_sandbox_policy_fingerprint_is_deterministic_and_sensitive() -> None:
    first = SandboxExecutionPolicy(
        allowed_environment_names=("TZ", "LANG"),
        writable_tmp_paths=("/workspace-output", "/tmp"),
    )
    second = SandboxExecutionPolicy(
        allowed_environment_names=("LANG", "TZ"),
        writable_tmp_paths=("/tmp", "/workspace-output"),
    )
    changed = replace(
        first,
        resources=replace(first.resources, timeout_seconds=first.resources.timeout_seconds + 1),
    )

    assert first.canonical_data() == second.canonical_data()
    assert first.fingerprint() == second.fingerprint()
    assert first.fingerprint() != changed.fingerprint()
    serialized = json.dumps(first.canonical_data(), sort_keys=True)
    assert "function" not in serialized
    assert " object at 0x" not in serialized
