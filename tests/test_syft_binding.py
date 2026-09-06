from __future__ import annotations

import hashlib
import json
from importlib.metadata import version
from pathlib import Path

import pytest

from securescan.execution import CancellableProcessRequest, CancellableProcessResult
from securescan.scanners.syft import (
    SYFT_ARCHIVE_FILENAME,
    SYFT_ARCHIVE_SHA256,
    SYFT_CONFIG_SHA256,
    SYFT_EXECUTABLE_SHA256,
    SYFT_JSON_SCHEMA_VERSION,
    SYFT_PURL_DISTRIBUTION,
    SYFT_PURL_VERSION,
    SYFT_VERSION,
    SyftConfigurationIntegrityError,
    SyftExecutableIntegrityError,
    SyftNormalizationDependencyError,
    SyftVersionVerificationError,
    TrustedSyftBinding,
)
from securescan.scanners.syft import binding as syft_binding


def _write(path: Path, content: bytes, mode: int) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(mode)
    return hashlib.sha256(content).hexdigest()


def _binding(tmp_path: Path) -> TrustedSyftBinding:
    executable = tmp_path / "syft"
    config = tmp_path / "securescan-syft-v1.yaml"
    return TrustedSyftBinding(
        executable_path=executable,
        executable_sha256=_write(executable, b"syft", 0o700),
        config_path=config,
        config_sha256=_write(config, b"check-for-app-update: false\n", 0o600),
    )


def _result(
    *,
    version: str = SYFT_VERSION,
    application: str = "syft",
    schema: str = SYFT_JSON_SCHEMA_VERSION,
    platform: str = "linux/amd64",
    return_code: int = 0,
    stderr: bytes = b"",
) -> CancellableProcessResult:
    stdout = json.dumps(
        {
            "application": application,
            "platform": platform,
            "schemaVersion": schema,
            "version": version,
        }
    ).encode()
    return CancellableProcessResult(
        return_code=return_code,
        stdout=stdout,
        stderr=stderr,
        duration_ms=1,
        timed_out=False,
        output_limit_exceeded=False,
        termination_requested=False,
        force_killed=False,
    )


class _Handle:
    def __init__(self, result: CancellableProcessResult) -> None:
        self.result = result

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        pass

    def wait(self, timeout_seconds: float | None = None):
        assert timeout_seconds == 7.0
        return self.result

    def poll(self):
        return self.result


class _Executor:
    def __init__(self, result: CancellableProcessResult | None = None) -> None:
        self.result = result or _result()
        self.requests: list[CancellableProcessRequest] = []

    def start(self, request: CancellableProcessRequest) -> _Handle:
        self.requests.append(request)
        return _Handle(self.result)


def test_frozen_release_identity() -> None:
    assert SYFT_VERSION == "1.51.0"
    assert SYFT_ARCHIVE_FILENAME == "syft_1.51.0_linux_amd64.tar.gz"
    assert SYFT_ARCHIVE_SHA256 == "2a2e837a2c8d59ec9af5472ee22d3b04ee463c4e44476ecf993fd1e5ab6ebc7f"
    assert SYFT_EXECUTABLE_SHA256 == (
        "5a8b71e94f4607973145f02e27e01d50b9f7c7bc41e38d40b39606ad138b43b5"
    )
    assert SYFT_CONFIG_SHA256 == (
        "4cf5feb873a8eef91b81d9869c95f0b317357ef3e8c7aa4b859f60f435770875"
    )
    assert SYFT_PURL_DISTRIBUTION == "packageurl-python"
    assert SYFT_PURL_VERSION == "0.17.6"
    assert version(SYFT_PURL_DISTRIBUTION) == SYFT_PURL_VERSION


def test_wrong_purl_normalization_dependency_version_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(syft_binding, "version", lambda _distribution: "0.17.5")
    with pytest.raises(SyftNormalizationDependencyError):
        _binding(tmp_path)


def test_exact_version_is_verified_with_empty_environment(tmp_path: Path) -> None:
    executor = _Executor()
    binding = _binding(tmp_path)
    binding.verify_runtime(executor)
    assert len(executor.requests) == 1
    assert executor.requests[0].argv == (str(binding.executable_path), "version", "-o", "json")
    assert dict(executor.requests[0].environment or {}) == {}


@pytest.mark.parametrize(
    "result",
    [
        _result(version="1.50.0"),
        _result(application="not-syft"),
        _result(schema="16.1.9"),
        _result(platform="darwin/arm64"),
        _result(return_code=1),
        _result(stderr=b"diagnostic"),
    ],
)
def test_wrong_runtime_identity_fails_closed(
    tmp_path: Path, result: CancellableProcessResult
) -> None:
    with pytest.raises(SyftVersionVerificationError):
        _binding(tmp_path).verify_runtime(_Executor(result))


def test_binary_and_config_mismatch_fail_closed(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    binding.executable_path.write_bytes(b"changed")
    with pytest.raises(SyftExecutableIntegrityError):
        binding.verify_runtime(_Executor())
    binding = _binding(tmp_path)
    binding.config_path.write_bytes(b"changed")
    with pytest.raises(SyftConfigurationIntegrityError):
        binding.verify_runtime(_Executor())


def test_symlinks_and_unsafe_modes_fail_closed(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    binding.executable_path.unlink()
    target = tmp_path / "target"
    target.write_bytes(b"syft")
    target.chmod(0o700)
    binding.executable_path.symlink_to(target)
    with pytest.raises(SyftExecutableIntegrityError):
        binding.verify_runtime(_Executor())


def test_directory_command_contract_is_exact(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    root = tmp_path / "projection"
    root.mkdir()
    request = binding.authorize_directory_execution(root, _Executor())
    assert request.argv == (
        str(binding.executable_path),
        "scan",
        str(root),
        "--from",
        "dir",
        "--base-path",
        str(root),
        "--output",
        "syft-json",
        "--config",
        str(binding.config_path),
        "--quiet",
        "--parallelism",
        "4",
    )
    assert dict(request.environment or {}) == {}
    assert request.stdin_data is None
    assert request.timeout_seconds == 300
    assert request.stdout_limit_bytes == 100 * 1024 * 1024
    assert request.stderr_limit_bytes == 64 * 1024
    assert not any(value in request.argv for value in ("registry", "docker", "podman", "--enrich"))
