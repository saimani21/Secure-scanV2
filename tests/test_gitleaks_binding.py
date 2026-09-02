from __future__ import annotations

import hashlib
import inspect
import json
import os
from collections.abc import Callable
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from securescan.execution import CancellableProcessRequest, CancellableProcessResult
from securescan.execution.cancellable_process import CancellableProcessExecutor
from securescan.scanners.gitleaks import (
    GITLEAKS_ARCHIVE_FILENAME,
    GITLEAKS_ARCHIVE_SHA256,
    GITLEAKS_EXECUTABLE_SHA256,
    GITLEAKS_SCANNER_ID,
    GITLEAKS_VERSION,
    GitleaksConfigurationIntegrityError,
    GitleaksExecutableIntegrityError,
    GitleaksVersionVerificationError,
    InvalidGitleaksBindingError,
    InvalidGitleaksExecutionRequestError,
    TrustedGitleaksBinding,
    build_gitleaks_binding_artifact,
    canonical_gitleaks_binding_artifact,
    create_default_gitleaks_binding,
)

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_PATH = ROOT / "benchmarks/gitleaks/gitleaks-binding-v1.json"
EXPECTED_BINDING_DIGEST = (
    "8d9f224e1c5ddabef508a26be2966f51dc2a9c2e5805ea3bffcf444b3cae9561"
)


def _result(
    *,
    stdout: bytes = b"8.30.1\n",
    stderr: bytes = b"",
    return_code: int = 0,
    timed_out: bool = False,
) -> CancellableProcessResult:
    return CancellableProcessResult(
        return_code=return_code,
        stdout=stdout,
        stderr=stderr,
        duration_ms=1,
        timed_out=timed_out,
        output_limit_exceeded=False,
        termination_requested=False,
        force_killed=False,
    )


class _Handle:
    def __init__(
        self,
        result: CancellableProcessResult | None,
        callback: Callable[[], None] | None = None,
    ) -> None:
        self._result = result
        self._callback = callback

    def __enter__(self) -> _Handle:
        return self

    def __exit__(self, *_exc_info: object) -> None:
        return None

    def wait(self, timeout_seconds: float | None = None) -> CancellableProcessResult | None:
        assert timeout_seconds == 7.0
        if self._callback is not None:
            self._callback()
        return self._result

    def poll(self) -> CancellableProcessResult | None:
        return self._result


class _Executor:
    def __init__(
        self,
        result: CancellableProcessResult | None = None,
        callback: Callable[[], None] | None = None,
    ) -> None:
        self._result = _result() if result is None else result
        self._callback = callback
        self.requests: list[CancellableProcessRequest] = []

    def start(self, request: CancellableProcessRequest) -> _Handle:
        self.requests.append(request)
        return _Handle(self._result, self._callback)


def _write(path: Path, content: bytes, mode: int) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(mode)
    return hashlib.sha256(content).hexdigest()


def _binding(
    tmp_path: Path,
    *,
    executable_content: bytes = b"trusted binary",
) -> TrustedGitleaksBinding:
    executable = tmp_path / "gitleaks"
    config = tmp_path / "securescan-gitleaks-v1.toml"
    ignore = tmp_path / "securescan-gitleaks-v1.ignore"
    return TrustedGitleaksBinding(
        executable_path=executable,
        executable_sha256=_write(executable, executable_content, 0o700),
        config_path=config,
        config_sha256=_write(config, b"[extend]\nuseDefault = true\n", 0o600),
        ignore_path=ignore,
        ignore_sha256=_write(ignore, b"# no entries\n", 0o600),
    )


def test_official_release_and_binary_identity_are_frozen() -> None:
    assert GITLEAKS_SCANNER_ID == "gitleaks"
    assert GITLEAKS_VERSION == "8.30.1"
    assert GITLEAKS_ARCHIVE_FILENAME == "gitleaks_8.30.1_linux_x64.tar.gz"
    assert GITLEAKS_ARCHIVE_SHA256 == (
        "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
    )
    assert GITLEAKS_EXECUTABLE_SHA256 == (
        "88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509"
    )


def test_expected_binary_and_exact_version_are_accepted(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    executor = _Executor()

    binding.verify_runtime(executor)

    assert len(executor.requests) == 1
    request = executor.requests[0]
    assert request.argv == (str(binding.executable_path), "version")
    assert request.cwd == binding.executable_path.parent
    assert dict(request.environment or {}) == {}
    assert request.timeout_seconds == 5.0


@pytest.mark.parametrize(
    "result",
    [
        _result(stdout=b"8.30.0\n"),
        _result(stdout=b"gitleaks version 8.30.1\n"),
        _result(stdout=b"8.30.1"),
        _result(stdout=b"8.30.1\nextra\n"),
        _result(stderr=b"unexpected diagnostic"),
        _result(return_code=1),
        _result(return_code=-15, timed_out=True),
    ],
)
def test_wrong_or_malformed_version_result_fails_closed(
    tmp_path: Path,
    result: CancellableProcessResult,
) -> None:
    with pytest.raises(GitleaksVersionVerificationError):
        _binding(tmp_path).verify_runtime(_Executor(result))


def test_missing_nonregular_symlink_and_untrusted_binary_are_rejected(
    tmp_path: Path,
) -> None:
    binding = _binding(tmp_path)
    binding.executable_path.unlink()
    with pytest.raises(GitleaksExecutableIntegrityError):
        binding.verify_runtime(_Executor())

    target = tmp_path / "target"
    target.write_bytes(b"trusted binary")
    target.chmod(0o700)
    binding.executable_path.symlink_to(target)
    with pytest.raises(GitleaksExecutableIntegrityError):
        binding.verify_runtime(_Executor())

    binding.executable_path.unlink()
    binding.executable_path.mkdir()
    with pytest.raises(GitleaksExecutableIntegrityError):
        binding.verify_runtime(_Executor())


def test_binary_mutation_during_version_verification_fails_closed(tmp_path: Path) -> None:
    binding = _binding(tmp_path)

    def mutate() -> None:
        binding.executable_path.write_bytes(b"hostile replacement")

    with pytest.raises(GitleaksExecutableIntegrityError):
        binding.verify_runtime(_Executor(callback=mutate))


def test_absolute_paths_and_fixed_identity_are_required(tmp_path: Path) -> None:
    trusted = _binding(tmp_path)
    values = {
        "executable_path": trusted.executable_path,
        "executable_sha256": trusted.executable_sha256,
        "config_path": trusted.config_path,
        "config_sha256": trusted.config_sha256,
        "ignore_path": trusted.ignore_path,
        "ignore_sha256": trusted.ignore_sha256,
    }
    for field in ("executable_path", "config_path", "ignore_path"):
        hostile = dict(values)
        hostile[field] = Path(hostile[field].name)
        with pytest.raises(InvalidGitleaksBindingError):
            TrustedGitleaksBinding(**hostile)  # type: ignore[arg-type]

    object.__setattr__(trusted, "scanner_id", "lookalike")
    with pytest.raises(InvalidGitleaksBindingError):
        trusted.canonical_data()


def test_configuration_and_ignore_digest_mismatches_fail_closed(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    binding.config_path.write_text("[extend]\nuseDefault = false\n", encoding="utf-8")
    with pytest.raises(GitleaksConfigurationIntegrityError):
        binding.build_current_snapshot_request(tmp_path)


def test_scan_request_rechecks_executable_digest(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    binding.executable_path.write_bytes(b"hostile replacement")

    with pytest.raises(GitleaksExecutableIntegrityError):
        binding.build_current_snapshot_request(tmp_path)

    binding = _binding(tmp_path)
    binding.ignore_path.write_text("hostile:fingerprint:1\n", encoding="utf-8")
    with pytest.raises(GitleaksConfigurationIntegrityError):
        binding.build_current_snapshot_request(tmp_path)


def test_current_snapshot_command_shape_is_exact_and_environment_is_empty(
    tmp_path: Path,
) -> None:
    binding = _binding(tmp_path)
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()

    request = binding.authorize_current_snapshot_execution(snapshot, _Executor())

    assert request.argv == (
        str(binding.executable_path),
        "dir",
        "--config",
        str(binding.config_path),
        "--gitleaks-ignore-path",
        str(binding.ignore_path),
        "--report-format",
        "json",
        "--report-path",
        "-",
        "--redact=100",
        "--ignore-gitleaks-allow",
        "--no-banner",
        "--no-color",
        "--log-level",
        "error",
        "--max-archive-depth",
        "0",
        "--max-decode-depth",
        "0",
        "--timeout",
        "295",
        "--exit-code",
        "1",
        str(snapshot),
    )
    assert request.cwd == binding.config_path.parent
    assert dict(request.environment or {}) == {}
    assert request.stdin_data is None
    assert request.timeout_seconds == 300.0
    assert request.stdout_limit_bytes == 64 * 1024 * 1024
    assert request.stderr_limit_bytes == 64 * 1024


def test_history_network_and_user_flag_expansion_are_impossible(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    request = binding.build_current_snapshot_request(snapshot)

    assert request.argv[1] == "dir"
    assert "git" not in request.argv
    assert "--log-opts" not in request.argv
    assert "clone" not in request.argv
    assert all("://" not in argument for argument in request.argv)
    assert tuple(inspect.signature(binding.build_current_snapshot_request).parameters) == (
        "snapshot_root",
    )


def test_start_uses_the_verified_request_and_returns_a_cancellable_handle(
    tmp_path: Path,
) -> None:
    binding = _binding(tmp_path)
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    executor = _Executor()

    handle = binding.start_current_snapshot_execution(snapshot, executor)

    assert isinstance(handle, _Handle)
    assert len(executor.requests) == 2
    assert executor.requests[0].argv == (str(binding.executable_path), "version")
    assert executor.requests[1].argv[1] == "dir"


def test_scan_root_must_be_an_existing_absolute_nonsymlink_directory(
    tmp_path: Path,
) -> None:
    binding = _binding(tmp_path)
    for invalid in (Path("relative"), tmp_path / "missing"):
        with pytest.raises(InvalidGitleaksExecutionRequestError):
            binding.build_current_snapshot_request(invalid)
    file_path = tmp_path / "file"
    file_path.write_text("not a root", encoding="utf-8")
    with pytest.raises(InvalidGitleaksExecutionRequestError):
        binding.build_current_snapshot_request(file_path)
    directory = tmp_path / "directory"
    directory.mkdir()
    link = tmp_path / "link"
    link.symlink_to(directory, target_is_directory=True)
    with pytest.raises(InvalidGitleaksExecutionRequestError):
        binding.build_current_snapshot_request(link)


def test_process_infrastructure_never_uses_a_shell() -> None:
    source = inspect.getsource(CancellableProcessExecutor.start)
    assert "shell=False" in source
    assert "shell=True" not in source


def test_binding_is_immutable_deterministic_and_path_independent(tmp_path: Path) -> None:
    first = _binding(tmp_path / "first")
    second = _binding(tmp_path / "second")

    assert first.binding_digest() == second.binding_digest()
    assert str(tmp_path) not in json.dumps(first.canonical_data())
    with pytest.raises(FrozenInstanceError):
        first.scanner_version = "8.30.0"  # type: ignore[misc]


def test_committed_artifact_is_canonical_and_contains_no_host_path() -> None:
    binding = create_default_gitleaks_binding(Path("/opt/securescan/bin/gitleaks"))
    artifact = build_gitleaks_binding_artifact(binding)

    assert binding.binding_digest() == EXPECTED_BINDING_DIGEST
    assert ARTIFACT_PATH.read_bytes() == canonical_gitleaks_binding_artifact(binding)
    assert artifact["binding_digest"] == EXPECTED_BINDING_DIGEST
    assert artifact["maturity"] == "detected"
    assert artifact["execution"] == {
        "archive_traversal": False,
        "current_snapshot_only": True,
        "history_scanning": False,
        "mode": "dir",
        "network_acquisition": False,
        "recursive_decoding": False,
        "repository_inline_allow_directives": False,
    }
    assert "/home/" not in ARTIFACT_PATH.read_text(encoding="utf-8")


def test_sensitive_process_output_is_never_copied_into_errors(tmp_path: Path) -> None:
    sensitive = b"credential-material-must-not-escape"
    with pytest.raises(GitleaksVersionVerificationError) as raised:
        _binding(tmp_path).verify_runtime(_Executor(_result(stdout=sensitive)))
    assert sensitive.decode("ascii") not in str(raised.value)
    assert str(tmp_path) not in str(raised.value)


def test_default_configuration_files_are_exact_and_nonexecutable() -> None:
    binding = create_default_gitleaks_binding(Path("/opt/securescan/bin/gitleaks"))
    assert hashlib.sha256(binding.config_path.read_bytes()).hexdigest() == (
        binding.config_sha256
    )
    assert hashlib.sha256(binding.ignore_path.read_bytes()).hexdigest() == (
        binding.ignore_sha256
    )
    assert not os.access(binding.config_path, os.X_OK)
    assert not os.access(binding.ignore_path, os.X_OK)
