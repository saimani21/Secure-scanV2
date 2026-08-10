from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from securescan.execution import (
    CancellableProcessRequest,
    CancellableProcessResult,
)
from securescan.source.enry_client import (
    EnryBatchResult,
    EnryClient,
    EnryHelperExecutionError,
    EnryHelperIntegrityError,
    EnryHelperOutputLimitError,
    EnryHelperTimeoutError,
    InvalidEnryClientConfigurationError,
    TrustedEnryHelper,
)
from securescan.source.enry_protocol import (
    ENRY_HELPER_VERSION,
    ENRY_LIBRARY_VERSION,
    ENRY_SCHEMA_VERSION,
    EnryFileInput,
    EnryProtocolError,
)

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_LOCAL_HELPER = _PROJECT_ROOT / "tools/enry-helper/bin/securescan-enry-helper"


def _helper_response(
    *,
    helper_version: str = ENRY_HELPER_VERSION,
) -> bytes:
    return (
        json.dumps(
            {
                "candidate_languages": ["Python"],
                "enry_version": ENRY_LIBRARY_VERSION,
                "helper_version": helper_version,
                "is_binary": False,
                "is_configuration": False,
                "is_documentation": False,
                "is_dot_file": False,
                "is_generated": False,
                "is_image": False,
                "is_test": False,
                "is_vendor": False,
                "language": "Python",
                "ok": True,
                "relative_path": "src/app.py",
                "request_id": "file-00000000",
                "schema_version": ENRY_SCHEMA_VERSION,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


def _process_result(
    *,
    return_code: int = 0,
    stdout: bytes | None = None,
    stderr: bytes = b"",
    timed_out: bool = False,
    output_limit_exceeded: bool = False,
    termination_requested: bool = False,
    force_killed: bool = False,
) -> CancellableProcessResult:
    return CancellableProcessResult(
        return_code=return_code,
        stdout=_helper_response() if stdout is None else stdout,
        stderr=stderr,
        duration_ms=12,
        timed_out=timed_out,
        output_limit_exceeded=output_limit_exceeded,
        termination_requested=termination_requested,
        force_killed=force_killed,
    )


class _FakeHandle:
    def __init__(
        self,
        result: CancellableProcessResult | None,
        on_wait: Callable[[], None] | None = None,
        poll_result: CancellableProcessResult | None = None,
    ) -> None:
        self.result = result
        self.on_wait = on_wait
        self.poll_result = poll_result
        self.wait_timeout_seconds: float | None = None

    def __enter__(self) -> _FakeHandle:
        return self

    def __exit__(self, *_exc_info: object) -> None:
        return None

    def wait(
        self,
        timeout_seconds: float | None = None,
    ) -> CancellableProcessResult | None:
        self.wait_timeout_seconds = timeout_seconds
        if self.on_wait is not None:
            self.on_wait()
        return self.result

    def poll(self) -> CancellableProcessResult | None:
        return self.poll_result


class _FakeExecutor:
    def __init__(
        self,
        result: CancellableProcessResult | None = None,
        *,
        on_wait: Callable[[], None] | None = None,
        start_error: Exception | None = None,
    ) -> None:
        self.handle = _FakeHandle(
            _process_result() if result is None else result,
            on_wait,
        )
        self.start_error = start_error
        self.requests: list[CancellableProcessRequest] = []

    def start(self, request: CancellableProcessRequest) -> _FakeHandle:
        self.requests.append(request)
        if self.start_error is not None:
            raise self.start_error
        return self.handle


def _trusted_helper(
    tmp_path: Path,
    *,
    content: bytes = b"trusted helper executable",
    mode: int = 0o700,
    path_name: str = "enry-helper",
) -> tuple[Path, TrustedEnryHelper]:
    helper_path = tmp_path / path_name
    helper_path.write_bytes(content)
    helper_path.chmod(mode)
    digest = hashlib.sha256(content).hexdigest()
    return helper_path, TrustedEnryHelper(
        helper_path=helper_path,
        expected_sha256=digest,
    )


def _files() -> tuple[EnryFileInput, ...]:
    return (EnryFileInput("src/app.py", b"print('sensitive-value')\n"),)


def test_client_uses_exact_path_empty_environment_and_stdin_only(
    tmp_path: Path,
) -> None:
    helper_path, configuration = _trusted_helper(tmp_path)
    executor = _FakeExecutor()

    result = EnryClient(configuration, executor).classify(_files())

    request = executor.requests[0]
    assert request.argv == (str(helper_path),)
    assert request.cwd == helper_path.parent
    assert request.environment == {}
    assert request.stdin_data is not None
    assert b"sensitive-value" not in request.stdin_data
    assert all("sensitive-value" not in argument for argument in request.argv)
    assert dict(request.environment) == {}
    assert executor.handle.wait_timeout_seconds == configuration.timeout_seconds + 2
    assert result.classifications[0].language == "Python"


def test_valid_execution_returns_immutable_canonical_batch(
    tmp_path: Path,
) -> None:
    _, configuration = _trusted_helper(tmp_path)

    result = EnryClient(configuration, _FakeExecutor()).classify(_files())

    assert isinstance(result, EnryBatchResult)
    assert result.helper_sha256 == configuration.expected_sha256
    assert result.helper_version == ENRY_HELPER_VERSION
    assert result.enry_version == ENRY_LIBRARY_VERSION
    assert result.duration_ms == 12
    with pytest.raises(FrozenInstanceError):
        result.duration_ms = 13  # type: ignore[misc]


def test_client_exposes_immutable_configuration(tmp_path: Path) -> None:
    _, configuration = _trusted_helper(tmp_path)
    client = EnryClient(configuration, _FakeExecutor())

    assert client.configuration is configuration
    with pytest.raises(FrozenInstanceError):
        client.configuration.timeout_seconds = 1  # type: ignore[misc]


def test_wrong_digest_is_rejected_before_execution(tmp_path: Path) -> None:
    helper_path, _ = _trusted_helper(tmp_path)
    configuration = TrustedEnryHelper(
        helper_path=helper_path,
        expected_sha256="0" * 64,
    )
    executor = _FakeExecutor()

    with pytest.raises(EnryHelperIntegrityError) as raised:
        EnryClient(configuration, executor).classify(_files())

    assert executor.requests == []
    assert str(helper_path) not in str(raised.value)
    assert configuration.expected_sha256 not in str(raised.value)


def test_symlink_helper_is_rejected(tmp_path: Path) -> None:
    target_path, target_configuration = _trusted_helper(tmp_path)
    link_path = tmp_path / "helper-link"
    link_path.symlink_to(target_path)
    configuration = TrustedEnryHelper(
        helper_path=link_path,
        expected_sha256=target_configuration.expected_sha256,
    )
    executor = _FakeExecutor()

    with pytest.raises(EnryHelperIntegrityError):
        EnryClient(configuration, executor).classify(_files())

    assert executor.requests == []


@pytest.mark.parametrize("mode", [0o600, 0o720, 0o702])
def test_unsafe_helper_modes_are_rejected(tmp_path: Path, mode: int) -> None:
    _, configuration = _trusted_helper(tmp_path, mode=mode)
    executor = _FakeExecutor()

    with pytest.raises(EnryHelperIntegrityError):
        EnryClient(configuration, executor).classify(_files())

    assert executor.requests == []


@pytest.mark.parametrize(
    ("result", "error_type"),
    [
        (
            _process_result(
                return_code=-15,
                timed_out=True,
                termination_requested=True,
            ),
            EnryHelperTimeoutError,
        ),
        (
            _process_result(
                return_code=-15,
                output_limit_exceeded=True,
                termination_requested=True,
            ),
            EnryHelperOutputLimitError,
        ),
        (_process_result(return_code=2), EnryHelperExecutionError),
        (
            _process_result(return_code=0, termination_requested=True),
            EnryHelperExecutionError,
        ),
        (_process_result(return_code=0, force_killed=True), EnryHelperExecutionError),
        (_process_result(return_code=0, stderr=b"unsafe stderr"), EnryHelperExecutionError),
    ],
)
def test_execution_failures_are_mapped(
    tmp_path: Path,
    result: CancellableProcessResult,
    error_type: type[EnryHelperExecutionError],
) -> None:
    _, configuration = _trusted_helper(tmp_path)

    with pytest.raises(error_type):
        EnryClient(configuration, _FakeExecutor(result)).classify(_files())


def test_missing_final_result_is_an_execution_error(tmp_path: Path) -> None:
    _, configuration = _trusted_helper(tmp_path)
    executor = _FakeExecutor()
    executor.handle.result = None

    with pytest.raises(EnryHelperExecutionError):
        EnryClient(configuration, executor).classify(_files())


@pytest.mark.parametrize(
    ("final_result", "error_type"),
    [
        (
            _process_result(
                return_code=-9,
                timed_out=True,
                termination_requested=True,
                force_killed=True,
            ),
            EnryHelperTimeoutError,
        ),
        (
            _process_result(
                return_code=-9,
                output_limit_exceeded=True,
                termination_requested=True,
                force_killed=True,
            ),
            EnryHelperOutputLimitError,
        ),
    ],
)
def test_cleanup_final_result_preserves_specific_failure(
    tmp_path: Path,
    final_result: CancellableProcessResult,
    error_type: type[EnryHelperExecutionError],
) -> None:
    _, configuration = _trusted_helper(tmp_path)
    executor = _FakeExecutor()
    executor.handle.result = None
    executor.handle.poll_result = final_result

    with pytest.raises(error_type):
        EnryClient(configuration, executor).classify(_files())


def test_helper_mutation_during_execution_is_detected(tmp_path: Path) -> None:
    helper_path, configuration = _trusted_helper(tmp_path)

    def mutate_helper() -> None:
        helper_path.write_bytes(b"mutated helper")

    executor = _FakeExecutor(on_wait=mutate_helper)

    with pytest.raises(EnryHelperIntegrityError):
        EnryClient(configuration, executor).classify(_files())


def test_helper_replacement_during_execution_is_detected(tmp_path: Path) -> None:
    helper_content = b"trusted helper executable"
    helper_path, configuration = _trusted_helper(
        tmp_path,
        content=helper_content,
    )

    def replace_helper() -> None:
        replacement = tmp_path / "replacement"
        replacement.write_bytes(helper_content)
        replacement.chmod(0o700)
        os.replace(replacement, helper_path)

    executor = _FakeExecutor(on_wait=replace_helper)

    with pytest.raises(EnryHelperIntegrityError):
        EnryClient(configuration, executor).classify(_files())


def test_protocol_mismatch_remains_an_explicit_protocol_error(
    tmp_path: Path,
) -> None:
    _, configuration = _trusted_helper(tmp_path)
    executor = _FakeExecutor(
        _process_result(stdout=_helper_response(helper_version="9.9.9"))
    )

    with pytest.raises(EnryProtocolError):
        EnryClient(configuration, executor).classify(_files())


def test_client_errors_never_include_sensitive_values(tmp_path: Path) -> None:
    helper_path, configuration = _trusted_helper(
        tmp_path,
        path_name="sensitive-helper-name",
    )
    sensitive = "sensitive-executor-value"
    executor = _FakeExecutor(start_error=RuntimeError(sensitive))

    with pytest.raises(EnryHelperExecutionError) as raised:
        EnryClient(configuration, executor).classify(_files())

    message = str(raised.value)
    assert sensitive not in message
    assert str(helper_path) not in message
    assert configuration.expected_sha256 not in message
    assert "sensitive-value" not in message


def test_helper_stderr_never_appears_in_execution_errors(tmp_path: Path) -> None:
    _, configuration = _trusted_helper(tmp_path)
    sensitive_stderr = b"sensitive helper stderr"
    executor = _FakeExecutor(
        _process_result(stderr=sensitive_stderr),
    )

    with pytest.raises(EnryHelperExecutionError) as raised:
        EnryClient(configuration, executor).classify(_files())

    assert sensitive_stderr.decode("ascii") not in str(raised.value)


@pytest.mark.parametrize(
    "overrides",
    [
        {"helper_path": Path("relative/helper")},
        {"helper_path": Path("/trusted/../helper")},
        {"expected_sha256": "A" * 64},
        {"expected_helper_version": ""},
        {"expected_helper_version": "v\u0085ersion"},
        {"expected_enry_version": " bad "},
        {"timeout_seconds": 0},
        {"timeout_seconds": 301},
        {"maximum_files_per_batch": 0},
        {"maximum_files_per_batch": 4097},
        {"maximum_payload_bytes": 1024 * 1024 - 1},
        {"maximum_payload_bytes": 16 * 1024 * 1024 + 1},
        {"stdout_limit_bytes": 0},
        {"stderr_limit_bytes": 100 * 1024 * 1024 + 1},
    ],
)
def test_configuration_rejects_invalid_values_without_filesystem_io(
    overrides: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "helper_path": Path("/trusted/helper"),
        "expected_sha256": "a" * 64,
    }
    values.update(overrides)

    with pytest.raises(InvalidEnryClientConfigurationError):
        TrustedEnryHelper(**values)  # type: ignore[arg-type]


@pytest.mark.skipif(not _LOCAL_HELPER.exists(), reason="local Enry helper is absent")
def test_real_local_helper_classifies_languages_and_flags() -> None:
    helper_digest = hashlib.sha256(_LOCAL_HELPER.read_bytes()).hexdigest()
    configuration = TrustedEnryHelper(
        helper_path=_LOCAL_HELPER,
        expected_sha256=helper_digest,
    )
    files = (
        EnryFileInput("assets/blob.bin", b"\x00\x01\x02\x03"),
        EnryFileInput(
            "generated/generated.go",
            b"// Code generated by SecureScan. DO NOT EDIT.\npackage generated\n",
        ),
        EnryFileInput("src/app.py", b"def main():\n    return True\n"),
        EnryFileInput("src/app_test.go", b"package app\n"),
        EnryFileInput("vendor/example/lib.go", b"package example\n"),
    )

    result = EnryClient(configuration).classify(files)
    classifications = {
        classification.relative_path: classification
        for classification in result.classifications
    }

    assert classifications["assets/blob.bin"].is_binary is True
    assert classifications["assets/blob.bin"].language is None
    assert classifications["generated/generated.go"].language == "Go"
    assert classifications["generated/generated.go"].is_generated is True
    assert classifications["src/app.py"].language == "Python"
    assert classifications["src/app_test.go"].language == "Go"
    assert classifications["src/app_test.go"].is_test is True
    assert classifications["vendor/example/lib.go"].language == "Go"
    assert classifications["vendor/example/lib.go"].is_vendor is True
    assert result.helper_version == "0.2.3"
    assert result.enry_version == "v2.9.6"
    assert result.helper_sha256 == helper_digest
    assert str(_PROJECT_ROOT) not in repr(result)
    assert all(not Path(item.relative_path).is_absolute() for item in result.classifications)
