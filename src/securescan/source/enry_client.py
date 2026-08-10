from __future__ import annotations

import hashlib
import os
import re
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from securescan.execution import (
    CancellableProcessExecutor,
    CancellableProcessHandle,
    CancellableProcessRequest,
    CancellableProcessResult,
)
from securescan.source.enry_protocol import (
    ENRY_HELPER_VERSION,
    ENRY_LIBRARY_VERSION,
    EnryClassification,
    EnryFileInput,
    decode_enry_responses,
    encode_enry_requests,
)

_MEBIBYTE = 1024 * 1024
_MAX_EXECUTOR_INPUT_BYTES = 16 * _MEBIBYTE
_MAX_EXECUTOR_OUTPUT_BYTES = 100 * _MEBIBYTE
_HASH_READ_BYTES = 64 * 1024
_EXECUTOR_COMPLETION_GRACE_SECONDS = 2.0
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class EnryClientError(RuntimeError):
    """Raised when trusted Enry helper execution cannot produce a result."""

    def __init__(self) -> None:
        super().__init__("Enry client operation failed")


class InvalidEnryClientConfigurationError(EnryClientError, ValueError):
    """Raised when trusted helper configuration is invalid."""

    def __init__(self) -> None:
        RuntimeError.__init__(self, "Enry client configuration is invalid")


class EnryHelperIntegrityError(EnryClientError):
    """Raised when the trusted helper fails identity verification."""

    def __init__(self) -> None:
        RuntimeError.__init__(self, "Enry helper integrity verification failed")


class EnryHelperExecutionError(EnryClientError):
    """Raised when the trusted helper process fails."""

    def __init__(self) -> None:
        RuntimeError.__init__(self, "Enry helper execution failed")


class EnryHelperTimeoutError(EnryHelperExecutionError):
    """Raised when the trusted helper exceeds its configured timeout."""

    def __init__(self) -> None:
        RuntimeError.__init__(self, "Enry helper execution timed out")


class EnryHelperOutputLimitError(EnryHelperExecutionError):
    """Raised when the trusted helper exceeds an output limit."""

    def __init__(self) -> None:
        RuntimeError.__init__(self, "Enry helper output limit was exceeded")


def _is_control_character(character: str) -> bool:
    return unicodedata.category(character) == "Cc"


def _valid_clean_string(value: object) -> bool:
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    if any(_is_control_character(character) for character in value):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _valid_helper_path(value: object) -> bool:
    if not isinstance(value, Path) or not value.is_absolute() or not value.name:
        return False
    if ".." in value.parts:
        return False
    return _valid_clean_string(str(value))


def _bounded_integer(value: object, minimum: int, maximum: int) -> bool:
    return type(value) is int and minimum <= value <= maximum


@dataclass(frozen=True, slots=True)
class TrustedEnryHelper:
    helper_path: Path
    expected_sha256: str
    expected_helper_version: str = ENRY_HELPER_VERSION
    expected_enry_version: str = ENRY_LIBRARY_VERSION
    timeout_seconds: float = 30
    maximum_files_per_batch: int = 256
    maximum_payload_bytes: int = 8 * _MEBIBYTE
    stdout_limit_bytes: int = 8 * _MEBIBYTE
    stderr_limit_bytes: int = 64 * 1024

    def __post_init__(self) -> None:
        if (
            not _valid_helper_path(self.helper_path)
            or not isinstance(self.expected_sha256, str)
            or _SHA256_PATTERN.fullmatch(self.expected_sha256) is None
            or not _valid_clean_string(self.expected_helper_version)
            or not _valid_clean_string(self.expected_enry_version)
            or isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not 0 < self.timeout_seconds <= 300
            or not _bounded_integer(self.maximum_files_per_batch, 1, 4096)
            or not _bounded_integer(
                self.maximum_payload_bytes,
                _MEBIBYTE,
                _MAX_EXECUTOR_INPUT_BYTES,
            )
            or not _bounded_integer(
                self.stdout_limit_bytes,
                1,
                _MAX_EXECUTOR_OUTPUT_BYTES,
            )
            or not _bounded_integer(
                self.stderr_limit_bytes,
                1,
                _MAX_EXECUTOR_OUTPUT_BYTES,
            )
        ):
            raise InvalidEnryClientConfigurationError


@dataclass(frozen=True, slots=True)
class EnryBatchResult:
    classifications: tuple[EnryClassification, ...]
    helper_sha256: str
    helper_version: str
    enry_version: str
    duration_ms: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.classifications, tuple)
            or not self.classifications
            or any(
                not isinstance(item, EnryClassification)
                for item in self.classifications
            )
            or not isinstance(self.helper_sha256, str)
            or _SHA256_PATTERN.fullmatch(self.helper_sha256) is None
            or not _valid_clean_string(self.helper_version)
            or not _valid_clean_string(self.enry_version)
            or type(self.duration_ms) is not int
            or self.duration_ms < 0
        ):
            raise EnryClientError
        paths = tuple(item.relative_path for item in self.classifications)
        if paths != tuple(sorted(paths)) or len(set(paths)) != len(paths):
            raise EnryClientError


@dataclass(frozen=True, slots=True)
class _HelperIdentity:
    device: int
    inode: int
    size: int
    modification_nanoseconds: int
    change_nanoseconds: int
    sha256: str


class _EnryExecutor(Protocol):
    def start(
        self,
        request: CancellableProcessRequest,
    ) -> CancellableProcessHandle: ...


def _metadata_matches(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_dev == second.st_dev
        and first.st_ino == second.st_ino
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
        and first.st_ctime_ns == second.st_ctime_ns
        and first.st_mode == second.st_mode
    )


def _verify_helper(configuration: TrustedEnryHelper) -> _HelperIdentity:
    try:
        path_metadata = os.lstat(configuration.helper_path)
        if (
            not stat.S_ISREG(path_metadata.st_mode)
            or not path_metadata.st_mode
            & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            or path_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise EnryHelperIntegrityError

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(configuration.helper_path, flags)
        try:
            opened_metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened_metadata.st_mode)
                or not _metadata_matches(path_metadata, opened_metadata)
            ):
                raise EnryHelperIntegrityError

            digest = hashlib.sha256()
            bytes_read = 0
            while True:
                chunk = os.read(descriptor, _HASH_READ_BYTES)
                if not chunk:
                    break
                bytes_read += len(chunk)
                digest.update(chunk)

            final_metadata = os.fstat(descriptor)
            if (
                bytes_read != path_metadata.st_size
                or not _metadata_matches(opened_metadata, final_metadata)
            ):
                raise EnryHelperIntegrityError
        finally:
            os.close(descriptor)
    except EnryHelperIntegrityError:
        raise
    except (OSError, ValueError):
        raise EnryHelperIntegrityError from None

    helper_sha256 = digest.hexdigest()
    if helper_sha256 != configuration.expected_sha256:
        raise EnryHelperIntegrityError
    return _HelperIdentity(
        device=path_metadata.st_dev,
        inode=path_metadata.st_ino,
        size=path_metadata.st_size,
        modification_nanoseconds=path_metadata.st_mtime_ns,
        change_nanoseconds=path_metadata.st_ctime_ns,
        sha256=helper_sha256,
    )


class EnryClient:
    def __init__(
        self,
        configuration: TrustedEnryHelper,
        executor: CancellableProcessExecutor | _EnryExecutor | None = None,
    ) -> None:
        if not isinstance(configuration, TrustedEnryHelper):
            raise InvalidEnryClientConfigurationError
        self._configuration = configuration
        self._executor: _EnryExecutor = (
            CancellableProcessExecutor() if executor is None else executor
        )

    @property
    def configuration(self) -> TrustedEnryHelper:
        return self._configuration

    def classify(
        self,
        files: tuple[EnryFileInput, ...],
    ) -> EnryBatchResult:
        identity_before = _verify_helper(self._configuration)
        payload, correlations = encode_enry_requests(
            files,
            maximum_files=self._configuration.maximum_files_per_batch,
            maximum_payload_bytes=self._configuration.maximum_payload_bytes,
        )
        request = CancellableProcessRequest(
            argv=(str(self._configuration.helper_path),),
            cwd=self._configuration.helper_path.parent,
            environment={},
            timeout_seconds=self._configuration.timeout_seconds,
            stdout_limit_bytes=self._configuration.stdout_limit_bytes,
            stderr_limit_bytes=self._configuration.stderr_limit_bytes,
            stdin_data=payload,
        )

        result: CancellableProcessResult | None = None
        execution_started = False
        execution_failed = False
        try:
            handle = self._executor.start(request)
            execution_started = True
            with handle as active_handle:
                result = active_handle.wait(
                    timeout_seconds=(
                        self._configuration.timeout_seconds
                        + _EXECUTOR_COMPLETION_GRACE_SECONDS
                    )
                )
            if result is None:
                result = handle.poll()
        except Exception:
            execution_failed = True

        if execution_started:
            identity_after = _verify_helper(self._configuration)
            if identity_after != identity_before:
                raise EnryHelperIntegrityError
        if execution_failed or result is None or not isinstance(
            result,
            CancellableProcessResult,
        ):
            raise EnryHelperExecutionError
        if result.timed_out:
            raise EnryHelperTimeoutError
        if result.output_limit_exceeded:
            raise EnryHelperOutputLimitError
        if (
            result.return_code != 0
            or result.termination_requested
            or result.force_killed
            or result.stderr
        ):
            raise EnryHelperExecutionError

        classifications = decode_enry_responses(
            result.stdout,
            expected_correlations=correlations,
            expected_helper_version=self._configuration.expected_helper_version,
            expected_enry_version=self._configuration.expected_enry_version,
        )
        return EnryBatchResult(
            classifications=classifications,
            helper_sha256=identity_before.sha256,
            helper_version=self._configuration.expected_helper_version,
            enry_version=self._configuration.expected_enry_version,
            duration_ms=result.duration_ms,
        )
