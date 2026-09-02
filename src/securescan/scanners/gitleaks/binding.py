from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol

from securescan.execution import (
    CancellableProcessExecutor,
    CancellableProcessHandle,
    CancellableProcessRequest,
    CancellableProcessResult,
)
from securescan.source.enums import AnalysisCapability, SourceSupportState

GITLEAKS_SCANNER_ID: Final = "gitleaks"
GITLEAKS_VERSION: Final = "8.30.1"
GITLEAKS_ARCHIVE_FILENAME: Final = "gitleaks_8.30.1_linux_x64.tar.gz"
GITLEAKS_ARCHIVE_SHA256: Final = (
    "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
)
GITLEAKS_EXECUTABLE_SHA256: Final = (
    "88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509"
)
GITLEAKS_CONFIG_ID: Final = "securescan-gitleaks-built-in-default-v1"
GITLEAKS_CONFIG_VERSION: Final = "1"
GITLEAKS_BINDING_SCHEMA_VERSION: Final = "securescan-gitleaks-binding-v1"

_BINDING_STREAM_VERSION = b"securescan-gitleaks-binding-v0.4A\0"
_EXPECTED_VERSION_STDOUT = f"{GITLEAKS_VERSION}\n".encode("ascii")
_CONFIG_FILENAME = "securescan-gitleaks-v1.toml"
_IGNORE_FILENAME = "securescan-gitleaks-v1.ignore"
_CONFIG_SHA256 = "ca699281a4752ca677d7f1c1c22d97d2afca9c169eae28054486d4d95bae7fb4"
_IGNORE_SHA256 = "c5f2fc626c9cae855bbf0261d37ea80600cb65a270483a2df536a6c1c60e8f85"
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_VERSION_TIMEOUT_SECONDS = 5.0
_SCAN_TIMEOUT_SECONDS = 300.0
_SCANNER_TIMEOUT_SECONDS = 295
_STDOUT_LIMIT_BYTES = 64 * 1024 * 1024
_STDERR_LIMIT_BYTES = 64 * 1024
_HASH_READ_BYTES = 64 * 1024


class GitleaksBindingError(RuntimeError):
    """Base class for fixed-message Gitleaks binding failures."""


class InvalidGitleaksBindingError(GitleaksBindingError, ValueError):
    def __init__(self) -> None:
        RuntimeError.__init__(self, "Trusted Gitleaks binding is invalid")


class GitleaksExecutableIntegrityError(GitleaksBindingError):
    def __init__(self) -> None:
        super().__init__("Trusted Gitleaks executable integrity verification failed")


class GitleaksConfigurationIntegrityError(GitleaksBindingError):
    def __init__(self) -> None:
        super().__init__("Trusted Gitleaks configuration integrity verification failed")


class GitleaksVersionVerificationError(GitleaksBindingError):
    def __init__(self) -> None:
        super().__init__("Trusted Gitleaks version verification failed")


class InvalidGitleaksExecutionRequestError(GitleaksBindingError, ValueError):
    def __init__(self) -> None:
        RuntimeError.__init__(self, "Trusted Gitleaks execution request is invalid")


class _ProcessExecutor(Protocol):
    def start(self, request: CancellableProcessRequest) -> CancellableProcessHandle: ...


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    inode: int
    size: int
    modification_nanoseconds: int
    change_nanoseconds: int
    sha256: str


def _valid_absolute_path(value: object, *, expected_name: str | None = None) -> bool:
    return (
        isinstance(value, Path)
        and value.is_absolute()
        and ".." not in value.parts
        and bool(value.name)
        and (expected_name is None or value.name == expected_name)
    )


def _valid_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_PATTERN.fullmatch(value) is not None


def _metadata_matches(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_dev == second.st_dev
        and first.st_ino == second.st_ino
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
        and first.st_ctime_ns == second.st_ctime_ns
        and first.st_mode == second.st_mode
    )


def _verify_regular_file(
    path: Path,
    expected_sha256: str,
    *,
    executable: bool,
    error_type: type[GitleaksBindingError],
) -> _FileIdentity:
    try:
        path_metadata = os.lstat(path)
        unsafe_mode = path_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        executable_mode = path_metadata.st_mode & (
            stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        )
        if (
            not stat.S_ISREG(path_metadata.st_mode)
            or stat.S_ISLNK(path_metadata.st_mode)
            or path_metadata.st_nlink != 1
            or unsafe_mode
            or (executable and not executable_mode)
            or (not executable and executable_mode)
        ):
            raise error_type()

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
            os,
            "O_NOFOLLOW",
            0,
        )
        descriptor = os.open(path, flags)
        try:
            opened_metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened_metadata.st_mode)
                or not _metadata_matches(path_metadata, opened_metadata)
            ):
                raise error_type()
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
                raise error_type()
        finally:
            os.close(descriptor)
    except GitleaksBindingError:
        raise
    except (OSError, ValueError):
        raise error_type() from None

    actual_sha256 = digest.hexdigest()
    if actual_sha256 != expected_sha256:
        raise error_type()
    return _FileIdentity(
        device=path_metadata.st_dev,
        inode=path_metadata.st_ino,
        size=path_metadata.st_size,
        modification_nanoseconds=path_metadata.st_mtime_ns,
        change_nanoseconds=path_metadata.st_ctime_ns,
        sha256=actual_sha256,
    )


def _canonical_json(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


@dataclass(frozen=True, slots=True)
class TrustedGitleaksBinding:
    executable_path: Path
    executable_sha256: str
    config_path: Path
    config_sha256: str
    ignore_path: Path
    ignore_sha256: str
    scanner_id: str = GITLEAKS_SCANNER_ID
    scanner_version: str = GITLEAKS_VERSION
    schema_version: str = GITLEAKS_BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        self._validate_state()

    def _validate_state(self) -> None:
        if (
            self.scanner_id != GITLEAKS_SCANNER_ID
            or self.scanner_version != GITLEAKS_VERSION
            or self.schema_version != GITLEAKS_BINDING_SCHEMA_VERSION
            or not _valid_absolute_path(
                self.executable_path,
                expected_name="gitleaks",
            )
            or not _valid_absolute_path(
                self.config_path,
                expected_name=_CONFIG_FILENAME,
            )
            or not _valid_absolute_path(
                self.ignore_path,
                expected_name=_IGNORE_FILENAME,
            )
            or not _valid_sha256(self.executable_sha256)
            or not _valid_sha256(self.config_sha256)
            or not _valid_sha256(self.ignore_sha256)
        ):
            raise InvalidGitleaksBindingError

    def canonical_data(self) -> dict[str, Any]:
        self._validate_state()
        return {
            "binding_schema_version": self.schema_version,
            "capabilities": [AnalysisCapability.SECRET_DETECTION.value],
            "configuration": {
                "id": GITLEAKS_CONFIG_ID,
                "ignore_filename": _IGNORE_FILENAME,
                "ignore_sha256": self.ignore_sha256,
                "model": "project-owned-config-extending-version-pinned-built-in-defaults",
                "sha256": self.config_sha256,
                "version": GITLEAKS_CONFIG_VERSION,
            },
            "execution": {
                "archive_traversal": False,
                "current_snapshot_only": True,
                "history_scanning": False,
                "mode": "dir",
                "network_acquisition": False,
                "recursive_decoding": False,
                "repository_inline_allow_directives": False,
            },
            "executable": {
                "archive_filename": GITLEAKS_ARCHIVE_FILENAME,
                "archive_sha256": GITLEAKS_ARCHIVE_SHA256,
                "expected_version_stdout_ascii": f"{GITLEAKS_VERSION} followed by LF",
                "filename": "gitleaks",
                "identity_policy": "absolute-regular-nonsymlink-single-link-executable-sha256",
                "platform": "linux_x64",
                "sha256": self.executable_sha256,
                "version_argv": ["gitleaks", "version"],
            },
            "license": "MIT",
            "maturity": SourceSupportState.DETECTED.value,
            "process": {
                "arbitrary_scanner_flags": False,
                "environment": {},
                "shell": False,
                "stderr_limit_bytes": _STDERR_LIMIT_BYTES,
                "stdin": False,
                "stdout_limit_bytes": _STDOUT_LIMIT_BYTES,
                "timeout_seconds": int(_SCAN_TIMEOUT_SECONDS),
            },
            "scanner_id": self.scanner_id,
            "scanner_version": self.scanner_version,
        }

    def binding_digest(self) -> str:
        digest = hashlib.sha256()
        digest.update(_BINDING_STREAM_VERSION)
        digest.update(_canonical_json(self.canonical_data()))
        return digest.hexdigest()

    def verify_runtime(
        self,
        executor: CancellableProcessExecutor | _ProcessExecutor | None = None,
    ) -> None:
        self._validate_state()
        binary_before = _verify_regular_file(
            self.executable_path,
            self.executable_sha256,
            executable=True,
            error_type=GitleaksExecutableIntegrityError,
        )
        self._verify_configuration()
        process_executor: _ProcessExecutor = (
            CancellableProcessExecutor() if executor is None else executor
        )
        request = CancellableProcessRequest(
            argv=(str(self.executable_path), "version"),
            cwd=self.executable_path.parent,
            environment={},
            timeout_seconds=_VERSION_TIMEOUT_SECONDS,
            stdout_limit_bytes=4096,
            stderr_limit_bytes=4096,
        )
        result: CancellableProcessResult | None = None
        failed = False
        try:
            handle = process_executor.start(request)
            with handle as active_handle:
                result = active_handle.wait(
                    timeout_seconds=_VERSION_TIMEOUT_SECONDS + 2,
                )
            if result is None:
                result = handle.poll()
        except Exception:
            failed = True

        binary_after = _verify_regular_file(
            self.executable_path,
            self.executable_sha256,
            executable=True,
            error_type=GitleaksExecutableIntegrityError,
        )
        self._verify_configuration()
        if binary_after != binary_before:
            raise GitleaksExecutableIntegrityError
        if (
            failed
            or result is None
            or not isinstance(result, CancellableProcessResult)
            or result.return_code != 0
            or result.stdout != _EXPECTED_VERSION_STDOUT
            or result.stderr
            or result.timed_out
            or result.output_limit_exceeded
            or result.termination_requested
            or result.force_killed
        ):
            raise GitleaksVersionVerificationError

    def build_current_snapshot_request(
        self,
        snapshot_root: Path,
    ) -> CancellableProcessRequest:
        self._validate_state()
        _verify_regular_file(
            self.executable_path,
            self.executable_sha256,
            executable=True,
            error_type=GitleaksExecutableIntegrityError,
        )
        self._verify_configuration()
        try:
            metadata = os.lstat(snapshot_root)
        except (OSError, TypeError, ValueError):
            raise InvalidGitleaksExecutionRequestError from None
        if (
            not _valid_absolute_path(snapshot_root)
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
        ):
            raise InvalidGitleaksExecutionRequestError
        return CancellableProcessRequest(
            argv=(
                str(self.executable_path),
                "dir",
                "--config",
                str(self.config_path),
                "--gitleaks-ignore-path",
                str(self.ignore_path),
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
                str(_SCANNER_TIMEOUT_SECONDS),
                "--exit-code",
                "1",
                str(snapshot_root),
            ),
            cwd=self.config_path.parent,
            environment={},
            timeout_seconds=_SCAN_TIMEOUT_SECONDS,
            stdout_limit_bytes=_STDOUT_LIMIT_BYTES,
            stderr_limit_bytes=_STDERR_LIMIT_BYTES,
        )

    def authorize_current_snapshot_execution(
        self,
        snapshot_root: Path,
        executor: CancellableProcessExecutor | _ProcessExecutor | None = None,
    ) -> CancellableProcessRequest:
        self.verify_runtime(executor)
        return self.build_current_snapshot_request(snapshot_root)

    def start_current_snapshot_execution(
        self,
        snapshot_root: Path,
        executor: CancellableProcessExecutor | _ProcessExecutor | None = None,
    ) -> CancellableProcessHandle:
        process_executor: _ProcessExecutor = (
            CancellableProcessExecutor() if executor is None else executor
        )
        request = self.authorize_current_snapshot_execution(
            snapshot_root,
            process_executor,
        )
        try:
            return process_executor.start(request)
        except Exception:
            raise InvalidGitleaksExecutionRequestError from None

    def _verify_configuration(self) -> None:
        _verify_regular_file(
            self.config_path,
            self.config_sha256,
            executable=False,
            error_type=GitleaksConfigurationIntegrityError,
        )
        _verify_regular_file(
            self.ignore_path,
            self.ignore_sha256,
            executable=False,
            error_type=GitleaksConfigurationIntegrityError,
        )


def create_default_gitleaks_binding(executable_path: Path) -> TrustedGitleaksBinding:
    config_root = Path(__file__).resolve().parent / "config"
    return TrustedGitleaksBinding(
        executable_path=executable_path,
        executable_sha256=GITLEAKS_EXECUTABLE_SHA256,
        config_path=config_root / _CONFIG_FILENAME,
        config_sha256=_CONFIG_SHA256,
        ignore_path=config_root / _IGNORE_FILENAME,
        ignore_sha256=_IGNORE_SHA256,
    )


def build_gitleaks_binding_artifact(
    binding: TrustedGitleaksBinding,
) -> dict[str, Any]:
    if not isinstance(binding, TrustedGitleaksBinding):
        raise InvalidGitleaksBindingError
    data = binding.canonical_data()
    return {
        **data,
        "binding_digest": binding.binding_digest(),
        "confidentiality": {
            "finding_identity_excludes_secret_material": True,
            "hash_of_secret_is_not_public_identity": True,
            "raw_secrets_in_errors_logs_metrics_or_provenance": False,
            "scanner_output_redaction_percent": 100,
        },
        "limitations": [
            "No parser or normalized secret findings are implemented in v0.4A.",
            (
                "A detection is secret-like source material, not proof of a currently "
                "valid, active, or exploitable credential."
            ),
            (
                "Git history scanning, remote acquisition, and provider credential "
                "validation are outside Source v1."
            ),
        ],
        "provisioning": {
            "acquisition": (
                "operator-installed official GitHub release archive before production "
                "execution"
            ),
            "download_during_scan": False,
            "release_url": "https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1",
        },
    }


def canonical_gitleaks_binding_artifact(binding: TrustedGitleaksBinding) -> bytes:
    return _canonical_json(build_gitleaks_binding_artifact(binding))
