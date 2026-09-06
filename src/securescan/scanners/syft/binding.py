from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Final, Protocol

from securescan.execution import (
    CancellableProcessExecutor,
    CancellableProcessHandle,
    CancellableProcessRequest,
    CancellableProcessResult,
)
from securescan.source.enums import AnalysisCapability, SourceSupportState

SYFT_SCANNER_ID: Final = "syft"
SYFT_VERSION: Final = "1.51.0"
SYFT_PLATFORM: Final = "linux/amd64"
SYFT_JSON_SCHEMA_VERSION: Final = "16.1.10"
SYFT_ARCHIVE_FILENAME: Final = "syft_1.51.0_linux_amd64.tar.gz"
SYFT_ARCHIVE_SHA256: Final = "2a2e837a2c8d59ec9af5472ee22d3b04ee463c4e44476ecf993fd1e5ab6ebc7f"
SYFT_EXECUTABLE_SHA256: Final = "5a8b71e94f4607973145f02e27e01d50b9f7c7bc41e38d40b39606ad138b43b5"
SYFT_CONFIG_SHA256: Final = "4cf5feb873a8eef91b81d9869c95f0b317357ef3e8c7aa4b859f60f435770875"
SYFT_BINDING_SCHEMA_VERSION: Final = "securescan-syft-binding-s1"
SYFT_SOURCE_ANALYZER_ID: Final = "syft-source-v1"
SYFT_PURL_DISTRIBUTION: Final = "packageurl-python"
SYFT_PURL_VERSION: Final = "0.17.6"

_CONFIG_FILENAME = "securescan-syft-v1.yaml"
_BINDING_STREAM_VERSION = b"securescan-syft-binding-s1\0"
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_VERSION_TIMEOUT_SECONDS = 5.0
_SCAN_TIMEOUT_SECONDS = 300.0
_STDOUT_LIMIT_BYTES = 100 * 1024 * 1024
_STDERR_LIMIT_BYTES = 64 * 1024
_PARALLELISM = 4
_HASH_READ_BYTES = 64 * 1024


class SyftBindingError(RuntimeError):
    """Base class for fixed-message Syft binding failures."""


class InvalidSyftBindingError(SyftBindingError, ValueError):
    def __init__(self) -> None:
        RuntimeError.__init__(self, "Trusted Syft binding is invalid")


class SyftExecutableIntegrityError(SyftBindingError):
    def __init__(self) -> None:
        super().__init__("Trusted Syft executable integrity verification failed")


class SyftConfigurationIntegrityError(SyftBindingError):
    def __init__(self) -> None:
        super().__init__("Trusted Syft configuration integrity verification failed")


class SyftVersionVerificationError(SyftBindingError):
    def __init__(self) -> None:
        super().__init__("Trusted Syft version verification failed")


class SyftNormalizationDependencyError(SyftBindingError):
    def __init__(self) -> None:
        super().__init__("Trusted Syft normalization dependency verification failed")


class InvalidSyftExecutionRequestError(SyftBindingError, ValueError):
    def __init__(self) -> None:
        RuntimeError.__init__(self, "Trusted Syft execution request is invalid")


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
    error_type: type[SyftBindingError],
) -> _FileIdentity:
    try:
        path_metadata = os.lstat(path)
        executable_mode = path_metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        if (
            not stat.S_ISREG(path_metadata.st_mode)
            or stat.S_ISLNK(path_metadata.st_mode)
            or path_metadata.st_nlink != 1
            or path_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or (executable and not executable_mode)
            or (not executable and executable_mode)
        ):
            raise error_type()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened_metadata = os.fstat(descriptor)
            if not stat.S_ISREG(opened_metadata.st_mode) or not _metadata_matches(
                path_metadata, opened_metadata
            ):
                raise error_type()
            digest = hashlib.sha256()
            bytes_read = 0
            while chunk := os.read(descriptor, _HASH_READ_BYTES):
                bytes_read += len(chunk)
                digest.update(chunk)
            final_metadata = os.fstat(descriptor)
            if bytes_read != path_metadata.st_size or not _metadata_matches(
                opened_metadata, final_metadata
            ):
                raise error_type()
        finally:
            os.close(descriptor)
    except SyftBindingError:
        raise
    except (OSError, TypeError, ValueError):
        raise error_type() from None
    actual = digest.hexdigest()
    if actual != expected_sha256:
        raise error_type()
    return _FileIdentity(
        path_metadata.st_dev,
        path_metadata.st_ino,
        path_metadata.st_size,
        path_metadata.st_mtime_ns,
        path_metadata.st_ctime_ns,
        actual,
    )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_nonfinite(_value: str) -> None:
    raise ValueError


def _valid_version_output(payload: bytes) -> bool:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, ValueError, TypeError):
        return False
    return (
        isinstance(value, dict)
        and value.get("application") == SYFT_SCANNER_ID
        and value.get("version") == SYFT_VERSION
        and value.get("platform") == SYFT_PLATFORM
        and value.get("schemaVersion") == SYFT_JSON_SCHEMA_VERSION
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


def verify_syft_purl_dependency() -> None:
    try:
        runtime_version = version(SYFT_PURL_DISTRIBUTION)
    except PackageNotFoundError:
        raise SyftNormalizationDependencyError from None
    if runtime_version != SYFT_PURL_VERSION:
        raise SyftNormalizationDependencyError


@dataclass(frozen=True, slots=True)
class TrustedSyftBinding:
    executable_path: Path
    executable_sha256: str
    config_path: Path
    config_sha256: str
    scanner_id: str = SYFT_SCANNER_ID
    scanner_version: str = SYFT_VERSION
    schema_version: str = SYFT_BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        self._validate_state()

    def _validate_state(self) -> None:
        verify_syft_purl_dependency()
        if (
            self.scanner_id != SYFT_SCANNER_ID
            or self.scanner_version != SYFT_VERSION
            or self.schema_version != SYFT_BINDING_SCHEMA_VERSION
            or not _valid_absolute_path(self.executable_path, expected_name="syft")
            or not _valid_absolute_path(self.config_path, expected_name=_CONFIG_FILENAME)
            or _SHA256_PATTERN.fullmatch(self.executable_sha256) is None
            or _SHA256_PATTERN.fullmatch(self.config_sha256) is None
        ):
            raise InvalidSyftBindingError

    def canonical_data(self) -> dict[str, Any]:
        self._validate_state()
        return {
            "binding_schema_version": self.schema_version,
            "capabilities": [AnalysisCapability.PACKAGE_INVENTORY.value],
            "configuration": {
                "filename": _CONFIG_FILENAME,
                "sha256": self.config_sha256,
                "auto_discovery": False,
                "enrichment": False,
                "network_enrichment": False,
                "network_requested": False,
                "os_egress_sandbox": False,
            },
            "execution": {
                "mode": "directory",
                "output_format": "syft-json",
                "schema_version": SYFT_JSON_SCHEMA_VERSION,
                "requested_cataloger_strategy": "directory-defaults",
                "parallelism": _PARALLELISM,
            },
            "executable": {
                "archive_filename": SYFT_ARCHIVE_FILENAME,
                "archive_sha256": SYFT_ARCHIVE_SHA256,
                "filename": "syft",
                "identity_policy": "absolute-regular-nonsymlink-single-link-executable-sha256",
                "platform": SYFT_PLATFORM,
                "sha256": self.executable_sha256,
                "version_argv": ["syft", "version", "-o", "json"],
            },
            "license": "Apache-2.0",
            "maturity": SourceSupportState.SCANNABLE.value,
            "normalization": {
                "purl": {
                    "distribution": SYFT_PURL_DISTRIBUTION,
                    "version": SYFT_PURL_VERSION,
                }
            },
            "process": {
                "environment": {},
                "inner_timeout_seconds": None,
                "outer_timeout_seconds": int(_SCAN_TIMEOUT_SECONDS),
                "shell": False,
                "stderr_limit_bytes": _STDERR_LIMIT_BYTES,
                "stdin": False,
                "stdout_limit_bytes": _STDOUT_LIMIT_BYTES,
            },
            "scanner_id": self.scanner_id,
            "scanner_version": self.scanner_version,
        }

    def binding_digest(self) -> str:
        digest = hashlib.sha256()
        digest.update(_BINDING_STREAM_VERSION)
        digest.update(_canonical_json(self.canonical_data()))
        return digest.hexdigest()

    def _verify_configuration(self) -> None:
        _verify_regular_file(
            self.config_path,
            self.config_sha256,
            executable=False,
            error_type=SyftConfigurationIntegrityError,
        )

    def verify_runtime(
        self,
        executor: CancellableProcessExecutor | _ProcessExecutor | None = None,
    ) -> None:
        self._validate_state()
        before = _verify_regular_file(
            self.executable_path,
            self.executable_sha256,
            executable=True,
            error_type=SyftExecutableIntegrityError,
        )
        self._verify_configuration()
        process_executor: _ProcessExecutor = (
            CancellableProcessExecutor() if executor is None else executor
        )
        request = CancellableProcessRequest(
            argv=(str(self.executable_path), "version", "-o", "json"),
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
                result = active_handle.wait(timeout_seconds=7.0)
            if result is None:
                result = handle.poll()
        except Exception:
            failed = True
        after = _verify_regular_file(
            self.executable_path,
            self.executable_sha256,
            executable=True,
            error_type=SyftExecutableIntegrityError,
        )
        self._verify_configuration()
        if before != after:
            raise SyftExecutableIntegrityError
        if (
            failed
            or result is None
            or result.return_code != 0
            or result.stderr
            or result.timed_out
            or result.output_limit_exceeded
            or result.termination_requested
            or result.force_killed
            or not _valid_version_output(result.stdout)
        ):
            raise SyftVersionVerificationError

    def build_directory_request(self, projection_root: Path) -> CancellableProcessRequest:
        self._validate_state()
        _verify_regular_file(
            self.executable_path,
            self.executable_sha256,
            executable=True,
            error_type=SyftExecutableIntegrityError,
        )
        self._verify_configuration()
        try:
            metadata = os.lstat(projection_root)
        except (OSError, TypeError, ValueError):
            raise InvalidSyftExecutionRequestError from None
        if (
            not _valid_absolute_path(projection_root)
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
        ):
            raise InvalidSyftExecutionRequestError
        root = str(projection_root)
        return CancellableProcessRequest(
            argv=(
                str(self.executable_path),
                "scan",
                root,
                "--from",
                "dir",
                "--base-path",
                root,
                "--output",
                "syft-json",
                "--config",
                str(self.config_path),
                "--quiet",
                "--parallelism",
                str(_PARALLELISM),
            ),
            cwd=self.config_path.parent,
            environment={},
            timeout_seconds=_SCAN_TIMEOUT_SECONDS,
            stdout_limit_bytes=_STDOUT_LIMIT_BYTES,
            stderr_limit_bytes=_STDERR_LIMIT_BYTES,
        )

    def authorize_directory_execution(
        self,
        projection_root: Path,
        executor: CancellableProcessExecutor | _ProcessExecutor | None = None,
    ) -> CancellableProcessRequest:
        self.verify_runtime(executor)
        return self.build_directory_request(projection_root)

    def start_directory_execution(
        self,
        projection_root: Path,
        executor: CancellableProcessExecutor | _ProcessExecutor | None = None,
    ) -> CancellableProcessHandle:
        process_executor: _ProcessExecutor = (
            CancellableProcessExecutor() if executor is None else executor
        )
        request = self.authorize_directory_execution(projection_root, process_executor)
        try:
            return process_executor.start(request)
        except Exception:
            raise InvalidSyftExecutionRequestError from None


def create_default_syft_binding(executable_path: Path) -> TrustedSyftBinding:
    config_path = Path(__file__).resolve().parent / "config" / _CONFIG_FILENAME
    return TrustedSyftBinding(
        executable_path=executable_path,
        executable_sha256=SYFT_EXECUTABLE_SHA256,
        config_path=config_path,
        config_sha256=SYFT_CONFIG_SHA256,
    )


def build_syft_binding_artifact(binding: TrustedSyftBinding) -> dict[str, Any]:
    if not isinstance(binding, TrustedSyftBinding):
        raise InvalidSyftBindingError
    return {
        **binding.canonical_data(),
        "binding_digest": binding.binding_digest(),
        "claims": {
            "inventory_only": True,
            "dependency_semantics": False,
            "reachability": False,
            "vulnerability_or_cve": False,
        },
        "provisioning": {
            "download_during_scan": False,
            "official_release_url": ("https://github.com/anchore/syft/releases/tag/v1.51.0"),
        },
    }


def canonical_syft_binding_artifact(binding: TrustedSyftBinding) -> bytes:
    return _canonical_json(build_syft_binding_artifact(binding))


def build_syft_contract(binding: TrustedSyftBinding) -> dict[str, Any]:
    if not isinstance(binding, TrustedSyftBinding):
        raise InvalidSyftBindingError
    return {
        "capability": AnalysisCapability.PACKAGE_INVENTORY.value,
        "claims": {
            "dependency_semantics": False,
            "inventory_current_snapshot": True,
            "reachability": False,
            "vulnerability_or_cve": False,
        },
        "execution": {
            "environment": {},
            "inner_timeout_seconds": None,
            "mode": "directory",
            "network_enrichment": False,
            "network_requested": False,
            "os_egress_sandbox": False,
            "outer_timeout_seconds": int(_SCAN_TIMEOUT_SECONDS),
            "output": "syft-json",
            "parallelism": _PARALLELISM,
            "shell": False,
            "stderr_limit_bytes": _STDERR_LIMIT_BYTES,
            "stdin": False,
            "stdout_limit_bytes": _STDOUT_LIMIT_BYTES,
        },
        "identity": {
            "package_key": ["package_type", "package_name", "package_version", "purl"],
            "package_observation_id": ["package_key", "found_by", "sorted_locations"],
            "syft_artifact_id_trusted": False,
        },
        "normalization": {
            "purl": {
                "distribution": SYFT_PURL_DISTRIBUTION,
                "version": SYFT_PURL_VERSION,
            }
        },
        "parser": {
            "artifact_relationships_required": True,
            "artifacts_required": True,
            "descriptor": {"name": SYFT_SCANNER_ID, "version": SYFT_VERSION},
            "metadata_persisted": False,
            "schema": {
                "url": (
                    "https://raw.githubusercontent.com/anchore/syft/main/schema/json/"
                    "schema-16.1.10.json"
                ),
                "version": SYFT_JSON_SCHEMA_VERSION,
            },
            "source_type": "directory",
        },
        "scanner": {
            "archive_sha256": SYFT_ARCHIVE_SHA256,
            "binding_digest": binding.binding_digest(),
            "config_sha256": binding.config_sha256,
            "executable_sha256": binding.executable_sha256,
            "id": binding.scanner_id,
            "version": binding.scanner_version,
        },
        "schema_version": "securescan-syft-s1-contract-v1",
        "support_state": SourceSupportState.SCANNABLE.value,
    }


def canonical_syft_contract(binding: TrustedSyftBinding) -> bytes:
    return _canonical_json(build_syft_contract(binding))
