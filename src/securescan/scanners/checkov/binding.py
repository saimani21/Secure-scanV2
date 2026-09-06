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

CHECKOV_SCANNER_ID: Final = "checkov"
CHECKOV_VERSION: Final = "3.3.16"
CHECKOV_DISTRIBUTION_SHA256: Final = (
    "6f7f611f45c765af9b6acd43e603a438153d86007d02dffa7903a1125f9b5089"
)
CHECKOV_CONFIG_SHA256: Final = "119a53d13286a9de37691a0e683bf8d14aa98abbba13c1ef75a448aa419d59b7"
CHECKOV_TOOLCHAIN_LOCK_SHA256: Final = (
    "9d8dcc6645b6d4f2035fb90fc500cdd62b1f68dd1dbafc63320d06e3f04a47d0"
)
CHECKOV_TOOLCHAIN_DIGEST: Final = (
    "a8e451a6ed27fcf1ab0e639b5effbe4bb6e38ef8378058f95f51d7b5f99eefea"
)
CHECKOV_LAUNCHER_TEMPLATE_SHA256: Final = (
    "51a09ff89b7771a501ab20498ee396369185f5781eedae24fe9940410fa135b4"
)
CHECKOV_PYTHON_IMPLEMENTATION: Final = "CPython"
CHECKOV_PYTHON_VERSION: Final = "3.12.3"
CHECKOV_BINDING_SCHEMA_VERSION: Final = "securescan-checkov-binding-s3"
CHECKOV_SOURCE_ANALYZER_ID: Final = "checkov-source-v1"
CHECKOV_FRAMEWORKS: Final = (
    "terraform",
    "cloudformation",
    "kubernetes",
    "dockerfile",
    "github_actions",
)
CHECKOV_EXCLUDED_FRAMEWORKS: Final = (
    "terraform_plan",
    "helm",
    "kustomize",
    "bicep",
    "arm",
    "serverless",
    "openapi",
    "json",
    "yaml",
    "argo_workflows",
    "gitlab_ci",
    "bitbucket_pipelines",
    "github_configuration",
    "sca_package",
    "sca_image",
    "secrets",
)
CHECKOV_AUTHORITY_EXCLUDED_CHECKS: Final = (
    "CKV_AWS_41",
    "CKV_AWS_45",
    "CKV_AWS_46",
    "CKV_AWS_295",
    "CKV_AWS_384",
    "CKV_AZURE_45",
    "CKV_AZURE_239",
    "CKV_BCW_1",
    "CKV_LIN_1",
    "CKV_NCP_17",
    "CKV_OCI_1",
    "CKV_OPENSTACK_1",
    "CKV_OPENSTACK_4",
    "CKV_PAN_1",
    "CKV_TC_13",
)

_CONFIG_FILENAME = "securescan-checkov-v1.yaml"
_TOOLCHAIN_LOCK_FILENAME = "checkov-3.3.16-cp312-linux-x86_64.lock"
_DEFAULT_TOOLCHAIN_LOCK = Path(__file__).resolve().parent / "toolchain" / _TOOLCHAIN_LOCK_FILENAME
_BINDING_DOMAIN = b"securescan-checkov-binding-s3\0"
_TOOLCHAIN_DOMAIN = b"securescan-checkov-toolchain-s3\0"
_LAUNCHER_PLACEHOLDER = b"#!<CHECKOV_VENV>/bin/python\n"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_LOCK_LINE = re.compile(
    r"(?P<name>[A-Za-z0-9_.-]+)==(?P<version>[A-Za-z0-9_.+-]+) "
    r"--hash=sha256:(?P<sha256>[0-9a-f]{64})  # (?P<filename>[A-Za-z0-9_.+-]+\.whl)\Z",
    re.ASCII,
)
_VERSION_STDOUT = b"3.3.16\n"
_VERSION_TIMEOUT_SECONDS = 10.0
_SCAN_TIMEOUT_SECONDS = 300.0
_STDOUT_LIMIT_BYTES = 64 * 1024 * 1024
_STDERR_LIMIT_BYTES = 64 * 1024
_READ_BYTES = 64 * 1024


class CheckovBindingError(RuntimeError):
    pass


class InvalidCheckovBindingError(CheckovBindingError, ValueError):
    def __init__(self) -> None:
        RuntimeError.__init__(self, "Trusted Checkov binding is invalid")


class CheckovExecutableIntegrityError(CheckovBindingError):
    def __init__(self) -> None:
        super().__init__("Trusted Checkov executable integrity verification failed")


class CheckovConfigurationIntegrityError(CheckovBindingError):
    def __init__(self) -> None:
        super().__init__("Trusted Checkov configuration integrity verification failed")


class CheckovToolchainIntegrityError(CheckovBindingError):
    def __init__(self) -> None:
        super().__init__("Trusted Checkov toolchain integrity verification failed")


class CheckovVersionVerificationError(CheckovBindingError):
    def __init__(self) -> None:
        super().__init__("Trusted Checkov version verification failed")


class InvalidCheckovExecutionRequestError(CheckovBindingError, ValueError):
    def __init__(self) -> None:
        RuntimeError.__init__(self, "Trusted Checkov execution request is invalid")


class _ProcessExecutor(Protocol):
    def start(self, request: CancellableProcessRequest) -> CancellableProcessHandle: ...


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    sha256: str


def _same_stat(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _read_verified_file(
    path: Path,
    expected_sha256: str | None,
    *,
    executable: bool,
    error: type[CheckovBindingError],
) -> tuple[_FileIdentity, bytes]:
    try:
        before = os.lstat(path)
        execute_bits = before.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_nlink != 1
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or (executable and not execute_bits)
            or (not executable and execute_bits)
        ):
            raise error()
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or not _same_stat(before, opened):
                raise error()
            digest = hashlib.sha256()
            size = 0
            chunks: list[bytes] = []
            while chunk := os.read(descriptor, _READ_BYTES):
                size += len(chunk)
                digest.update(chunk)
                chunks.append(chunk)
            after = os.fstat(descriptor)
            if size != before.st_size or not _same_stat(opened, after):
                raise error()
        finally:
            os.close(descriptor)
    except CheckovBindingError:
        raise
    except (OSError, TypeError, ValueError):
        raise error() from None
    actual = digest.hexdigest()
    if expected_sha256 is not None and actual != expected_sha256:
        raise error()
    return (
        _FileIdentity(
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
            actual,
        ),
        b"".join(chunks),
    )


def _verify_file(
    path: Path,
    expected_sha256: str | None,
    *,
    executable: bool,
    error: type[CheckovBindingError],
) -> _FileIdentity:
    return _read_verified_file(
        path,
        expected_sha256,
        executable=executable,
        error=error,
    )[0]


def _verify_launcher(path: Path, expected_sha256: str | None) -> _FileIdentity:
    identity, payload = _read_verified_file(
        path,
        expected_sha256,
        executable=True,
        error=CheckovExecutableIntegrityError,
    )
    shebang, separator, body = payload.partition(b"\n")
    try:
        expected_shebang = b"#!" + os.fsencode(path.parent / "python")
    except (TypeError, ValueError):
        raise CheckovExecutableIntegrityError from None
    if (
        separator != b"\n"
        or shebang != expected_shebang
        or hashlib.sha256(_LAUNCHER_PLACEHOLDER + body).hexdigest()
        != CHECKOV_LAUNCHER_TEMPLATE_SHA256
    ):
        raise CheckovExecutableIntegrityError
    return identity


def _canonical_json(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode()
        + b"\n"
    )


def _canonical_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _toolchain_data(lock_path: Path, lock_sha256: str) -> dict[str, Any]:
    _identity, payload = _read_verified_file(
        lock_path,
        lock_sha256,
        executable=False,
        error=CheckovToolchainIntegrityError,
    )
    try:
        lines = payload.decode("ascii").splitlines()
        distributions: list[dict[str, str]] = []
        for line in lines:
            match = _LOCK_LINE.fullmatch(line)
            if match is None:
                raise ValueError
            distributions.append(
                {
                    "name": _canonical_distribution_name(match["name"]),
                    "version": match["version"],
                }
            )
        if (
            len(distributions) != 97
            or len({item["name"] for item in distributions}) != len(distributions)
            or not any(
                item == {"name": "checkov", "version": CHECKOV_VERSION}
                for item in distributions
            )
        ):
            raise ValueError
        distributions.sort(key=lambda item: (item["name"], item["version"]))
    except (UnicodeDecodeError, ValueError):
        raise CheckovToolchainIntegrityError from None
    return {
        "distribution_count": len(distributions),
        "distributions": distributions,
        "installation": {
            "dependencies_resolved_during_install": False,
            "hashes_required": True,
            "lock_filename": _TOOLCHAIN_LOCK_FILENAME,
            "lock_sha256": lock_sha256,
            "wheel_platform": "cp312-linux-x86_64",
        },
        "python": {
            "implementation": CHECKOV_PYTHON_IMPLEMENTATION,
            "version": CHECKOV_PYTHON_VERSION,
        },
    }


def _toolchain_digest(data: dict[str, Any]) -> str:
    digest = hashlib.sha256()
    digest.update(_TOOLCHAIN_DOMAIN)
    digest.update(_canonical_json(data))
    return digest.hexdigest()


def _toolchain_probe_stdout(data: dict[str, Any]) -> bytes:
    return _canonical_json(
        {
            "distributions": data["distributions"],
            "python": data["python"],
        }
    )


_TOOLCHAIN_PROBE = (
    "import importlib.metadata as m,json,platform,re;"
    "d=sorted((re.sub(r'[-_.]+','-',x.metadata['Name']).lower(),x.version) "
    "for x in m.distributions());"
    "print(json.dumps({'distributions':[{'name':n,'version':v} for n,v in d],"
    "'python':{'implementation':platform.python_implementation(),"
    "'version':platform.python_version()}},ensure_ascii=True,separators=(',',':'),"
    "sort_keys=True))"
)


@dataclass(frozen=True, slots=True)
class TrustedCheckovBinding:
    executable_path: Path
    local_launcher_sha256: str
    config_path: Path
    config_sha256: str
    toolchain_lock_path: Path = _DEFAULT_TOOLCHAIN_LOCK
    toolchain_lock_sha256: str = CHECKOV_TOOLCHAIN_LOCK_SHA256
    scanner_id: str = CHECKOV_SCANNER_ID
    scanner_version: str = CHECKOV_VERSION
    schema_version: str = CHECKOV_BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.scanner_id != CHECKOV_SCANNER_ID
            or self.scanner_version != CHECKOV_VERSION
            or self.schema_version != CHECKOV_BINDING_SCHEMA_VERSION
            or not self.executable_path.is_absolute()
            or self.executable_path.name != "checkov"
            or ".." in self.executable_path.parts
            or not self.config_path.is_absolute()
            or self.config_path.name != _CONFIG_FILENAME
            or ".." in self.config_path.parts
            or _SHA256.fullmatch(self.local_launcher_sha256) is None
            or _SHA256.fullmatch(self.config_sha256) is None
            or not self.toolchain_lock_path.is_absolute()
            or self.toolchain_lock_path.name != _TOOLCHAIN_LOCK_FILENAME
            or _SHA256.fullmatch(self.toolchain_lock_sha256) is None
        ):
            raise InvalidCheckovBindingError

    def canonical_data(self) -> dict[str, Any]:
        toolchain = _toolchain_data(self.toolchain_lock_path, self.toolchain_lock_sha256)
        digest = _toolchain_digest(toolchain)
        if digest != CHECKOV_TOOLCHAIN_DIGEST:
            raise CheckovToolchainIntegrityError
        return {
            "binding_schema_version": self.schema_version,
            "capabilities": [AnalysisCapability.CONFIGURATION_SECURITY.value],
            "configuration": {
                "auto_discovery_authoritative": False,
                "filename": _CONFIG_FILENAME,
                "sha256": self.config_sha256,
                "trusted_cli_overrides": True,
            },
            "execution": {
                "compact": True,
                "download_external_modules": False,
                "evaluate_variables": False,
                "frameworks": list(CHECKOV_FRAMEWORKS),
                "output": "json",
                "quiet": False,
                "skip_download": True,
                "soft_fail": True,
                "authority_excluded_checks": list(CHECKOV_AUTHORITY_EXCLUDED_CHECKS),
            },
            "executable": {
                "distribution": "checkov",
                "distribution_sha256": CHECKOV_DISTRIBUTION_SHA256,
                "filename": "checkov",
                "launcher_identity_policy": (
                    "exact-venv-python-shebang-plus-frozen-normalized-template"
                ),
                "launcher_sha256_in_binding_identity": False,
                "launcher_template_sha256": CHECKOV_LAUNCHER_TEMPLATE_SHA256,
                "version_argv": ["checkov", "--version"],
            },
            "license": "Apache-2.0",
            "maturity": SourceSupportState.SCANNABLE.value,
            "network": {
                "credentials": False,
                "external_checks": False,
                "external_modules": False,
                "os_egress_sandbox": False,
                "platform_downloads": False,
            },
            "process": {
                "environment": {},
                "shell": False,
                "stderr_limit_bytes": _STDERR_LIMIT_BYTES,
                "stdin": False,
                "stdout_limit_bytes": _STDOUT_LIMIT_BYTES,
                "timeout_seconds": int(_SCAN_TIMEOUT_SECONDS),
            },
            "scanner_id": self.scanner_id,
            "scanner_version": self.scanner_version,
            "toolchain": {**toolchain, "digest": digest},
        }

    def binding_digest(self) -> str:
        digest = hashlib.sha256()
        digest.update(_BINDING_DOMAIN)
        digest.update(_canonical_json(self.canonical_data()))
        return digest.hexdigest()

    def _verify_config(self) -> None:
        _verify_file(
            self.config_path,
            self.config_sha256,
            executable=False,
            error=CheckovConfigurationIntegrityError,
        )

    def verify_runtime(self, executor: _ProcessExecutor | None = None) -> None:
        before = _verify_launcher(self.executable_path, self.local_launcher_sha256)
        self._verify_config()
        toolchain = _toolchain_data(self.toolchain_lock_path, self.toolchain_lock_sha256)
        if _toolchain_digest(toolchain) != CHECKOV_TOOLCHAIN_DIGEST:
            raise CheckovToolchainIntegrityError
        process_executor = CancellableProcessExecutor() if executor is None else executor
        version_result: CancellableProcessResult | None = None
        toolchain_result: CancellableProcessResult | None = None
        try:
            toolchain_handle = process_executor.start(
                CancellableProcessRequest(
                    argv=(
                        str(self.executable_path.parent / "python"),
                        "-I",
                        "-c",
                        _TOOLCHAIN_PROBE,
                    ),
                    cwd=self.config_path.parent,
                    environment={},
                    timeout_seconds=_VERSION_TIMEOUT_SECONDS,
                    stdout_limit_bytes=64 * 1024,
                    stderr_limit_bytes=4096,
                )
            )
            with toolchain_handle as active:
                toolchain_result = active.wait(timeout_seconds=12.0)
            if toolchain_result is None:
                toolchain_result = toolchain_handle.poll()
            version_handle = process_executor.start(
                CancellableProcessRequest(
                    argv=(str(self.executable_path), "--version"),
                    cwd=self.config_path.parent,
                    environment={},
                    timeout_seconds=_VERSION_TIMEOUT_SECONDS,
                    stdout_limit_bytes=4096,
                    stderr_limit_bytes=4096,
                )
            )
            with version_handle as active:
                version_result = active.wait(timeout_seconds=12.0)
            if version_result is None:
                version_result = version_handle.poll()
        except Exception:
            version_result = None
            toolchain_result = None
        after = _verify_launcher(self.executable_path, self.local_launcher_sha256)
        self._verify_config()
        if before != after:
            raise CheckovExecutableIntegrityError
        if (
            toolchain_result is None
            or toolchain_result.return_code != 0
            or toolchain_result.stdout != _toolchain_probe_stdout(toolchain)
            or toolchain_result.stderr
            or toolchain_result.timed_out
            or toolchain_result.output_limit_exceeded
            or toolchain_result.termination_requested
            or toolchain_result.force_killed
        ):
            raise CheckovToolchainIntegrityError
        if (
            version_result is None
            or version_result.return_code != 0
            or version_result.stdout != _VERSION_STDOUT
            or version_result.stderr
            or version_result.timed_out
            or version_result.output_limit_exceeded
            or version_result.termination_requested
            or version_result.force_killed
        ):
            raise CheckovVersionVerificationError

    def build_directory_request(self, projection_root: Path) -> CancellableProcessRequest:
        _verify_launcher(self.executable_path, self.local_launcher_sha256)
        self._verify_config()
        try:
            metadata = os.lstat(projection_root)
        except (OSError, TypeError, ValueError):
            raise InvalidCheckovExecutionRequestError from None
        if (
            not projection_root.is_absolute()
            or ".." in projection_root.parts
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            raise InvalidCheckovExecutionRequestError
        return CancellableProcessRequest(
            argv=(
                str(self.executable_path),
                "--directory",
                str(projection_root),
                "--config-file",
                str(self.config_path),
                "--framework",
                *CHECKOV_FRAMEWORKS,
                "--output",
                "json",
                "--compact",
                "--soft-fail",
                "--skip-download",
                "--skip-results-upload",
                "--download-external-modules",
                "false",
                "--evaluate-variables",
                "false",
                "--skip-check",
                ",".join(CHECKOV_AUTHORITY_EXCLUDED_CHECKS),
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
        executor: _ProcessExecutor | None = None,
    ) -> CancellableProcessRequest:
        self.verify_runtime(executor)
        return self.build_directory_request(projection_root)

    def start_directory_execution(
        self,
        projection_root: Path,
        executor: _ProcessExecutor | None = None,
    ) -> CancellableProcessHandle:
        process_executor = CancellableProcessExecutor() if executor is None else executor
        request = self.authorize_directory_execution(projection_root, process_executor)
        try:
            return process_executor.start(request)
        except Exception:
            raise InvalidCheckovExecutionRequestError from None


def create_default_checkov_binding(executable_path: Path) -> TrustedCheckovBinding:
    config_path = Path(__file__).resolve().parent / "config" / _CONFIG_FILENAME
    launcher = _verify_launcher(executable_path, None)
    return TrustedCheckovBinding(
        executable_path=executable_path,
        local_launcher_sha256=launcher.sha256,
        config_path=config_path,
        config_sha256=CHECKOV_CONFIG_SHA256,
    )


def build_checkov_binding_artifact(binding: TrustedCheckovBinding) -> dict[str, Any]:
    if not isinstance(binding, TrustedCheckovBinding):
        raise InvalidCheckovBindingError
    return {
        **binding.canonical_data(),
        "binding_digest": binding.binding_digest(),
        "excluded_frameworks": list(CHECKOV_EXCLUDED_FRAMEWORKS),
        "claims": {
            "configuration_source_evidence": True,
            "deployed_state": False,
            "dependency_advisories": False,
            "image_vulnerabilities": False,
            "reachability": False,
            "secrets": False,
        },
        "authority_excluded_checks": list(CHECKOV_AUTHORITY_EXCLUDED_CHECKS),
    }


def canonical_checkov_binding_artifact(binding: TrustedCheckovBinding) -> bytes:
    return _canonical_json(build_checkov_binding_artifact(binding))
