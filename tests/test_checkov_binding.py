from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from securescan.execution import CancellableProcessRequest, CancellableProcessResult
from securescan.scanners.checkov import (
    CHECKOV_AUTHORITY_EXCLUDED_CHECKS,
    CHECKOV_CONFIG_SHA256,
    CHECKOV_DISTRIBUTION_SHA256,
    CHECKOV_FRAMEWORKS,
    CHECKOV_LAUNCHER_TEMPLATE_SHA256,
    CHECKOV_TOOLCHAIN_DIGEST,
    CHECKOV_TOOLCHAIN_LOCK_SHA256,
    CHECKOV_VERSION,
    CheckovConfigurationIntegrityError,
    CheckovExecutableIntegrityError,
    CheckovToolchainIntegrityError,
    CheckovVersionVerificationError,
    TrustedCheckovBinding,
    build_checkov_binding_artifact,
)
from securescan.scanners.checkov.binding import _toolchain_data, _toolchain_probe_stdout

ROOT = Path(__file__).resolve().parents[1]
LOCK = (
    ROOT
    / "src/securescan/scanners/checkov/toolchain/checkov-3.3.16-cp312-linux-x86_64.lock"
)


def _write(path: Path, content: bytes, mode: int) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(mode)
    return hashlib.sha256(content).hexdigest()


def _binding(tmp_path: Path, *, launcher: bytes | None = None) -> TrustedCheckovBinding:
    executable = tmp_path / "bin" / "checkov"
    config = tmp_path / "config" / "securescan-checkov-v1.yaml"
    if launcher is None:
        launcher = (
            f"#!{executable.parent / 'python'}\n".encode()
            + b"from checkov.main import Checkov\n"
            + b"import warnings\n"
            + b"import sys\n\n"
            + b"if __name__ == '__main__':\n"
            + b"    with warnings.catch_warnings():\n"
            + b'        warnings.simplefilter("ignore", category=SyntaxWarning)\n'
            + b"        sys.exit(Checkov().run())\n"
        )
    return TrustedCheckovBinding(
        executable,
        _write(executable, launcher, 0o700),
        config,
        _write(config, b"framework: [terraform]\n", 0o600),
    )


def _result(
    *, stdout: bytes, stderr: bytes = b"", return_code: int = 0
) -> CancellableProcessResult:
    return CancellableProcessResult(
        return_code, stdout, stderr, 1, False, False, False, False
    )


class _Handle:
    def __init__(self, result: CancellableProcessResult) -> None:
        self.result = result

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def wait(self, timeout_seconds: float | None = None):
        assert timeout_seconds == 12.0
        return self.result

    def poll(self):
        return self.result


class _Executor:
    def __init__(
        self,
        binding: TrustedCheckovBinding,
        *,
        toolchain_result: CancellableProcessResult | None = None,
        version_result: CancellableProcessResult | None = None,
    ) -> None:
        toolchain = _toolchain_data(
            binding.toolchain_lock_path, binding.toolchain_lock_sha256
        )
        self.toolchain_result = toolchain_result or _result(
            stdout=_toolchain_probe_stdout(toolchain)
        )
        self.version_result = version_result or _result(stdout=b"3.3.16\n")
        self.requests: list[CancellableProcessRequest] = []

    def start(self, request: CancellableProcessRequest) -> _Handle:
        self.requests.append(request)
        return _Handle(
            self.toolchain_result if "-I" in request.argv else self.version_result
        )


def test_frozen_identity_authority_and_toolchain_boundary() -> None:
    assert CHECKOV_VERSION == "3.3.16"
    assert CHECKOV_DISTRIBUTION_SHA256 == (
        "6f7f611f45c765af9b6acd43e603a438153d86007d02dffa7903a1125f9b5089"
    )
    assert CHECKOV_CONFIG_SHA256 == (
        "119a53d13286a9de37691a0e683bf8d14aa98abbba13c1ef75a448aa419d59b7"
    )
    assert CHECKOV_TOOLCHAIN_LOCK_SHA256 == (
        "9d8dcc6645b6d4f2035fb90fc500cdd62b1f68dd1dbafc63320d06e3f04a47d0"
    )
    assert CHECKOV_TOOLCHAIN_DIGEST == (
        "a8e451a6ed27fcf1ab0e639b5effbe4bb6e38ef8378058f95f51d7b5f99eefea"
    )
    assert CHECKOV_LAUNCHER_TEMPLATE_SHA256 == (
        "51a09ff89b7771a501ab20498ee396369185f5781eedae24fe9940410fa135b4"
    )
    assert len(_toolchain_data(LOCK, CHECKOV_TOOLCHAIN_LOCK_SHA256)["distributions"]) == 97
    assert CHECKOV_FRAMEWORKS == (
        "terraform",
        "cloudformation",
        "kubernetes",
        "dockerfile",
        "github_actions",
    )
    assert "CKV_AWS_41" in CHECKOV_AUTHORITY_EXCLUDED_CHECKS


def test_exact_toolchain_and_version_checks_use_empty_environment(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    executor = _Executor(binding)
    binding.verify_runtime(executor)
    toolchain_request, version_request = executor.requests
    assert toolchain_request.argv[0] == str(binding.executable_path.parent / "python")
    assert toolchain_request.argv[1:3] == ("-I", "-c")
    assert version_request.argv == (str(binding.executable_path), "--version")
    assert dict(toolchain_request.environment or {}) == {}
    assert dict(version_request.environment or {}) == {}


@pytest.mark.parametrize(
    "result",
    [
        _result(stdout=b"3.3.15\n"),
        _result(stdout=b"3.3.16"),
        _result(stdout=b"3.3.16\n", stderr=b"warning"),
        _result(stdout=b"3.3.16\n", return_code=1),
    ],
)
def test_wrong_version_or_process_shape_fails_closed(
    tmp_path: Path, result: CancellableProcessResult
) -> None:
    binding = _binding(tmp_path)
    with pytest.raises(CheckovVersionVerificationError):
        binding.verify_runtime(_Executor(binding, version_result=result))


def test_wrong_toolchain_inventory_fails_closed(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    with pytest.raises(CheckovToolchainIntegrityError):
        binding.verify_runtime(
            _Executor(binding, toolchain_result=_result(stdout=b'{"distributions":[]}\n'))
        )


def test_modified_toolchain_lock_fails_closed(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    copied_lock = tmp_path / binding.toolchain_lock_path.name
    copied_lock.write_bytes(binding.toolchain_lock_path.read_bytes() + b"changed\n")
    copied_lock.chmod(0o600)
    modified = replace(binding, toolchain_lock_path=copied_lock)
    with pytest.raises(CheckovToolchainIntegrityError):
        modified.canonical_data()


def test_binary_and_config_integrity_fail_closed(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    binding.executable_path.write_bytes(b"changed")
    with pytest.raises(CheckovExecutableIntegrityError):
        binding.verify_runtime(_Executor(binding))
    binding = _binding(tmp_path)
    binding.config_path.write_bytes(b"changed")
    with pytest.raises(CheckovConfigurationIntegrityError):
        binding.verify_runtime(_Executor(binding))


def test_symlinked_binary_and_config_fail_closed(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    binding.executable_path.unlink()
    target = tmp_path / "binary"
    target.write_bytes(b"checkov")
    target.chmod(0o700)
    binding.executable_path.symlink_to(target)
    with pytest.raises(CheckovExecutableIntegrityError):
        binding.verify_runtime(_Executor(binding))


def test_wrong_launcher_template_or_shebang_fails_closed(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    malicious = _binding(tmp_path / "malicious", launcher=b"#!/bin/sh\nexit 0\n")
    with pytest.raises(CheckovExecutableIntegrityError):
        malicious.verify_runtime(_Executor(binding))


def test_directory_command_contract_is_exact(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    projection = tmp_path / "projection"
    projection.mkdir()
    request = binding.authorize_directory_execution(projection, _Executor(binding))
    assert request.argv == (
        str(binding.executable_path),
        "--directory",
        str(projection),
        "--config-file",
        str(binding.config_path),
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
    )
    assert dict(request.environment or {}) == {}
    assert request.stdin_data is None
    assert request.timeout_seconds == 300
    assert request.stdout_limit_bytes == 64 * 1024 * 1024
    assert request.stderr_limit_bytes == 64 * 1024


def test_outside_projection_file_expression_cannot_enable_variable_evaluation(
    tmp_path: Path,
) -> None:
    outside_marker = "SECURESCAN_HARMLESS_OUTSIDE_PROJECTION_MARKER_7D91C4"
    outside = tmp_path / "outside" / "sentinel.txt"
    outside.parent.mkdir()
    outside.write_text(outside_marker)
    projection = tmp_path / "projection"
    projection.mkdir()
    (projection / "main.tf").write_text(
        'locals { outside = file("../outside/sentinel.txt") }\n'
        f'locals {{ absolute = file("{outside}") }}\n'
    )
    binding = _binding(tmp_path / "trusted")
    request = binding.authorize_directory_execution(projection, _Executor(binding))
    option = request.argv.index("--evaluate-variables")
    assert request.argv[option + 1] == "false"
    assert outside_marker not in "\0".join(request.argv)
    assert request.stdin_data is None
    assert dict(request.environment or {}) == {}


def test_binding_identity_excludes_path_dependent_launcher_hash(tmp_path: Path) -> None:
    first = _binding(tmp_path / "a")
    second = _binding(tmp_path / "b")
    assert first.local_launcher_sha256 != second.local_launcher_sha256
    assert first.binding_digest() == second.binding_digest()
    assert "local_launcher_sha256" not in build_checkov_binding_artifact(first)
    assert build_checkov_binding_artifact(first)["executable"][
        "launcher_sha256_in_binding_identity"
    ] is False
    assert build_checkov_binding_artifact(first)["executable"][
        "launcher_template_sha256"
    ] == CHECKOV_LAUNCHER_TEMPLATE_SHA256


def test_binding_artifact_denies_overlapping_authorities(tmp_path: Path) -> None:
    artifact = build_checkov_binding_artifact(_binding(tmp_path))
    assert artifact["claims"]["secrets"] is False
    assert artifact["claims"]["dependency_advisories"] is False
    assert artifact["claims"]["image_vulnerabilities"] is False
    assert artifact["authority_excluded_checks"] == list(CHECKOV_AUTHORITY_EXCLUDED_CHECKS)
    assert artifact["network"]["os_egress_sandbox"] is False
