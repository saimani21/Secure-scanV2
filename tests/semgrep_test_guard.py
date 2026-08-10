from __future__ import annotations

import os
import re
import subprocess

import pytest

SEMGREP_TEST_IMAGE_ENV = "SECURESCAN_TEST_SEMGREP_IMAGE"
REQUIRE_SEMGREP_TESTS_ENV = "SECURESCAN_REQUIRE_SEMGREP_TESTS"
_DIGEST_IMAGE_PATTERN = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z", re.ASCII)
_CHECK_TIMEOUT_SECONDS = 5


def require_semgrep_tests() -> bool:
    return os.environ.get(REQUIRE_SEMGREP_TESTS_ENV) == "1"


def _unavailable(message: str) -> None:
    if require_semgrep_tests():
        pytest.fail(message)
    pytest.skip(message)


def _safe_check(argv: tuple[str, ...]) -> subprocess.CompletedProcess[bytes] | None:
    try:
        return subprocess.run(  # noqa: S603 - fixed Docker CLI prerequisite check
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            shell=False,
            timeout=_CHECK_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def validated_semgrep_test_image() -> str:
    image_reference = os.environ.get(SEMGREP_TEST_IMAGE_ENV)
    if image_reference is None:
        _unavailable("Semgrep integration image is not configured")
        raise AssertionError("unreachable")
    if _DIGEST_IMAGE_PATTERN.fullmatch(image_reference) is None:
        pytest.fail("Semgrep integration image must use an immutable digest")

    version = _safe_check(("docker", "version", "--format", "{{.Server.Version}}"))
    if version is None or version.returncode != 0:
        _unavailable("Semgrep integration service is unavailable")
    image = _safe_check(
        ("docker", "image", "inspect", "--format", "{{.Id}}", image_reference)
    )
    if image is None or image.returncode != 0:
        _unavailable("Semgrep integration image is not available locally")
    return image_reference
