from __future__ import annotations

import os
import re
import subprocess

import pytest

DOCKER_TEST_IMAGE_ENV = "SECURESCAN_TEST_DOCKER_IMAGE"
REQUIRE_DOCKER_TESTS_ENV = "SECURESCAN_REQUIRE_DOCKER_TESTS"
_DIGEST_IMAGE_PATTERN = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z", re.ASCII)
_CHECK_TIMEOUT_SECONDS = 5


def require_docker_tests() -> bool:
    return os.environ.get(REQUIRE_DOCKER_TESTS_ENV) == "1"


def docker_test_image_is_configured() -> bool:
    return DOCKER_TEST_IMAGE_ENV in os.environ


def _run_safe_check(argv: tuple[str, ...]) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(  # noqa: S603 - fixed Docker CLI checks, no shell
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            shell=False,
            timeout=_CHECK_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pytest.fail("Docker integration prerequisite check failed")


def validated_docker_test_image() -> str:
    image_reference = os.environ.get(DOCKER_TEST_IMAGE_ENV)
    if image_reference is None:
        message = "Docker integration image is not configured"
        if require_docker_tests():
            pytest.fail(message)
        pytest.skip(message)
    if _DIGEST_IMAGE_PATTERN.fullmatch(image_reference) is None:
        pytest.fail("Docker integration image must use an immutable digest")

    version = _run_safe_check(("docker", "version", "--format", "{{.Server.Version}}"))
    if version.returncode != 0:
        pytest.fail("Docker integration service is unavailable")

    image = _run_safe_check(
        ("docker", "image", "inspect", "--format", "{{.Id}}", image_reference)
    )
    if image.returncode != 0:
        pytest.fail("Docker integration image is not available locally")
    return image_reference
