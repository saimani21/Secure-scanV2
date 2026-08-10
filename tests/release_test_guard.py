from __future__ import annotations

import os
from dataclasses import dataclass

import pytest
from docker_test_guard import (
    REQUIRE_DOCKER_TESTS_ENV,
    validated_docker_test_image,
)
from postgres_test_guard import (
    REQUIRE_POSTGRES_TESTS_ENV,
    validated_postgres_test_url,
)
from semgrep_test_guard import (
    REQUIRE_SEMGREP_TESTS_ENV,
    validated_semgrep_test_image,
)

REQUIRE_RELEASE_TESTS_ENV = "SECURESCAN_REQUIRE_RELEASE_TESTS"


@dataclass(frozen=True, slots=True)
class ReleaseTestEnvironment:
    postgres_url: str
    docker_image: str
    semgrep_image: str


def require_release_tests() -> bool:
    return os.environ.get(REQUIRE_RELEASE_TESTS_ENV) == "1"


def validated_release_test_environment() -> ReleaseTestEnvironment:
    if not require_release_tests():
        pytest.skip("Release integration tests require explicit strict release mode")
    required_flags = (
        REQUIRE_POSTGRES_TESTS_ENV,
        REQUIRE_DOCKER_TESTS_ENV,
        REQUIRE_SEMGREP_TESTS_ENV,
    )
    if any(os.environ.get(name) != "1" for name in required_flags):
        pytest.fail("Strict release mode requires all integration safety guards")
    return ReleaseTestEnvironment(
        postgres_url=validated_postgres_test_url(),
        docker_image=validated_docker_test_image(),
        semgrep_image=validated_semgrep_test_image(),
    )
