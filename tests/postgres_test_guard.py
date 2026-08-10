from __future__ import annotations

import os

import pytest
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

POSTGRES_TEST_URL_ENV = "SECURESCAN_TEST_POSTGRES_URL"
REQUIRE_POSTGRES_TESTS_ENV = "SECURESCAN_REQUIRE_POSTGRES_TESTS"


def require_postgres_tests() -> bool:
    return os.environ.get(REQUIRE_POSTGRES_TESTS_ENV) == "1"


def postgres_test_url_is_configured() -> bool:
    return POSTGRES_TEST_URL_ENV in os.environ


def validated_postgres_test_url() -> str:
    database_url = os.environ.get(POSTGRES_TEST_URL_ENV)
    if database_url is None:
        message = (
            "SECURESCAN_TEST_POSTGRES_URL is not configured; "
            "PostgreSQL integration tests cannot execute"
        )
        if require_postgres_tests():
            pytest.fail(message)
        pytest.skip(message)

    try:
        parsed_url = make_url(database_url)
    except ArgumentError:
        pytest.fail("Unsafe SECURESCAN_TEST_POSTGRES_URL: URL could not be parsed")
    if not parsed_url.get_backend_name().startswith("postgresql"):
        pytest.fail("Unsafe SECURESCAN_TEST_POSTGRES_URL: backend must be PostgreSQL")
    if not parsed_url.database:
        pytest.fail("Unsafe SECURESCAN_TEST_POSTGRES_URL: database name is required")
    if parsed_url.database == "securescan" or not parsed_url.database.endswith("_test"):
        pytest.fail("Unsafe SECURESCAN_TEST_POSTGRES_URL: database name must end with _test")
    return database_url
