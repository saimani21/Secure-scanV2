from __future__ import annotations

import pytest
from postgres_test_guard import validated_postgres_test_url


def test_postgres_guard_skips_clearly_in_ordinary_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SECURESCAN_TEST_POSTGRES_URL", raising=False)
    monkeypatch.delenv("SECURESCAN_REQUIRE_POSTGRES_TESTS", raising=False)

    with pytest.raises(pytest.skip.Exception, match="cannot execute"):
        validated_postgres_test_url()


def test_postgres_guard_fails_when_strict_mode_has_no_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SECURESCAN_TEST_POSTGRES_URL", raising=False)
    monkeypatch.setenv("SECURESCAN_REQUIRE_POSTGRES_TESTS", "1")

    with pytest.raises(pytest.fail.Exception, match="cannot execute"):
        validated_postgres_test_url()


def test_postgres_guard_rejects_development_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "SECURESCAN_TEST_POSTGRES_URL",
        "postgresql+psycopg://127.0.0.1/securescan",
    )
    monkeypatch.setenv("SECURESCAN_REQUIRE_POSTGRES_TESTS", "1")

    with pytest.raises(pytest.fail.Exception, match="must end with _test"):
        validated_postgres_test_url()
