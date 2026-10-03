from __future__ import annotations

import pytest
from sqlalchemy.exc import OperationalError

from securescan.jobs.transaction_retry import run_with_bounded_transaction_retry


class _DatabaseFailure(Exception):
    def __init__(self, sqlstate: str) -> None:
        super().__init__(sqlstate)
        self.sqlstate = sqlstate


def _operational_error(sqlstate: str) -> OperationalError:
    return OperationalError("SELECT 1", {}, _DatabaseFailure(sqlstate))


@pytest.mark.parametrize("sqlstate", ["40001", "40P01"])
def test_bounded_transaction_retry_accepts_only_transient_sqlstates(sqlstate: str) -> None:
    calls = 0

    def operation() -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise _operational_error(sqlstate)
        return "committed"

    assert run_with_bounded_transaction_retry(operation) == "committed"
    assert calls == 2


def test_bounded_transaction_retry_does_not_retry_other_database_errors() -> None:
    calls = 0

    def operation() -> None:
        nonlocal calls
        calls += 1
        raise _operational_error("23505")

    with pytest.raises(OperationalError):
        run_with_bounded_transaction_retry(operation)
    assert calls == 1


def test_bounded_transaction_retry_stops_after_three_attempts() -> None:
    calls = 0

    def operation() -> None:
        nonlocal calls
        calls += 1
        raise _operational_error("40P01")

    with pytest.raises(OperationalError):
        run_with_bounded_transaction_retry(operation)
    assert calls == 3
