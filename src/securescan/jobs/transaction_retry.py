from __future__ import annotations

from collections.abc import Callable

from sqlalchemy.exc import DBAPIError

_RETRYABLE_TRANSACTION_SQLSTATES = frozenset({"40001", "40P01"})
_MAX_TRANSACTION_ATTEMPTS = 3


def run_with_bounded_transaction_retry[Result](operation: Callable[[], Result]) -> Result:
    """Retry only database-selected deadlock/serialization victims."""

    for attempt in range(_MAX_TRANSACTION_ATTEMPTS):
        try:
            return operation()
        except DBAPIError as error:
            sqlstate = getattr(error.orig, "sqlstate", None)
            if (
                sqlstate not in _RETRYABLE_TRANSACTION_SQLSTATES
                or attempt + 1 == _MAX_TRANSACTION_ATTEMPTS
            ):
                raise
    raise AssertionError("bounded transaction retry exhausted without an outcome")
