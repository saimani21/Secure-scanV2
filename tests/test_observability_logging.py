from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any
from uuid import UUID

import pytest

from securescan.observability.context import (
    CORRELATION_ID_HEADER,
    CorrelationIdMiddleware,
    _reset_correlation_id,
    _set_correlation_id,
    get_correlation_id,
)
from securescan.observability.logging import SafeJsonFormatter


async def _invoke_middleware(request_id: bytes | None) -> tuple[str, list[dict[str, Any]]]:
    observed_id = ""

    async def application(scope, receive, send) -> None:
        nonlocal observed_id
        observed_id = get_correlation_id() or ""
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    headers = [] if request_id is None else [(b"x-request-id", request_id)]
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": headers,
    }
    messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    await CorrelationIdMiddleware(application)(scope, receive, send)
    return observed_id, messages


def _response_request_id(messages: list[dict[str, Any]]) -> str:
    start = next(message for message in messages if message["type"] == "http.response.start")
    headers = dict(start["headers"])
    return headers[CORRELATION_ID_HEADER.lower().encode("ascii")].decode("ascii")


def test_valid_request_id_is_preserved_and_returned() -> None:
    observed_id, messages = asyncio.run(_invoke_middleware(b"scan.request_123-abc"))

    assert observed_id == "scan.request_123-abc"
    assert _response_request_id(messages) == observed_id
    assert get_correlation_id() is None


@pytest.mark.parametrize(
    "invalid_id",
    [
        b"contains whitespace",
        b"contains\x01control",
        b"x" * 65,
    ],
)
def test_invalid_request_id_is_replaced_with_uuid(invalid_id: bytes) -> None:
    observed_id, messages = asyncio.run(_invoke_middleware(invalid_id))

    assert str(UUID(observed_id)) == observed_id
    assert _response_request_id(messages) == observed_id
    assert invalid_id.decode("ascii") != observed_id


def test_correlation_context_is_reset_between_requests() -> None:
    first_id, _ = asyncio.run(_invoke_middleware(b"first-request"))
    assert get_correlation_id() is None

    second_id, _ = asyncio.run(_invoke_middleware(None))

    assert first_id == "first-request"
    assert second_id != first_id
    assert str(UUID(second_id)) == second_id
    assert get_correlation_id() is None


def test_safe_json_formatter_emits_required_fields_and_allowed_context() -> None:
    formatter = SafeJsonFormatter()
    token = _set_correlation_id("correlation-123")
    try:
        record = logging.LogRecord(
            name="securescan.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="Worker operation completed",
            args=(),
            exc_info=None,
        )
        record.event = "worker_cycle"
        record.job_id = "job-123"
        record.duration_ms = 42
        record.request = {"authorization": "private"}

        payload = json.loads(formatter.format(record))
    finally:
        _reset_correlation_id(token)

    assert set(payload) == {
        "timestamp",
        "level",
        "logger",
        "message",
        "correlation_id",
        "event",
        "job_id",
        "duration_ms",
    }
    assert payload["level"] == "INFO"
    assert payload["logger"] == "securescan.test"
    assert payload["message"] == "Worker operation completed"
    assert payload["correlation_id"] == "correlation-123"
    assert payload["duration_ms"] == 42
    assert "authorization" not in json.dumps(payload)


def test_safe_json_formatter_exposes_only_exception_type() -> None:
    formatter = SafeJsonFormatter()
    try:
        raise RuntimeError("postgresql://admin:super-secret@database/private SQL credentials")
    except RuntimeError:
        record = logging.LogRecord(
            name="securescan.test",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="Database operation failed",
            args=(),
            exc_info=sys.exc_info(),
        )

    serialized = formatter.format(record)
    payload = json.loads(serialized)
    assert payload["exception_type"] == "RuntimeError"
    assert "postgresql://" not in serialized
    assert "super-secret" not in serialized
    assert "credentials" not in serialized
    assert "Traceback" not in serialized
