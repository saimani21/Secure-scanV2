from __future__ import annotations

import re
from contextvars import ContextVar, Token
from uuid import uuid4

CORRELATION_ID_HEADER = "X-Request-ID"

_CORRELATION_ID_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,64}\Z", re.ASCII)
_correlation_id: ContextVar[str | None] = ContextVar(
    "securescan_correlation_id",
    default=None,
)


def get_correlation_id() -> str | None:
    return _correlation_id.get()


def _set_correlation_id(correlation_id: str) -> Token[str | None]:
    return _correlation_id.set(correlation_id)


def _reset_correlation_id(token: Token[str | None]) -> None:
    _correlation_id.reset(token)


def _validated_or_generated_correlation_id(value: object) -> str:
    if isinstance(value, str) and _CORRELATION_ID_PATTERN.fullmatch(value):
        return value
    return str(uuid4())


class CorrelationIdMiddleware:
    def __init__(self, app) -> None:
        self._app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        incoming_id: str | None = None
        for name, value in scope.get("headers", ()):
            if name.lower() != b"x-request-id":
                continue
            try:
                incoming_id = value.decode("ascii")
            except UnicodeDecodeError:
                incoming_id = None
            break

        correlation_id = _validated_or_generated_correlation_id(incoming_id)
        token = _set_correlation_id(correlation_id)

        async def send_with_correlation_id(message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", ()))
                headers = [
                    (name, value) for name, value in headers if name.lower() != b"x-request-id"
                ]
                headers.append(
                    (
                        CORRELATION_ID_HEADER.lower().encode("ascii"),
                        correlation_id.encode("ascii"),
                    )
                )
                message = {**message, "headers": headers}
            await send(message)

        try:
            await self._app(scope, receive, send_with_correlation_id)
        finally:
            _reset_correlation_id(token)
