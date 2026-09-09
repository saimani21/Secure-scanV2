from __future__ import annotations

import hashlib
import json
import os
import socket
import sys
from collections.abc import Callable
from typing import Any

import httpx

from securescan.advisories.osv import (
    OSV_ADVISORY_RESPONSE_LIMIT_BYTES,
    OSV_BASE_URL,
    OSV_CONNECT_TIMEOUT_SECONDS,
    OSV_QUERY_RESPONSE_LIMIT_BYTES,
    OSV_REQUEST_TIMEOUT_SECONDS,
    OsvDependencyAnalysis,
    OsvFailureCode,
    OsvHttpResponse,
    OsvIntegrationError,
    TrustedOsvClient,
    group_advisories,
)

from .osv_execution import (
    OSV_HELPER_PROTOCOL_VERSION,
    OsvRequestOperation,
    SourceOsvExecutionError,
    SourceOsvExecutionInput,
    SourceOsvFailureCode,
    analysis_document,
)

_MAX_PERMIT_MESSAGE_BYTES = 16 * 1024
_MAX_HELPER_INPUT_BYTES = 16 * 1024 * 1024


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _strict_json(payload: bytes, *, maximum: int) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    if not payload or len(payload) > maximum:
        raise ValueError
    value = json.loads(
        payload.decode("utf-8"),
        object_pairs_hook=pairs,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
    )
    if not isinstance(value, dict) or _canonical_json(value) != payload:
        raise ValueError
    return value


class PermitAwareOsvTransport:
    """Frozen OSV HTTP transport with one attempt-bound permit per invocation."""

    def __init__(
        self,
        *,
        socket_path: str,
        attempt_token: str,
        base_url: str = OSV_BASE_URL,
        client_factory: Callable[..., httpx.Client] = httpx.Client,
    ) -> None:
        if base_url != OSV_BASE_URL and not _allowed_loopback_test_url(base_url):
            raise SourceOsvExecutionError
        self._socket_path = socket_path
        self._attempt_token = attempt_token
        self._sequence = 0
        self._attempts: dict[str, int] = {}
        self._client = client_factory(
            base_url=base_url,
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(
                connect=OSV_CONNECT_TIMEOUT_SECONDS,
                read=OSV_REQUEST_TIMEOUT_SECONDS,
                write=OSV_REQUEST_TIMEOUT_SECONDS,
                pool=OSV_CONNECT_TIMEOUT_SECONDS,
            ),
            headers={"Accept": "application/json", "User-Agent": "SecureScan-OSV-S6CB"},
        )
        self._last_failure_code: SourceOsvFailureCode | None = None

    def close(self) -> None:
        self._client.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None,
        limit: int,
    ) -> OsvHttpResponse:
        operation = (
            OsvRequestOperation.QUERY_BATCH
            if method == "POST" and path == "/v1/querybatch"
            else OsvRequestOperation.ADVISORY_GET
            if method == "GET" and path.startswith("/v1/vulns/")
            else None
        )
        if (
            operation is None
            or limit
            not in {OSV_QUERY_RESPONSE_LIMIT_BYTES, OSV_ADVISORY_RESPONSE_LIMIT_BYTES}
            or (operation is OsvRequestOperation.QUERY_BATCH) != (json_body is not None)
        ):
            raise OsvIntegrationError(OsvFailureCode.HTTP_ERROR)
        logical = hashlib.sha256(
            _canonical_json({"json_body": json_body, "method": method, "path": path})
        ).hexdigest()
        transport_attempt = self._attempts.get(logical, 0) + 1
        self._attempts[logical] = transport_attempt
        self._sequence += 1
        self._request_permit(operation, logical, transport_attempt)
        body = bytearray()
        self._client.cookies.clear()
        try:
            with self._client.stream(method, path, json=json_body) as response:
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > limit:
                        raise OsvIntegrationError(OsvFailureCode.RESPONSE_LIMIT)
                self._last_failure_code = _status_failure_code(response.status_code)
                return OsvHttpResponse(response.status_code, bytes(body))
        except httpx.ConnectTimeout:
            self._last_failure_code = SourceOsvFailureCode.CONNECT_TIMEOUT
            raise
        except httpx.TimeoutException:
            self._last_failure_code = SourceOsvFailureCode.READ_WRITE_TIMEOUT
            raise
        except (httpx.NetworkError, OSError):
            self._last_failure_code = SourceOsvFailureCode.NETWORK_FAILURE
            raise
        finally:
            self._client.cookies.clear()

    def classify_failure(self, code: OsvFailureCode) -> SourceOsvFailureCode:
        if code in {
            OsvFailureCode.HTTP_ERROR,
            OsvFailureCode.ADVISORY_FETCH_FAILED,
            OsvFailureCode.NETWORK_FAILURE,
            OsvFailureCode.TIMEOUT,
        } and self._last_failure_code is not None:
            return self._last_failure_code
        return {
            OsvFailureCode.NETWORK_FAILURE: SourceOsvFailureCode.NETWORK_FAILURE,
            OsvFailureCode.TIMEOUT: SourceOsvFailureCode.READ_WRITE_TIMEOUT,
            OsvFailureCode.RESPONSE_LIMIT: SourceOsvFailureCode.INVALID_OSV_SCHEMA,
            OsvFailureCode.HTTP_ERROR: SourceOsvFailureCode.HTTP_PERMANENT_ERROR,
            OsvFailureCode.QUERY_RESPONSE_INVALID: SourceOsvFailureCode.INVALID_OSV_SCHEMA,
            OsvFailureCode.PAGINATION_INVALID: (
                SourceOsvFailureCode.PAGINATION_INTEGRITY_FAILURE
            ),
            OsvFailureCode.ADVISORY_FETCH_FAILED: (
                SourceOsvFailureCode.HTTP_PERMANENT_ERROR
            ),
            OsvFailureCode.ADVISORY_SCHEMA_INVALID: (
                SourceOsvFailureCode.INVALID_OSV_SCHEMA
            ),
            OsvFailureCode.DATA_CHANGED_DURING_QUERY: (
                SourceOsvFailureCode.OSV_DATA_CHANGED_DURING_QUERY
            ),
            OsvFailureCode.RUNTIME_DEPENDENCY_INVALID: (
                SourceOsvFailureCode.HELPER_EXECUTION_FAILURE
            ),
        }[code]

    def _request_permit(
        self,
        operation: OsvRequestOperation,
        logical_request_digest: str,
        transport_attempt_number: int,
    ) -> None:
        request = _canonical_json(
            {
                "attempt_token": self._attempt_token,
                "logical_request_digest": logical_request_digest,
                "operation_kind": operation.value,
                "protocol_version": OSV_HELPER_PROTOCOL_VERSION,
                "request_sequence": self._sequence,
                "transport_attempt_number": transport_attempt_number,
            }
        )
        if len(request) > _MAX_PERMIT_MESSAGE_BYTES:
            raise OsvIntegrationError(OsvFailureCode.NETWORK_FAILURE)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
                channel.settimeout(OSV_CONNECT_TIMEOUT_SECONDS)
                channel.connect(self._socket_path)
                channel.sendall(request)
                response = _read_bounded(channel, _MAX_PERMIT_MESSAGE_BYTES)
            decoded = _strict_json(response, maximum=_MAX_PERMIT_MESSAGE_BYTES)
            if decoded != {
                "authorized": True,
                "protocol_version": OSV_HELPER_PROTOCOL_VERSION,
                "request_sequence": self._sequence,
            }:
                raise ValueError
        except (OSError, TypeError, ValueError, UnicodeError):
            raise OsvIntegrationError(OsvFailureCode.NETWORK_FAILURE) from None


def _allowed_loopback_test_url(value: str) -> bool:
    if os.environ.get("SECURESCAN_OSV_ALLOW_LOOPBACK_TEST_TRANSPORT") != "1":
        return False
    try:
        parsed = httpx.URL(value)
    except Exception:
        return False
    return bool(
        parsed.scheme == "http"
        and parsed.host in {"127.0.0.1", "::1", "localhost"}
        and parsed.port is not None
        and parsed.query == b""
        and parsed.fragment == ""
    )


def _status_failure_code(status_code: int) -> SourceOsvFailureCode | None:
    if status_code == 200:
        return None
    if status_code == 429:
        return SourceOsvFailureCode.HTTP_RATE_LIMIT
    if status_code in {500, 502, 503, 504}:
        return SourceOsvFailureCode.HTTP_RETRYABLE_SERVER_ERROR
    return SourceOsvFailureCode.HTTP_PERMANENT_ERROR


def _read_bounded(channel: socket.socket, maximum: int) -> bytes:
    data = bytearray()
    while len(data) <= maximum:
        chunk = channel.recv(min(4096, maximum + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk:
            break
    if len(data) > maximum or not data.endswith(b"\n") or data.count(b"\n") != 1:
        raise ValueError
    return bytes(data)


def execute(execution_input: SourceOsvExecutionInput, transport: Any) -> OsvDependencyAnalysis:
    client = TrustedOsvClient(transport)
    matches = client.query(execution_input.candidates)
    findings = tuple(
        sorted(
            (
                finding
                for match in matches
                for finding in group_advisories(match.candidate, match.advisories)
            ),
            key=lambda item: item.finding_id,
        )
    )
    candidate_ids = tuple(item.candidate_id for item in execution_input.candidates)
    return OsvDependencyAnalysis(
        candidates=execution_input.candidates,
        gaps=(),
        candidate_matches=matches,
        findings=findings,
        completed_candidate_ids=candidate_ids,
        zero_advisory_candidate_ids=tuple(
            item.candidate.candidate_id for item in matches if not item.references
        ),
    )


def main() -> int:
    transport: PermitAwareOsvTransport | None = None
    try:
        payload = sys.stdin.buffer.read(_MAX_HELPER_INPUT_BYTES + 1)
        if len(payload) > _MAX_HELPER_INPUT_BYTES:
            raise SourceOsvExecutionError
        root = _strict_json(payload, maximum=_MAX_HELPER_INPUT_BYTES)
        if not isinstance(root, dict) or set(root) != {
            "attempt_token",
            "execution_input",
            "protocol_version",
        }:
            raise SourceOsvExecutionError
        if root["protocol_version"] != OSV_HELPER_PROTOCOL_VERSION:
            raise SourceOsvExecutionError
        execution_input = SourceOsvExecutionInput.from_json(
            _canonical_json(root["execution_input"])
        )
        socket_path = os.environ["SECURESCAN_OSV_PERMIT_SOCKET"]
        base_url = os.environ.get("SECURESCAN_OSV_BASE_URL", OSV_BASE_URL)
        transport = PermitAwareOsvTransport(
            socket_path=socket_path,
            attempt_token=root["attempt_token"],
            base_url=base_url,
        )
        try:
            analysis = execute(execution_input, transport)
        finally:
            transport.close()
        sys.stdout.buffer.write(
            _canonical_json(
                {
                    "analysis": analysis_document(analysis),
                    "protocol_version": OSV_HELPER_PROTOCOL_VERSION,
                    "status": "SUCCEEDED",
                }
            )
        )
        return 0
    except OsvIntegrationError as exc:
        failure_code = (
            transport.classify_failure(exc.code)
            if transport is not None
            else SourceOsvFailureCode.HELPER_EXECUTION_FAILURE
        )
        sys.stdout.buffer.write(
            _canonical_json(
                {
                    "failure_code": failure_code.value,
                    "protocol_version": OSV_HELPER_PROTOCOL_VERSION,
                    "status": "FAILED",
                }
            )
        )
        return 2
    except Exception:
        sys.stdout.buffer.write(
            _canonical_json(
                {
                    "failure_code": "OSV_HELPER_EXECUTION_FAILURE",
                    "protocol_version": OSV_HELPER_PROTOCOL_VERSION,
                    "status": "FAILED",
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
