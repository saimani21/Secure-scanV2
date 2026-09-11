from __future__ import annotations

import time
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Final, Protocol

import httpx

from securescan.advisories.osv.models import (
    OSV_API_VERSION,
    OSV_CVSS_DISTRIBUTION,
    OSV_CVSS_VERSION,
    OSV_HTTP_DISTRIBUTION,
    OSV_HTTP_VERSION,
    OSV_PROVIDER_ID,
    OSV_PURL_DISTRIBUTION,
    OSV_PURL_VERSION,
    OsvAdvisoryObservation,
    OsvAdvisoryReference,
    OsvFailureCode,
    OsvIntegrationError,
    OsvQueryCandidate,
    osv_advisory_revision_matches,
)
from securescan.advisories.osv.parser import (
    OSV_MAX_AFFECTED_ENTRIES,
    OSV_MAX_ALIASES,
    OSV_MAX_EVENTS_PER_RANGE,
    OSV_MAX_FIXED_VERSIONS,
    OSV_MAX_PAGE_TOKEN_BYTES,
    OSV_MAX_QUERY_REFERENCES_PER_RESULT,
    OSV_MAX_RANGES_PER_AFFECTED,
    OSV_MAX_REFERENCES,
    OSV_MAX_SEVERITY_ENTRIES,
    OSV_MAX_SUMMARY_BYTES,
    OSV_MAX_VERSIONS_PER_AFFECTED,
    parse_advisory_response,
    parse_query_response,
)

OSV_BASE_URL: Final = "https://api.osv.dev"
OSV_QUERY_ENDPOINT: Final = "/v1/querybatch"
OSV_RECORD_ENDPOINT_TEMPLATE: Final = "/v1/vulns/{id}"
OSV_BATCH_SIZE: Final = 100
OSV_MAX_CANDIDATES: Final = 1_000
OSV_MAX_BATCHES: Final = 10
OSV_MAX_PAGES_PER_CANDIDATE: Final = 5
OSV_MAX_ADVISORY_IDS: Final = 10_000
OSV_CONNECT_TIMEOUT_SECONDS: Final = 5.0
OSV_REQUEST_TIMEOUT_SECONDS: Final = 25.0
OSV_MAX_RETRY_ATTEMPTS: Final = 3
OSV_QUERY_RESPONSE_LIMIT_BYTES: Final = 8 * 1024 * 1024
OSV_ADVISORY_RESPONSE_LIMIT_BYTES: Final = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class OsvHttpResponse:
    status_code: int
    body: bytes


class OsvTransport(Protocol):
    def request(
        self, method: str, path: str, *, json_body: dict[str, Any] | None, limit: int
    ) -> OsvHttpResponse: ...


class HttpxOsvTransport:
    def __init__(self) -> None:
        self._client = httpx.Client(
            base_url=OSV_BASE_URL,
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(
                connect=OSV_CONNECT_TIMEOUT_SECONDS,
                read=OSV_REQUEST_TIMEOUT_SECONDS,
                write=OSV_REQUEST_TIMEOUT_SECONDS,
                pool=OSV_CONNECT_TIMEOUT_SECONDS,
            ),
            headers={"Accept": "application/json", "User-Agent": "SecureScan-OSV-S2"},
        )

    def __enter__(self) -> HttpxOsvTransport:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def request(
        self, method: str, path: str, *, json_body: dict[str, Any] | None, limit: int
    ) -> OsvHttpResponse:
        body = bytearray()
        self._client.cookies.clear()
        try:
            with self._client.stream(method, path, json=json_body) as response:
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > limit:
                        raise OsvIntegrationError(OsvFailureCode.RESPONSE_LIMIT)
                return OsvHttpResponse(response.status_code, bytes(body))
        finally:
            self._client.cookies.clear()


@dataclass(frozen=True, slots=True)
class OsvCandidateMatch:
    candidate: OsvQueryCandidate
    references: tuple[OsvAdvisoryReference, ...]
    advisories: tuple[OsvAdvisoryObservation, ...]

    def __post_init__(self) -> None:
        expected = tuple(
            sorted(
                (reference.osv_record_id, reference.modified)
                for reference in self.references
            )
        )
        actual = tuple(
            sorted((advisory.osv_record_id, advisory.modified) for advisory in self.advisories)
        )
        revisions_match = (
            len(expected) == len(actual)
            and all(
                expected_id == actual_id
                and osv_advisory_revision_matches(expected_modified, actual_modified)
                for (
                    (expected_id, expected_modified),
                    (actual_id, actual_modified),
                ) in zip(expected, actual, strict=True)
            )
        )
        if (
            not isinstance(self.candidate, OsvQueryCandidate)
            or self.references
            != tuple(
                sorted(
                    set(self.references),
                    key=lambda item: (item.osv_record_id, item.modified),
                )
            )
            or not revisions_match
            or any(
                advisory.applicable_package_key != self.candidate.package_key
                for advisory in self.advisories
            )
        ):
            raise ValueError("OSV candidate match is invalid")


def verify_osv_runtime_dependencies() -> None:
    try:
        if (
            version(OSV_HTTP_DISTRIBUTION) != OSV_HTTP_VERSION
            or version(OSV_CVSS_DISTRIBUTION) != OSV_CVSS_VERSION
            or version(OSV_PURL_DISTRIBUTION) != OSV_PURL_VERSION
        ):
            raise ValueError
    except (PackageNotFoundError, ValueError):
        raise OsvIntegrationError(OsvFailureCode.RUNTIME_DEPENDENCY_INVALID) from None


class TrustedOsvClient:
    def __init__(self, transport: OsvTransport, *, sleep: Any = time.sleep) -> None:
        if not hasattr(transport, "request") or not callable(transport.request):
            raise TypeError("OSV transport is invalid")
        verify_osv_runtime_dependencies()
        self._transport = transport
        self._sleep = sleep

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None,
        limit: int,
        fetch: bool = False,
    ) -> bytes:
        for attempt in range(OSV_MAX_RETRY_ATTEMPTS):
            try:
                response = self._transport.request(
                    method, path, json_body=json_body, limit=limit
                )
            except OsvIntegrationError:
                raise
            except (httpx.TimeoutException, TimeoutError):
                if attempt + 1 == OSV_MAX_RETRY_ATTEMPTS:
                    raise OsvIntegrationError(OsvFailureCode.TIMEOUT) from None
                self._sleep(0.05 * (2**attempt))
                continue
            except (httpx.NetworkError, OSError):
                if attempt + 1 == OSV_MAX_RETRY_ATTEMPTS:
                    code = (
                        OsvFailureCode.ADVISORY_FETCH_FAILED
                        if fetch
                        else OsvFailureCode.NETWORK_FAILURE
                    )
                    raise OsvIntegrationError(code) from None
                self._sleep(0.05 * (2**attempt))
                continue
            if response.status_code == 200:
                return response.body
            if (
                response.status_code == 429
                or response.status_code in {500, 502, 503, 504}
            ) and attempt + 1 < OSV_MAX_RETRY_ATTEMPTS:
                self._sleep(0.05 * (2**attempt))
                continue
            code = OsvFailureCode.ADVISORY_FETCH_FAILED if fetch else OsvFailureCode.HTTP_ERROR
            raise OsvIntegrationError(code)
        raise OsvIntegrationError(OsvFailureCode.NETWORK_FAILURE)

    def _query_page(
        self, candidates: tuple[OsvQueryCandidate, ...], tokens: tuple[str | None, ...]
    ) -> tuple[tuple[tuple[OsvAdvisoryReference, ...], str | None], ...]:
        payload = {
            "queries": [
                candidate.query_data(token)
                for candidate, token in zip(candidates, tokens, strict=True)
            ]
        }
        body = self._request(
            "POST",
            OSV_QUERY_ENDPOINT,
            json_body=payload,
            limit=OSV_QUERY_RESPONSE_LIMIT_BYTES,
        )
        return parse_query_response(body, len(candidates))

    def query(self, candidates: tuple[OsvQueryCandidate, ...]) -> tuple[OsvCandidateMatch, ...]:
        if (
            not isinstance(candidates, tuple)
            or len(candidates) > OSV_MAX_CANDIDATES
            or candidates != tuple(sorted(candidates, key=lambda item: item.candidate_id))
            or len({item.candidate_id for item in candidates}) != len(candidates)
        ):
            raise OsvIntegrationError(OsvFailureCode.QUERY_RESPONSE_INVALID)
        references_by_candidate: dict[str, dict[str, OsvAdvisoryReference]] = {
            item.candidate_id: {} for item in candidates
        }
        batches = tuple(
            candidates[index : index + OSV_BATCH_SIZE]
            for index in range(0, len(candidates), OSV_BATCH_SIZE)
        )
        if len(batches) > OSV_MAX_BATCHES:
            raise OsvIntegrationError(OsvFailureCode.QUERY_RESPONSE_INVALID)
        for batch in batches:
            results = self._query_page(batch, (None,) * len(batch))
            for candidate, (references, token) in zip(batch, results, strict=True):
                seen_tokens: set[str] = set()
                page_count = 1
                while True:
                    target = references_by_candidate[candidate.candidate_id]
                    for reference in references:
                        previous = target.get(reference.osv_record_id)
                        if previous is not None and previous.modified != reference.modified:
                            raise OsvIntegrationError(
                                OsvFailureCode.DATA_CHANGED_DURING_QUERY
                            )
                        target[reference.osv_record_id] = reference
                    if token is None:
                        break
                    if token in seen_tokens or page_count >= OSV_MAX_PAGES_PER_CANDIDATE:
                        raise OsvIntegrationError(OsvFailureCode.PAGINATION_INVALID)
                    seen_tokens.add(token)
                    page_count += 1
                    ((references, token),) = self._query_page((candidate,), (token,))
        total = sum(len(value) for value in references_by_candidate.values())
        if total > OSV_MAX_ADVISORY_IDS:
            raise OsvIntegrationError(OsvFailureCode.RESPONSE_LIMIT)
        revisions: dict[str, str] = {}
        for references in references_by_candidate.values():
            for reference in references.values():
                previous = revisions.get(reference.osv_record_id)
                if previous is not None and previous != reference.modified:
                    raise OsvIntegrationError(OsvFailureCode.DATA_CHANGED_DURING_QUERY)
                revisions[reference.osv_record_id] = reference.modified
        advisory_cache: dict[tuple[str, str], bytes] = {}
        matches = []
        for candidate in candidates:
            references = tuple(
                sorted(
                    references_by_candidate[candidate.candidate_id].values(),
                    key=lambda item: (item.osv_record_id, item.modified),
                )
            )
            advisories = []
            for reference in references:
                cache_key = (reference.osv_record_id, reference.modified)
                body = advisory_cache.get(cache_key)
                if body is None:
                    body = self._request(
                        "GET",
                        OSV_RECORD_ENDPOINT_TEMPLATE.format(id=reference.osv_record_id),
                        json_body=None,
                        limit=OSV_ADVISORY_RESPONSE_LIMIT_BYTES,
                        fetch=True,
                    )
                    advisory_cache[cache_key] = body
                advisories.append(
                    parse_advisory_response(body, expected=reference, candidate=candidate)
                )
            matches.append(OsvCandidateMatch(candidate, references, tuple(advisories)))
        return tuple(matches)


def build_osv_service_contract() -> dict[str, Any]:
    return {
        "api_version": OSV_API_VERSION,
        "base_url": OSV_BASE_URL,
        "limits": {
            "advisory_response_bytes": OSV_ADVISORY_RESPONSE_LIMIT_BYTES,
            "batch_size": OSV_BATCH_SIZE,
            "connect_timeout_seconds": OSV_CONNECT_TIMEOUT_SECONDS,
            "max_advisory_ids": OSV_MAX_ADVISORY_IDS,
            "max_batches": OSV_MAX_BATCHES,
            "max_candidates": OSV_MAX_CANDIDATES,
            "max_pages_per_candidate": OSV_MAX_PAGES_PER_CANDIDATE,
            "max_retry_attempts": OSV_MAX_RETRY_ATTEMPTS,
            "query_response_bytes": OSV_QUERY_RESPONSE_LIMIT_BYTES,
            "request_timeout_seconds": OSV_REQUEST_TIMEOUT_SECONDS,
        },
        "network": {
            "cookies": False,
            "credentials": False,
            "follow_redirects": False,
            "host": "api.osv.dev",
            "os_egress_sandbox": False,
            "port": 443,
            "scheme": "https",
            "source_content_transmitted": False,
            "trust_env": False,
        },
        "provider_id": OSV_PROVIDER_ID,
        "query_endpoint": OSV_QUERY_ENDPOINT,
        "record_endpoint": OSV_RECORD_ENDPOINT_TEMPLATE,
        "transport": {
            "distribution": OSV_HTTP_DISTRIBUTION,
            "version": OSV_HTTP_VERSION,
        },
        "normalization": {
            "max_affected_entries": OSV_MAX_AFFECTED_ENTRIES,
            "max_aliases": OSV_MAX_ALIASES,
            "max_events_per_range": OSV_MAX_EVENTS_PER_RANGE,
            "max_fixed_versions": OSV_MAX_FIXED_VERSIONS,
            "max_page_token_bytes": OSV_MAX_PAGE_TOKEN_BYTES,
            "max_query_references_per_result": OSV_MAX_QUERY_REFERENCES_PER_RESULT,
            "max_ranges_per_affected": OSV_MAX_RANGES_PER_AFFECTED,
            "max_references": OSV_MAX_REFERENCES,
            "max_severity_entries": OSV_MAX_SEVERITY_ENTRIES,
            "max_summary_utf8_bytes": OSV_MAX_SUMMARY_BYTES,
            "max_versions_per_affected": OSV_MAX_VERSIONS_PER_AFFECTED,
        },
        "purl_normalization": {
            "distribution": OSV_PURL_DISTRIBUTION,
            "version": OSV_PURL_VERSION,
        },
        "cvss": {
            "distribution": OSV_CVSS_DISTRIBUTION,
            "version": OSV_CVSS_VERSION,
        },
    }
