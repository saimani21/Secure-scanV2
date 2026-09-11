from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import pytest

import securescan.advisories.osv.client as client_module
from securescan.advisories.osv import (
    OSV_HTTP_VERSION,
    OSV_PURL_VERSION,
    OsvFailureCode,
    OsvHttpResponse,
    OsvIntegrationError,
    TrustedOsvClient,
    build_osv_service_contract,
    verify_osv_runtime_dependencies,
)
from securescan.benchmarks.osv_s2 import build_controlled_candidates

_MODIFIED = "2026-08-06T00:00:00Z"


def _json(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def _advisory(record_id: str, purl: str, *, modified: str = _MODIFIED) -> bytes:
    return _json(
        {
            "schema_version": "1.9.0",
            "id": record_id,
            "modified": modified,
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "x", "purl": purl},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                }
            ],
        }
    )


@dataclass
class _Transport:
    outcomes: list[OsvHttpResponse | BaseException]

    def __post_init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any] | None, int]] = []

    def request(
        self, method: str, path: str, *, json_body: dict[str, Any] | None, limit: int
    ) -> OsvHttpResponse:
        self.calls.append((method, path, json_body, limit))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def _candidate():
    return next(
        value
        for value in build_controlled_candidates()
        if value.purl == "pkg:pypi/pyyaml@5.3.1"
    )


def test_query_zero_advisories_is_success_and_transmits_only_versioned_purl() -> None:
    candidate = _candidate()
    transport = _Transport([OsvHttpResponse(200, b'{"results":[{}]}')])
    (match,) = TrustedOsvClient(transport, sleep=lambda _: None).query((candidate,))
    assert match.references == ()
    assert match.advisories == ()
    method, path, body, _ = transport.calls[0]
    assert (method, path) == ("POST", "/v1/querybatch")
    assert body == {"queries": [{"package": {"purl": candidate.purl}}]}
    serialized = _json(body)
    assert candidate.locations[0].encode() not in serialized
    assert b"source" not in serialized


def test_duplicate_ids_fetch_once_and_results_bind_to_ordered_candidate() -> None:
    candidate = _candidate()
    query = OsvHttpResponse(
        200,
        _json(
            {
                "results": [
                    {
                        "vulns": [
                            {"id": "PYSEC-2024-1", "modified": _MODIFIED},
                            {"id": "PYSEC-2024-1", "modified": _MODIFIED},
                        ]
                    }
                ]
            }
        ),
    )
    transport = _Transport(
        [query, OsvHttpResponse(200, _advisory("PYSEC-2024-1", "pkg:pypi/requests"))]
    )
    (match,) = TrustedOsvClient(transport, sleep=lambda _: None).query((candidate,))
    assert tuple(value.osv_record_id for value in match.references) == ("PYSEC-2024-1",)
    assert [call[0] for call in transport.calls] == ["POST", "GET"]


def test_query_accepts_advisory_with_higher_precision_revision() -> None:
    candidate = _candidate()
    reference_modified = "2026-09-10T03:50:25.139398Z"
    observed_modified = "2026-09-10T03:50:25.139398550Z"
    query = OsvHttpResponse(
        200,
        _json(
            {
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "GHSA-9hjg-9r4m-mvj7",
                                "modified": reference_modified,
                            }
                        ]
                    }
                ]
            }
        ),
    )
    advisory = OsvHttpResponse(
        200,
        _advisory(
            "GHSA-9hjg-9r4m-mvj7",
            "pkg:pypi/pyyaml",
            modified=observed_modified,
        ),
    )
    (match,) = TrustedOsvClient(
        _Transport([query, advisory]), sleep=lambda _: None
    ).query((candidate,))
    assert match.references[0].modified == reference_modified
    assert match.advisories[0].modified == observed_modified


def test_pagination_is_per_candidate_and_repeated_token_fails() -> None:
    candidate = _candidate()
    first = OsvHttpResponse(
        200,
        _json({"results": [{"vulns": [], "next_page_token": "page-2"}]}),
    )
    final = OsvHttpResponse(200, _json({"results": [{}]}))
    transport = _Transport([first, final])
    TrustedOsvClient(transport, sleep=lambda _: None).query((candidate,))
    assert transport.calls[1][2] == {
        "queries": [{"package": {"purl": candidate.purl}, "page_token": "page-2"}]
    }

    repeated = _Transport([first, first])
    with pytest.raises(OsvIntegrationError) as caught:
        TrustedOsvClient(repeated, sleep=lambda _: None).query((candidate,))
    assert caught.value.code is OsvFailureCode.PAGINATION_INVALID


@pytest.mark.parametrize(
    ("outcomes", "expected"),
    [
        ([OsvHttpResponse(400, b"")], OsvFailureCode.HTTP_ERROR),
        ([OsvHttpResponse(302, b"")], OsvFailureCode.HTTP_ERROR),
        ([TimeoutError(), TimeoutError(), TimeoutError()], OsvFailureCode.TIMEOUT),
        ([OSError(), OSError(), OSError()], OsvFailureCode.NETWORK_FAILURE),
    ],
)
def test_failures_never_become_clean_results(outcomes, expected) -> None:
    with pytest.raises(OsvIntegrationError) as caught:
        TrustedOsvClient(_Transport(outcomes), sleep=lambda _: None).query((_candidate(),))
    assert caught.value.code is expected


@pytest.mark.parametrize("status", [429, 500, 503])
def test_transient_statuses_retry_bounded_then_succeed(status: int) -> None:
    transport = _Transport(
        [OsvHttpResponse(status, b""), OsvHttpResponse(200, b'{"results":[{}]}')]
    )
    TrustedOsvClient(transport, sleep=lambda _: None).query((_candidate(),))
    assert len(transport.calls) == 2


def test_querybatch_cross_candidate_conflicting_revisions_remain_rejected() -> None:
    candidates = build_controlled_candidates()[:2]
    response = OsvHttpResponse(
        200,
        _json(
            {
                "results": [
                    {"vulns": [{"id": "GO-2024-1", "modified": _MODIFIED}]},
                    {
                        "vulns": [
                            {"id": "GO-2024-1", "modified": "2026-08-07T00:00:00Z"}
                        ]
                    },
                ]
            }
        ),
    )
    with pytest.raises(OsvIntegrationError) as caught:
        TrustedOsvClient(_Transport([response]), sleep=lambda _: None).query(candidates)
    assert caught.value.code is OsvFailureCode.DATA_CHANGED_DURING_QUERY


def test_batch_splitting_and_candidate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    candidates = build_controlled_candidates()
    monkeypatch.setattr(client_module, "OSV_BATCH_SIZE", 2)
    transport = _Transport(
        [OsvHttpResponse(200, _json({"results": [{}, {}]})) for _ in range(3)]
    )
    assert len(TrustedOsvClient(transport, sleep=lambda _: None).query(candidates)) == 6
    assert len(transport.calls) == 3


def test_runtime_dependencies_and_service_boundary_are_frozen() -> None:
    verify_osv_runtime_dependencies()
    contract = build_osv_service_contract()
    assert contract["base_url"] == "https://api.osv.dev"
    assert contract["transport"]["version"] == OSV_HTTP_VERSION
    assert contract["purl_normalization"]["version"] == OSV_PURL_VERSION
    assert contract["network"] == {
        "cookies": False,
        "credentials": False,
        "follow_redirects": False,
        "host": "api.osv.dev",
        "os_egress_sandbox": False,
        "port": 443,
        "scheme": "https",
        "source_content_transmitted": False,
        "trust_env": False,
    }


def test_wrong_runtime_dependency_version_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(client_module, "version", lambda _name: "unexpected")
    with pytest.raises(OsvIntegrationError) as caught:
        verify_osv_runtime_dependencies()
    assert caught.value.code is OsvFailureCode.RUNTIME_DEPENDENCY_INVALID


def test_packageurl_runtime_identity_is_independently_verified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    versions = {"httpx": "0.28.1", "cvss": "3.6", "packageurl-python": "wrong"}
    monkeypatch.setattr(client_module, "version", versions.__getitem__)
    with pytest.raises(OsvIntegrationError) as caught:
        verify_osv_runtime_dependencies()
    assert caught.value.code is OsvFailureCode.RUNTIME_DEPENDENCY_INVALID


def test_response_limit_failure_is_preserved() -> None:
    failure = OsvIntegrationError(OsvFailureCode.RESPONSE_LIMIT)
    with pytest.raises(OsvIntegrationError) as caught:
        TrustedOsvClient(_Transport([failure]), sleep=lambda _: None).query((_candidate(),))
    assert caught.value.code is OsvFailureCode.RESPONSE_LIMIT


def test_advisory_fetch_failure_is_distinct() -> None:
    query = OsvHttpResponse(
        200,
        _json(
            {
                "results": [
                    {"vulns": [{"id": "PYSEC-2024-1", "modified": _MODIFIED}]}
                ]
            }
        ),
    )
    transport = _Transport([query, OsvHttpResponse(404, b"")])
    with pytest.raises(OsvIntegrationError) as caught:
        TrustedOsvClient(transport, sleep=lambda _: None).query((_candidate(),))
    assert caught.value.code is OsvFailureCode.ADVISORY_FETCH_FAILED


def test_same_advisory_revision_is_fetched_once_across_candidates() -> None:
    candidates = tuple(
        value for value in build_controlled_candidates() if value.purl_type == "pypi"
    )
    query = OsvHttpResponse(
        200,
        _json(
            {
                "results": [
                    {"vulns": [{"id": "PYSEC-2024-1", "modified": _MODIFIED}]},
                    {"vulns": [{"id": "PYSEC-2024-1", "modified": _MODIFIED}]},
                ]
            }
        ),
    )
    advisory = OsvHttpResponse(200, _advisory("PYSEC-2024-1", "pkg:pypi/pyyaml"))
    transport = _Transport([query, advisory])
    assert len(TrustedOsvClient(transport, sleep=lambda _: None).query(candidates)) == 2
    assert [call[0] for call in transport.calls] == ["POST", "GET"]


def test_pagination_depth_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(client_module, "OSV_MAX_PAGES_PER_CANDIDATE", 1)
    response = OsvHttpResponse(
        200, _json({"results": [{"next_page_token": "more"}]})
    )
    with pytest.raises(OsvIntegrationError) as caught:
        TrustedOsvClient(_Transport([response]), sleep=lambda _: None).query((_candidate(),))
    assert caught.value.code is OsvFailureCode.PAGINATION_INVALID


def test_permanent_5xx_is_not_retried() -> None:
    transport = _Transport([OsvHttpResponse(501, b"")])
    with pytest.raises(OsvIntegrationError) as caught:
        TrustedOsvClient(transport, sleep=lambda _: None).query((_candidate(),))
    assert caught.value.code is OsvFailureCode.HTTP_ERROR
    assert len(transport.calls) == 1
