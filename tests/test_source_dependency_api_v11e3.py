from __future__ import annotations

from types import SimpleNamespace
from uuid import UUID

import pytest
from fastapi import FastAPI, HTTPException
from pydantic import ValidationError

from securescan.api.source_scan_routes import list_dependencies, router
from securescan.api.source_scan_schemas import DependencyAdvisoryResponse
from securescan.product_core import (
    SourceDependencyAdvisorySummary,
    SourceDependencySummary,
    SourceScanPage,
    SourceScanQueryPersistenceError,
)

_RUN_ID = UUID("11111111-1111-4111-8111-111111111111")
_FINDING_A = "finding-public-a"
_FINDING_B = "finding-public-b"


def _advisory(
    *,
    finding_id: str = _FINDING_A,
    canonical_advisory_id: str = "CVE-2026-1000",
) -> SourceDependencyAdvisorySummary:
    return SourceDependencyAdvisorySummary(
        canonical_advisory_id=canonical_advisory_id,
        finding_id=finding_id,
        osv_record_ids=("GHSA-aaaa-bbbb-cccc", "OSV-2026-1"),
        aliases=("CVE-2026-1000",),
        cve_aliases=("CVE-2026-1000",),
        ghsa_aliases=("GHSA-aaaa-bbbb-cccc",),
        fixed_versions=("2.0.0",),
        priority_band="HIGH",
    )


def _dependency(
    *,
    evaluation: str = "COMPLETE",
    reason: str | None = None,
    count: int | None = 1,
    advisories: tuple[SourceDependencyAdvisorySummary, ...] | None = None,
) -> SourceDependencySummary:
    projected = (_advisory(),) if advisories is None else advisories
    return SourceDependencySummary(
        component_ref="component-package-a",
        name="requests",
        version="2.31.0",
        package_type="python",
        purl="pkg:pypi/requests@2.31.0",
        locations=({"kind": "REPOSITORY_PATH", "path": "requirements.lock"},),
        vulnerability_evaluation=evaluation,
        vulnerability_evaluation_reason=reason,
        known_vulnerability_count=count,
        advisories=projected,
        advisory_aliases=("compatibility-alias-from-e2",),
        fixed_versions=("compatibility-fixed-from-e2",),
        priority_bands=("UNRANKED",),
    )


def _serialize(
    *dependencies: SourceDependencySummary,
    limit: int = 50,
    offset: int = 0,
):
    calls: list[tuple[str, int, int]] = []

    def load(run_id: str, *, limit: int, offset: int):
        calls.append((run_id, limit, offset))
        return SourceScanPage(tuple(dependencies), len(dependencies), limit, offset)

    response = list_dependencies(
        _RUN_ID,
        SimpleNamespace(list_dependencies=load),
        limit=limit,
        offset=offset,
    )
    return response, calls


def test_dependency_route_serializes_exact_nested_e2_projection() -> None:
    response, calls = _serialize(_dependency(), limit=7, offset=3)
    payload = response.model_dump(mode="json")

    assert calls == [(str(_RUN_ID), 7, 3)]
    assert payload["total"] == 1
    assert payload["limit"] == 7
    assert payload["offset"] == 3
    dependency = payload["items"][0]
    assert dependency["component_ref"] == "component-package-a"
    assert dependency["known_vulnerability_count"] == 1
    assert dependency["advisory_aliases"] == ["compatibility-alias-from-e2"]
    assert dependency["fixed_versions"] == ["compatibility-fixed-from-e2"]
    assert dependency["priority_bands"] == ["UNRANKED"]
    assert dependency["advisories"] == [
        {
            "canonical_advisory_id": "CVE-2026-1000",
            "finding_id": _FINDING_A,
            "osv_record_ids": ["GHSA-aaaa-bbbb-cccc", "OSV-2026-1"],
            "aliases": ["CVE-2026-1000"],
            "cve_aliases": ["CVE-2026-1000"],
            "ghsa_aliases": ["GHSA-aaaa-bbbb-cccc"],
            "fixed_versions": ["2.0.0"],
            "priority_band": "HIGH",
        }
    ]


@pytest.mark.parametrize(
    ("evaluation", "reason", "count", "advisories"),
    [
        ("COMPLETE", None, 0, ()),
        ("COMPLETE", None, 1, (_advisory(),)),
        ("PARTIAL", "SYFT_PREREQUISITE_PARTIAL", None, (_advisory(),)),
        ("FAILED", "NETWORK_FAILURE", None, ()),
        ("NOT_APPLICABLE", "OUTSIDE_SCOPE", None, ()),
    ],
)
def test_dependency_route_preserves_e2_count_null_and_advisory_semantics(
    evaluation: str,
    reason: str | None,
    count: int | None,
    advisories: tuple[SourceDependencyAdvisorySummary, ...],
) -> None:
    response, _calls = _serialize(
        _dependency(
            evaluation=evaluation,
            reason=reason,
            count=count,
            advisories=advisories,
        )
    )
    payload = response.model_dump(mode="json")["items"][0]
    assert payload["vulnerability_evaluation"] == evaluation
    assert payload["vulnerability_evaluation_reason"] == reason
    assert payload["known_vulnerability_count"] == count
    assert len(payload["advisories"]) == len(advisories)


def test_dependency_route_preserves_e2_advisory_order_without_regrouping() -> None:
    second = _advisory(
        finding_id=_FINDING_B,
        canonical_advisory_id="GHSA-zzzz-yyyy-xxxx",
    )
    first = _advisory()
    response, _calls = _serialize(
        _dependency(count=2, advisories=(second, first))
    )
    advisories = response.model_dump(mode="json")["items"][0]["advisories"]
    assert [item["finding_id"] for item in advisories] == [_FINDING_B, _FINDING_A]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.pop("canonical_advisory_id"),
        lambda value: value.__setitem__("finding_id", 7),
        lambda value: value.__setitem__("priority_band", ["HIGH"]),
        lambda value: value.__setitem__("aliases", ["CVE-2026-1000", 7]),
        lambda value: value.__setitem__("unexpected", "internal"),
    ],
)
def test_dependency_advisory_response_rejects_malformed_shape(mutation) -> None:
    value = {
        "canonical_advisory_id": "CVE-2026-1000",
        "finding_id": _FINDING_A,
        "osv_record_ids": ["OSV-2026-1"],
        "aliases": ["CVE-2026-1000"],
        "cve_aliases": ["CVE-2026-1000"],
        "ghsa_aliases": [],
        "fixed_versions": ["2.0.0"],
        "priority_band": "HIGH",
    }
    mutation(value)
    with pytest.raises(ValidationError):
        DependencyAdvisoryResponse.model_validate(value)


def test_dependency_route_maps_projection_integrity_failure_to_safe_error() -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise SourceScanQueryPersistenceError

    with pytest.raises(HTTPException) as raised:
        list_dependencies(_RUN_ID, SimpleNamespace(list_dependencies=fail))
    assert raised.value.status_code == 503
    assert raised.value.detail == {
        "code": "QUERY_UNAVAILABLE",
        "message": "Source scan query is unavailable",
    }


def test_dependency_response_exposes_no_internal_execution_material() -> None:
    response, _calls = _serialize(_dependency())
    rendered = response.model_dump_json()
    for forbidden in (
        "native_finding_identity",
        "advisory_group_key",
        "artifact_sha256",
        "storage_path",
        "workspace_root",
        "node_id",
        "job_id",
        "attempt_id",
        "lease_token",
        "command",
        "stdout",
        "stderr",
        "credential",
        "operator_config",
    ):
        assert forbidden not in rendered


def test_openapi_exposes_additive_dependency_advisory_contract() -> None:
    application = FastAPI()
    application.include_router(router)
    document = application.openapi()
    operation = document["paths"]["/v1/scans/{run_id}/dependencies"]["get"]
    assert operation["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/DependencyPageResponse"
    }
    assert [item["name"] for item in operation["parameters"]] == [
        "run_id",
        "limit",
        "offset",
    ]

    schemas = document["components"]["schemas"]
    page = schemas["DependencyPageResponse"]
    dependency = schemas["DependencySummaryResponse"]
    advisory = schemas["DependencyAdvisoryResponse"]
    assert page["properties"]["items"]["items"] == {
        "$ref": "#/components/schemas/DependencySummaryResponse"
    }
    assert dependency["properties"]["advisories"]["items"] == {
        "$ref": "#/components/schemas/DependencyAdvisoryResponse"
    }
    assert set(advisory["properties"]) == {
        "canonical_advisory_id",
        "finding_id",
        "osv_record_ids",
        "aliases",
        "cve_aliases",
        "ghsa_aliases",
        "fixed_versions",
        "priority_band",
    }
    assert set(advisory["required"]) == set(advisory["properties"])
    count_schema = dependency["properties"]["known_vulnerability_count"]
    assert {item.get("type") for item in count_schema["anyOf"]} == {
        "integer",
        "null",
    }
    for field in ("version", "purl", "vulnerability_evaluation_reason"):
        assert "null" in {
            item.get("type") for item in dependency["properties"][field]["anyOf"]
        }
