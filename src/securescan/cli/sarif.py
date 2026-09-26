from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import quote

from securescan.product_core import (
    SourceFindingSummary,
    SourceProductStatus,
    SourceScanPage,
    SourceScanQueryError,
)

from .source import (
    SourceCliError,
    SourceCliServices,
    _canonical_uuid,
    query_report,
    query_scan,
    translate_query_error,
)

SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/"
    "sarif-schema-2.1.0.json"
)
SARIF_PAGE_SIZE = 200
_CWE = re.compile(r"CWE-[1-9][0-9]{0,5}\Z")
_LEVELS = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
    "UNRANKED": "none",
}
_CATEGORY_BY_AUTHORITY = {
    "semgrep-ce": "CODE_SECURITY",
    "gitleaks": "SECRET_EXPOSURE",
    "checkov": "CONFIGURATION_SECURITY",
    "osv.dev": "DEPENDENCY_VULNERABILITY",
}
_EVIDENCE_KIND_BY_AUTHORITY = {
    "semgrep-ce": "SEMGREP_RULE_MATCH",
    "gitleaks": "GITLEAKS_SECRET_OBSERVATION",
    "checkov": "CHECKOV_POLICY_OBSERVATION",
    "osv.dev": "OSV_ADVISORY_GROUP",
}


@dataclass(frozen=True, slots=True)
class _ProjectedFinding:
    finding_id: str
    rule_id: str
    level: str
    message: str
    locations: tuple[dict[str, Any], ...]
    properties: dict[str, Any]
    rule_cwe_ids: tuple[str, ...]


def build_sarif_bytes(services: SourceCliServices, run_id: str) -> bytes:
    normalized = _canonical_uuid(run_id, code="SCAN_NOT_FOUND")
    summary = query_scan(services, normalized)
    if summary.product_status is not SourceProductStatus.COMPLETED:
        if summary.product_status in {
            SourceProductStatus.FAILED,
            SourceProductStatus.CANCELLED,
            SourceProductStatus.BLOCKED_BY_PREDECESSOR,
        }:
            raise SourceCliError(
                "SARIF_SCAN_FAILED",
                f"SARIF is unavailable for a {summary.product_status.value} scan",
                5,
            )
        raise SourceCliError(
            "SARIF_NOT_READY", "SARIF requires a completed Source scan", 3
        )

    summaries = _traverse_findings(services, normalized)
    if summary.finding_count != len(summaries):
        raise _integrity()
    published = query_report(services, normalized)
    if published.run_id != normalized:
        raise _integrity()
    report = _mapping(published.report)
    scope = _mapping(report.get("scope"))
    if scope.get("source_run_id") != normalized:
        raise _integrity()

    report_findings = _indexed(report.get("findings"), "finding_id")
    summary_ids = {item.finding_id for item in summaries}
    if set(report_findings) != summary_ids:
        raise _integrity()
    evidence = _indexed(report.get("evidence"), "evidence_id")
    components = _indexed(report.get("components", []), "component_ref")

    projections = tuple(
        _project(item, report_findings[item.finding_id], evidence, components)
        for item in sorted(summaries, key=lambda value: value.finding_id)
    )
    rules: dict[str, set[str]] = {}
    for item in projections:
        rules.setdefault(item.rule_id, set()).update(item.rule_cwe_ids)
    document = {
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "results": [_result(item) for item in projections],
                "tool": {
                    "driver": {
                        "name": "SecureScan",
                        "rules": [
                            _rule(rule_id, tuple(sorted(rules[rule_id])))
                            for rule_id in sorted(rules)
                        ],
                    }
                },
            }
        ],
        "version": "2.1.0",
    }
    try:
        return (
            json.dumps(
                document,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, UnicodeError, ValueError):
        raise _integrity() from None


def _traverse_findings(
    services: SourceCliServices, run_id: str
) -> tuple[SourceFindingSummary, ...]:
    items: list[SourceFindingSummary] = []
    identifiers: set[str] = set()
    expected_total: int | None = None
    offset = 0
    while expected_total is None or offset < expected_total:
        try:
            page = services.queries.list_findings(
                run_id,
                authority=None,
                category=None,
                priority=None,
                lifecycle_state=None,
                limit=SARIF_PAGE_SIZE,
                offset=offset,
            )
        except SourceScanQueryError as exc:
            raise translate_query_error(exc) from None
        _validate_page(page, offset, expected_total)
        if expected_total is None:
            expected_total = page.total
        for item in page.items:
            if item.finding_id in identifiers:
                raise _integrity()
            identifiers.add(item.finding_id)
            items.append(item)
        offset += len(page.items)
    if expected_total is None or len(items) != expected_total:
        raise _integrity()
    return tuple(items)


def _validate_page(
    page: SourceScanPage[SourceFindingSummary],
    offset: int,
    expected_total: int | None,
) -> None:
    if (
        type(page.total) is not int
        or page.total < 0
        or page.limit != SARIF_PAGE_SIZE
        or page.offset != offset
        or len(page.items) > SARIF_PAGE_SIZE
        or offset + len(page.items) > page.total
        or (offset < page.total and not page.items)
        or (
            offset + len(page.items) < page.total
            and len(page.items) != SARIF_PAGE_SIZE
        )
        or (expected_total is not None and page.total != expected_total)
    ):
        raise _integrity()


def _project(
    summary: SourceFindingSummary,
    raw_finding: Mapping[str, Any],
    evidence: Mapping[str, Mapping[str, Any]],
    components: Mapping[str, Mapping[str, Any]],
) -> _ProjectedFinding:
    authority = summary.authority
    if (
        _CATEGORY_BY_AUTHORITY.get(authority) != summary.category
        or raw_finding.get("authority") != authority
        or raw_finding.get("category") != summary.category
        or _mapping(raw_finding.get("subject")) != dict(summary.subject)
    ):
        raise _integrity()
    raw_locations = _mapping_sequence(raw_finding.get("locations"))
    primary = None if not raw_locations else raw_locations[0]
    if primary != (None if summary.primary_location is None else dict(summary.primary_location)):
        raise _integrity()

    subject = _mapping(raw_finding.get("subject"))
    payload = _primary_payload(raw_finding, authority, evidence)
    rule_id, message, metadata, cwe_ids = _authority_projection(
        authority, subject, payload, components
    )
    properties: dict[str, Any] = {
        "securescanAuthority": authority,
        "securescanCategory": summary.category,
        "securescanFindingId": summary.finding_id,
        "securescanLifecycle": summary.lifecycle_state,
        "securescanPriority": summary.priority_band,
        "securescanPriorityReasonCodes": sorted(summary.priority_reason_codes),
    }
    if summary.severity is not None:
        properties["securescanSeverity"] = summary.severity
    properties.update(metadata)
    if cwe_ids:
        properties["securescanCweIds"] = list(cwe_ids)
    level = _LEVELS.get(summary.priority_band)
    if level is None:
        raise _integrity()
    locations = tuple(
        location
        for location in sorted(
            (_sarif_location(item) for item in raw_locations),
            key=_canonical_sort_key,
        )
        if location is not None
    )
    return _ProjectedFinding(
        summary.finding_id,
        rule_id,
        level,
        message,
        locations,
        properties,
        cwe_ids,
    )


def _primary_payload(
    finding: Mapping[str, Any],
    authority: str,
    evidence: Mapping[str, Mapping[str, Any]],
) -> Mapping[str, Any]:
    references = _string_sequence(finding.get("primary_evidence_refs"))
    expected_kind = _EVIDENCE_KIND_BY_AUTHORITY[authority]
    matches: list[Mapping[str, Any]] = []
    for reference in references:
        item = evidence.get(reference)
        if item is None or item.get("authority") != authority:
            raise _integrity()
        if item.get("evidence_kind") == expected_kind:
            matches.append(_mapping(item.get("payload")))
    if len(matches) != 1 or matches[0].get("kind") != expected_kind:
        raise _integrity()
    return matches[0]


def _authority_projection(
    authority: str,
    subject: Mapping[str, Any],
    payload: Mapping[str, Any],
    components: Mapping[str, Mapping[str, Any]],
) -> tuple[str, str, dict[str, Any], tuple[str, ...]]:
    if authority == "semgrep-ce":
        rule = _text(subject.get("rule_id"))
        if payload.get("rule_id") != rule:
            raise _integrity()
        cwe_ids = tuple(sorted(_string_sequence(payload.get("cwe_ids", []))))
        if any(_CWE.fullmatch(value) is None for value in cwe_ids):
            raise _integrity()
        return f"semgrep-ce:{rule}", _text(payload.get("message")), {}, cwe_ids
    if authority == "gitleaks":
        rule = _text(subject.get("rule_id"))
        if payload.get("rule_id") != rule:
            raise _integrity()
        detection = _text(payload.get("detection_kind"))
        return (
            f"gitleaks:{rule}",
            f"Secret detected by Gitleaks rule {rule}.",
            {"securescanDetectionKind": detection},
            (),
        )
    if authority == "checkov":
        check_id = _text(payload.get("check_id"))
        return (
            f"checkov:{check_id}",
            _text(payload.get("check_name")),
            {
                "securescanCheckovFramework": _text(payload.get("framework")),
                "securescanCheckovResource": _text(payload.get("resource")),
            },
            (),
        )
    if authority == "osv.dev":
        advisory = _text(payload.get("canonical_advisory_id"))
        component_ref = _text(subject.get("component_ref"))
        component = components.get(component_ref)
        if component is None:
            raise _integrity()
        package = _mapping(component.get("payload"))
        name = _text(package.get("package_name"))
        version = _text(package.get("package_version"))
        metadata = {
            "securescanAdvisoryAliases": sorted(
                _string_sequence(payload.get("aliases", []))
            ),
            "securescanCanonicalAdvisoryId": advisory,
            "securescanFixedVersions": sorted(
                _string_sequence(payload.get("fixed_versions", []))
            ),
            "securescanPackageName": name,
            "securescanPackageType": _text(package.get("package_type")),
            "securescanPackageVersion": version,
        }
        purl = package.get("purl")
        if purl is not None:
            metadata["securescanPackagePurl"] = _text(purl)
        return (
            f"osv.dev:{advisory}",
            f"{advisory} affects {name} {version}.",
            metadata,
            (),
        )
    raise _integrity()


def _sarif_location(location: Mapping[str, Any]) -> dict[str, Any] | None:
    kind = location.get("kind")
    if kind == "REPOSITORY_SCOPE":
        return None
    if kind not in {"SOURCE_SPAN", "REPOSITORY_PATH"}:
        raise _integrity()
    path = _repository_uri(location.get("path"))
    physical: dict[str, Any] = {"artifactLocation": {"uri": path}}
    if kind == "SOURCE_SPAN":
        start_line = _positive_integer(location.get("start_line"))
        end_line = _positive_integer(location.get("end_line"))
        if end_line < start_line:
            raise _integrity()
        region: dict[str, int] = {"endLine": end_line, "startLine": start_line}
        start_column = location.get("start_column")
        if start_column is not None:
            region["startColumn"] = _positive_integer(start_column)
        physical["region"] = region
    return {"physicalLocation": physical}


def _repository_uri(value: object) -> str:
    path = _text(value)
    pure = PurePosixPath(path)
    if (
        pure.is_absolute()
        or "\\" in path
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise _integrity()
    return quote(path, safe="/-._~")


def _result(item: _ProjectedFinding) -> dict[str, Any]:
    result: dict[str, Any] = {
        "level": item.level,
        "message": {"text": item.message},
        "partialFingerprints": {"securescanFindingId/v1": item.finding_id},
        "properties": item.properties,
        "ruleId": item.rule_id,
    }
    if item.locations:
        result["locations"] = list(item.locations)
    return result


def _rule(rule_id: str, cwe_ids: tuple[str, ...]) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": rule_id,
        "shortDescription": {"text": rule_id},
    }
    properties: dict[str, Any] = {
        "securescanAuthority": rule_id.split(":", 1)[0]
    }
    if cwe_ids:
        properties["securescanCweIds"] = list(cwe_ids)
    rule["properties"] = properties
    return rule


def _indexed(value: object, key: str) -> dict[str, Mapping[str, Any]]:
    indexed: dict[str, Mapping[str, Any]] = {}
    for item in _mapping_sequence(value):
        identifier = _text(item.get(key))
        if identifier in indexed:
            raise _integrity()
        indexed[identifier] = item
    return indexed


def _mapping(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise _integrity()
    return value


def _mapping_sequence(value: object) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise _integrity()
    return tuple(_mapping(item) for item in value)


def _string_sequence(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise _integrity()
    result = tuple(_text(item) for item in value)
    if result != tuple(sorted(set(result))):
        raise _integrity()
    return result


def _text(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise _integrity()
    return value


def _positive_integer(value: object) -> int:
    if type(value) is not int or value < 1:
        raise _integrity()
    return value


def _canonical_sort_key(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _integrity() -> SourceCliError:
    return SourceCliError(
        "SARIF_INTEGRITY_FAILURE",
        "Authoritative Source evidence could not be exported safely",
        5,
    )
