from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any, Final

from cvss import CVSS2, CVSS3, CVSS4
from jsonschema import Draft202012Validator, FormatChecker
from packageurl import PackageURL

from securescan.advisories.osv.models import (
    OSV_SCHEMA_SHA256,
    OsvAdvisoryObservation,
    OsvAdvisoryReference,
    OsvCvssEvidence,
    OsvCvssScope,
    OsvFailureCode,
    OsvIntegrationError,
    OsvQueryCandidate,
    canonical_package_name,
    purl_package_name,
    valid_osv_timestamp,
)

_MAX_QUERY_RESPONSE_BYTES: Final = 8 * 1024 * 1024
_MAX_ADVISORY_RESPONSE_BYTES: Final = 16 * 1024 * 1024
_MAX_JSON_DEPTH: Final = 64
_MAX_STRING: Final = 16_384
_MAX_ARRAY: Final = 100_000
OSV_MAX_ALIASES: Final = 1_024
OSV_MAX_AFFECTED_ENTRIES: Final = 256
OSV_MAX_RANGES_PER_AFFECTED: Final = 128
OSV_MAX_EVENTS_PER_RANGE: Final = 512
OSV_MAX_SEVERITY_ENTRIES: Final = 64
OSV_MAX_FIXED_VERSIONS: Final = 1_024
OSV_MAX_SUMMARY_BYTES: Final = 16_384
OSV_MAX_PAGE_TOKEN_BYTES: Final = 4_096
OSV_MAX_QUERY_REFERENCES_PER_RESULT: Final = 4_096
OSV_MAX_REFERENCES: Final = 4_096
OSV_MAX_VERSIONS_PER_AFFECTED: Final = 10_000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]{1,199}\Z", re.ASCII)
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z", re.ASCII)
_GHSA = re.compile(
    r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}\Z",
    re.ASCII,
)


def _duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _nonfinite(_value: str) -> None:
    raise ValueError


def _validate_tree(value: object, depth: int = 0) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise ValueError
    if value is None or isinstance(value, (str, bool)) or type(value) is int:
        if isinstance(value, str) and len(value) > _MAX_STRING:
            raise ValueError
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError
        return
    if isinstance(value, list):
        if len(value) > _MAX_ARRAY:
            raise ValueError
        for item in value:
            _validate_tree(item, depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > _MAX_ARRAY:
            raise ValueError
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > _MAX_STRING:
                raise ValueError
            _validate_tree(item, depth + 1)
        return
    raise ValueError


def strict_json(payload: bytes, *, limit: int, code: OsvFailureCode) -> object:
    if not isinstance(payload, bytes) or len(payload) > limit:
        raise OsvIntegrationError(OsvFailureCode.RESPONSE_LIMIT)
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_duplicate_keys,
            parse_constant=_nonfinite,
        )
        _validate_tree(value)
        return value
    except (UnicodeDecodeError, ValueError, TypeError):
        raise OsvIntegrationError(code) from None


def _timestamp(value: object) -> str:
    if not valid_osv_timestamp(value):
        raise ValueError
    assert isinstance(value, str)
    return value


def _bounded_collection(value: object, limit: int) -> None:
    if isinstance(value, list) and len(value) > limit:
        raise ValueError


def _validate_advisory_limits(value: dict[str, Any]) -> None:
    _bounded_collection(value.get("aliases"), OSV_MAX_ALIASES)
    _bounded_collection(value.get("affected"), OSV_MAX_AFFECTED_ENTRIES)
    _bounded_collection(value.get("severity"), OSV_MAX_SEVERITY_ENTRIES)
    _bounded_collection(value.get("references"), OSV_MAX_REFERENCES)
    affected_values = value.get("affected")
    if not isinstance(affected_values, list):
        return
    for affected in affected_values:
        if not isinstance(affected, dict):
            continue
        _bounded_collection(affected.get("ranges"), OSV_MAX_RANGES_PER_AFFECTED)
        _bounded_collection(affected.get("severity"), OSV_MAX_SEVERITY_ENTRIES)
        _bounded_collection(affected.get("versions"), OSV_MAX_VERSIONS_PER_AFFECTED)
        ranges = affected.get("ranges")
        if not isinstance(ranges, list):
            continue
        for range_value in ranges:
            if isinstance(range_value, dict):
                _bounded_collection(range_value.get("events"), OSV_MAX_EVENTS_PER_RANGE)


def parse_query_response(
    payload: bytes, expected_count: int
) -> tuple[tuple[tuple[OsvAdvisoryReference, ...], str | None], ...]:
    value = strict_json(
        payload,
        limit=_MAX_QUERY_RESPONSE_BYTES,
        code=OsvFailureCode.QUERY_RESPONSE_INVALID,
    )
    try:
        if not isinstance(value, dict) or set(value) != {"results"}:
            raise ValueError
        results = value["results"]
        if not isinstance(results, list) or len(results) != expected_count:
            raise ValueError
        parsed = []
        for result in results:
            if not isinstance(result, dict) or not set(result) <= {"vulns", "next_page_token"}:
                raise ValueError
            raw_vulns = result.get("vulns", [])
            token = result.get("next_page_token")
            if (
                not isinstance(raw_vulns, list)
                or len(raw_vulns) > OSV_MAX_QUERY_REFERENCES_PER_RESULT
                or (
                    token is not None
                    and (
                        not isinstance(token, str)
                        or not token
                        or len(token.encode("utf-8")) > OSV_MAX_PAGE_TOKEN_BYTES
                    )
                )
            ):
                raise ValueError
            references = []
            seen: dict[str, str] = {}
            for raw in raw_vulns:
                if not isinstance(raw, dict) or set(raw) != {"id", "modified"}:
                    raise ValueError
                record_id = raw["id"]
                modified = _timestamp(raw["modified"])
                if not isinstance(record_id, str) or _ID.fullmatch(record_id) is None:
                    raise ValueError
                previous = seen.get(record_id)
                if previous is not None and previous != modified:
                    raise ValueError
                if previous is None:
                    seen[record_id] = modified
                    references.append(OsvAdvisoryReference(record_id, modified))
            parsed.append((tuple(references), token))
        return tuple(parsed)
    except (TypeError, ValueError):
        raise OsvIntegrationError(OsvFailureCode.QUERY_RESPONSE_INVALID) from None


def _load_schema() -> dict[str, Any]:
    path = Path(__file__).resolve().parent / "schema" / "osv-schema-1.9.0.json"
    try:
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != OSV_SCHEMA_SHA256:
            raise ValueError
        value = json.loads(payload)
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (OSError, ValueError, TypeError):
        raise OsvIntegrationError(OsvFailureCode.ADVISORY_SCHEMA_INVALID) from None


_SCHEMA = _load_schema()
_VALIDATOR = Draft202012Validator(_SCHEMA, format_checker=FormatChecker())


def _versionless_purl(value: str) -> str:
    parsed = PackageURL.from_string(value)
    return PackageURL(
        type=parsed.type,
        namespace=parsed.namespace,
        name=parsed.name,
        version=None,
        qualifiers=parsed.qualifiers,
        subpath=parsed.subpath,
    ).to_string()


def _parse_cvss(
    items: object, *, scope: OsvCvssScope
) -> tuple[OsvCvssEvidence, ...]:
    if items is None or items == ():
        return ()
    if not isinstance(items, list) or len(items) > OSV_MAX_SEVERITY_ENTRIES:
        raise ValueError
    result: set[OsvCvssEvidence] = set()
    classes = {"CVSS_V2": CVSS2, "CVSS_V3": CVSS3, "CVSS_V4": CVSS4}
    for item in items:
        if not isinstance(item, dict):
            raise ValueError
        cvss_type = item.get("type")
        if cvss_type not in classes:
            continue
        vector = item.get("score")
        source = item.get("source")
        if not isinstance(vector, str) or (source is not None and not isinstance(source, str)):
            raise ValueError
        calculator = classes[cvss_type](vector)
        result.add(
            OsvCvssEvidence(
                cvss_type=cvss_type,
                vector=vector,
                source=source,
                base_score=float(calculator.base_score),
                scope=scope,
            )
        )
    return tuple(
        sorted(
            result,
            key=lambda item: (
                item.cvss_type,
                item.vector,
                item.source or "",
                item.scope.value,
            ),
        )
    )


_ECOSYSTEM_BY_PURL_TYPE: Final = {"golang": "Go", "npm": "npm", "pypi": "PyPI"}


def _affected_package_matches(package: object, candidate: OsvQueryCandidate) -> bool:
    if not isinstance(package, dict):
        return False
    affected_purl = package.get("purl")
    if affected_purl is not None:
        if not isinstance(affected_purl, str):
            raise ValueError
        parsed = PackageURL.from_string(affected_purl)
        if parsed.version is not None:
            raise ValueError
        return parsed.to_string() == _versionless_purl(candidate.purl)
    ecosystem = package.get("ecosystem")
    name = package.get("name")
    if (
        ecosystem != _ECOSYSTEM_BY_PURL_TYPE[candidate.purl_type]
        or not isinstance(name, str)
    ):
        return False
    candidate_purl = PackageURL.from_string(candidate.purl)
    return canonical_package_name(candidate.purl_type, name) == purl_package_name(
        candidate_purl
    )


def parse_advisory_response(
    payload: bytes,
    *,
    expected: OsvAdvisoryReference,
    candidate: OsvQueryCandidate,
) -> OsvAdvisoryObservation:
    value = strict_json(
        payload,
        limit=_MAX_ADVISORY_RESPONSE_BYTES,
        code=OsvFailureCode.ADVISORY_SCHEMA_INVALID,
    )
    try:
        if not isinstance(value, dict):
            raise ValueError
        _validate_advisory_limits(value)
        errors = tuple(_VALIDATOR.iter_errors(value))
        if errors:
            raise ValueError
        record_id = value.get("id")
        modified = _timestamp(value.get("modified"))
        if record_id != expected.osv_record_id or modified != expected.modified:
            raise OsvIntegrationError(OsvFailureCode.DATA_CHANGED_DURING_QUERY)
        if value.get("withdrawn") is not None:
            _timestamp(value.get("withdrawn"))
            raise OsvIntegrationError(OsvFailureCode.DATA_CHANGED_DURING_QUERY)
        aliases = tuple(sorted(set(value.get("aliases") or ())))
        if any(not isinstance(item, str) or _ID.fullmatch(item) is None for item in aliases):
            raise ValueError
        published_value = value.get("published")
        published = None if published_value is None else _timestamp(published_value)
        summary_value = value.get("summary")
        summary = None if summary_value is None else str(summary_value)
        if summary is not None and len(summary.encode("utf-8")) > OSV_MAX_SUMMARY_BYTES:
            raise ValueError
        fixed: set[str] = set()
        cvss_values = list(
            _parse_cvss(value.get("severity"), scope=OsvCvssScope.ADVISORY)
        )
        for affected in value.get("affected") or ():
            package = affected.get("package") if isinstance(affected, dict) else None
            if not _affected_package_matches(package, candidate):
                continue
            cvss_values.extend(
                _parse_cvss(
                    affected.get("severity"), scope=OsvCvssScope.MATCHED_PACKAGE
                )
            )
            for range_value in affected.get("ranges") or ():
                if not isinstance(range_value, dict):
                    raise ValueError
                range_type = range_value.get("type")
                for event in range_value.get("events") or ():
                    if not isinstance(event, dict):
                        raise ValueError
                    fixed_value = event.get("fixed")
                    if fixed_value is not None and range_type in {"SEMVER", "ECOSYSTEM"}:
                        if not isinstance(fixed_value, str) or not fixed_value:
                            raise ValueError
                        fixed.add(fixed_value)
                        if len(fixed) > OSV_MAX_FIXED_VERSIONS:
                            raise ValueError
        cvss = tuple(
            sorted(
                set(cvss_values),
                key=lambda item: (
                    item.cvss_type,
                    item.vector,
                    item.source or "",
                    item.scope.value,
                ),
            )
        )
        identity_values = {record_id, *aliases}
        return OsvAdvisoryObservation(
            osv_record_id=record_id,
            modified=modified,
            published=published,
            aliases=aliases,
            cve_aliases=tuple(sorted(item for item in identity_values if _CVE.fullmatch(item))),
            ghsa_aliases=tuple(sorted(item for item in identity_values if _GHSA.fullmatch(item))),
            summary=summary,
            applicable_package_key=candidate.package_key,
            fixed_versions=tuple(sorted(fixed)),
            cvss=cvss,
        )
    except OsvIntegrationError:
        raise
    except (TypeError, ValueError):
        raise OsvIntegrationError(OsvFailureCode.ADVISORY_SCHEMA_INVALID) from None
