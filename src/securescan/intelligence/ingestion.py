from __future__ import annotations

import csv
import gzip
import io
import json
import math
from datetime import UTC, date, datetime
from decimal import Decimal, InvalidOperation
from importlib.resources import files
from typing import Any

from jsonschema import Draft7Validator, FormatChecker

from .cve import validate_cve_id
from .models import IntelligenceSource, ParsedSnapshot

KEV_PARSER_CONTRACT = "securescan-cisa-kev-v1"
EPSS_PARSER_CONTRACT = "securescan-first-epss-v1"
NVD_PARSER_CONTRACT = "securescan-nvd-cve-2.0-v1"
KEV_MAX_BYTES = 16 * 1024 * 1024
KEV_MAX_RECORDS = 100_000
EPSS_MAX_COMPRESSED_BYTES = 32 * 1024 * 1024
EPSS_MAX_DECOMPRESSED_BYTES = 256 * 1024 * 1024
EPSS_MAX_RECORDS = 1_000_000
MAX_FIELD_BYTES = 64 * 1024
NVD_MAX_BYTES = 8 * 1024 * 1024


class IntelligenceIngestionError(ValueError):
    pass


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise IntelligenceIngestionError("duplicate JSON key")
        result[key] = value
    return result


def _constant(_: str) -> None:
    raise IntelligenceIngestionError("non-finite number")


def _json(payload: bytes, limit: int) -> Any:
    if not payload or len(payload) > limit:
        raise IntelligenceIngestionError("intelligence document size is invalid")
    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_duplicates,
            parse_constant=_constant,
        )
    except IntelligenceIngestionError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise IntelligenceIngestionError("intelligence document is invalid") from None


def _timestamp(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        raise IntelligenceIngestionError("timestamp is invalid") from None
    if result.tzinfo is None:
        raise IntelligenceIngestionError("timestamp is invalid")
    return result.astimezone(UTC)


def _bounded_text(value: object, *, allow_empty: bool = False) -> str:
    if (
        not isinstance(value, str)
        or (not allow_empty and not value)
        or len(value.encode("utf-8")) > MAX_FIELD_BYTES
    ):
        raise IntelligenceIngestionError("field is invalid")
    return value


def parse_kev_snapshot(payload: bytes) -> ParsedSnapshot:
    value = _json(payload, KEV_MAX_BYTES)
    schema = json.loads(
        files("securescan.intelligence.schema")
        .joinpath("known_exploited_vulnerabilities_schema.json")
        .read_text(encoding="utf-8")
    )
    if not isinstance(value, dict) or tuple(
        Draft7Validator(schema, format_checker=FormatChecker()).iter_errors(value)
    ):
        raise IntelligenceIngestionError("KEV schema validation failed")
    records = value["vulnerabilities"]
    if len(records) != value["count"] or len(records) > KEV_MAX_RECORDS:
        raise IntelligenceIngestionError("KEV count is invalid")
    normalized = []
    seen = set()
    for raw in records:
        cve = validate_cve_id(raw["cveID"])
        if cve in seen:
            raise IntelligenceIngestionError("duplicate KEV CVE")
        seen.add(cve)
        item = {
            "cve_id": cve,
            "vendor_project": _bounded_text(raw["vendorProject"]),
            "product": _bounded_text(raw["product"]),
            "vulnerability_name": _bounded_text(raw["vulnerabilityName"]),
            "date_added": date.fromisoformat(raw["dateAdded"]).isoformat(),
            "short_description": _bounded_text(raw["shortDescription"]),
            "required_action": _bounded_text(raw["requiredAction"]),
            "due_date": date.fromisoformat(raw["dueDate"]).isoformat(),
            "known_ransomware_campaign_use": raw.get("knownRansomwareCampaignUse"),
            "notes": raw.get("notes"),
            "cwes": sorted(set(raw.get("cwes", []))),
        }
        for optional in ("known_ransomware_campaign_use", "notes"):
            if item[optional] is not None:
                item[optional] = _bounded_text(item[optional], allow_empty=True)
        normalized.append(item)
    return ParsedSnapshot(
        source=IntelligenceSource.CISA_KEV,
        source_effective_at=_timestamp(value["dateReleased"]),
        parser_contract_version=KEV_PARSER_CONTRACT,
        source_schema="cisagov-kev-schema-2026-10-02",
        source_metadata={
            "catalog_version": _bounded_text(value["catalogVersion"]),
            "date_released": value["dateReleased"],
        },
        records=tuple(sorted(normalized, key=lambda item: item["cve_id"])),
    )


def _bounded_gunzip(payload: bytes) -> bytes:
    if not payload or len(payload) > EPSS_MAX_COMPRESSED_BYTES:
        raise IntelligenceIngestionError("EPSS compressed size is invalid")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(payload), mode="rb") as stream:
            decoded = stream.read(EPSS_MAX_DECOMPRESSED_BYTES + 1)
    except (EOFError, OSError):
        raise IntelligenceIngestionError("EPSS gzip is invalid") from None
    if len(decoded) > EPSS_MAX_DECOMPRESSED_BYTES:
        raise IntelligenceIngestionError("EPSS decompressed size exceeded")
    return decoded


def _probability(value: str) -> float:
    try:
        decimal = Decimal(value)
    except (InvalidOperation, TypeError):
        raise IntelligenceIngestionError("EPSS probability is invalid") from None
    result = float(decimal)
    if not math.isfinite(result) or not Decimal(0) <= decimal <= Decimal(1):
        raise IntelligenceIngestionError("EPSS probability is invalid")
    return result


def parse_epss_snapshot(payload: bytes) -> ParsedSnapshot:
    decoded = _bounded_gunzip(payload)
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        raise IntelligenceIngestionError("EPSS CSV encoding is invalid") from None
    lines = text.splitlines()
    if not lines or not lines[0].startswith("#"):
        raise IntelligenceIngestionError("EPSS metadata is missing")
    metadata = {}
    for part in lines[0][1:].split(","):
        key, separator, raw = part.strip().partition(":")
        if separator:
            metadata[key.strip()] = raw.strip()
    model_version = metadata.get("model_version")
    score_date = metadata.get("score_date")
    if not model_version or not score_date:
        raise IntelligenceIngestionError("EPSS metadata is invalid")
    try:
        effective = datetime.combine(date.fromisoformat(score_date), datetime.min.time(), UTC)
    except ValueError:
        raise IntelligenceIngestionError("EPSS score date is invalid") from None
    reader = csv.DictReader(lines[1:], strict=True)
    if reader.fieldnames != ["cve", "epss", "percentile"]:
        raise IntelligenceIngestionError("EPSS columns are invalid")
    records = []
    seen = set()
    try:
        for raw in reader:
            if len(records) >= EPSS_MAX_RECORDS or None in raw:
                raise IntelligenceIngestionError("EPSS row limit or shape is invalid")
            if any(len(str(value).encode("utf-8")) > MAX_FIELD_BYTES for value in raw.values()):
                raise IntelligenceIngestionError("EPSS field is too large")
            try:
                cve = validate_cve_id(raw["cve"])
            except ValueError:
                raise IntelligenceIngestionError("EPSS CVE is invalid") from None
            if cve in seen:
                raise IntelligenceIngestionError("duplicate EPSS CVE")
            seen.add(cve)
            records.append(
                {
                    "cve_id": cve,
                    "epss": _probability(raw["epss"]),
                    "percentile": _probability(raw["percentile"]),
                }
            )
    except csv.Error:
        raise IntelligenceIngestionError("EPSS CSV is invalid") from None
    return ParsedSnapshot(
        source=IntelligenceSource.FIRST_EPSS,
        source_effective_at=effective,
        parser_contract_version=EPSS_PARSER_CONTRACT,
        source_schema="first-epss-daily-csv-v1",
        source_metadata={"model_version": model_version, "score_date": score_date},
        records=tuple(sorted(records, key=lambda item: item["cve_id"])),
    )


def parse_nvd_enrichment(payload: bytes, *, expected_cve: str) -> dict[str, Any]:
    expected_cve = validate_cve_id(expected_cve)
    value = _json(payload, NVD_MAX_BYTES)
    if (
        not isinstance(value, dict)
        or value.get("format") != "NVD_CVE"
        or value.get("version") != "2.0"
        or value.get("totalResults") != 1
        or not isinstance(value.get("vulnerabilities"), list)
        or len(value["vulnerabilities"]) != 1
    ):
        raise IntelligenceIngestionError("NVD response envelope is invalid")
    cve = value["vulnerabilities"][0].get("cve")
    if not isinstance(cve, dict) or cve.get("id") != expected_cve:
        raise IntelligenceIngestionError("NVD returned the wrong CVE")
    descriptions = []
    for item in cve.get("descriptions", []):
        if isinstance(item, dict) and item.get("lang") == "en":
            descriptions.append(_bounded_text(item.get("value")))
    weaknesses = []
    for weakness in cve.get("weaknesses", []):
        if not isinstance(weakness, dict):
            raise IntelligenceIngestionError("NVD weakness is invalid")
        for item in weakness.get("description", []):
            if isinstance(item, dict) and item.get("lang") == "en":
                weaknesses.append(_bounded_text(item.get("value")))
    metrics = []
    raw_metrics = cve.get("metrics", {})
    if not isinstance(raw_metrics, dict):
        raise IntelligenceIngestionError("NVD metrics are invalid")
    for metric_type, entries in sorted(raw_metrics.items()):
        if not isinstance(entries, list) or len(entries) > 100:
            raise IntelligenceIngestionError("NVD metrics are invalid")
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("cvssData"), dict):
                raise IntelligenceIngestionError("NVD metric is invalid")
            data = entry["cvssData"]
            metrics.append(
                {
                    "metric_type": _bounded_text(metric_type),
                    "source": _bounded_text(entry.get("source")),
                    "type": _bounded_text(entry.get("type")),
                    "version": _bounded_text(data.get("version")),
                    "vector": _bounded_text(data.get("vectorString")),
                    "base_score": data.get("baseScore"),
                    "base_severity": data.get("baseSeverity"),
                }
            )
    references = []
    for reference in cve.get("references", []):
        if not isinstance(reference, dict):
            raise IntelligenceIngestionError("NVD reference is invalid")
        references.append(
            {
                "source": reference.get("source"),
                "url": _bounded_text(reference.get("url")),
                "tags": sorted(set(reference.get("tags", []))),
            }
        )
    return {
        "cve_id": expected_cve,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "english_descriptions": sorted(set(descriptions)),
        "weaknesses": sorted(set(weaknesses)),
        "metrics": sorted(
            metrics, key=lambda item: (item["metric_type"], item["source"], item["vector"])
        ),
        "references": sorted(references, key=lambda item: item["url"]),
    }
