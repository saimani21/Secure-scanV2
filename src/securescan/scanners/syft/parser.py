from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Final

from packageurl import PackageURL

from securescan.scanners.syft.binding import (
    SYFT_JSON_SCHEMA_VERSION,
    SYFT_SCANNER_ID,
    SYFT_VERSION,
    verify_syft_purl_dependency,
)

SYFT_PARSER_SCHEMA_VERSION: Final = "securescan-syft-parser-s1"

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_PROJECTION_ID_PATTERN = re.compile(r"securescan-source-projection-[0-9a-f]{16,48}\Z", re.ASCII)
_MAX_DOCUMENT_BYTES = 100 * 1024 * 1024
_MAX_ARTIFACTS = 250_000
_MAX_RELATIONSHIPS = 1_000_000
_MAX_LOCATIONS = 10_000
_MAX_CATALOGERS = 1_000
_MAX_STRING = 16_384
_MAX_PATH = 16_384
_MAX_JSON_DEPTH = 64
_PACKAGE_KEY_DOMAIN = b"securescan-syft-package-key-s1\0"
_OBSERVATION_ID_DOMAIN = b"securescan-syft-package-observation-s1\0"


class SyftParserError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Syft output is invalid")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _reject_nonfinite(_value: str) -> None:
    raise ValueError


def _validate_json_tree(value: object, depth: int = 0) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise ValueError
    if value is None or isinstance(value, (str, bool)):
        return
    if type(value) is int:
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_tree(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError
            _validate_json_tree(item, depth + 1)
        return
    raise ValueError


def _bounded_string(value: object, *, allow_empty: bool = False) -> str:
    if (
        not isinstance(value, str)
        or (not allow_empty and not value)
        or len(value) > _MAX_STRING
        or any(unicodedata.category(character).startswith("C") for character in value)
    ):
        raise ValueError
    return value


def _valid_public_string(value: object) -> bool:
    try:
        _bounded_string(value)
    except ValueError:
        return False
    return True


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and _SHA256_PATTERN.fullmatch(value) is not None


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _identity(domain: bytes, value: object) -> str:
    digest = hashlib.sha256()
    digest.update(domain)
    digest.update(_canonical_json(value))
    return digest.hexdigest()


def _normalize_location(value: object, authorized_paths: frozenset[str]) -> str:
    raw = _bounded_string(value)
    if raw.startswith("/"):
        raw = raw[1:]
    if not raw or len(raw.encode("utf-8")) > _MAX_PATH or "\\" in raw or "\x00" in raw:
        raise ValueError
    path = PurePosixPath(raw)
    if (
        path.is_absolute()
        or path.as_posix() != raw
        or any(part in {"", ".", ".."} for part in raw.split("/"))
        or raw not in authorized_paths
    ):
        raise ValueError
    return raw


def _valid_relative_location(value: object) -> bool:
    try:
        raw = _bounded_string(value)
    except ValueError:
        return False
    path = PurePosixPath(raw)
    return (
        len(raw.encode("utf-8")) <= _MAX_PATH
        and "\\" not in raw
        and not path.is_absolute()
        and path.as_posix() == raw
        and all(part not in {"", ".", ".."} for part in raw.split("/"))
    )


def _normalize_purl(value: object) -> str | None:
    if value in {None, ""}:
        return None
    raw = _bounded_string(value)
    try:
        parsed = PackageURL.from_string(raw)
        canonical = parsed.to_string()
    except (TypeError, ValueError):
        raise ValueError from None
    if not parsed.type or not parsed.name or len(canonical) > _MAX_STRING:
        raise ValueError
    return canonical


@dataclass(frozen=True, slots=True)
class PackageObservation:
    scanner_id: str
    scanner_version: str
    package_name: str
    package_version: str | None
    package_type: str
    language: str | None
    purl: str | None
    found_by: str
    locations: tuple[str, ...]
    projection_id: str
    snapshot_digest: str
    binding_digest: str
    package_key: str
    package_observation_id: str

    def __post_init__(self) -> None:
        coordinates = {
            "name": self.package_name,
            "purl": self.purl,
            "type": self.package_type,
            "version": self.package_version,
        }
        structural = {
            "cataloger": self.found_by,
            "locations": list(self.locations),
            "package_key": self.package_key,
        }
        if (
            self.scanner_id != SYFT_SCANNER_ID
            or self.scanner_version != SYFT_VERSION
            or not _valid_public_string(self.package_name)
            or not _valid_public_string(self.package_type)
            or self.package_version == ""
            or (self.package_version is not None and not _valid_public_string(self.package_version))
            or self.language == ""
            or (self.language is not None and not _valid_public_string(self.language))
            or self.purl == ""
            or _normalize_purl(self.purl) != self.purl
            or not self.found_by
            or not _valid_public_string(self.found_by)
            or not isinstance(self.locations, tuple)
            or not self.locations
            or self.locations != tuple(sorted(set(self.locations)))
            or any(not _valid_relative_location(item) for item in self.locations)
            or _PROJECTION_ID_PATTERN.fullmatch(self.projection_id) is None
            or not _valid_digest(self.snapshot_digest)
            or not _valid_digest(self.binding_digest)
            or self.package_key != _identity(_PACKAGE_KEY_DOMAIN, coordinates)
            or self.package_observation_id != _identity(_OBSERVATION_ID_DOMAIN, structural)
        ):
            raise ValueError("Package observation is invalid")

    @classmethod
    def create(
        cls,
        *,
        package_name: str,
        package_version: str | None,
        package_type: str,
        language: str | None,
        purl: str | None,
        found_by: str,
        locations: tuple[str, ...],
        projection_id: str,
        snapshot_digest: str,
        binding_digest: str,
    ) -> PackageObservation:
        coordinates = {
            "name": package_name,
            "purl": purl,
            "type": package_type,
            "version": package_version,
        }
        package_key = _identity(_PACKAGE_KEY_DOMAIN, coordinates)
        structural = {
            "cataloger": found_by,
            "locations": list(locations),
            "package_key": package_key,
        }
        return cls(
            scanner_id=SYFT_SCANNER_ID,
            scanner_version=SYFT_VERSION,
            package_name=package_name,
            package_version=package_version,
            package_type=package_type,
            language=language,
            purl=purl,
            found_by=found_by,
            locations=locations,
            projection_id=projection_id,
            snapshot_digest=snapshot_digest,
            binding_digest=binding_digest,
            package_key=package_key,
            package_observation_id=_identity(_OBSERVATION_ID_DOMAIN, structural),
        )

    def canonical_data(self) -> dict[str, Any]:
        return {
            "binding_digest": self.binding_digest,
            "found_by": self.found_by,
            "language": self.language,
            "locations": list(self.locations),
            "package_key": self.package_key,
            "package_name": self.package_name,
            "package_observation_id": self.package_observation_id,
            "package_type": self.package_type,
            "package_version": self.package_version,
            "projection_id": self.projection_id,
            "purl": self.purl,
            "scanner_id": self.scanner_id,
            "scanner_version": self.scanner_version,
            "snapshot_digest": self.snapshot_digest,
        }


@dataclass(frozen=True, slots=True)
class SyftParseResult:
    scanner_id: str
    scanner_version: str
    binding_digest: str
    projection_id: str
    snapshot_digest: str
    syft_schema_version: str
    requested_cataloger_strategy: tuple[str, ...]
    used_catalogers: tuple[str, ...]
    observations: tuple[PackageObservation, ...]
    package_count: int
    schema_version: str = SYFT_PARSER_SCHEMA_VERSION

    def __post_init__(self) -> None:
        expected_order = tuple(
            sorted(
                self.observations,
                key=lambda item: (
                    item.package_observation_id,
                    item.package_key,
                    item.package_name,
                ),
            )
        )
        if (
            self.schema_version != SYFT_PARSER_SCHEMA_VERSION
            or self.scanner_id != SYFT_SCANNER_ID
            or self.scanner_version != SYFT_VERSION
            or not _valid_digest(self.binding_digest)
            or _PROJECTION_ID_PATTERN.fullmatch(self.projection_id) is None
            or not _valid_digest(self.snapshot_digest)
            or self.syft_schema_version != SYFT_JSON_SCHEMA_VERSION
            or self.requested_cataloger_strategy != ("directory", "file")
            or self.used_catalogers != tuple(sorted(set(self.used_catalogers)))
            or self.observations != expected_order
            or self.package_count != len(self.observations)
            or any(
                observation.projection_id != self.projection_id
                or observation.snapshot_digest != self.snapshot_digest
                or observation.binding_digest != self.binding_digest
                for observation in self.observations
            )
        ):
            raise ValueError("Syft parse result is invalid")

    def canonical_data(self) -> dict[str, Any]:
        return {
            "binding_digest": self.binding_digest,
            "observations": [item.canonical_data() for item in self.observations],
            "package_count": self.package_count,
            "projection_id": self.projection_id,
            "requested_cataloger_strategy": list(self.requested_cataloger_strategy),
            "scanner_id": self.scanner_id,
            "scanner_version": self.scanner_version,
            "schema_version": self.schema_version,
            "snapshot_digest": self.snapshot_digest,
            "syft_schema_version": self.syft_schema_version,
            "used_catalogers": list(self.used_catalogers),
        }

    def canonical_json(self) -> bytes:
        return _canonical_json(self.canonical_data()) + b"\n"


def _parse_catalogers(descriptor: dict[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    configuration = descriptor.get("configuration")
    if not isinstance(configuration, dict):
        raise ValueError
    catalogers = configuration.get("catalogers")
    if not isinstance(catalogers, dict):
        raise ValueError
    requested = catalogers.get("requested")
    if not isinstance(requested, dict) or requested.get("default") != ["directory", "file"]:
        raise ValueError
    used = catalogers.get("used")
    if (
        not isinstance(used, list)
        or len(used) > _MAX_CATALOGERS
        or any(not isinstance(item, str) or not item for item in used)
    ):
        raise ValueError
    return ("directory", "file"), tuple(sorted(set(used)))


def parse_syft_json(
    payload: bytes,
    *,
    expected_source_root: str,
    authorized_paths: frozenset[str],
    projection_id: str,
    snapshot_digest: str,
    binding_digest: str,
) -> SyftParseResult:
    verify_syft_purl_dependency()
    if (
        not isinstance(payload, bytes)
        or len(payload) > _MAX_DOCUMENT_BYTES
        or not expected_source_root.startswith("/")
        or not authorized_paths
        or _PROJECTION_ID_PATTERN.fullmatch(projection_id) is None
        or not _valid_digest(snapshot_digest)
        or not _valid_digest(binding_digest)
    ):
        raise SyftParserError
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
        _validate_json_tree(document)
        if not isinstance(document, dict):
            raise ValueError
        for required in ("artifacts", "artifactRelationships", "source", "descriptor", "schema"):
            if required not in document:
                raise ValueError
        artifacts = document["artifacts"]
        relationships = document["artifactRelationships"]
        source = document["source"]
        descriptor = document["descriptor"]
        schema = document["schema"]
        if (
            not isinstance(artifacts, list)
            or len(artifacts) > _MAX_ARTIFACTS
            or not isinstance(relationships, list)
            or len(relationships) > _MAX_RELATIONSHIPS
            or any(not isinstance(item, dict) for item in relationships)
            or not isinstance(source, dict)
            or source.get("type") != "directory"
            or source.get("name") != expected_source_root
            or not isinstance(source.get("metadata"), dict)
            or source["metadata"].get("path") != expected_source_root
            or not isinstance(descriptor, dict)
            or descriptor.get("name") != SYFT_SCANNER_ID
            or descriptor.get("version") != SYFT_VERSION
            or not isinstance(schema, dict)
            or schema.get("version") != SYFT_JSON_SCHEMA_VERSION
            or schema.get("url")
            != "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.1.10.json"
        ):
            raise ValueError
        requested, used = _parse_catalogers(descriptor)
        observations: list[PackageObservation] = []
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                raise ValueError
            name = _bounded_string(artifact.get("name"))
            raw_version = _bounded_string(artifact.get("version"), allow_empty=True)
            package_version = raw_version or None
            package_type = _bounded_string(artifact.get("type"))
            raw_language = artifact.get("language")
            language = None if raw_language in {None, ""} else _bounded_string(raw_language)
            found_by = _bounded_string(artifact.get("foundBy"))
            purl = _normalize_purl(artifact.get("purl"))
            raw_locations = artifact.get("locations")
            if (
                not isinstance(raw_locations, list)
                or not raw_locations
                or len(raw_locations) > _MAX_LOCATIONS
            ):
                raise ValueError
            locations = tuple(
                sorted(
                    {
                        _normalize_location(location.get("path"), authorized_paths)
                        for location in raw_locations
                        if isinstance(location, dict)
                    }
                )
            )
            if len(locations) != len(raw_locations) or not locations:
                raise ValueError
            observations.append(
                PackageObservation.create(
                    package_name=name,
                    package_version=package_version,
                    package_type=package_type,
                    language=language,
                    purl=purl,
                    found_by=found_by,
                    locations=locations,
                    projection_id=projection_id,
                    snapshot_digest=snapshot_digest,
                    binding_digest=binding_digest,
                )
            )
        ordered = tuple(
            sorted(
                observations,
                key=lambda item: (
                    item.package_observation_id,
                    item.package_key,
                    item.package_name,
                ),
            )
        )
        return SyftParseResult(
            scanner_id=SYFT_SCANNER_ID,
            scanner_version=SYFT_VERSION,
            binding_digest=binding_digest,
            projection_id=projection_id,
            snapshot_digest=snapshot_digest,
            syft_schema_version=SYFT_JSON_SCHEMA_VERSION,
            requested_cataloger_strategy=requested,
            used_catalogers=used,
            observations=ordered,
            package_count=len(ordered),
        )
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, UnicodeEncodeError):
        raise SyftParserError from None


def parse_syft_execution_result(
    envelope: object,
    projection: object,
) -> SyftParseResult:
    from securescan.scanners.syft.source_execution import (
        SyftExecutionResultEnvelope,
        SyftExecutionStatus,
    )
    from securescan.source.projection import PreparedSourceProjection

    if (
        not isinstance(envelope, SyftExecutionResultEnvelope)
        or envelope.execution_status is not SyftExecutionStatus.COMPLETED
        or envelope.failure_code is not None
        or not isinstance(projection, PreparedSourceProjection)
        or envelope.projection_id != projection.projection_id
        or envelope.context_digest != projection.context_digest
        or envelope.projection_digest != projection.projection_digest
    ):
        raise SyftParserError
    return parse_syft_json(
        envelope.stdout_bytes,
        expected_source_root=str(projection.source_directory),
        authorized_paths=frozenset(entry.relative_path for entry in projection.manifest.entries),
        projection_id=projection.projection_id,
        snapshot_digest=projection.projection_digest,
        binding_digest=envelope.binding_digest,
    )
