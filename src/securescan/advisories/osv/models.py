from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Final

from packageurl import PackageURL

from securescan.scanners.syft import PackageObservation

OSV_PROVIDER_ID: Final = "osv.dev"
OSV_API_VERSION: Final = "v1"
OSV_SCHEMA_VERSION: Final = "1.9.0"
OSV_SCHEMA_SHA256: Final = "cdb8292f72945cfdf06d3e044280d7c0867105a3a1ae6d4547c983eba20810a2"
OSV_SUPPORTED_PURL_TYPES: Final = frozenset({"golang", "npm", "pypi"})
OSV_SUPPORTED_PACKAGE_TYPE_MAPPING: Final = {
    "go-module": "golang",
    "npm": "npm",
    "python": "pypi",
}
OSV_HTTP_DISTRIBUTION: Final = "httpx"
OSV_HTTP_VERSION: Final = "0.28.1"
OSV_CVSS_DISTRIBUTION: Final = "cvss"
OSV_CVSS_VERSION: Final = "3.6"
OSV_PURL_DISTRIBUTION: Final = "packageurl-python"
OSV_PURL_VERSION: Final = "0.17.6"

_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]{1,199}\Z", re.ASCII)
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z", re.ASCII)
_GHSA = re.compile(
    r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-"
    r"[23456789cfghjmpqrvwx]{4}\Z",
    re.ASCII,
)
_QUERY_DOMAIN = b"securescan-osv-query-candidate-s2\0"
_GROUP_DOMAIN = b"securescan-osv-advisory-group-s2\0"
_FINDING_DOMAIN = b"securescan-dependency-vulnerability-finding-s2\0"
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z\Z",
    re.ASCII,
)
_PYPI_SEPARATOR = re.compile(r"[-_.]+", re.ASCII)
_PYPI_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\Z", re.ASCII)


class OsvGapReason(StrEnum):
    PACKAGE_VERSION_UNRESOLVED = "OSV_PACKAGE_VERSION_UNRESOLVED"
    PACKAGE_PURL_UNRESOLVED = "OSV_PACKAGE_PURL_UNRESOLVED"
    UNSUPPORTED_PURL_TYPE = "OSV_UNSUPPORTED_PURL_TYPE"
    PURL_VERSION_MISMATCH = "OSV_PURL_VERSION_MISMATCH"
    PURL_PACKAGE_MISMATCH = "OSV_PURL_PACKAGE_MISMATCH"


class OsvCvssScope(StrEnum):
    ADVISORY = "ADVISORY"
    MATCHED_PACKAGE = "MATCHED_PACKAGE"


class OsvFailureCode(StrEnum):
    RUNTIME_DEPENDENCY_INVALID = "OSV_RUNTIME_DEPENDENCY_INVALID"
    NETWORK_FAILURE = "OSV_NETWORK_FAILURE"
    TIMEOUT = "OSV_TIMEOUT"
    RESPONSE_LIMIT = "OSV_RESPONSE_LIMIT"
    HTTP_ERROR = "OSV_HTTP_ERROR"
    QUERY_RESPONSE_INVALID = "OSV_QUERY_RESPONSE_INVALID"
    PAGINATION_INVALID = "OSV_PAGINATION_INVALID"
    ADVISORY_FETCH_FAILED = "OSV_ADVISORY_FETCH_FAILED"
    ADVISORY_SCHEMA_INVALID = "OSV_ADVISORY_SCHEMA_INVALID"
    DATA_CHANGED_DURING_QUERY = "OSV_DATA_CHANGED_DURING_QUERY"


class OsvIntegrationError(RuntimeError):
    def __init__(self, code: OsvFailureCode) -> None:
        self.code = code
        super().__init__("OSV dependency advisory matching failed")


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _digest(domain: bytes, value: object) -> str:
    digest = hashlib.sha256()
    digest.update(domain)
    digest.update(canonical_json(value))
    return digest.hexdigest()


def _valid_sha(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def valid_osv_timestamp(value: object) -> bool:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        return False
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return True


def canonical_package_name(purl_type: str, value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("OSV package name is invalid")
    if purl_type == "pypi":
        if _PYPI_NAME.fullmatch(value) is None:
            raise ValueError("OSV package name is invalid")
        return _PYPI_SEPARATOR.sub("-", value).lower()
    if purl_type in {"npm", "golang"}:
        return value
    raise ValueError("OSV package name is invalid")


def purl_package_name(purl: PackageURL) -> str:
    value = f"{purl.namespace}/{purl.name}" if purl.namespace else purl.name
    return canonical_package_name(purl.type, value)


@dataclass(frozen=True, slots=True)
class OsvQueryCandidate:
    candidate_id: str
    package_key: str
    package_name: str
    package_version: str
    package_type: str
    purl: str
    purl_type: str
    package_observation_ids: tuple[str, ...]
    locations: tuple[str, ...]
    projection_id: str
    snapshot_digest: str
    syft_binding_digest: str

    def __post_init__(self) -> None:
        identity = {
            "package_key": self.package_key,
            "purl": self.purl,
        }
        if (
            self.candidate_id != _digest(_QUERY_DOMAIN, identity)
            or not _valid_sha(self.package_key)
            or not self.package_name
            or not self.package_version
            or not self.package_type
            or self.purl_type not in OSV_SUPPORTED_PURL_TYPES
            or not self.package_observation_ids
            or self.package_observation_ids != tuple(sorted(set(self.package_observation_ids)))
            or any(not _valid_sha(value) for value in self.package_observation_ids)
            or not self.locations
            or self.locations != tuple(sorted(set(self.locations)))
            or not self.projection_id
            or not _valid_sha(self.snapshot_digest)
            or not _valid_sha(self.syft_binding_digest)
        ):
            raise ValueError("OSV query candidate is invalid")
        try:
            parsed = PackageURL.from_string(self.purl)
        except ValueError:
            raise ValueError("OSV query candidate is invalid") from None
        if (
            parsed.to_string() != self.purl
            or parsed.type != self.purl_type
            or parsed.version != self.package_version
            or canonical_package_name(parsed.type, self.package_name)
            != purl_package_name(parsed)
        ):
            raise ValueError("OSV query candidate is invalid")

    @classmethod
    def create(cls, observations: tuple[PackageObservation, ...]) -> OsvQueryCandidate:
        first = observations[0]
        purl = first.purl
        if purl is None or first.package_version is None:
            raise ValueError
        parsed = PackageURL.from_string(purl)
        identity = {"package_key": first.package_key, "purl": purl}
        return cls(
            candidate_id=_digest(_QUERY_DOMAIN, identity),
            package_key=first.package_key,
            package_name=first.package_name,
            package_version=first.package_version,
            package_type=first.package_type,
            purl=purl,
            purl_type=parsed.type,
            package_observation_ids=tuple(
                sorted(item.package_observation_id for item in observations)
            ),
            locations=tuple(sorted({path for item in observations for path in item.locations})),
            projection_id=first.projection_id,
            snapshot_digest=first.snapshot_digest,
            syft_binding_digest=first.binding_digest,
        )

    def query_data(self, page_token: str | None = None) -> dict[str, Any]:
        result: dict[str, Any] = {"package": {"purl": self.purl}}
        if page_token is not None:
            result["page_token"] = page_token
        return result


@dataclass(frozen=True, slots=True)
class OsvPackageGap:
    package_key: str
    package_observation_ids: tuple[str, ...]
    locations: tuple[str, ...]
    reason_code: OsvGapReason

    def __post_init__(self) -> None:
        if (
            not _valid_sha(self.package_key)
            or not self.package_observation_ids
            or self.package_observation_ids
            != tuple(sorted(set(self.package_observation_ids)))
            or any(not _valid_sha(value) for value in self.package_observation_ids)
            or not self.locations
            or self.locations != tuple(sorted(set(self.locations)))
            or not isinstance(self.reason_code, OsvGapReason)
        ):
            raise ValueError("OSV package gap is invalid")


def build_osv_query_candidates(
    observations: tuple[PackageObservation, ...],
) -> tuple[tuple[OsvQueryCandidate, ...], tuple[OsvPackageGap, ...]]:
    groups: dict[str, list[PackageObservation]] = {}
    for observation in observations:
        if not isinstance(observation, PackageObservation):
            raise ValueError("OSV package evidence is invalid")
        groups.setdefault(observation.package_key, []).append(observation)
    candidates: list[OsvQueryCandidate] = []
    gaps: list[OsvPackageGap] = []
    for package_key, values in sorted(groups.items()):
        group = tuple(sorted(values, key=lambda item: item.package_observation_id))
        first = group[0]
        comparable = (
            first.package_name,
            first.package_version,
            first.package_type,
            first.purl,
            first.projection_id,
            first.snapshot_digest,
            first.binding_digest,
        )
        if any(
            (
                item.package_name,
                item.package_version,
                item.package_type,
                item.purl,
                item.projection_id,
                item.snapshot_digest,
                item.binding_digest,
            )
            != comparable
            for item in group
        ):
            raise ValueError("OSV package evidence is contradictory")
        reason: OsvGapReason | None = None
        parsed: PackageURL | None = None
        if first.package_version is None:
            reason = OsvGapReason.PACKAGE_VERSION_UNRESOLVED
        elif first.purl is None:
            reason = OsvGapReason.PACKAGE_PURL_UNRESOLVED
        else:
            try:
                parsed = PackageURL.from_string(first.purl)
            except ValueError:
                reason = OsvGapReason.PACKAGE_PURL_UNRESOLVED
            if parsed is not None and parsed.version != first.package_version:
                reason = OsvGapReason.PURL_VERSION_MISMATCH
            elif parsed is not None and (
                parsed.type not in OSV_SUPPORTED_PURL_TYPES
                or OSV_SUPPORTED_PACKAGE_TYPE_MAPPING.get(first.package_type) != parsed.type
            ):
                reason = OsvGapReason.UNSUPPORTED_PURL_TYPE
            elif parsed is not None and (
                canonical_package_name(parsed.type, first.package_name)
                != purl_package_name(parsed)
            ):
                reason = OsvGapReason.PURL_PACKAGE_MISMATCH
        if reason is None:
            candidates.append(OsvQueryCandidate.create(group))
        else:
            gaps.append(
                OsvPackageGap(
                    package_key=package_key,
                    package_observation_ids=tuple(
                        sorted(item.package_observation_id for item in group)
                    ),
                    locations=tuple(
                        sorted({path for item in group for path in item.locations})
                    ),
                    reason_code=reason,
                )
            )
    return tuple(candidates), tuple(gaps)


@dataclass(frozen=True, slots=True)
class OsvAdvisoryReference:
    osv_record_id: str
    modified: str

    def __post_init__(self) -> None:
        if not _valid_id(self.osv_record_id) or not valid_osv_timestamp(self.modified):
            raise ValueError("OSV advisory reference is invalid")


@dataclass(frozen=True, slots=True)
class OsvCvssEvidence:
    cvss_type: str
    vector: str
    source: str | None
    base_score: float
    scope: OsvCvssScope

    def __post_init__(self) -> None:
        if (
            self.cvss_type not in {"CVSS_V2", "CVSS_V3", "CVSS_V4"}
            or not self.vector
            or self.source == ""
            or not isinstance(self.base_score, float)
            or not 0.0 <= self.base_score <= 10.0
            or not isinstance(self.scope, OsvCvssScope)
        ):
            raise ValueError("OSV CVSS evidence is invalid")


@dataclass(frozen=True, slots=True)
class OsvAdvisoryObservation:
    osv_record_id: str
    modified: str
    published: str | None
    aliases: tuple[str, ...]
    cve_aliases: tuple[str, ...]
    ghsa_aliases: tuple[str, ...]
    summary: str | None
    applicable_package_key: str
    fixed_versions: tuple[str, ...]
    cvss: tuple[OsvCvssEvidence, ...]
    source_service: str = OSV_PROVIDER_ID
    api_version: str = OSV_API_VERSION
    matched_by: str = "OSV_QUERYBATCH"

    def __post_init__(self) -> None:
        identities = {self.osv_record_id, *self.aliases}
        if (
            not _valid_id(self.osv_record_id)
            or not valid_osv_timestamp(self.modified)
            or (self.published is not None and not valid_osv_timestamp(self.published))
            or self.aliases != tuple(sorted(set(self.aliases)))
            or any(not _valid_id(value) for value in self.aliases)
            or self.cve_aliases
            != tuple(sorted(value for value in identities if _CVE.fullmatch(value)))
            or self.ghsa_aliases
            != tuple(sorted(value for value in identities if _GHSA.fullmatch(value)))
            or self.summary == ""
            or not _valid_sha(self.applicable_package_key)
            or self.fixed_versions != tuple(sorted(set(self.fixed_versions)))
            or any(not value for value in self.fixed_versions)
            or self.cvss
            != tuple(
                sorted(
                    set(self.cvss),
                    key=lambda item: (
                        item.cvss_type,
                        item.vector,
                        item.source or "",
                        item.scope.value,
                    ),
                )
            )
            or self.source_service != OSV_PROVIDER_ID
            or self.api_version != OSV_API_VERSION
            or self.matched_by != "OSV_QUERYBATCH"
        ):
            raise ValueError("OSV advisory observation is invalid")


@dataclass(frozen=True, slots=True)
class DependencyVulnerabilityFinding:
    finding_id: str
    advisory_group_key: str
    package_key: str
    package_name: str
    package_version: str
    package_type: str
    purl: str
    package_observation_ids: tuple[str, ...]
    locations: tuple[str, ...]
    canonical_advisory_id: str
    osv_record_ids: tuple[str, ...]
    aliases: tuple[str, ...]
    cve_aliases: tuple[str, ...]
    ghsa_aliases: tuple[str, ...]
    affected_match: str
    fixed_versions: tuple[str, ...]
    cvss: tuple[OsvCvssEvidence, ...]
    modified: tuple[tuple[str, str], ...]
    source_service: str
    api_version: str
    projection_id: str
    snapshot_digest: str
    syft_binding_digest: str

    def __post_init__(self) -> None:
        identity_values = {*self.osv_record_ids, *self.aliases}
        group_data = {
            "aliases": self.aliases,
            "osv_record_ids": self.osv_record_ids,
            "package_key": self.package_key,
        }
        expected_group = _digest(_GROUP_DOMAIN, group_data)
        modified_valid = (
            self.modified == tuple(sorted(set(self.modified)))
            and tuple(record_id for record_id, _ in self.modified) == self.osv_record_ids
            and all(
                _valid_id(record_id) and valid_osv_timestamp(modified)
                for record_id, modified in self.modified
            )
        )
        if (
            not _valid_sha(self.package_key)
            or self.advisory_group_key != expected_group
            or self.finding_id
            != _digest(_FINDING_DOMAIN, {"advisory_group_key": expected_group})
            or not self.package_name
            or not self.package_version
            or not self.package_type
            or not self.purl
            or self.package_observation_ids
            != tuple(sorted(set(self.package_observation_ids)))
            or any(not _valid_sha(value) for value in self.package_observation_ids)
            or self.locations != tuple(sorted(set(self.locations)))
            or not self.locations
            or self.osv_record_ids != tuple(sorted(set(self.osv_record_ids)))
            or not self.osv_record_ids
            or any(not _valid_id(value) for value in self.osv_record_ids)
            or self.aliases != tuple(sorted(set(self.aliases)))
            or any(not _valid_id(value) for value in self.aliases)
            or self.cve_aliases
            != tuple(sorted(value for value in identity_values if _CVE.fullmatch(value)))
            or self.ghsa_aliases
            != tuple(sorted(value for value in identity_values if _GHSA.fullmatch(value)))
            or self.canonical_advisory_id
            != (
                self.cve_aliases[0]
                if self.cve_aliases
                else self.ghsa_aliases[0]
                if self.ghsa_aliases
                else self.osv_record_ids[0]
            )
            or self.affected_match != "MATCHED_BY_OSV_QUERY"
            or self.fixed_versions != tuple(sorted(set(self.fixed_versions)))
            or self.cvss
            != tuple(
                sorted(
                    set(self.cvss),
                    key=lambda item: (
                        item.cvss_type,
                        item.vector,
                        item.source or "",
                        item.base_score,
                        item.scope.value,
                    ),
                )
            )
            or not modified_valid
            or self.source_service != OSV_PROVIDER_ID
            or self.api_version != OSV_API_VERSION
            or not self.projection_id
            or not _valid_sha(self.snapshot_digest)
            or not _valid_sha(self.syft_binding_digest)
        ):
            raise ValueError("dependency vulnerability finding is invalid")


def group_advisories(
    candidate: OsvQueryCandidate,
    advisories: tuple[OsvAdvisoryObservation, ...],
) -> tuple[DependencyVulnerabilityFinding, ...]:
    if any(item.applicable_package_key != candidate.package_key for item in advisories):
        raise ValueError("OSV advisory evidence is not bound to the package candidate")
    remaining = list(advisories)
    components: list[list[OsvAdvisoryObservation]] = []
    while remaining:
        component = [remaining.pop(0)]
        identities = {component[0].osv_record_id, *component[0].aliases}
        changed = True
        while changed:
            changed = False
            for advisory in tuple(remaining):
                current = {advisory.osv_record_id, *advisory.aliases}
                if identities & current:
                    component.append(advisory)
                    remaining.remove(advisory)
                    identities.update(current)
                    changed = True
        components.append(component)
    findings: list[DependencyVulnerabilityFinding] = []
    for component in components:
        records = tuple(sorted(item.osv_record_id for item in component))
        aliases = tuple(sorted({alias for item in component for alias in item.aliases}))
        identity_values = {*records, *aliases}
        cves = tuple(sorted(value for value in identity_values if _CVE.fullmatch(value)))
        ghsas = tuple(sorted(value for value in identity_values if _GHSA.fullmatch(value)))
        canonical_id = cves[0] if cves else (ghsas[0] if ghsas else records[0])
        group_data = {
            "aliases": aliases,
            "osv_record_ids": records,
            "package_key": candidate.package_key,
        }
        group_key = _digest(_GROUP_DOMAIN, group_data)
        finding_id = _digest(_FINDING_DOMAIN, {"advisory_group_key": group_key})
        findings.append(
            DependencyVulnerabilityFinding(
                finding_id=finding_id,
                advisory_group_key=group_key,
                package_key=candidate.package_key,
                package_name=candidate.package_name,
                package_version=candidate.package_version,
                package_type=candidate.package_type,
                purl=candidate.purl,
                package_observation_ids=candidate.package_observation_ids,
                locations=candidate.locations,
                canonical_advisory_id=canonical_id,
                osv_record_ids=records,
                aliases=aliases,
                cve_aliases=cves,
                ghsa_aliases=ghsas,
                affected_match="MATCHED_BY_OSV_QUERY",
                fixed_versions=tuple(
                    sorted({value for item in component for value in item.fixed_versions})
                ),
                cvss=tuple(
                    sorted(
                        {value for item in component for value in item.cvss},
                        key=lambda item: (
                            item.cvss_type,
                            item.vector,
                            item.source or "",
                            item.base_score,
                            item.scope.value,
                        ),
                    )
                ),
                modified=tuple(sorted((item.osv_record_id, item.modified) for item in component)),
                source_service=OSV_PROVIDER_ID,
                api_version=OSV_API_VERSION,
                projection_id=candidate.projection_id,
                snapshot_digest=candidate.snapshot_digest,
                syft_binding_digest=candidate.syft_binding_digest,
            )
        )
    return tuple(sorted(findings, key=lambda item: item.finding_id))
