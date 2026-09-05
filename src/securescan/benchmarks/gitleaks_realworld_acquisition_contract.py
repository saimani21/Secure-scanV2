from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

from securescan.benchmarks.gitleaks_realworld_contract import (
    GITLEAKS_BINDING_ARTIFACT_PATH,
    GITLEAKS_BINDING_ARTIFACT_SHA256,
    GITLEAKS_BINDING_DIGEST,
    GITLEAKS_CONFIG_PATH,
    GITLEAKS_CONFIG_SHA256,
    GITLEAKS_IGNORE_PATH,
    GITLEAKS_IGNORE_SHA256,
    GITLEAKS_MATURITY,
    GITLEAKS_REALWORLD_CONTRACT_PATH,
    GITLEAKS_REALWORLD_CONTRACT_SHA256,
    GITLEAKS_SCANNER_ID,
    GITLEAKS_SCANNER_VERSION,
    GitleaksRealworldAcquisitionMethod,
    GitleaksRealworldContractError,
    GitleaksRealworldRepositoryRole,
    load_gitleaks_realworld_contract,
)
from securescan.workspaces.models import RepositoryIntakeLimits

GITLEAKS_REALWORLD_ACQUISITION_POLICY_SCHEMA_VERSION: Final = (
    "securescan-gitleaks-realworld-acquisition-policy-v1"
)
GITLEAKS_REALWORLD_ACQUISITION_POLICY_ID: Final = (
    "securescan-gitleaks-v0.4f5-acquisition-policy-v1"
)
GITLEAKS_REALWORLD_ACQUISITION_POLICY_PATH: Final = (
    "benchmarks/gitleaks/realworld/acquisition-policy-v1.json"
)
GITLEAKS_REALWORLD_ACQUISITION_POLICY_SHA256: Final = (
    "0449a961bf33fae46c994b086a23e50158d271e1eb48ad2f385fe9cc2305c7e3"
)

GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SCHEMA_VERSION: Final = (
    "securescan-gitleaks-realworld-acquisition-manifest-v1"
)
GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_ID: Final = (
    "securescan-gitleaks-v0.4f5-acquisition-manifest-v1"
)
GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SCHEMA_PATH: Final = (
    "benchmarks/gitleaks/realworld/acquisition-manifest-schema-v1.json"
)
GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SCHEMA_SHA256: Final = (
    "2afbca45b41d684cb44bb8fdf0a51238fe251046b0b5acda9445b56251238d10"
)
GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_PATH: Final = (
    "benchmarks/gitleaks/realworld/acquisition-manifest-v1.json"
)

GITLEAKS_F5A_COMMIT: Final = "21298b3da86067dcf36665441e1a4ee5f94f4dc3"
GITLEAKS_F5A_TAG: Final = "source-v0.4F5A-gitleaks-realworld-contract"

GITLEAKS_ARCHIVE_MAX_DOWNLOADED_BYTES: Final = 268_435_456
GITLEAKS_ARCHIVE_FORMATS: Final = ("tar.gz",)
GITLEAKS_ROLE_EVIDENCE_VOCABULARY: Final = (
    "application_entrypoint",
    "package_manifest",
    "documentation_directory",
    "examples_directory",
    "tests_directory",
    "vendor_directory",
    "generated_directory",
    "multiple_language_families",
    "binary_asset",
    "configuration_asset",
)

_MAX_DOCUMENT_BYTES = 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_COMMIT = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
_REPOSITORY_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z", re.ASCII)
_LICENSE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9-.+]{0,127}\Z", re.ASCII)
_ENTRY_FIELDS: Final = (
    "slot_id",
    "role",
    "repository_id",
    "upstream_url",
    "archive_url",
    "exact_commit_sha",
    "license_identifier",
    "acquisition_method",
    "archive_sha256",
    "archive_byte_count",
    "snapshot_digest",
    "file_count",
    "byte_count",
    "pre_scan_role_evidence",
    "pre_scan_role_rationale",
)
_FORBIDDEN_MANIFEST_FIELDS: Final = (
    "Secret",
    "Match",
    "Fingerprint",
    "credential_hash",
    "raw_secret_content",
    "scanner_output",
    "host_checkout_path",
    "temporary_extraction_path",
)


class GitleaksRealworldAcquisitionContractError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Gitleaks real-world acquisition contract is invalid")


class GitleaksRealworldAcquisitionManifestState(StrEnum):
    PRE_SELECTION = "PRE_SELECTION"
    SELECTED = "SELECTED"
    ACQUIRED = "ACQUIRED"


def _valid_https_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and hostname is not None
        and bool(hostname)
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
    )


@dataclass(frozen=True, slots=True)
class GitleaksRealworldAcquisitionManifestEntry:
    slot_id: str
    role: GitleaksRealworldRepositoryRole
    repository_id: str | None = None
    upstream_url: str | None = None
    archive_url: str | None = None
    exact_commit_sha: str | None = None
    license_identifier: str | None = None
    acquisition_method: GitleaksRealworldAcquisitionMethod | None = None
    archive_sha256: str | None = None
    archive_byte_count: int | None = None
    snapshot_digest: str | None = None
    file_count: int | None = None
    byte_count: int | None = None
    pre_scan_role_evidence: tuple[str, ...] | None = None
    pre_scan_role_rationale: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.slot_id, str)
            or not isinstance(self.role, GitleaksRealworldRepositoryRole)
            or self.slot_id != self.role.value.split("_", 1)[0]
            or (
                self.repository_id is not None
                and (
                    not isinstance(self.repository_id, str)
                    or _REPOSITORY_ID.fullmatch(self.repository_id) is None
                )
            )
            or (
                self.upstream_url is not None
                and (
                    not isinstance(self.upstream_url, str)
                    or not _valid_https_url(self.upstream_url)
                )
            )
            or (
                self.archive_url is not None
                and (
                    not isinstance(self.archive_url, str)
                    or not _valid_https_url(self.archive_url)
                )
            )
            or (
                self.exact_commit_sha is not None
                and (
                    not isinstance(self.exact_commit_sha, str)
                    or _COMMIT.fullmatch(self.exact_commit_sha) is None
                )
            )
            or (
                self.license_identifier is not None
                and (
                    not isinstance(self.license_identifier, str)
                    or _LICENSE_ID.fullmatch(self.license_identifier) is None
                )
            )
            or (
                self.acquisition_method is not None
                and not isinstance(
                    self.acquisition_method,
                    GitleaksRealworldAcquisitionMethod,
                )
            )
            or (
                self.archive_sha256 is not None
                and (
                    not isinstance(self.archive_sha256, str)
                    or _SHA256.fullmatch(self.archive_sha256) is None
                )
            )
            or (
                self.archive_byte_count is not None
                and (
                    type(self.archive_byte_count) is not int
                    or not 1
                    <= self.archive_byte_count
                    <= GITLEAKS_ARCHIVE_MAX_DOWNLOADED_BYTES
                )
            )
            or (
                self.snapshot_digest is not None
                and (
                    not isinstance(self.snapshot_digest, str)
                    or _SHA256.fullmatch(self.snapshot_digest) is None
                )
            )
            or (
                self.file_count is not None
                and (type(self.file_count) is not int or self.file_count < 1)
            )
            or (
                self.byte_count is not None
                and (type(self.byte_count) is not int or self.byte_count < 0)
            )
            or (
                self.pre_scan_role_evidence is not None
                and (
                    not isinstance(self.pre_scan_role_evidence, tuple)
                    or not self.pre_scan_role_evidence
                    or len(set(self.pre_scan_role_evidence))
                    != len(self.pre_scan_role_evidence)
                    or any(
                        evidence not in GITLEAKS_ROLE_EVIDENCE_VOCABULARY
                        for evidence in self.pre_scan_role_evidence
                    )
                )
            )
            or (
                self.pre_scan_role_rationale is not None
                and (
                    not isinstance(self.pre_scan_role_rationale, str)
                    or not self.pre_scan_role_rationale
                    or len(self.pre_scan_role_rationale) > 2048
                )
            )
        ):
            raise GitleaksRealworldAcquisitionContractError

    def canonical_data(self) -> dict[str, object]:
        return {
            "acquisition_method": (
                None if self.acquisition_method is None else self.acquisition_method.value
            ),
            "archive_byte_count": self.archive_byte_count,
            "archive_sha256": self.archive_sha256,
            "archive_url": self.archive_url,
            "byte_count": self.byte_count,
            "exact_commit_sha": self.exact_commit_sha,
            "file_count": self.file_count,
            "license_identifier": self.license_identifier,
            "pre_scan_role_evidence": (
                None
                if self.pre_scan_role_evidence is None
                else list(self.pre_scan_role_evidence)
            ),
            "pre_scan_role_rationale": self.pre_scan_role_rationale,
            "repository_id": self.repository_id,
            "role": self.role.value,
            "slot_id": self.slot_id,
            "snapshot_digest": self.snapshot_digest,
            "upstream_url": self.upstream_url,
        }


@dataclass(frozen=True, slots=True)
class GitleaksRealworldAcquisitionManifestModel:
    state: GitleaksRealworldAcquisitionManifestState
    entries: tuple[GitleaksRealworldAcquisitionManifestEntry, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.state, GitleaksRealworldAcquisitionManifestState)
            or not isinstance(self.entries, tuple)
            or len(self.entries) != 6
            or not all(
                isinstance(entry, GitleaksRealworldAcquisitionManifestEntry)
                for entry in self.entries
            )
            or tuple(entry.role for entry in self.entries)
            != tuple(GitleaksRealworldRepositoryRole)
            or len({entry.slot_id for entry in self.entries}) != 6
        ):
            raise GitleaksRealworldAcquisitionContractError
        selection_values = tuple(
            (
                entry.repository_id,
                entry.upstream_url,
                entry.archive_url,
                entry.exact_commit_sha,
                entry.license_identifier,
                entry.acquisition_method,
                entry.pre_scan_role_evidence,
                entry.pre_scan_role_rationale,
            )
            for entry in self.entries
        )
        acquisition_values = tuple(
            (
                entry.archive_sha256,
                entry.archive_byte_count,
                entry.snapshot_digest,
                entry.file_count,
                entry.byte_count,
            )
            for entry in self.entries
        )
        if (
            (
                self.state is GitleaksRealworldAcquisitionManifestState.PRE_SELECTION
                and any(
                    value is not None
                    for values in (*selection_values, *acquisition_values)
                    for value in values
                )
            )
            or (
                self.state is GitleaksRealworldAcquisitionManifestState.SELECTED
                and (
                    any(value is None for values in selection_values for value in values)
                    or any(
                        value is not None
                        for values in acquisition_values
                        for value in values
                    )
                )
            )
            or (
                self.state is GitleaksRealworldAcquisitionManifestState.ACQUIRED
                and any(
                    value is None
                    for values in (*selection_values, *acquisition_values)
                    for value in values
                )
            )
        ):
            raise GitleaksRealworldAcquisitionContractError
        if (
            self.state is not GitleaksRealworldAcquisitionManifestState.PRE_SELECTION
            and (
                len({entry.repository_id for entry in self.entries}) != 6
                or len({entry.upstream_url for entry in self.entries}) != 6
                or len({entry.archive_url for entry in self.entries}) != 6
                or len(
                    {
                        (entry.upstream_url, entry.exact_commit_sha)
                        for entry in self.entries
                    }
                )
                != 6
            )
        ):
            raise GitleaksRealworldAcquisitionContractError
        if (
            self.state is GitleaksRealworldAcquisitionManifestState.ACQUIRED
            and len({entry.snapshot_digest for entry in self.entries}) != 6
        ):
            raise GitleaksRealworldAcquisitionContractError


def canonical_gitleaks_realworld_acquisition(value: object) -> bytes:
    try:
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
    except (TypeError, ValueError, UnicodeEncodeError):
        raise GitleaksRealworldAcquisitionContractError from None


def _workspace_limits() -> dict[str, object]:
    limits = RepositoryIntakeLimits()
    return {
        "authority": "securescan.workspaces.models.RepositoryIntakeLimits",
        "max_directory_depth": limits.max_directory_depth,
        "max_file_count": limits.max_file_count,
        "max_relative_path_bytes": limits.max_relative_path_bytes,
        "max_single_file_bytes": limits.max_single_file_bytes,
        "max_total_bytes": limits.max_total_bytes,
        "policy": "UNCHANGED_PRODUCTION_DEFAULTS",
    }


def gitleaks_realworld_acquisition_policy_document() -> dict[str, object]:
    limits = RepositoryIntakeLimits()
    return {
        "acquisition_sequence": [
            "DOWNLOAD_DURING_EXPLICIT_ACQUISITION_CHECKPOINT",
            "VERIFY_COMPLETE_ARCHIVE_SHA256",
            "VALIDATE_ALL_ARCHIVE_MEMBERS_AND_LIMITS",
            "EXTRACT_MEMBER_BY_MEMBER_TO_TEMPORARY_LOCATION",
            "VALIDATE_LOCAL_ORDINARY_SOURCE_TREE",
            "INGEST_WITH_REPOSITORY_WORKSPACE_MANAGER",
            "RECORD_REPOSITORY_MANIFEST_IDENTITY",
        ],
        "archive_extraction": {
            "allowed_materialized_member_types": ["REGULAR_FILE", "DIRECTORY"],
            "absolute_member_paths": "REJECT",
            "containment_after_normalization": "REQUIRED",
            "device_fifo_socket_and_special_entries": "REJECT",
            "dotdot_traversal": "REJECT",
            "duplicate_output_paths": "REJECT",
            "member_processing": "VALIDATE_THEN_WRITE_INDIVIDUALLY",
            "normalized_path_escape": "REJECT",
            "normalized_path_collisions": "REJECT",
            "standard_library_extractall": "FORBIDDEN",
            "symlinks_and_hardlinks": "REJECT",
            "temporary_extraction_location": "OUTSIDE_REPOSITORY",
            "top_level_provider_directory": {
                "containment_validation_before_stripping": True,
                "mode": "STRIP_EXACTLY_ONE_COMMON_TOP_LEVEL_DIRECTORY",
                "post_strip_empty_path": "REJECT",
                "required": True,
            },
        },
        "archive_limits": {
            "max_downloaded_archive_bytes": GITLEAKS_ARCHIVE_MAX_DOWNLOADED_BYTES,
            "max_expanded_member_bytes": limits.max_single_file_bytes,
            "max_member_count": limits.max_file_count,
            "max_normalized_relative_path_bytes": limits.max_relative_path_bytes,
            "max_path_depth": limits.max_directory_depth,
            "max_total_expanded_bytes": limits.max_total_bytes,
            "policy": "ARCHIVE_SPECIFIC_BOUNDS_ALIGNED_TO_WORKSPACE_INTAKE",
        },
        "archive_transport": {
            "allowed_formats": list(GITLEAKS_ARCHIVE_FORMATS),
            "archive_sha256_verified_before_extraction_acceptance": True,
            "checksum_algorithm": "SHA-256",
            "network_phase": "EXPLICIT_ACQUISITION_CHECKPOINT_ONLY",
        },
        "f5a": {
            "commit": GITLEAKS_F5A_COMMIT,
            "contract_sha256": GITLEAKS_REALWORLD_CONTRACT_SHA256,
            "tag": GITLEAKS_F5A_TAG,
        },
        "maturity": GITLEAKS_MATURITY,
        "policy_id": GITLEAKS_REALWORLD_ACQUISITION_POLICY_ID,
        "prohibited_operations": {
            "archive_symlink_or_hardlink_materialization": True,
            "build": True,
            "git_checkout": True,
            "git_submodules": True,
            "hooks": True,
            "package_install": True,
            "recursive_remote_acquisition": True,
            "repository_code_execution": True,
        },
        "purpose": "PRE_SELECTION_UNTRUSTED_ARCHIVE_ACQUISITION_POLICY",
        "repository_workspace_limits": _workspace_limits(),
        "schema_version": GITLEAKS_REALWORLD_ACQUISITION_POLICY_SCHEMA_VERSION,
        "snapshot_identity": {
            "authority": "RepositoryWorkspaceManager/RepositoryManifest",
            "byte_count_field": "total_bytes",
            "digest_field": "content_digest",
            "file_count_field": "file_count",
        },
    }


def _unresolved_repository_slots() -> list[dict[str, object]]:
    entries = tuple(
        GitleaksRealworldAcquisitionManifestEntry(
            slot_id=role.value.split("_", 1)[0],
            role=role,
        )
        for role in GitleaksRealworldRepositoryRole
    )
    model = GitleaksRealworldAcquisitionManifestModel(
        state=GitleaksRealworldAcquisitionManifestState.PRE_SELECTION,
        entries=entries,
    )
    return [entry.canonical_data() for entry in model.entries]


def gitleaks_realworld_acquisition_manifest_schema_document() -> dict[str, object]:
    return {
        "acquisition_manifest_id": GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_ID,
        "acquisition_state": "PRE_SELECTION",
        "allowed_acquisition_methods": [
            GitleaksRealworldAcquisitionMethod.UPSTREAM_ARCHIVE.value
        ],
        "allowed_acquisition_states": [
            state.value for state in GitleaksRealworldAcquisitionManifestState
        ],
        "bindings": {
            "acquisition_policy_sha256": GITLEAKS_REALWORLD_ACQUISITION_POLICY_SHA256,
            "config_sha256": GITLEAKS_CONFIG_SHA256,
            "f5a_contract_sha256": GITLEAKS_REALWORLD_CONTRACT_SHA256,
            "ignore_sha256": GITLEAKS_IGNORE_SHA256,
            "scanner_binding_digest": GITLEAKS_BINDING_DIGEST,
            "scanner_id": GITLEAKS_SCANNER_ID,
            "scanner_version": GITLEAKS_SCANNER_VERSION,
        },
        "confidentiality": {
            "forbidden_fields": list(_FORBIDDEN_MANIFEST_FIELDS),
            "raw_secret_material_allowed": False,
        },
        "contains_result_or_finding_data": False,
        "future_acquired_entry_requirements": {
            "all_entry_fields_required": True,
            "archive_url_exact_commit_association": (
                "REQUIRED_WITHOUT_PROVIDER_SPECIFIC_URL_LAYOUT"
            ),
            "distinct_by": [
                "repository_id",
                "upstream_url",
                "archive_url",
                "snapshot_digest",
                "(upstream_url,exact_commit_sha)",
            ],
            "one_repository_per_primary_slot": True,
        },
        "maturity": GITLEAKS_MATURITY,
        "repository_count": 6,
        "repository_entry_fields": list(_ENTRY_FIELDS),
        "repository_slots": _unresolved_repository_slots(),
        "role_evidence_vocabulary": list(GITLEAKS_ROLE_EVIDENCE_VOCABULARY),
        "schema_version": GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SCHEMA_VERSION,
        "state_requirements": {
            "ACQUIRED": {
                "required_resolved": list(_ENTRY_FIELDS[2:]),
                "unique": [
                    "repository_id",
                    "upstream_url",
                    "archive_url",
                    "snapshot_digest",
                    "(upstream_url,exact_commit_sha)",
                ],
            },
            "PRE_SELECTION": {
                "required_null": list(_ENTRY_FIELDS[2:]),
            },
            "SELECTED": {
                "required_null": [
                    "archive_sha256",
                    "archive_byte_count",
                    "snapshot_digest",
                    "file_count",
                    "byte_count",
                ],
                "required_resolved": [
                    "repository_id",
                    "upstream_url",
                    "archive_url",
                    "exact_commit_sha",
                    "license_identifier",
                    "acquisition_method",
                    "pre_scan_role_evidence",
                    "pre_scan_role_rationale",
                ],
                "unique": [
                    "repository_id",
                    "upstream_url",
                    "archive_url",
                    "(upstream_url,exact_commit_sha)",
                ],
            },
        },
    }


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_nonfinite(_value: str) -> None:
    raise ValueError


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_stable_file(path: Path) -> bytes:
    descriptor = -1
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_size > _MAX_DOCUMENT_BYTES
        ):
            raise OSError
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _stat_identity(opened) != _stat_identity(before):
            raise OSError
        payload = bytearray()
        while len(payload) <= _MAX_DOCUMENT_BYTES:
            chunk = os.read(
                descriptor,
                min(65536, _MAX_DOCUMENT_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        finished = os.fstat(descriptor)
        after = path.lstat()
        if (
            len(payload) > _MAX_DOCUMENT_BYTES
            or len(payload) != before.st_size
            or _stat_identity(finished) != _stat_identity(before)
            or _stat_identity(after) != _stat_identity(before)
        ):
            raise OSError
        return bytes(payload)
    except OSError:
        raise GitleaksRealworldAcquisitionContractError from None
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)


def _load_canonical_json(path: Path, expected_sha256: str) -> dict[str, object]:
    payload = _read_stable_file(path)
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, ValueError):
        raise GitleaksRealworldAcquisitionContractError from None
    if (
        not isinstance(value, dict)
        or canonical_gitleaks_realworld_acquisition(value) != payload
        or hashlib.sha256(payload).hexdigest() != expected_sha256
    ):
        raise GitleaksRealworldAcquisitionContractError
    return value


def load_gitleaks_realworld_acquisition_policy(path: Path) -> dict[str, object]:
    value = _load_canonical_json(path, GITLEAKS_REALWORLD_ACQUISITION_POLICY_SHA256)
    if value != gitleaks_realworld_acquisition_policy_document():
        raise GitleaksRealworldAcquisitionContractError
    return value


def load_gitleaks_realworld_acquisition_manifest_schema(
    path: Path,
) -> dict[str, object]:
    value = _load_canonical_json(
        path,
        GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SCHEMA_SHA256,
    )
    if value != gitleaks_realworld_acquisition_manifest_schema_document():
        raise GitleaksRealworldAcquisitionContractError
    return value


def verify_gitleaks_realworld_acquisition_contract(
    repository_root: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    if not isinstance(repository_root, Path) or not repository_root.is_absolute():
        raise GitleaksRealworldAcquisitionContractError
    try:
        load_gitleaks_realworld_contract(repository_root / GITLEAKS_REALWORLD_CONTRACT_PATH)
    except GitleaksRealworldContractError:
        raise GitleaksRealworldAcquisitionContractError from None
    policy = load_gitleaks_realworld_acquisition_policy(
        repository_root / GITLEAKS_REALWORLD_ACQUISITION_POLICY_PATH
    )
    manifest_schema = load_gitleaks_realworld_acquisition_manifest_schema(
        repository_root / GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SCHEMA_PATH
    )
    for relative, expected_sha256 in (
        (GITLEAKS_BINDING_ARTIFACT_PATH, GITLEAKS_BINDING_ARTIFACT_SHA256),
        (GITLEAKS_CONFIG_PATH, GITLEAKS_CONFIG_SHA256),
        (GITLEAKS_IGNORE_PATH, GITLEAKS_IGNORE_SHA256),
    ):
        if hashlib.sha256(_read_stable_file(repository_root / relative)).hexdigest() != (
            expected_sha256
        ):
            raise GitleaksRealworldAcquisitionContractError
    return policy, manifest_schema
