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

GITLEAKS_REALWORLD_CONTRACT_SCHEMA_VERSION: Final = (
    "securescan-gitleaks-realworld-contract-v1"
)
GITLEAKS_REALWORLD_EVALUATION_ID: Final = "securescan-gitleaks-v0.4f5-realworld-v1"
GITLEAKS_REALWORLD_CONTRACT_PATH: Final = (
    "benchmarks/gitleaks/realworld/realworld-contract-v1.json"
)
GITLEAKS_REALWORLD_RESULT_PATH: Final = (
    "benchmarks/gitleaks/realworld/realworld-result-v1.json"
)
GITLEAKS_REALWORLD_CONTRACT_SHA256: Final = (
    "8a6269cc9d655ff3bc733a69dfbafaec9eab13a01df53a6aebe26f8cf0812982"
)

GITLEAKS_SCANNER_ID: Final = "gitleaks"
GITLEAKS_SCANNER_VERSION: Final = "8.30.1"
GITLEAKS_BINDING_DIGEST: Final = (
    "8d9f224e1c5ddabef508a26be2966f51dc2a9c2e5805ea3bffcf444b3cae9561"
)
GITLEAKS_BINDING_ARTIFACT_PATH: Final = "benchmarks/gitleaks/gitleaks-binding-v1.json"
GITLEAKS_BINDING_ARTIFACT_SHA256: Final = (
    "8d0e06a802158827bbe685b7970ffa075ae07f6393debbb088c3b9bf29f1bd44"
)
GITLEAKS_CONFIG_PATH: Final = (
    "src/securescan/scanners/gitleaks/config/securescan-gitleaks-v1.toml"
)
GITLEAKS_CONFIG_SHA256: Final = (
    "ca699281a4752ca677d7f1c1c22d97d2afca9c169eae28054486d4d95bae7fb4"
)
GITLEAKS_IGNORE_PATH: Final = (
    "src/securescan/scanners/gitleaks/config/securescan-gitleaks-v1.ignore"
)
GITLEAKS_IGNORE_SHA256: Final = (
    "c5f2fc626c9cae855bbf0261d37ea80600cb65a270483a2df536a6c1c60e8f85"
)
GITLEAKS_F3B_COMMIT: Final = "d183336c129977c4279cd1058bbe060742de0e54"
GITLEAKS_F3B_TAG: Final = "source-v0.4F3B-gitleaks-initial-baseline"
GITLEAKS_F3B_REPORT_PATH: Final = "benchmarks/gitleaks/initial-v0.4f-baseline.json"
GITLEAKS_F3B_REPORT_SHA256: Final = (
    "62f9c00f79c659d56490a181de231f0aa3cdca6a418f2ca5a9215f7ed1bbbb34"
)
GITLEAKS_F4C_COMMIT: Final = "7dfba8f63b10480fc1dbbc49e486de9b267835fa"
GITLEAKS_F4C_TAG: Final = "source-v0.4F4C-gitleaks-characterization"
GITLEAKS_F4C_CHARACTERIZATION_PATH: Final = (
    "benchmarks/gitleaks/adversarial-v1-characterization.json"
)
GITLEAKS_F4C_CHARACTERIZATION_SHA256: Final = (
    "0687a8ec0ea9bdc1cb1d7a5c44dea5872b8a3c86cc3903b0d2e972ccef982404"
)
GITLEAKS_MATURITY: Final = "SCANNABLE"

_MAX_DOCUMENT_BYTES = 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_COMMIT = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
_REPOSITORY_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z", re.ASCII)
_LICENSE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9-.+]{0,127}\Z", re.ASCII)


class GitleaksRealworldAcquisitionState(StrEnum):
    PRE_ACQUISITION = "PRE_ACQUISITION"
    ACQUIRED = "ACQUIRED"


class GitleaksRealworldRepositoryRole(StrEnum):
    RW01_SMALL_APPLICATION = "RW01_SMALL_APPLICATION"
    RW02_LIBRARY_PACKAGE = "RW02_LIBRARY_PACKAGE"
    RW03_DOCS_EXAMPLES_HEAVY = "RW03_DOCS_EXAMPLES_HEAVY"
    RW04_DEPENDENCY_GENERATED_PATH_HEAVY = "RW04_DEPENDENCY_GENERATED_PATH_HEAVY"
    RW05_MULTI_LANGUAGE = "RW05_MULTI_LANGUAGE"
    RW06_BINARY_CONFIG_ASSETS = "RW06_BINARY_CONFIG_ASSETS"


class GitleaksRealworldAcquisitionMethod(StrEnum):
    UPSTREAM_ARCHIVE = "UPSTREAM_ARCHIVE"


class GitleaksRealworldReviewClassification(StrEnum):
    LIKELY_CREDENTIAL_MATERIAL = "LIKELY_CREDENTIAL_MATERIAL"
    DETECTOR_SHAPED_EXAMPLE = "DETECTOR_SHAPED_EXAMPLE"
    TEST_FIXTURE = "TEST_FIXTURE"
    DOCUMENTATION_EXAMPLE = "DOCUMENTATION_EXAMPLE"
    PLACEHOLDER = "PLACEHOLDER"
    PATH_ONLY_OBSERVATION = "PATH_ONLY_OBSERVATION"
    UNRESOLVED = "UNRESOLVED"


class GitleaksRealworldContractError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Gitleaks real-world contract is invalid")


@dataclass(frozen=True, slots=True)
class GitleaksRealworldRepositorySlot:
    slot_id: str
    role: GitleaksRealworldRepositoryRole
    repository_id: str | None = None
    upstream_url: str | None = None
    exact_commit_sha: str | None = None
    license_identifier: str | None = None
    acquisition_method: GitleaksRealworldAcquisitionMethod | None = None
    archive_sha256: str | None = None
    snapshot_digest: str | None = None
    file_count: int | None = None
    byte_count: int | None = None
    role_selection_evidence: tuple[str, ...] | None = None
    role_selection_rationale: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.slot_id, str)
            or not isinstance(self.role, GitleaksRealworldRepositoryRole)
            or self.slot_id != self.role.value.split("_", 1)[0]
        ):
            raise GitleaksRealworldContractError
        values = (
            self.repository_id,
            self.upstream_url,
            self.exact_commit_sha,
            self.license_identifier,
            self.acquisition_method,
            self.archive_sha256,
            self.snapshot_digest,
            self.file_count,
            self.byte_count,
            self.role_selection_evidence,
            self.role_selection_rationale,
        )
        if all(value is None for value in values):
            return
        if any(value is None for value in values):
            raise GitleaksRealworldContractError
        if (
            not isinstance(self.repository_id, str)
            or _REPOSITORY_ID.fullmatch(self.repository_id) is None
            or not isinstance(self.upstream_url, str)
            or not isinstance(self.exact_commit_sha, str)
            or _COMMIT.fullmatch(self.exact_commit_sha) is None
            or not isinstance(self.license_identifier, str)
            or _LICENSE_ID.fullmatch(self.license_identifier) is None
            or not isinstance(self.acquisition_method, GitleaksRealworldAcquisitionMethod)
            or not isinstance(self.archive_sha256, str)
            or _SHA256.fullmatch(self.archive_sha256) is None
            or not isinstance(self.snapshot_digest, str)
            or _SHA256.fullmatch(self.snapshot_digest) is None
            or type(self.file_count) is not int
            or self.file_count < 1
            or type(self.byte_count) is not int
            or self.byte_count < 0
            or not isinstance(self.role_selection_evidence, tuple)
            or not self.role_selection_evidence
            or any(
                not isinstance(item, str) or not item or len(item) > 512
                for item in self.role_selection_evidence
            )
            or not isinstance(self.role_selection_rationale, str)
            or not self.role_selection_rationale
            or len(self.role_selection_rationale) > 2048
            or not _valid_upstream_url(self.upstream_url)
        ):
            raise GitleaksRealworldContractError

    @property
    def resolved(self) -> bool:
        return self.repository_id is not None

    def canonical_data(self) -> dict[str, object]:
        return {
            "acquisition_method": (
                None if self.acquisition_method is None else self.acquisition_method.value
            ),
            "archive_sha256": self.archive_sha256,
            "byte_count": self.byte_count,
            "exact_commit_sha": self.exact_commit_sha,
            "file_count": self.file_count,
            "license_identifier": self.license_identifier,
            "repository_id": self.repository_id,
            "role": self.role.value,
            "role_selection_evidence": (
                None
                if self.role_selection_evidence is None
                else list(self.role_selection_evidence)
            ),
            "role_selection_rationale": self.role_selection_rationale,
            "slot_id": self.slot_id,
            "snapshot_digest": self.snapshot_digest,
            "upstream_url": self.upstream_url,
        }


@dataclass(frozen=True, slots=True)
class GitleaksRealworldRepositorySelection:
    state: GitleaksRealworldAcquisitionState
    slots: tuple[GitleaksRealworldRepositorySlot, ...]

    def __post_init__(self) -> None:
        expected_roles = tuple(GitleaksRealworldRepositoryRole)
        if (
            not isinstance(self.state, GitleaksRealworldAcquisitionState)
            or not isinstance(self.slots, tuple)
            or len(self.slots) != 6
            or not all(isinstance(slot, GitleaksRealworldRepositorySlot) for slot in self.slots)
        ):
            raise GitleaksRealworldContractError
        resolved_slots = tuple(slot for slot in self.slots if slot.resolved)
        if (
            tuple(slot.role for slot in self.slots) != expected_roles
            or len({slot.slot_id for slot in self.slots}) != 6
            or len({slot.role for slot in self.slots}) != 6
            or (
                self.state is GitleaksRealworldAcquisitionState.PRE_ACQUISITION
                and any(slot.resolved for slot in self.slots)
            )
            or (
                self.state is GitleaksRealworldAcquisitionState.ACQUIRED
                and any(not slot.resolved for slot in self.slots)
            )
            or (
                self.state is GitleaksRealworldAcquisitionState.ACQUIRED
                and (
                    len({slot.repository_id for slot in resolved_slots}) != 6
                    or len({slot.upstream_url for slot in resolved_slots}) != 6
                    or len({slot.snapshot_digest for slot in resolved_slots}) != 6
                    or len(
                        {
                            (slot.upstream_url, slot.exact_commit_sha)
                            for slot in resolved_slots
                        }
                    )
                    != 6
                )
            )
        ):
            raise GitleaksRealworldContractError

    def canonical_data(self) -> dict[str, object]:
        return {
            "slot_count": len(self.slots),
            "slots": [slot.canonical_data() for slot in self.slots],
            "state": self.state.value,
        }


def pre_acquisition_repository_selection() -> GitleaksRealworldRepositorySelection:
    return GitleaksRealworldRepositorySelection(
        state=GitleaksRealworldAcquisitionState.PRE_ACQUISITION,
        slots=tuple(
            GitleaksRealworldRepositorySlot(
                slot_id=role.value.split("_", 1)[0],
                role=role,
            )
            for role in GitleaksRealworldRepositoryRole
        ),
    )


def canonical_gitleaks_realworld_contract(value: object) -> bytes:
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
        raise GitleaksRealworldContractError from None


def _valid_upstream_url(value: str) -> bool:
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


def _role_eligibility() -> list[dict[str, object]]:
    return [
        {
            "requirements": [
                "ORDINARY_STANDALONE_APPLICATION",
                "BOUNDED_NON_LIBRARY_APPLICATION_REPOSITORY",
            ],
            "role": GitleaksRealworldRepositoryRole.RW01_SMALL_APPLICATION.value,
        },
        {
            "requirements": [
                "REUSABLE_LIBRARY_OR_PACKAGE",
                "PACKAGE_OR_BUILD_METADATA_EXPECTED",
            ],
            "role": GitleaksRealworldRepositoryRole.RW02_LIBRARY_PACKAGE.value,
        },
        {
            "requirements": [
                "MATERIALLY_CONTAINS_DOCUMENTATION_EXAMPLES_OR_TEST_STYLE_MATERIAL"
            ],
            "role": GitleaksRealworldRepositoryRole.RW03_DOCS_EXAMPLES_HEAVY.value,
        },
        {
            "requirements": [
                "MATERIALLY_CONTAINS_COMMITTED_VENDOR_GENERATED_OR_DEPENDENCY_LIKE_PATHS",
                "PATHS_RELEVANT_TO_INHERITED_SCANNER_PATH_BEHAVIOR",
            ],
            "role": (
                GitleaksRealworldRepositoryRole.RW04_DEPENDENCY_GENERATED_PATH_HEAVY.value
            ),
        },
        {
            "requirements": [
                "MATERIALLY_CONTAINS_MULTIPLE_SOURCE_OR_CONFIGURATION_LANGUAGE_FAMILIES"
            ],
            "role": GitleaksRealworldRepositoryRole.RW05_MULTI_LANGUAGE.value,
        },
        {
            "requirements": [
                "MATERIALLY_CONTAINS_NONEMPTY_BINARY_OR_CONFIGURATION_ASSETS",
                "ASSETS_RELEVANT_TO_REPOSITORY_WIDE_SECRET_SCANNING",
            ],
            "role": GitleaksRealworldRepositoryRole.RW06_BINARY_CONFIG_ASSETS.value,
        },
    ]


def _contract_document() -> dict[str, object]:
    return {
        "acquisition": {
            "archive_acceptance": {
                "complete_archive_sha256_verified_before_acceptance": True,
                "download_phase": "EXPLICIT_ACQUISITION_CHECKPOINT_ONLY",
            },
            "archive_extraction": {
                "absolute_member_paths": "REJECT",
                "device_fifo_socket_and_special_entries": "REJECT",
                "dotdot_traversal": "REJECT",
                "duplicate_normalized_output_paths": "REJECT",
                "limits": {
                    "authority": "F5B_FROZEN_ACQUISITION_POLICY",
                    "member_count": "BOUNDED",
                    "per_file_size": "BOUNDED",
                    "relative_path_length": "BOUNDED",
                    "total_expanded_bytes": "BOUNDED",
                },
                "normalized_path_escape": "REJECT",
                "provider_top_level_directory": (
                    "NORMALIZE_OR_STRIP_ONLY_AFTER_CONTAINMENT_VALIDATION"
                ),
                "symlink_or_hardlink_escape": "REJECT",
            },
            "network_access_phase": "EXPLICIT_ACQUISITION_CHECKPOINT_ONLY",
            "operations": {
                "build": False,
                "hooks": False,
                "install": False,
                "repository_code_execution": False,
            },
            "output": "LOCAL_ORDINARY_SOURCE_TREE",
            "required_metadata": [
                "repository_id",
                "role",
                "upstream_url",
                "exact_commit_sha",
                "license_identifier",
                "acquisition_method",
                "archive_sha256",
                "snapshot_digest",
                "file_count",
                "byte_count",
                "role_selection_evidence",
                "role_selection_rationale",
            ],
            "repository_workspace_ingress": "EXISTING_REPOSITORY_WORKSPACE_MANAGER",
            "scan_snapshot_excludes_git_history": True,
            "scan_uses_local_acquired_snapshot_only": True,
            "snapshot_identity": {
                "authority": "SECURESCAN_REPOSITORY_MANIFEST",
                "byte_count_field": "total_bytes",
                "digest_field": "content_digest",
                "file_count_field": "file_count",
                "scan_identity_source": "VERIFIED_LOCAL_SOURCE_SNAPSHOT",
            },
        },
        "confidentiality": {
            "forbidden_report_fields": [
                "Secret",
                "Match",
                "raw Fingerprint",
                "credential hash",
                "raw stdout",
                "raw stderr",
                "host path",
                "temporary path",
                "repository checkout path",
                "provider validation response",
            ],
            "public_finding_identity": "STRUCTURAL_V0_4E_FINDING_ID",
            "raw_scanner_streams": "SENSITIVE_IN_MEMORY_ONLY",
            "sanitized_parser_output_only": True,
        },
        "evaluation": {
            "accuracy_scoring": {
                "authorized": False,
                "authorization_requirement": (
                    "SEPARATELY_FROZEN_COMPLETE_GROUND_TRUTH"
                ),
            },
            "operational_metrics": [
                "selected_file_count",
                "selected_byte_count",
                "execution_status",
                "return_code",
                "parsed_finding_count",
                "content_finding_count",
                "path_finding_count",
                "observed_rule_ids",
                "unique_structural_finding_count",
                "duplicate_structural_finding_count",
                "unexpected_execution_failure_count",
                "unexpected_parser_failure_count",
                "unexpected_confidentiality_failure_count",
            ],
            "repeatability": {
                "comparison": "CANONICAL_STRUCTURAL_FINDING_SET_EQUALITY",
                "fixed_inputs": [
                    "repository_snapshot_digest",
                    "binding_digest",
                    "config_sha256",
                    "ignore_sha256",
                ],
            },
        },
        "evaluation_id": GITLEAKS_REALWORLD_EVALUATION_ID,
        "evidence": {
            "f3b": {
                "commit": GITLEAKS_F3B_COMMIT,
                "report_sha256": GITLEAKS_F3B_REPORT_SHA256,
                "role": "CONTROLLED_ACCURACY_EVIDENCE",
                "tag": GITLEAKS_F3B_TAG,
            },
            "f4c": {
                "characterization_sha256": GITLEAKS_F4C_CHARACTERIZATION_SHA256,
                "commit": GITLEAKS_F4C_COMMIT,
                "role": "LIMITATION_AND_CLAIM_EVIDENCE",
                "tag": GITLEAKS_F4C_TAG,
            },
        },
        "failure_semantics": {
            "outcome": "NEVER_SUCCESSFUL_OR_CLEAN",
            "states": [
                "FAILED",
                "TIMED_OUT",
                "CANCELLED",
                "OUTPUT_LIMIT_EXCEEDED",
                "INVALID_EXIT",
                "MALFORMED_JSON",
                "PARSER_REJECTION",
                "CONFIDENTIALITY_VIOLATION",
            ],
        },
        "maturity": GITLEAKS_MATURITY,
        "purpose": "BOUNDED_OPERATIONAL_EVALUATION_WITHOUT_COMPLETE_GROUND_TRUTH",
        "repository_selection": {
            **pre_acquisition_repository_selection().canonical_data(),
            "one_primary_slot_per_repository": True,
            "pre_scan_role_selection": {
                "evidence_and_rationale_required": True,
                "required_before_gitleaks_execution": True,
            },
            "role_eligibility": _role_eligibility(),
        },
        "result_artifact": {
            "exists_in_f5a": False,
            "path": GITLEAKS_REALWORLD_RESULT_PATH,
        },
        "review": {
            "classifications": [item.value for item in GitleaksRealworldReviewClassification],
            "credential_usability_claim": False,
            "optional": True,
            "provider_validation": False,
            "raw_credential_persistence": False,
            "reviewed_observation_identity": "STRUCTURAL_V0_4E_FINDING_ID",
        },
        "scan_constraints": {
            "current_snapshot_only": True,
            "git_history": False,
            "provider_validation": False,
            "scanner_network_access": False,
            "scanner_output": "SENSITIVE_IN_MEMORY_ONLY",
            "source_execution": "PRODUCTION_SOURCE_EXECUTION_BRIDGE_ONLY",
        },
        "scanner": {
            "binding_artifact_sha256": GITLEAKS_BINDING_ARTIFACT_SHA256,
            "binding_digest": GITLEAKS_BINDING_DIGEST,
            "config_sha256": GITLEAKS_CONFIG_SHA256,
            "id": GITLEAKS_SCANNER_ID,
            "ignore_sha256": GITLEAKS_IGNORE_SHA256,
            "version": GITLEAKS_SCANNER_VERSION,
        },
        "schema_version": GITLEAKS_REALWORLD_CONTRACT_SCHEMA_VERSION,
    }


def gitleaks_realworld_contract_document() -> dict[str, object]:
    return _contract_document()


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
        raise GitleaksRealworldContractError from None
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
        raise GitleaksRealworldContractError from None
    if (
        not isinstance(value, dict)
        or canonical_gitleaks_realworld_contract(value) != payload
        or hashlib.sha256(payload).hexdigest() != expected_sha256
    ):
        raise GitleaksRealworldContractError
    return value


def _verify_frozen_inputs(repository_root: Path) -> None:
    f3b = _load_canonical_json(
        repository_root / GITLEAKS_F3B_REPORT_PATH,
        GITLEAKS_F3B_REPORT_SHA256,
    )
    f4c = _load_canonical_json(
        repository_root / GITLEAKS_F4C_CHARACTERIZATION_PATH,
        GITLEAKS_F4C_CHARACTERIZATION_SHA256,
    )
    _load_canonical_json(
        repository_root / GITLEAKS_BINDING_ARTIFACT_PATH,
        GITLEAKS_BINDING_ARTIFACT_SHA256,
    )
    for relative, expected in (
        (GITLEAKS_CONFIG_PATH, GITLEAKS_CONFIG_SHA256),
        (GITLEAKS_IGNORE_PATH, GITLEAKS_IGNORE_SHA256),
    ):
        if hashlib.sha256(_read_stable_file(repository_root / relative)).hexdigest() != expected:
            raise GitleaksRealworldContractError
    if (
        f3b.get("schema_version") != "securescan-gitleaks-benchmark-report-v1"
        or f3b.get("scanner_id") != GITLEAKS_SCANNER_ID
        or f3b.get("scanner_version") != GITLEAKS_SCANNER_VERSION
        or f3b.get("binding_digest") != GITLEAKS_BINDING_DIGEST
        or f4c.get("schema_version") != "securescan-gitleaks-characterization-v1"
        or f4c.get("characterization_id")
        != "securescan-gitleaks-v0.4f4-characterization-v1"
        or f4c.get("maturity") != GITLEAKS_MATURITY
    ):
        raise GitleaksRealworldContractError


def load_gitleaks_realworld_contract(path: Path) -> dict[str, object]:
    value = _load_canonical_json(path, GITLEAKS_REALWORLD_CONTRACT_SHA256)
    if value != _contract_document():
        raise GitleaksRealworldContractError
    return value


def verify_gitleaks_realworld_contract(repository_root: Path) -> dict[str, object]:
    if not isinstance(repository_root, Path) or not repository_root.is_absolute():
        raise GitleaksRealworldContractError
    _verify_frozen_inputs(repository_root)
    contract = load_gitleaks_realworld_contract(
        repository_root / GITLEAKS_REALWORLD_CONTRACT_PATH
    )
    return contract
