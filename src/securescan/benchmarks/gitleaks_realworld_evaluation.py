from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Final
from uuid import NAMESPACE_URL, uuid5

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.benchmarks.gitleaks_realworld_acquisition import (
    GITLEAKS_REALWORLD_ACQUIRED_MANIFEST_SHA256,
    load_gitleaks_realworld_acquired_manifest,
)
from securescan.benchmarks.gitleaks_realworld_acquisition_contract import (
    GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_PATH,
)
from securescan.benchmarks.gitleaks_realworld_contract import (
    GITLEAKS_BINDING_ARTIFACT_SHA256,
    GITLEAKS_CONFIG_SHA256,
    GITLEAKS_IGNORE_SHA256,
    GITLEAKS_MATURITY,
    GITLEAKS_REALWORLD_CONTRACT_SHA256,
    GITLEAKS_REALWORLD_EVALUATION_ID,
    GITLEAKS_REALWORLD_RESULT_PATH,
)
from securescan.domain.enums import ArtifactKind, JobStatus
from securescan.jobs.models import JobRecord
from securescan.scanners.gitleaks import (
    GITLEAKS_SCANNER_ID,
    GITLEAKS_SOURCE_ANALYZER_ID,
    GITLEAKS_VERSION,
    GitleaksDetectionKind,
    GitleaksExecutionResultEnvelope,
    GitleaksExecutionStatus,
    GitleaksParseResult,
    GitleaksSourceExecutionBridge,
    GitleaksSourceExecutionContextResolver,
    GitleaksSourceExecutionResolver,
    NormalizedGitleaksFinding,
    TrustedGitleaksBinding,
    build_gitleaks_finding_identities,
    create_default_gitleaks_binding,
    parse_gitleaks_execution_result,
)
from securescan.scanners.semgrep import (
    SourceExecutionEnvelope,
    SourceProjectionExecutionReference,
)
from securescan.source import (
    AnalysisCapability,
    PreparedSourceProjection,
    SourceExecutionContext,
    SourceExecutionSelectedFile,
    SourceProjectionManager,
)
from securescan.source.projection import (
    _VERIFICATION_LIMITS,
    _inventory_tree,
)
from securescan.workspaces import PreparedRepositoryWorkspace

GITLEAKS_REALWORLD_RUN_SCHEMA_VERSION: Final = (
    "securescan-gitleaks-realworld-result-v1"
)
GITLEAKS_REALWORLD_REPEATABILITY_SCHEMA_VERSION: Final = (
    "securescan-gitleaks-realworld-repeatability-v1"
)
GITLEAKS_REALWORLD_REPEATABILITY_PATH: Final = (
    "benchmarks/gitleaks/realworld/realworld-repeatability-v1.json"
)
GITLEAKS_REALWORLD_RESULT_SHA256: Final = (
    "33062f73834e348492349ce00b509f478ed5509b4b1b40183eba034be3a74313"
)
GITLEAKS_REALWORLD_RUN2_SHA256: Final = (
    "af6e9fce92c882b67392219c5a65e1805ed5511abef1cd5c476de1a555cfbaea"
)
GITLEAKS_REALWORLD_REPEATABILITY_SHA256: Final = (
    "8fde25f35da87d1e9abff97e087bf8bdb77116f622095b08e040278c21332303"
)
GITLEAKS_F5B3_COMMIT: Final = "618ce6c393208528842c200df3927cf8df81de22"
GITLEAKS_F5B3_TAG: Final = "source-v0.4F5B3-gitleaks-realworld-acquisition"

_EXECUTION_MODE = "production-source-current-snapshot"
_PURPOSE = "OPERATIONAL_GENERALIZATION_WITHOUT_COMPLETE_GROUND_TRUTH"
_FIXED_TIME = datetime(2066, 5, 12, 5, 12, 5, tzinfo=UTC)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_SLOT_IDS = tuple(f"RW{number:02d}" for number in range(1, 7))
_MAX_EVIDENCE_BYTES = 1024 * 1024
_FORBIDDEN_PUBLIC_KEYS = frozenset(
    {
        "Secret",
        "Match",
        "Fingerprint",
        "credential_hash",
        "raw_secret_content",
        "scanner_output",
        "stdout_bytes",
        "stderr_bytes",
        "host_path",
        "temporary_path",
    }
)


class GitleaksRealworldEvaluationError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Gitleaks real-world evaluation failed")


def _valid_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _canonical_json(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError):
        raise GitleaksRealworldEvaluationError from None


@dataclass(frozen=True, slots=True)
class GitleaksRealworldLocation:
    start_line: int
    end_line: int
    start_column: int | None
    end_column: int | None

    def __post_init__(self) -> None:
        if (
            type(self.start_line) is not int
            or type(self.end_line) is not int
            or not 1 <= self.start_line <= self.end_line <= 2_147_483_647
            or (self.start_column is None) is not (self.end_column is None)
            or any(
                value is not None
                and (type(value) is not int or not 1 <= value <= 2_147_483_647)
                for value in (self.start_column, self.end_column)
            )
            or (
                self.start_column is not None
                and self.end_column is not None
                and self.start_line == self.end_line
                and self.end_column < self.start_column
            )
        ):
            raise GitleaksRealworldEvaluationError

    def canonical_data(self) -> dict[str, int | None]:
        return {
            "end_column": self.end_column,
            "end_line": self.end_line,
            "start_column": self.start_column,
            "start_line": self.start_line,
        }


@dataclass(frozen=True, slots=True)
class GitleaksRealworldObservation:
    rule_id: str
    relative_path: str
    detection_kind: GitleaksDetectionKind
    location: GitleaksRealworldLocation | None
    finding_instance_id: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.rule_id, str)
            or not self.rule_id
            or not isinstance(self.relative_path, str)
            or not self.relative_path
            or self.relative_path.startswith("/")
            or "\\" in self.relative_path
            or any(part in {"", ".", ".."} for part in self.relative_path.split("/"))
            or not isinstance(self.detection_kind, GitleaksDetectionKind)
            or not _valid_sha256(self.finding_instance_id)
            or (
                self.detection_kind is GitleaksDetectionKind.PATH
                and self.location is not None
            )
            or (
                self.detection_kind is GitleaksDetectionKind.CONTENT
                and not isinstance(self.location, GitleaksRealworldLocation)
            )
        ):
            raise GitleaksRealworldEvaluationError

    def canonical_data(self) -> dict[str, object]:
        return {
            "detection_kind": self.detection_kind.value,
            "finding_instance_id": self.finding_instance_id,
            "location": None if self.location is None else self.location.canonical_data(),
            "relative_path": self.relative_path,
            "rule_id": self.rule_id,
        }

    def comparison_key(self) -> tuple[object, ...]:
        location = self.location
        return (
            self.rule_id,
            self.relative_path,
            self.detection_kind.value,
            None if location is None else location.start_line,
            None if location is None else location.end_line,
            None if location is None else location.start_column,
            None if location is None else location.end_column,
            self.finding_instance_id,
        )


def _observation_sort_key(
    observation: GitleaksRealworldObservation,
) -> tuple[object, ...]:
    return observation.comparison_key()


@dataclass(frozen=True, slots=True)
class GitleaksRealworldRepositoryResult:
    slot_id: str
    repository_id: str
    snapshot_digest: str
    selected_file_count: int
    selected_byte_count: int
    execution_status: GitleaksExecutionStatus
    return_code: int
    parsed_finding_count: int
    content_finding_count: int
    path_finding_count: int
    observed_rule_ids: tuple[str, ...]
    unique_structural_finding_count: int
    duplicate_structural_finding_count: int
    observations: tuple[GitleaksRealworldObservation, ...]

    def __post_init__(self) -> None:
        unique_ids = {observation.finding_instance_id for observation in self.observations}
        if (
            self.slot_id not in _SLOT_IDS
            or not isinstance(self.repository_id, str)
            or not self.repository_id
            or not _valid_sha256(self.snapshot_digest)
            or type(self.selected_file_count) is not int
            or self.selected_file_count < 1
            or type(self.selected_byte_count) is not int
            or self.selected_byte_count < 0
            or (
                self.execution_status
                is GitleaksExecutionStatus.COMPLETED_NO_FINDINGS
                and self.return_code != 0
            )
            or (
                self.execution_status
                is GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS
                and self.return_code != 1
            )
            or self.execution_status
            not in {
                GitleaksExecutionStatus.COMPLETED_NO_FINDINGS,
                GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS,
            }
            or any(
                type(value) is not int or value < 0
                for value in (
                    self.parsed_finding_count,
                    self.content_finding_count,
                    self.path_finding_count,
                    self.unique_structural_finding_count,
                    self.duplicate_structural_finding_count,
                )
            )
            or not isinstance(self.observations, tuple)
            or any(
                not isinstance(observation, GitleaksRealworldObservation)
                for observation in self.observations
            )
            or self.observations
            != tuple(sorted(self.observations, key=_observation_sort_key))
            or self.parsed_finding_count != len(self.observations)
            or self.content_finding_count
            != sum(
                observation.detection_kind is GitleaksDetectionKind.CONTENT
                for observation in self.observations
            )
            or self.path_finding_count
            != sum(
                observation.detection_kind is GitleaksDetectionKind.PATH
                for observation in self.observations
            )
            or self.content_finding_count + self.path_finding_count
            != self.parsed_finding_count
            or self.observed_rule_ids
            != tuple(sorted({observation.rule_id for observation in self.observations}))
            or self.unique_structural_finding_count != len(unique_ids)
            or self.duplicate_structural_finding_count
            != self.parsed_finding_count - len(unique_ids)
            or (
                self.execution_status
                is GitleaksExecutionStatus.COMPLETED_NO_FINDINGS
                and self.parsed_finding_count != 0
            )
            or (
                self.execution_status
                is GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS
                and self.parsed_finding_count == 0
            )
        ):
            raise GitleaksRealworldEvaluationError

    def canonical_data(self) -> dict[str, object]:
        return {
            "content_finding_count": self.content_finding_count,
            "duplicate_structural_finding_count": self.duplicate_structural_finding_count,
            "execution_status": self.execution_status.value,
            "observations": [observation.canonical_data() for observation in self.observations],
            "observed_rule_ids": list(self.observed_rule_ids),
            "parsed_finding_count": self.parsed_finding_count,
            "path_finding_count": self.path_finding_count,
            "repository_id": self.repository_id,
            "return_code": self.return_code,
            "selected_byte_count": self.selected_byte_count,
            "selected_file_count": self.selected_file_count,
            "slot_id": self.slot_id,
            "snapshot_digest": self.snapshot_digest,
            "unique_structural_finding_count": self.unique_structural_finding_count,
        }


@dataclass(frozen=True, slots=True)
class GitleaksRealworldRunReport:
    run_number: int
    repositories: tuple[GitleaksRealworldRepositoryResult, ...]

    def __post_init__(self) -> None:
        if (
            self.run_number not in {1, 2}
            or not isinstance(self.repositories, tuple)
            or len(self.repositories) != 6
            or any(
                not isinstance(repository, GitleaksRealworldRepositoryResult)
                for repository in self.repositories
            )
            or tuple(repository.slot_id for repository in self.repositories) != _SLOT_IDS
            or len({repository.repository_id for repository in self.repositories}) != 6
            or len({repository.snapshot_digest for repository in self.repositories}) != 6
        ):
            raise GitleaksRealworldEvaluationError

    def canonical_data(self) -> dict[str, object]:
        self.__post_init__()
        observations = tuple(
            (repository.repository_id, observation)
            for repository in self.repositories
            for observation in repository.observations
        )
        unique = {
            (repository_id, observation.finding_instance_id)
            for repository_id, observation in observations
        }
        parsed = len(observations)
        content = sum(
            observation.detection_kind is GitleaksDetectionKind.CONTENT
            for _repository_id, observation in observations
        )
        return {
            "acquired_manifest_sha256": GITLEAKS_REALWORLD_ACQUIRED_MANIFEST_SHA256,
            "aggregate": {
                "content_finding_count": content,
                "duplicate_structural_finding_count": parsed - len(unique),
                "observed_rule_ids": sorted(
                    {observation.rule_id for _repository_id, observation in observations}
                ),
                "parsed_finding_count": parsed,
                "path_finding_count": parsed - content,
                "repository_count": len(self.repositories),
                "selected_byte_count": sum(
                    repository.selected_byte_count for repository in self.repositories
                ),
                "selected_file_count": sum(
                    repository.selected_file_count for repository in self.repositories
                ),
                "unique_structural_finding_count": len(unique),
            },
            "confidentiality": {
                "credential_validation_performed": False,
                "secret_derived_public_identity": False,
                "structural_evidence_only": True,
            },
            "evaluation_id": GITLEAKS_REALWORLD_EVALUATION_ID,
            "execution_mode": _EXECUTION_MODE,
            "f5b3_commit": GITLEAKS_F5B3_COMMIT,
            "f5b3_tag": GITLEAKS_F5B3_TAG,
            "maturity": GITLEAKS_MATURITY,
            "purpose": _PURPOSE,
            "repositories": [repository.canonical_data() for repository in self.repositories],
            "run_number": self.run_number,
            "scanner": {
                "binding_artifact_sha256": GITLEAKS_BINDING_ARTIFACT_SHA256,
                "binding_digest": self._binding_digest(),
                "config_sha256": GITLEAKS_CONFIG_SHA256,
                "id": GITLEAKS_SCANNER_ID,
                "ignore_sha256": GITLEAKS_IGNORE_SHA256,
                "version": GITLEAKS_VERSION,
            },
            "schema_version": GITLEAKS_REALWORLD_RUN_SCHEMA_VERSION,
        }

    @staticmethod
    def _binding_digest() -> str:
        from securescan.benchmarks.gitleaks_contract import GITLEAKS_BINDING_DIGEST

        return GITLEAKS_BINDING_DIGEST

    def canonical_json(self) -> bytes:
        payload = _canonical_json(self.canonical_data())
        _validate_public_payload(payload, self.canonical_data())
        return payload


@dataclass(frozen=True, slots=True)
class GitleaksRealworldRepositoryRepeatability:
    slot_id: str
    repository_id: str
    run1_structural_count: int
    run2_structural_count: int
    run1_unique_structural_id_count: int
    run2_unique_structural_id_count: int
    missing_from_run2: int
    new_in_run2: int
    canonical_set_equal: bool

    def __post_init__(self) -> None:
        if (
            self.slot_id not in (*_SLOT_IDS, "RW00")
            or not isinstance(self.repository_id, str)
            or not self.repository_id
            or any(
                type(value) is not int or value < 0
                for value in (
                    self.run1_structural_count,
                    self.run2_structural_count,
                    self.run1_unique_structural_id_count,
                    self.run2_unique_structural_id_count,
                    self.missing_from_run2,
                    self.new_in_run2,
                )
            )
            or type(self.canonical_set_equal) is not bool
            or self.canonical_set_equal
            is not (self.missing_from_run2 == 0 and self.new_in_run2 == 0)
        ):
            raise GitleaksRealworldEvaluationError

    def canonical_data(self) -> dict[str, object]:
        return {
            "canonical_set_equal": self.canonical_set_equal,
            "missing_from_run2": self.missing_from_run2,
            "new_in_run2": self.new_in_run2,
            "repository_id": self.repository_id,
            "run1_structural_count": self.run1_structural_count,
            "run1_unique_structural_id_count": self.run1_unique_structural_id_count,
            "run2_structural_count": self.run2_structural_count,
            "run2_unique_structural_id_count": self.run2_unique_structural_id_count,
            "slot_id": self.slot_id,
        }


@dataclass(frozen=True, slots=True)
class GitleaksRealworldRepeatabilityReport:
    run1_sha256: str
    run2: GitleaksRealworldRunReport
    repositories: tuple[GitleaksRealworldRepositoryRepeatability, ...]
    aggregate: GitleaksRealworldRepositoryRepeatability

    def __post_init__(self) -> None:
        if (
            not _valid_sha256(self.run1_sha256)
            or not isinstance(self.run2, GitleaksRealworldRunReport)
            or self.run2.run_number != 2
            or not isinstance(self.repositories, tuple)
            or len(self.repositories) != 6
            or tuple(repository.slot_id for repository in self.repositories) != _SLOT_IDS
            or not isinstance(self.aggregate, GitleaksRealworldRepositoryRepeatability)
            or self.aggregate.slot_id != "RW00"
        ):
            raise GitleaksRealworldEvaluationError

    def canonical_data(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "aggregate": self.aggregate.canonical_data(),
            "evaluation_id": GITLEAKS_REALWORLD_EVALUATION_ID,
            "maturity": GITLEAKS_MATURITY,
            "purpose": "CANONICAL_STRUCTURAL_FINDING_SET_REPEATABILITY",
            "repositories": [repository.canonical_data() for repository in self.repositories],
            "run1_sha256": self.run1_sha256,
            "run2": self.run2.canonical_data(),
            "schema_version": GITLEAKS_REALWORLD_REPEATABILITY_SCHEMA_VERSION,
        }

    def canonical_json(self) -> bytes:
        payload = _canonical_json(self.canonical_data())
        _validate_public_payload(payload, self.canonical_data())
        return payload


def _stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_frozen_evidence(path: Path, expected_sha256: str) -> bytes:
    descriptor = -1
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 1
            or before.st_size > _MAX_EVIDENCE_BYTES
        ):
            raise GitleaksRealworldEvaluationError
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _stat_identity(opened) != _stat_identity(before)
        ):
            raise GitleaksRealworldEvaluationError
        content = bytearray()
        while len(content) <= _MAX_EVIDENCE_BYTES:
            chunk = os.read(
                descriptor,
                min(64 * 1024, _MAX_EVIDENCE_BYTES + 1 - len(content)),
            )
            if not chunk:
                break
            content.extend(chunk)
        after_open = os.fstat(descriptor)
        after_path = path.lstat()
        identities = {
            _stat_identity(before),
            _stat_identity(opened),
            _stat_identity(after_open),
            _stat_identity(after_path),
        }
        payload = bytes(content)
        if (
            len(identities) != 1
            or len(payload) != before.st_size
            or len(payload) > _MAX_EVIDENCE_BYTES
            or hashlib.sha256(payload).hexdigest() != expected_sha256
        ):
            raise GitleaksRealworldEvaluationError
        return payload
    except GitleaksRealworldEvaluationError:
        raise
    except Exception:
        raise GitleaksRealworldEvaluationError from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _reject_evidence_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError
        document[key] = value
    return document


def _reject_evidence_nonfinite(_value: str) -> None:
    raise ValueError


def _decode_frozen_evidence(payload: bytes) -> dict[str, object]:
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_evidence_duplicate_keys,
            parse_constant=_reject_evidence_nonfinite,
        )
    except (UnicodeDecodeError, ValueError):
        raise GitleaksRealworldEvaluationError from None
    if not isinstance(document, dict) or _canonical_json(document) != payload:
        raise GitleaksRealworldEvaluationError
    return document


def _exact_mapping(value: object, names: frozenset[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != names:
        raise GitleaksRealworldEvaluationError
    return value


def _exact_list(value: object) -> list[object]:
    if not isinstance(value, list):
        raise GitleaksRealworldEvaluationError
    return value


def _location_from_evidence(value: object) -> GitleaksRealworldLocation | None:
    if value is None:
        return None
    row = _exact_mapping(
        value,
        frozenset({"start_line", "end_line", "start_column", "end_column"}),
    )
    return GitleaksRealworldLocation(
        start_line=row["start_line"],  # type: ignore[arg-type]
        end_line=row["end_line"],  # type: ignore[arg-type]
        start_column=row["start_column"],  # type: ignore[arg-type]
        end_column=row["end_column"],  # type: ignore[arg-type]
    )


def _observation_from_evidence(value: object) -> GitleaksRealworldObservation:
    row = _exact_mapping(
        value,
        frozenset(
            {
                "detection_kind",
                "finding_instance_id",
                "location",
                "relative_path",
                "rule_id",
            }
        ),
    )
    return GitleaksRealworldObservation(
        rule_id=row["rule_id"],  # type: ignore[arg-type]
        relative_path=row["relative_path"],  # type: ignore[arg-type]
        detection_kind=GitleaksDetectionKind(row["detection_kind"]),  # type: ignore[arg-type]
        location=_location_from_evidence(row["location"]),
        finding_instance_id=row["finding_instance_id"],  # type: ignore[arg-type]
    )


def _repository_from_evidence(
    value: object,
) -> GitleaksRealworldRepositoryResult:
    row = _exact_mapping(
        value,
        frozenset(
            {
                "content_finding_count",
                "duplicate_structural_finding_count",
                "execution_status",
                "observations",
                "observed_rule_ids",
                "parsed_finding_count",
                "path_finding_count",
                "repository_id",
                "return_code",
                "selected_byte_count",
                "selected_file_count",
                "slot_id",
                "snapshot_digest",
                "unique_structural_finding_count",
            }
        ),
    )
    return GitleaksRealworldRepositoryResult(
        slot_id=row["slot_id"],  # type: ignore[arg-type]
        repository_id=row["repository_id"],  # type: ignore[arg-type]
        snapshot_digest=row["snapshot_digest"],  # type: ignore[arg-type]
        selected_file_count=row["selected_file_count"],  # type: ignore[arg-type]
        selected_byte_count=row["selected_byte_count"],  # type: ignore[arg-type]
        execution_status=GitleaksExecutionStatus(row["execution_status"]),  # type: ignore[arg-type]
        return_code=row["return_code"],  # type: ignore[arg-type]
        parsed_finding_count=row["parsed_finding_count"],  # type: ignore[arg-type]
        content_finding_count=row["content_finding_count"],  # type: ignore[arg-type]
        path_finding_count=row["path_finding_count"],  # type: ignore[arg-type]
        observed_rule_ids=tuple(  # type: ignore[arg-type]
            _exact_list(row["observed_rule_ids"])
        ),
        unique_structural_finding_count=row[  # type: ignore[arg-type]
            "unique_structural_finding_count"
        ],
        duplicate_structural_finding_count=row[  # type: ignore[arg-type]
            "duplicate_structural_finding_count"
        ],
        observations=tuple(
            _observation_from_evidence(item)
            for item in _exact_list(row["observations"])
        ),
    )


def _run_from_evidence(value: object) -> GitleaksRealworldRunReport:
    row = _exact_mapping(
        value,
        frozenset(
            {
                "acquired_manifest_sha256",
                "aggregate",
                "confidentiality",
                "evaluation_id",
                "execution_mode",
                "f5b3_commit",
                "f5b3_tag",
                "maturity",
                "purpose",
                "repositories",
                "run_number",
                "scanner",
                "schema_version",
            }
        ),
    )
    return GitleaksRealworldRunReport(
        run_number=row["run_number"],  # type: ignore[arg-type]
        repositories=tuple(
            _repository_from_evidence(item)
            for item in _exact_list(row["repositories"])
        ),
    )


def _comparison_from_evidence(
    value: object,
) -> GitleaksRealworldRepositoryRepeatability:
    row = _exact_mapping(
        value,
        frozenset(
            {
                "canonical_set_equal",
                "missing_from_run2",
                "new_in_run2",
                "repository_id",
                "run1_structural_count",
                "run1_unique_structural_id_count",
                "run2_structural_count",
                "run2_unique_structural_id_count",
                "slot_id",
            }
        ),
    )
    return GitleaksRealworldRepositoryRepeatability(
        slot_id=row["slot_id"],  # type: ignore[arg-type]
        repository_id=row["repository_id"],  # type: ignore[arg-type]
        run1_structural_count=row["run1_structural_count"],  # type: ignore[arg-type]
        run2_structural_count=row["run2_structural_count"],  # type: ignore[arg-type]
        run1_unique_structural_id_count=row[  # type: ignore[arg-type]
            "run1_unique_structural_id_count"
        ],
        run2_unique_structural_id_count=row[  # type: ignore[arg-type]
            "run2_unique_structural_id_count"
        ],
        missing_from_run2=row["missing_from_run2"],  # type: ignore[arg-type]
        new_in_run2=row["new_in_run2"],  # type: ignore[arg-type]
        canonical_set_equal=row["canonical_set_equal"],  # type: ignore[arg-type]
    )


def _repeatability_from_evidence(
    value: object,
) -> GitleaksRealworldRepeatabilityReport:
    row = _exact_mapping(
        value,
        frozenset(
            {
                "aggregate",
                "evaluation_id",
                "maturity",
                "purpose",
                "repositories",
                "run1_sha256",
                "run2",
                "schema_version",
            }
        ),
    )
    return GitleaksRealworldRepeatabilityReport(
        run1_sha256=row["run1_sha256"],  # type: ignore[arg-type]
        run2=_run_from_evidence(row["run2"]),
        repositories=tuple(
            _comparison_from_evidence(item)
            for item in _exact_list(row["repositories"])
        ),
        aggregate=_comparison_from_evidence(row["aggregate"]),
    )


def verify_gitleaks_realworld_evidence(
    repository_root: Path,
) -> tuple[GitleaksRealworldRunReport, GitleaksRealworldRepeatabilityReport]:
    if not isinstance(repository_root, Path) or not repository_root.is_absolute():
        raise GitleaksRealworldEvaluationError
    try:
        result_payload = _read_frozen_evidence(
            repository_root / GITLEAKS_REALWORLD_RESULT_PATH,
            GITLEAKS_REALWORLD_RESULT_SHA256,
        )
        repeatability_payload = _read_frozen_evidence(
            repository_root / GITLEAKS_REALWORLD_REPEATABILITY_PATH,
            GITLEAKS_REALWORLD_REPEATABILITY_SHA256,
        )
        result = _run_from_evidence(_decode_frozen_evidence(result_payload))
        repeatability = _repeatability_from_evidence(
            _decode_frozen_evidence(repeatability_payload)
        )
        if (
            result.run_number != 1
            or result.canonical_json() != result_payload
            or repeatability.canonical_json() != repeatability_payload
            or repeatability.run1_sha256 != GITLEAKS_REALWORLD_RESULT_SHA256
            or hashlib.sha256(repeatability.run2.canonical_json()).hexdigest()
            != GITLEAKS_REALWORLD_RUN2_SHA256
            or any(
                comparison.missing_from_run2 != 0
                or comparison.new_in_run2 != 0
                or not comparison.canonical_set_equal
                for comparison in (*repeatability.repositories, repeatability.aggregate)
            )
        ):
            raise GitleaksRealworldEvaluationError
        return result, repeatability
    except GitleaksRealworldEvaluationError:
        raise
    except Exception:
        raise GitleaksRealworldEvaluationError from None


def _validate_public_payload(payload: bytes, document: object) -> None:
    def keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value) | set().union(*(keys(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(keys(item) for item in value)) if value else set()
        return set()

    if keys(document) & _FORBIDDEN_PUBLIC_KEYS or any(
        forbidden in payload
        for forbidden in (
            b'"Secret"',
            b'"Match"',
            b'"Fingerprint"',
            b"credential_hash",
            b"raw_secret_content",
            b"stdout_bytes",
            b"stderr_bytes",
            b"/tmp/",
        )
    ):
        raise GitleaksRealworldEvaluationError


def _location(finding: NormalizedGitleaksFinding) -> GitleaksRealworldLocation | None:
    if finding.detection_kind is GitleaksDetectionKind.PATH:
        return None
    if finding.start_line is None or finding.end_line is None:
        raise GitleaksRealworldEvaluationError
    return GitleaksRealworldLocation(
        start_line=finding.start_line,
        end_line=finding.end_line,
        start_column=finding.start_column,
        end_column=finding.end_column,
    )


def _parse_completed_execution(
    result: GitleaksExecutionResultEnvelope,
    projection: PreparedSourceProjection,
) -> GitleaksParseResult:
    try:
        return parse_gitleaks_execution_result(result, projection)
    except Exception:
        raise GitleaksRealworldEvaluationError from None


def evaluate_gitleaks_realworld_repository(
    slot: dict[str, object],
    parse_result: GitleaksParseResult,
    *,
    execution_status: GitleaksExecutionStatus,
    return_code: int,
) -> GitleaksRealworldRepositoryResult:
    try:
        if (
            not isinstance(slot, dict)
            or not isinstance(parse_result, GitleaksParseResult)
            or parse_result.scanner_id != GITLEAKS_SCANNER_ID
            or parse_result.scanner_version != GITLEAKS_VERSION
            or parse_result.projection_digest != slot["snapshot_digest"]
            or (
                execution_status
                is GitleaksExecutionStatus.COMPLETED_NO_FINDINGS
                and return_code != 0
            )
            or (
                execution_status
                is GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS
                and return_code != 1
            )
            or execution_status
            not in {
                GitleaksExecutionStatus.COMPLETED_NO_FINDINGS,
                GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS,
            }
        ):
            raise GitleaksRealworldEvaluationError
        identities = build_gitleaks_finding_identities(parse_result.findings)
        observations = tuple(
            sorted(
                (
                    GitleaksRealworldObservation(
                        rule_id=finding.rule_id,
                        relative_path=finding.file_path,
                        detection_kind=finding.detection_kind,
                        location=_location(finding),
                        finding_instance_id=identity.finding_instance_id,
                    )
                    for finding, identity in zip(
                        parse_result.findings,
                        identities,
                        strict=True,
                    )
                ),
                key=_observation_sort_key,
            )
        )
        unique = {observation.finding_instance_id for observation in observations}
        return GitleaksRealworldRepositoryResult(
            slot_id=str(slot["slot_id"]),
            repository_id=str(slot["repository_id"]),
            snapshot_digest=str(slot["snapshot_digest"]),
            selected_file_count=int(slot["file_count"]),
            selected_byte_count=int(slot["byte_count"]),
            execution_status=execution_status,
            return_code=return_code,
            parsed_finding_count=len(observations),
            content_finding_count=sum(
                observation.detection_kind is GitleaksDetectionKind.CONTENT
                for observation in observations
            ),
            path_finding_count=sum(
                observation.detection_kind is GitleaksDetectionKind.PATH
                for observation in observations
            ),
            observed_rule_ids=tuple(sorted({observation.rule_id for observation in observations})),
            unique_structural_finding_count=len(unique),
            duplicate_structural_finding_count=len(observations) - len(unique),
            observations=observations,
        )
    except GitleaksRealworldEvaluationError:
        raise
    except Exception:
        raise GitleaksRealworldEvaluationError from None


def compare_gitleaks_realworld_runs(
    run1: GitleaksRealworldRunReport,
    run2: GitleaksRealworldRunReport,
) -> GitleaksRealworldRepeatabilityReport:
    if run1.run_number != 1 or run2.run_number != 2:
        raise GitleaksRealworldEvaluationError

    def comparison(
        first: GitleaksRealworldRepositoryResult,
        second: GitleaksRealworldRepositoryResult,
    ) -> GitleaksRealworldRepositoryRepeatability:
        if (
            first.slot_id != second.slot_id
            or first.repository_id != second.repository_id
            or first.snapshot_digest != second.snapshot_digest
            or first.selected_file_count != second.selected_file_count
            or first.selected_byte_count != second.selected_byte_count
        ):
            raise GitleaksRealworldEvaluationError
        first_set = {observation.comparison_key() for observation in first.observations}
        second_set = {observation.comparison_key() for observation in second.observations}
        return GitleaksRealworldRepositoryRepeatability(
            slot_id=first.slot_id,
            repository_id=first.repository_id,
            run1_structural_count=first.parsed_finding_count,
            run2_structural_count=second.parsed_finding_count,
            run1_unique_structural_id_count=len(first_set),
            run2_unique_structural_id_count=len(second_set),
            missing_from_run2=len(first_set - second_set),
            new_in_run2=len(second_set - first_set),
            canonical_set_equal=first_set == second_set,
        )

    repositories = tuple(
        comparison(first, second)
        for first, second in zip(run1.repositories, run2.repositories, strict=True)
    )
    first_aggregate = {
        (repository.repository_id, *observation.comparison_key())
        for repository in run1.repositories
        for observation in repository.observations
    }
    second_aggregate = {
        (repository.repository_id, *observation.comparison_key())
        for repository in run2.repositories
        for observation in repository.observations
    }
    aggregate = GitleaksRealworldRepositoryRepeatability(
        slot_id="RW00",
        repository_id="all-six-repositories",
        run1_structural_count=sum(
            repository.parsed_finding_count for repository in run1.repositories
        ),
        run2_structural_count=sum(
            repository.parsed_finding_count for repository in run2.repositories
        ),
        run1_unique_structural_id_count=len(first_aggregate),
        run2_unique_structural_id_count=len(second_aggregate),
        missing_from_run2=len(first_aggregate - second_aggregate),
        new_in_run2=len(second_aggregate - first_aggregate),
        canonical_set_equal=first_aggregate == second_aggregate,
    )
    return GitleaksRealworldRepeatabilityReport(
        run1_sha256=hashlib.sha256(run1.canonical_json()).hexdigest(),
        run2=run2,
        repositories=repositories,
        aggregate=aggregate,
    )


def _manifest_matches_slot(
    workspace: PreparedRepositoryWorkspace,
    slot: dict[str, object],
) -> bool:
    manifest = workspace.manifest
    return (
        manifest.content_digest == slot.get("snapshot_digest")
        and manifest.file_count == slot.get("file_count")
        and manifest.total_bytes == slot.get("byte_count")
    )


def _load_acquired_slots(repository_root: Path) -> tuple[dict[str, object], ...]:
    path = repository_root / GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_PATH
    document = load_gitleaks_realworld_acquired_manifest(path)
    if (
        document.get("acquisition_state") != "ACQUIRED"
        or document.get("maturity") != GITLEAKS_MATURITY
    ):
        raise GitleaksRealworldEvaluationError
    slots = document.get("repository_slots")
    if not isinstance(slots, list) or len(slots) != 6:
        raise GitleaksRealworldEvaluationError
    return tuple(slots)


def _prepare_verified_workspaces(
    repository_root: Path,
    retained_workspace_root: Path,
    slots: tuple[dict[str, object], ...],
) -> tuple[PreparedRepositoryWorkspace, ...]:
    try:
        retained = retained_workspace_root.resolve(strict=True)
        repository = repository_root.resolve(strict=True)
        if (
            not retained.is_dir()
            or retained.is_symlink()
            or retained == repository
            or retained.is_relative_to(repository)
            or repository.is_relative_to(retained)
        ):
            raise GitleaksRealworldEvaluationError
        children = tuple(sorted(retained.iterdir(), key=lambda path: path.name))
        if len(children) != 6:
            raise GitleaksRealworldEvaluationError
        by_digest = {str(slot["snapshot_digest"]): slot for slot in slots}
        prepared_by_digest: dict[str, PreparedRepositoryWorkspace] = {}
        for child in children:
            if child.is_symlink() or not child.is_dir() or not child.name.startswith(
                "securescan-workspace-"
            ):
                raise GitleaksRealworldEvaluationError
            source = child / "source"
            output = child / "output"
            inventory = _inventory_tree(
                source,
                _VERIFICATION_LIMITS,
                require_read_only=True,
            )
            workspace = PreparedRepositoryWorkspace(
                workspace_id=child.name,
                root_directory=child,
                source_directory=source,
                output_directory=output,
                manifest=inventory.manifest,
            )
            digest = workspace.manifest.content_digest
            slot = by_digest.get(digest)
            if slot is None or digest in prepared_by_digest or not _manifest_matches_slot(
                workspace, slot
            ):
                raise GitleaksRealworldEvaluationError
            prepared_by_digest[digest] = workspace
        if set(prepared_by_digest) != set(by_digest):
            raise GitleaksRealworldEvaluationError
        return tuple(
            prepared_by_digest[str(slot["snapshot_digest"])] for slot in slots
        )
    except GitleaksRealworldEvaluationError:
        raise
    except Exception:
        raise GitleaksRealworldEvaluationError from None


def _fixed_uuid(label: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"securescan:gitleaks:realworld:{label}"))


def _build_job(
    slot_id: str,
    run_number: int,
    envelope: SourceExecutionEnvelope,
) -> JobRecord:
    job_id = _fixed_uuid(f"run-{run_number}:{slot_id}:job")
    return JobRecord(
        id=job_id,
        run_id=_fixed_uuid(f"run-{run_number}:{slot_id}:source-run"),
        adapter_id=GITLEAKS_SCANNER_ID,
        status=JobStatus.RUNNING,
        priority=100,
        attempt_count=1,
        max_attempts=1,
        available_at=_FIXED_TIME,
        leased_by="gitleaks-realworld",
        lease_expires_at=_FIXED_TIME,
        heartbeat_at=_FIXED_TIME,
        cancel_requested=False,
        idempotency_key=hashlib.sha256(
            f"gitleaks-realworld:{run_number}:{slot_id}".encode()
        ).hexdigest(),
        payload_json=envelope.payload_json(),
        last_error=None,
        created_at=_FIXED_TIME,
        updated_at=_FIXED_TIME,
        started_at=_FIXED_TIME,
        finished_at=None,
        lease_token=_fixed_uuid(f"run-{run_number}:{slot_id}:lease"),
    )


def _execute_repository(
    slot: dict[str, object],
    workspace: PreparedRepositoryWorkspace,
    *,
    run_number: int,
    binding: TrustedGitleaksBinding,
    temporary_root: Path,
    process_executor: object | None,
) -> GitleaksRealworldRepositoryResult:
    if not _manifest_matches_slot(workspace, slot):
        raise GitleaksRealworldEvaluationError
    slot_id = str(slot["slot_id"])
    projection_manager = SourceProjectionManager.initialize_base_directory(
        temporary_root / f"projections-run-{run_number}-{slot_id.lower()}"
    )
    projection: PreparedSourceProjection | None = None
    context = SourceExecutionContext(
        source_run_id=_fixed_uuid(f"run-{run_number}:{slot_id}:source-run"),
        job_id=_fixed_uuid(f"run-{run_number}:{slot_id}:job"),
        repository_digest=workspace.manifest.content_digest,
        profile_digest=GITLEAKS_REALWORLD_ACQUIRED_MANIFEST_SHA256,
        plan_digest=GITLEAKS_REALWORLD_CONTRACT_SHA256,
        source_analyzer_id=GITLEAKS_SOURCE_ANALYZER_ID,
        capability=AnalysisCapability.SECRET_DETECTION,
        component_id=None,
        selected_files=tuple(
            SourceExecutionSelectedFile(entry=replace(entry), component_id=None)
            for entry in workspace.manifest.entries
        ),
        binding_digest=binding.binding_digest(),
        core_adapter_id=GITLEAKS_SCANNER_ID,
    )
    try:
        projection = projection_manager.build_projection(workspace, context)
        store = ContentAddressedArtifactStore(
            temporary_root / f"artifacts-run-{run_number}-{slot_id.lower()}"
        )
        artifact = store.put(
            context.canonical_json(),
            kind=ArtifactKind.SOURCE_EXECUTION_CONTEXT,
            media_type="application/json",
            sanitized=False,
        )
        envelope = SourceExecutionEnvelope(
            artifact_sha256=artifact.sha256,
            artifact_size_bytes=artifact.size_bytes,
            context_digest=context.context_digest(),
            projection_reference=SourceProjectionExecutionReference(
                projection_id=projection.projection_id,
                context_digest=projection.context_digest,
                projection_digest=projection.projection_digest,
            ),
        )
        resolver = GitleaksSourceExecutionResolver(
            GitleaksSourceExecutionContextResolver(store, binding),
            projection_manager,
        )
        bridge = GitleaksSourceExecutionBridge(resolver, binding, process_executor)
        with bridge.start(_build_job(slot_id, run_number, envelope)) as handle:
            result = handle.wait()
            if result is None:
                result = handle.poll()
        if not isinstance(result, GitleaksExecutionResultEnvelope):
            raise GitleaksRealworldEvaluationError
        parse_result = _parse_completed_execution(result, projection)
        return evaluate_gitleaks_realworld_repository(
            slot,
            parse_result,
            execution_status=result.execution_status,
            return_code=result.return_code,
        )
    except GitleaksRealworldEvaluationError:
        raise
    except Exception:
        raise GitleaksRealworldEvaluationError from None
    finally:
        if projection is not None:
            with suppress(Exception):
                projection_manager.cleanup_projection(projection)


def _execute_run(
    slots: tuple[dict[str, object], ...],
    workspaces: tuple[PreparedRepositoryWorkspace, ...],
    *,
    run_number: int,
    binding: TrustedGitleaksBinding,
    temporary_root: Path,
    process_executor: object | None,
) -> GitleaksRealworldRunReport:
    if len(slots) != 6 or len(workspaces) != 6:
        raise GitleaksRealworldEvaluationError
    return GitleaksRealworldRunReport(
        run_number=run_number,
        repositories=tuple(
            _execute_repository(
                slot,
                workspace,
                run_number=run_number,
                binding=binding,
                temporary_root=temporary_root,
                process_executor=process_executor,
            )
            for slot, workspace in zip(slots, workspaces, strict=True)
        ),
    )


def _require_absent(path: Path) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        raise GitleaksRealworldEvaluationError from None
    raise GitleaksRealworldEvaluationError


def _atomic_record(path: Path, payload: bytes) -> None:
    staging: Path | None = None
    try:
        _require_absent(path)
        metadata = path.parent.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise GitleaksRealworldEvaluationError
        descriptor, name = tempfile.mkstemp(prefix=f".{path.stem}-", dir=path.parent)
        staging = Path(name)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(staging, 0o644)
        os.link(staging, path, follow_symlinks=False)
    except GitleaksRealworldEvaluationError:
        raise
    except Exception:
        raise GitleaksRealworldEvaluationError from None
    finally:
        if staging is not None:
            with suppress(OSError):
                staging.unlink(missing_ok=True)


def run_and_record_gitleaks_realworld(
    repository_root: Path,
    executable_path: Path,
    retained_workspace_root: Path,
    *,
    process_executor: object | None = None,
) -> tuple[GitleaksRealworldRunReport, GitleaksRealworldRepeatabilityReport]:
    if (
        not isinstance(repository_root, Path)
        or not repository_root.is_absolute()
        or not isinstance(executable_path, Path)
        or not executable_path.is_absolute()
        or not isinstance(retained_workspace_root, Path)
        or not retained_workspace_root.is_absolute()
    ):
        raise GitleaksRealworldEvaluationError
    result_path = repository_root / GITLEAKS_REALWORLD_RESULT_PATH
    repeatability_path = repository_root / GITLEAKS_REALWORLD_REPEATABILITY_PATH
    _require_absent(result_path)
    _require_absent(repeatability_path)
    slots = _load_acquired_slots(repository_root)
    try:
        binding = create_default_gitleaks_binding(executable_path)
        if binding.binding_digest() != GitleaksRealworldRunReport._binding_digest():
            raise GitleaksRealworldEvaluationError
        with tempfile.TemporaryDirectory(
            prefix="securescan-gitleaks-realworld-"
        ) as temporary_name:
            temporary_root = Path(temporary_name).resolve()
            if temporary_root.is_relative_to(repository_root):
                raise GitleaksRealworldEvaluationError
            workspaces = _prepare_verified_workspaces(
                repository_root,
                retained_workspace_root,
                slots,
            )
            run1 = _execute_run(
                slots,
                workspaces,
                run_number=1,
                binding=binding,
                temporary_root=temporary_root,
                process_executor=process_executor,
            )
            _atomic_record(result_path, run1.canonical_json())
            run2 = _execute_run(
                slots,
                workspaces,
                run_number=2,
                binding=binding,
                temporary_root=temporary_root,
                process_executor=process_executor,
            )
            repeatability = compare_gitleaks_realworld_runs(run1, run2)
            _atomic_record(repeatability_path, repeatability.canonical_json())
            return run1, repeatability
    except GitleaksRealworldEvaluationError:
        raise
    except Exception:
        raise GitleaksRealworldEvaluationError from None
