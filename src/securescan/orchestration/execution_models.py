from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from securescan.scanners.checkov.parser import CheckovParseResult
    from securescan.scanners.gitleaks.parser import GitleaksParseResult
    from securescan.scanners.syft.parser import SyftParseResult
    from securescan.source.execution_context import SourceExecutionContext
    from securescan.source.projection import PreparedSourceProjection

SAFE_NATIVE_RESULT_SCHEMA_VERSION = "securescan-source-native-result-s6b-v1"
SAFE_NATIVE_RESULT_MEDIA_TYPE = "application/vnd.securescan.source-native-result+json"
CLEANUP_RECEIPT_SCHEMA_VERSION = "securescan-source-attempt-cleanup-s6b-v1"
SANDBOX_CLEANUP_RECEIPT_SCHEMA_VERSION = "securescan-source-sandbox-cleanup-s6b-v1"
_SANDBOX_ID_DOMAIN = b"securescan-source-sandbox-identity-s6b-v1\0"

_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z", re.ASCII)
_NATIVE_FIELDS = frozenset(
    {
        "analyzer_id",
        "attempt_number",
        "authority",
        "binding_digest",
        "context_digest",
        "job_id",
        "native_data",
        "native_schema_version",
        "node_id",
        "plan_digest",
        "profile_digest",
        "projection_digest",
        "projection_id",
        "repository_digest",
        "scanner_id",
        "scanner_version",
        "schema_version",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "attempt_number",
        "attempt_token",
        "cleanup_outcome",
        "job_id",
        "process_tree_empty",
        "scanner_pgid",
        "scanner_pid",
        "scanner_start_ticks",
        "schema_version",
        "supervisor_identity",
        "supervisor_pid",
        "supervisor_start_ticks",
    }
)
_SANDBOX_RECEIPT_FIELDS = frozenset(
    {
        "attempt_number",
        "attempt_token",
        "cleanup_outcome",
        "execution_backend",
        "execution_id",
        "execution_removed",
        "job_id",
        "sandbox_identity",
        "schema_version",
    }
)
_TRUSTED_NATIVE_IDENTITIES = {
    "checkov": (
        "3.3.16",
        "checkov-source-v1",
        "a4dc1feb9948d453d22eda0ab39cbcee7c377421fb54aa3d7285cad18eb2143e",
        "securescan-checkov-parser-s3",
    ),
    "gitleaks": (
        "8.30.1",
        "gitleaks-source-v1",
        "8d9f224e1c5ddabef508a26be2966f51dc2a9c2e5805ea3bffcf444b3cae9561",
        "securescan-gitleaks-parser-v0.4C",
    ),
    "semgrep-ce": (
        "1.171.0",
        "semgrep-source-v1",
        "1e317bf6e9eb6bb44feafa13ac7260b7d5c487b1117ce870ee1e946e1c60726c",
        "securescan-semgrep-sanitized-v1",
    ),
    "syft": (
        "1.51.0",
        "syft-source-v1",
        "392fdda53e1192ca40fb22893e5fce90828a4171e67e28eb09632d9bc8159da0",
        "securescan-syft-parser-s1",
    ),
}


class SourceScannerExecutionIntegrityError(RuntimeError):
    def __init__(self, message: str = "Source scanner execution evidence is invalid") -> None:
        super().__init__(message)


class AttemptContainmentOutcome(StrEnum):
    CLEAN = "CLEAN"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"


class SourceScannerFailureCode(StrEnum):
    EXECUTION_FAILURE = "SCANNER_EXECUTION_FAILURE"
    PARSER_FAILURE = "SCANNER_PARSER_FAILURE"
    PROJECTION_INTEGRITY_FAILURE = "PROJECTION_INTEGRITY_FAILURE"
    ARTIFACT_PERSISTENCE_FAILURE = "ARTIFACT_PERSISTENCE_FAILURE"
    CONTAINMENT_FAILURE = "ATTEMPT_CONTAINMENT_FAILURE"


def source_sandbox_execution_identity(job_id: str, attempt_number: int, attempt_token: str) -> str:
    if (
        not _canonical_uuid(job_id)
        or type(attempt_number) is not int
        or attempt_number < 1
        or not _canonical_uuid(attempt_token)
    ):
        raise SourceScannerExecutionIntegrityError
    digest = hashlib.sha256()
    digest.update(_SANDBOX_ID_DOMAIN)
    digest.update(job_id.encode("ascii"))
    digest.update(b"\0")
    digest.update(str(attempt_number).encode("ascii"))
    digest.update(b"\0")
    digest.update(attempt_token.encode("ascii"))
    return f"securescan-s6b-{digest.hexdigest()[:32]}"


def _canonical_json(value: object) -> bytes:
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


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_non_finite(_value: str) -> None:
    raise ValueError


def _canonical_uuid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(UUID(value)) == value
    except ValueError:
        return False


def _load_canonical_object(payload: bytes) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not payload or len(payload) > 100 * 1024 * 1024:
        raise SourceScannerExecutionIntegrityError
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
        )
    except (TypeError, ValueError, UnicodeError) as exc:
        raise SourceScannerExecutionIntegrityError from exc
    if not isinstance(value, dict) or _canonical_json(value) != payload:
        raise SourceScannerExecutionIntegrityError
    return value


def _freeze_json(value: object) -> object:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(child) for key, child in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(child) for child in value)
    return value


def _thaw_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw_json(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(child) for child in value]
    return value


@dataclass(frozen=True, slots=True, kw_only=True)
class SafeSourceNativeResult:
    authority: str
    node_id: str
    job_id: str
    attempt_number: int
    scanner_id: str
    scanner_version: str
    analyzer_id: str
    binding_digest: str
    context_digest: str
    projection_id: str
    projection_digest: str
    repository_digest: str
    profile_digest: str
    plan_digest: str
    native_schema_version: str
    native_data: Mapping[str, Any] = field(repr=False)
    schema_version: str = SAFE_NATIVE_RESULT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        trusted_identity = _TRUSTED_NATIVE_IDENTITIES.get(self.authority)
        if (
            self.schema_version != SAFE_NATIVE_RESULT_SCHEMA_VERSION
            or not _IDENTIFIER.fullmatch(self.authority)
            or _SHA256.fullmatch(self.node_id) is None
            or not _canonical_uuid(self.job_id)
            or type(self.attempt_number) is not int
            or self.attempt_number < 1
            or not _IDENTIFIER.fullmatch(self.scanner_id)
            or not isinstance(self.scanner_version, str)
            or not self.scanner_version
            or len(self.scanner_version) > 64
            or not _IDENTIFIER.fullmatch(self.analyzer_id)
            or any(
                _SHA256.fullmatch(value) is None
                for value in (
                    self.binding_digest,
                    self.context_digest,
                    self.projection_digest,
                    self.repository_digest,
                    self.profile_digest,
                    self.plan_digest,
                )
            )
            or not isinstance(self.projection_id, str)
            or not self.projection_id.startswith("securescan-source-projection-")
            or not isinstance(self.native_schema_version, str)
            or not self.native_schema_version
            or len(self.native_schema_version) > 128
            or not isinstance(self.native_data, Mapping)
            or trusted_identity
            != (
                self.scanner_version,
                self.analyzer_id,
                self.binding_digest,
                self.native_schema_version,
            )
            or self.scanner_id != self.authority
        ):
            raise SourceScannerExecutionIntegrityError
        try:
            frozen = _freeze_json(
                _load_canonical_object(_canonical_json(_thaw_json(self.native_data)))
            )
        except SourceScannerExecutionIntegrityError:
            raise
        if not isinstance(frozen, Mapping):
            raise SourceScannerExecutionIntegrityError
        native_projection_digest = frozen.get("projection_digest", frozen.get("snapshot_digest"))
        if (
            frozen.get("schema_version") != self.native_schema_version
            or frozen.get("scanner_id") != self.scanner_id
            or (
                self.authority != "semgrep-ce"
                and (
                    native_projection_digest != self.projection_digest
                    or frozen.get("projection_id") != self.projection_id
                )
            )
            or (
                self.authority == "gitleaks" and frozen.get("context_digest") != self.context_digest
            )
            or (
                self.authority != "semgrep-ce"
                and frozen.get("binding_digest") != self.binding_digest
            )
        ):
            raise SourceScannerExecutionIntegrityError
        object.__setattr__(self, "native_data", frozen)

    def canonical_data(self) -> dict[str, Any]:
        return {
            "analyzer_id": self.analyzer_id,
            "attempt_number": self.attempt_number,
            "authority": self.authority,
            "binding_digest": self.binding_digest,
            "context_digest": self.context_digest,
            "job_id": self.job_id,
            "native_data": _thaw_json(self.native_data),
            "native_schema_version": self.native_schema_version,
            "node_id": self.node_id,
            "plan_digest": self.plan_digest,
            "profile_digest": self.profile_digest,
            "projection_digest": self.projection_digest,
            "projection_id": self.projection_id,
            "repository_digest": self.repository_digest,
            "scanner_id": self.scanner_id,
            "scanner_version": self.scanner_version,
            "schema_version": self.schema_version,
        }

    def canonical_json(self) -> bytes:
        try:
            return _canonical_json(self.canonical_data())
        except (TypeError, ValueError, UnicodeError) as exc:
            raise SourceScannerExecutionIntegrityError from exc

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_json()).hexdigest()

    @classmethod
    def from_parse_result(
        cls,
        *,
        result: GitleaksParseResult | SyftParseResult | CheckovParseResult,
        node_id: str,
        job_id: str,
        attempt_number: int,
        authority: str,
        analyzer_id: str,
        context: SourceExecutionContext,
    ) -> SafeSourceNativeResult:
        from securescan.scanners.checkov.parser import CheckovParseResult
        from securescan.scanners.gitleaks.parser import GitleaksParseResult
        from securescan.scanners.syft.parser import SyftParseResult

        if not isinstance(result, (GitleaksParseResult, SyftParseResult, CheckovParseResult)):
            raise SourceScannerExecutionIntegrityError
        payload = result.canonical_json()
        native_data = _load_canonical_object(payload)
        projection_digest = (
            result.projection_digest
            if isinstance(result, GitleaksParseResult)
            else result.snapshot_digest
        )
        if (
            context.job_id != job_id
            or context.context_digest()
            != getattr(result, "context_digest", context.context_digest())
            or result.binding_digest != context.binding_digest
            or result.projection_id != native_data.get("projection_id")
        ):
            raise SourceScannerExecutionIntegrityError
        return cls(
            authority=authority,
            node_id=node_id,
            job_id=job_id,
            attempt_number=attempt_number,
            scanner_id=result.scanner_id,
            scanner_version=result.scanner_version,
            analyzer_id=analyzer_id,
            binding_digest=result.binding_digest,
            context_digest=context.context_digest(),
            projection_id=result.projection_id,
            projection_digest=projection_digest,
            repository_digest=context.repository_digest,
            profile_digest=context.profile_digest,
            plan_digest=context.plan_digest,
            native_schema_version=result.schema_version,
            native_data=native_data,
        )

    @classmethod
    def from_gitleaks_execution(
        cls,
        *,
        envelope: object,
        projection: PreparedSourceProjection,
        node_id: str,
        job_id: str,
        attempt_number: int,
        analyzer_id: str,
        context: SourceExecutionContext,
    ) -> SafeSourceNativeResult:
        """Parse one frozen Gitleaks envelope and retain only its safe typed result."""
        from securescan.scanners.gitleaks.parser import parse_gitleaks_execution_result

        try:
            result = parse_gitleaks_execution_result(envelope, projection)
            return cls.from_parse_result(
                result=result,
                node_id=node_id,
                job_id=job_id,
                attempt_number=attempt_number,
                authority="gitleaks",
                analyzer_id=analyzer_id,
                context=context,
            )
        except SourceScannerExecutionIntegrityError:
            raise
        except Exception:
            raise SourceScannerExecutionIntegrityError from None

    @classmethod
    def from_syft_execution(
        cls,
        *,
        envelope: object,
        projection: PreparedSourceProjection,
        node_id: str,
        job_id: str,
        attempt_number: int,
        analyzer_id: str,
        context: SourceExecutionContext,
    ) -> SafeSourceNativeResult:
        """Parse one frozen Syft envelope and retain only its safe typed result."""
        from securescan.scanners.syft.parser import parse_syft_execution_result

        try:
            result = parse_syft_execution_result(envelope, projection)
            return cls.from_parse_result(
                result=result,
                node_id=node_id,
                job_id=job_id,
                attempt_number=attempt_number,
                authority="syft",
                analyzer_id=analyzer_id,
                context=context,
            )
        except SourceScannerExecutionIntegrityError:
            raise
        except Exception:
            raise SourceScannerExecutionIntegrityError from None

    @classmethod
    def from_checkov_execution(
        cls,
        *,
        envelope: object,
        projection: PreparedSourceProjection,
        node_id: str,
        job_id: str,
        attempt_number: int,
        analyzer_id: str,
        context: SourceExecutionContext,
    ) -> SafeSourceNativeResult:
        """Parse one frozen Checkov envelope and retain only its safe typed result."""
        from securescan.scanners.checkov.parser import parse_checkov_execution_result

        try:
            result = parse_checkov_execution_result(
                envelope,
                projection_root=projection.source_directory,
                authorized_paths=frozenset(
                    item.relative_path for item in projection.manifest.entries
                ),
            )
            return cls.from_parse_result(
                result=result,
                node_id=node_id,
                job_id=job_id,
                attempt_number=attempt_number,
                authority="checkov",
                analyzer_id=analyzer_id,
                context=context,
            )
        except SourceScannerExecutionIntegrityError:
            raise
        except Exception:
            raise SourceScannerExecutionIntegrityError from None

    @classmethod
    def from_semgrep_sanitized(
        cls,
        *,
        payload: bytes,
        node_id: str,
        job_id: str,
        attempt_number: int,
        scanner_version: str,
        analyzer_id: str,
        context: SourceExecutionContext,
        projection_id: str,
        projection_digest: str,
    ) -> SafeSourceNativeResult:
        document = _load_canonical_object(payload + (b"" if payload.endswith(b"\n") else b"\n"))
        if (
            set(document) != {"results", "ruleset", "scanner_id", "schema_version", "summary"}
            or document.get("scanner_id") != "semgrep-ce"
            or document.get("schema_version") != "securescan-semgrep-sanitized-v1"
            or context.job_id != job_id
        ):
            raise SourceScannerExecutionIntegrityError
        return cls(
            authority="semgrep-ce",
            node_id=node_id,
            job_id=job_id,
            attempt_number=attempt_number,
            scanner_id="semgrep-ce",
            scanner_version=scanner_version,
            analyzer_id=analyzer_id,
            binding_digest=context.binding_digest,
            context_digest=context.context_digest(),
            projection_id=projection_id,
            projection_digest=projection_digest,
            repository_digest=context.repository_digest,
            profile_digest=context.profile_digest,
            plan_digest=context.plan_digest,
            native_schema_version="securescan-semgrep-sanitized-v1",
            native_data=document,
        )

    @classmethod
    def from_json(cls, payload: bytes) -> SafeSourceNativeResult:
        document = _load_canonical_object(payload)
        if set(document) != _NATIVE_FIELDS:
            raise SourceScannerExecutionIntegrityError
        try:
            result = cls(**document)
        except (TypeError, ValueError) as exc:
            raise SourceScannerExecutionIntegrityError from exc
        if result.canonical_json() != payload:
            raise SourceScannerExecutionIntegrityError
        return result


@dataclass(frozen=True, slots=True, kw_only=True)
class SourceAttemptCleanupReceipt:
    job_id: str
    attempt_number: int
    attempt_token: str = field(repr=False)
    supervisor_identity: str
    supervisor_pid: int
    supervisor_start_ticks: int
    scanner_pid: int | None
    scanner_pgid: int | None
    scanner_start_ticks: int | None
    cleanup_outcome: AttemptContainmentOutcome
    process_tree_empty: bool
    schema_version: str = CLEANUP_RECEIPT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        scanner_identity = (self.scanner_pid, self.scanner_pgid, self.scanner_start_ticks)
        if (
            self.schema_version != CLEANUP_RECEIPT_SCHEMA_VERSION
            or not _canonical_uuid(self.job_id)
            or type(self.attempt_number) is not int
            or self.attempt_number < 1
            or not _canonical_uuid(self.attempt_token)
            or _SHA256.fullmatch(self.supervisor_identity) is None
            or any(
                type(value) is not int or value < 1
                for value in (self.supervisor_pid, self.supervisor_start_ticks)
            )
            or not (
                all(value is None for value in scanner_identity)
                or all(type(value) is int and value > 0 for value in scanner_identity)
            )
            or not isinstance(self.cleanup_outcome, AttemptContainmentOutcome)
            or type(self.process_tree_empty) is not bool
            or (self.cleanup_outcome is AttemptContainmentOutcome.CLEAN) != self.process_tree_empty
        ):
            raise SourceScannerExecutionIntegrityError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "attempt_number": self.attempt_number,
            "attempt_token": self.attempt_token,
            "cleanup_outcome": self.cleanup_outcome.value,
            "job_id": self.job_id,
            "process_tree_empty": self.process_tree_empty,
            "scanner_pgid": self.scanner_pgid,
            "scanner_pid": self.scanner_pid,
            "scanner_start_ticks": self.scanner_start_ticks,
            "schema_version": self.schema_version,
            "supervisor_identity": self.supervisor_identity,
            "supervisor_pid": self.supervisor_pid,
            "supervisor_start_ticks": self.supervisor_start_ticks,
        }

    def canonical_json(self) -> bytes:
        return _canonical_json(self.canonical_data())

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_json()).hexdigest()

    @classmethod
    def from_json(cls, payload: bytes) -> SourceAttemptCleanupReceipt:
        document = _load_canonical_object(payload)
        if set(document) != _RECEIPT_FIELDS:
            raise SourceScannerExecutionIntegrityError
        try:
            document["cleanup_outcome"] = AttemptContainmentOutcome(document["cleanup_outcome"])
            receipt = cls(**document)
        except (TypeError, ValueError) as exc:
            raise SourceScannerExecutionIntegrityError from exc
        if receipt.canonical_json() != payload:
            raise SourceScannerExecutionIntegrityError
        return receipt


@dataclass(frozen=True, slots=True, kw_only=True)
class SourceSandboxCleanupReceipt:
    """Proof emitted only after the frozen Docker handle confirms removal."""

    job_id: str
    attempt_number: int
    attempt_token: str = field(repr=False)
    execution_backend: str
    execution_id: str
    sandbox_identity: str
    cleanup_outcome: AttemptContainmentOutcome
    execution_removed: bool
    schema_version: str = SANDBOX_CLEANUP_RECEIPT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != SANDBOX_CLEANUP_RECEIPT_SCHEMA_VERSION
            or not _canonical_uuid(self.job_id)
            or type(self.attempt_number) is not int
            or self.attempt_number < 1
            or not _canonical_uuid(self.attempt_token)
            or self.execution_backend != "docker-sandbox"
            or self.execution_id != self.job_id
            or self.sandbox_identity
            != source_sandbox_execution_identity(
                self.job_id, self.attempt_number, self.attempt_token
            )
            or self.cleanup_outcome is not AttemptContainmentOutcome.CLEAN
            or self.execution_removed is not True
        ):
            raise SourceScannerExecutionIntegrityError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "attempt_number": self.attempt_number,
            "attempt_token": self.attempt_token,
            "cleanup_outcome": self.cleanup_outcome.value,
            "execution_backend": self.execution_backend,
            "execution_id": self.execution_id,
            "execution_removed": self.execution_removed,
            "job_id": self.job_id,
            "sandbox_identity": self.sandbox_identity,
            "schema_version": self.schema_version,
        }

    def canonical_json(self) -> bytes:
        return _canonical_json(self.canonical_data())

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_json()).hexdigest()

    @classmethod
    def from_json(cls, payload: bytes) -> SourceSandboxCleanupReceipt:
        document = _load_canonical_object(payload)
        if set(document) != _SANDBOX_RECEIPT_FIELDS:
            raise SourceScannerExecutionIntegrityError
        try:
            document["cleanup_outcome"] = AttemptContainmentOutcome(document["cleanup_outcome"])
            receipt = cls(**document)
        except (TypeError, ValueError) as exc:
            raise SourceScannerExecutionIntegrityError from exc
        if receipt.canonical_json() != payload:
            raise SourceScannerExecutionIntegrityError
        return receipt
