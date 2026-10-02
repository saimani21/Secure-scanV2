from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from typing import Any, Final

from securescan.adapters.sandbox_policy import SandboxExecutionBackend
from securescan.adapters.trusted_registry import (
    TrustedAdapterDefinition,
    TrustedAdapterRegistry,
    TrustedAdapterRegistryError,
)
from securescan.execution.docker_sandbox import (
    DockerImageUnavailableError,
    DockerSandboxExecutor,
    DockerUnavailableError,
)
from securescan.scanners.semgrep.ruleset import TrustedSemgrepRuleset
from securescan.source.enums import AnalysisCapability
from securescan.source.planning import TrustedSourceAnalyzer

_BINDING_STREAM_VERSION = b"securescan-semgrep-source-binding-v1.3\0"
_SCHEMA_VERSION = "1.3"
_SOURCE_ANALYZER_ID = "semgrep-source-v1"
SEMGREP_ADAPTER_ID = "semgrep-ce"
DECLARED_SEMGREP_TOOL_VERSION = "1.171.0"
PRODUCTION_SEMGREP_IMAGE_REFERENCE: Final = (
    "semgrep/semgrep@sha256:bdf7013b2c3634a487671158da77c554f531742326b543a9464d2adf6c433ac8"
)
PRODUCTION_SEMGREP_BINDING_DIGEST: Final = (
    "1e317bf6e9eb6bb44feafa13ac7260b7d5c487b1117ce870ee1e946e1c60726c"
)
_CORE_ADAPTER_ID = SEMGREP_ADAPTER_ID
_TOOL_FAMILY = "semgrep"
_COMMAND_PREFIX = ("semgrep",)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class SemgrepSourceBindingError(RuntimeError):
    """Base error for fixed-message Semgrep Source binding failures."""


class InvalidSemgrepSourceBindingError(SemgrepSourceBindingError, ValueError):
    def __init__(self) -> None:
        super().__init__("Trusted Semgrep Source binding is invalid")


def _validated_definition(
    definition: object,
) -> TrustedAdapterDefinition:
    try:
        if not isinstance(definition, TrustedAdapterDefinition):
            raise TypeError
        validated = replace(
            definition,
            policy=replace(
                definition.policy,
                resources=replace(definition.policy.resources),
            ),
        )
    except Exception as exc:
        raise InvalidSemgrepSourceBindingError from exc
    if (
        validated != definition
        or definition.adapter_id != _CORE_ADAPTER_ID
        or definition.tool_name != _TOOL_FAMILY
        or definition.backend is not SandboxExecutionBackend.DOCKER_SANDBOX
        or definition.policy.backend is not SandboxExecutionBackend.DOCKER_SANDBOX
        or definition.command_prefix != _COMMAND_PREFIX
        or definition.test_only
        or not isinstance(definition.image_reference, str)
    ):
        raise InvalidSemgrepSourceBindingError
    return definition


def _validated_ruleset(ruleset: object) -> TrustedSemgrepRuleset:
    try:
        if not isinstance(ruleset, TrustedSemgrepRuleset):
            raise TypeError
        validated = replace(ruleset)
    except Exception as exc:
        raise InvalidSemgrepSourceBindingError from exc
    if validated != ruleset:
        raise InvalidSemgrepSourceBindingError
    return ruleset


@dataclass(frozen=True, slots=True, init=False)
class TrustedSemgrepSourceBinding:
    source_analyzer_id: str
    capability: AnalysisCapability
    core_adapter_id: str
    tool_family: str
    declared_tool_version: str
    execution_backend: SandboxExecutionBackend
    sandbox_policy_fingerprint: str
    ruleset_id: str
    ruleset_version: str
    ruleset_sha256: str
    image_reference: str
    schema_version: str

    def __init__(
        self,
        *,
        definition: TrustedAdapterDefinition,
        ruleset: TrustedSemgrepRuleset,
    ) -> None:
        trusted_definition = _validated_definition(definition)
        trusted_ruleset = _validated_ruleset(ruleset)
        assert trusted_definition.image_reference is not None
        object.__setattr__(self, "source_analyzer_id", _SOURCE_ANALYZER_ID)
        object.__setattr__(self, "capability", AnalysisCapability.SOURCE_SAST)
        object.__setattr__(self, "core_adapter_id", _CORE_ADAPTER_ID)
        object.__setattr__(self, "tool_family", _TOOL_FAMILY)
        object.__setattr__(
            self,
            "declared_tool_version",
            trusted_definition.tool_version,
        )
        object.__setattr__(self, "execution_backend", trusted_definition.backend)
        object.__setattr__(
            self,
            "sandbox_policy_fingerprint",
            trusted_definition.policy.fingerprint(),
        )
        object.__setattr__(self, "ruleset_id", trusted_ruleset.ruleset_id)
        object.__setattr__(self, "ruleset_version", trusted_ruleset.version)
        object.__setattr__(self, "ruleset_sha256", trusted_ruleset.sha256)
        object.__setattr__(
            self,
            "image_reference",
            trusted_definition.image_reference,
        )
        object.__setattr__(self, "schema_version", _SCHEMA_VERSION)
        self._validate_state()

    def _validate_state(self) -> None:
        if (
            self.schema_version != _SCHEMA_VERSION
            or self.source_analyzer_id != _SOURCE_ANALYZER_ID
            or self.capability is not AnalysisCapability.SOURCE_SAST
            or self.core_adapter_id != _CORE_ADAPTER_ID
            or self.tool_family != _TOOL_FAMILY
            or not isinstance(self.declared_tool_version, str)
            or not self.declared_tool_version
            or self.execution_backend is not SandboxExecutionBackend.DOCKER_SANDBOX
            or _SHA256_PATTERN.fullmatch(self.sandbox_policy_fingerprint) is None
            or not isinstance(self.ruleset_id, str)
            or not self.ruleset_id
            or not isinstance(self.ruleset_version, str)
            or not self.ruleset_version
            or _SHA256_PATTERN.fullmatch(self.ruleset_sha256) is None
            or not isinstance(self.image_reference, str)
            or not self.image_reference
        ):
            raise InvalidSemgrepSourceBindingError

    def canonical_data(self) -> dict[str, Any]:
        self._validate_state()
        return {
            "capability": self.capability.value,
            "core_adapter_id": self.core_adapter_id,
            "declared_tool_version": self.declared_tool_version,
            "execution_backend": self.execution_backend.value,
            "image_reference": self.image_reference,
            "ruleset": {
                "id": self.ruleset_id,
                "sha256": self.ruleset_sha256,
                "version": self.ruleset_version,
            },
            "sandbox_policy_fingerprint": self.sandbox_policy_fingerprint,
            "schema_version": self.schema_version,
            "source_analyzer_id": self.source_analyzer_id,
            "tool_family": self.tool_family,
        }

    def binding_digest(self) -> str:
        payload = json.dumps(
            self.canonical_data(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        digest = hashlib.sha256()
        digest.update(_BINDING_STREAM_VERSION)
        digest.update(payload)
        return digest.hexdigest()

    def matches_definition(self, definition: object) -> bool:
        trusted_definition = _validated_definition(definition)
        return (
            trusted_definition.adapter_id == self.core_adapter_id
            and trusted_definition.tool_name == self.tool_family
            and trusted_definition.tool_version == self.declared_tool_version
            and trusted_definition.backend is self.execution_backend
            and trusted_definition.policy.fingerprint() == self.sandbox_policy_fingerprint
            and trusted_definition.image_reference == self.image_reference
        )


def create_production_semgrep_source_binding(
    *,
    definition: TrustedAdapterDefinition,
    ruleset: TrustedSemgrepRuleset,
) -> TrustedSemgrepSourceBinding:
    """Build the one current Source-v1 production Semgrep binding."""

    binding = TrustedSemgrepSourceBinding(definition=definition, ruleset=ruleset)
    if (
        binding.image_reference != PRODUCTION_SEMGREP_IMAGE_REFERENCE
        or binding.declared_tool_version != DECLARED_SEMGREP_TOOL_VERSION
        or binding.binding_digest() != PRODUCTION_SEMGREP_BINDING_DIGEST
    ):
        raise InvalidSemgrepSourceBindingError
    return binding


def build_semgrep_source_analyzer_snapshot(
    binding: TrustedSemgrepSourceBinding,
    adapter_registry: TrustedAdapterRegistry,
    docker_executor: DockerSandboxExecutor,
) -> TrustedSourceAnalyzer:
    if (
        not isinstance(binding, TrustedSemgrepSourceBinding)
        or not isinstance(adapter_registry, TrustedAdapterRegistry)
        or not isinstance(docker_executor, DockerSandboxExecutor)
    ):
        raise InvalidSemgrepSourceBindingError
    binding._validate_state()
    try:
        definition = adapter_registry.resolve_definition(binding.core_adapter_id)
    except TrustedAdapterRegistryError as exc:
        raise InvalidSemgrepSourceBindingError from exc
    if not binding.matches_definition(definition):
        raise InvalidSemgrepSourceBindingError

    unavailable_reason_code: str | None = None
    try:
        docker_executor.verify_runtime_prerequisites(definition)
    except DockerUnavailableError:
        unavailable_reason_code = "SEMGREP_DOCKER_UNAVAILABLE"
    except DockerImageUnavailableError:
        unavailable_reason_code = "SEMGREP_IMAGE_UNAVAILABLE"
    except Exception as exc:
        raise InvalidSemgrepSourceBindingError from exc

    return TrustedSourceAnalyzer(
        analyzer_id=binding.source_analyzer_id,
        capabilities=(binding.capability,),
        available=unavailable_reason_code is None,
        unavailable_reason_code=unavailable_reason_code,
    )
