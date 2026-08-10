from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from securescan.adapters.base import ToolAdapter
from securescan.adapters.sandbox_policy import (
    SandboxExecutionBackend,
    SandboxExecutionPolicy,
)
from securescan.worker.models import (
    ControllableWorkerAdapter,
    WorkerAdapter,
    WorkerAdapterResolutionError,
)

_ADAPTER_ID_PATTERN = re.compile(r"[a-z][a-z0-9._-]{0,63}\Z", re.ASCII)
_DIGEST_IMAGE_PATTERN = re.compile(
    r"[^\s@]+@sha256:[0-9a-f]{64}\Z",
    re.ASCII,
)
_PUBLIC_ERROR_MESSAGES = {
    "definition": "Trusted adapter definition is invalid",
    "duplicate": "Trusted adapter registry contains a duplicate definition",
    "unknown": "Trusted adapter is not registered",
    "factory": "Trusted adapter could not be created",
}


class TrustedAdapterRegistryError(RuntimeError):
    """Base error for sanitized trusted-registry failures."""


class InvalidTrustedAdapterDefinitionError(TrustedAdapterRegistryError, ValueError):
    def __init__(self) -> None:
        super().__init__(_PUBLIC_ERROR_MESSAGES["definition"])


class DuplicateTrustedAdapterError(TrustedAdapterRegistryError, ValueError):
    def __init__(self) -> None:
        super().__init__(_PUBLIC_ERROR_MESSAGES["duplicate"])


class UnknownTrustedAdapterError(TrustedAdapterRegistryError, LookupError):
    def __init__(self) -> None:
        super().__init__(_PUBLIC_ERROR_MESSAGES["unknown"])


class TrustedAdapterFactoryError(TrustedAdapterRegistryError):
    def __init__(self) -> None:
        super().__init__(_PUBLIC_ERROR_MESSAGES["factory"])


type RegisteredAdapter = ToolAdapter | WorkerAdapter | ControllableWorkerAdapter


def _contains_control_characters(value: str) -> bool:
    return any(unicodedata.category(character).startswith("C") for character in value)


def _is_bounded_text(value: object, maximum_length: int) -> bool:
    return (
        isinstance(value, str)
        and value == value.strip()
        and 1 <= len(value) <= maximum_length
        and not _contains_control_characters(value)
    )


@dataclass(frozen=True, slots=True)
class TrustedAdapterDefinition:
    adapter_id: str
    display_name: str
    tool_name: str
    tool_version: str
    backend: SandboxExecutionBackend
    policy: SandboxExecutionPolicy
    factory: Callable[[], object]
    image_reference: str | None = None
    command_prefix: tuple[str, ...] = ()
    test_only: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.adapter_id, str)
            or _ADAPTER_ID_PATTERN.fullmatch(self.adapter_id) is None
            or not _is_bounded_text(self.display_name, 128)
            or not _is_bounded_text(self.tool_name, 128)
            or not _is_bounded_text(self.tool_version, 64)
            or not isinstance(self.backend, SandboxExecutionBackend)
            or not isinstance(self.policy, SandboxExecutionPolicy)
            or self.backend is not self.policy.backend
            or not callable(self.factory)
            or not isinstance(self.command_prefix, tuple)
            or not isinstance(self.test_only, bool)
        ):
            raise InvalidTrustedAdapterDefinitionError

        if any(
            not isinstance(argument, str)
            or not argument
            or "\0" in argument
            or _contains_control_characters(argument)
            for argument in self.command_prefix
        ):
            raise InvalidTrustedAdapterDefinitionError

        if self.backend is SandboxExecutionBackend.DOCKER_SANDBOX:
            if (
                self.test_only
                or not isinstance(self.image_reference, str)
                or _DIGEST_IMAGE_PATTERN.fullmatch(self.image_reference) is None
                or _contains_control_characters(self.image_reference)
                or not self.command_prefix
            ):
                raise InvalidTrustedAdapterDefinitionError
        elif (
            self.backend is not SandboxExecutionBackend.TEST_ONLY
            or not self.test_only
            or self.image_reference is not None
        ):
            raise InvalidTrustedAdapterDefinitionError


@dataclass(frozen=True, slots=True)
class PublicTrustedAdapterDefinition:
    adapter_id: str
    display_name: str
    tool_name: str
    tool_version: str
    backend: SandboxExecutionBackend
    policy_fingerprint: str


def _is_registered_adapter(adapter: object) -> bool:
    return isinstance(
        adapter,
        (ToolAdapter, WorkerAdapter, ControllableWorkerAdapter),
    )


@dataclass(frozen=True, slots=True, init=False)
class TrustedAdapterRegistry:
    _definitions: Mapping[str, TrustedAdapterDefinition]

    def __init__(self, definitions: Iterable[TrustedAdapterDefinition]) -> None:
        trusted_definitions: dict[str, TrustedAdapterDefinition] = {}
        try:
            for definition in definitions:
                if not isinstance(definition, TrustedAdapterDefinition):
                    raise InvalidTrustedAdapterDefinitionError
                if definition.adapter_id in trusted_definitions:
                    raise DuplicateTrustedAdapterError
                trusted_definitions[definition.adapter_id] = definition
        except TrustedAdapterRegistryError:
            raise
        except Exception as exc:
            raise InvalidTrustedAdapterDefinitionError from exc
        object.__setattr__(
            self,
            "_definitions",
            MappingProxyType(trusted_definitions),
        )

    def resolve_definition(self, adapter_id: str) -> TrustedAdapterDefinition:
        try:
            return self._definitions[adapter_id]
        except (KeyError, TypeError) as exc:
            raise UnknownTrustedAdapterError from exc

    def create_adapter(self, adapter_id: str) -> RegisteredAdapter:
        definition = self.resolve_definition(adapter_id)
        try:
            adapter = definition.factory()
            if not _is_registered_adapter(adapter):
                raise TypeError("Registered factory returned an incompatible adapter")
            if getattr(adapter, "adapter_id", None) != definition.adapter_id:
                raise TypeError("Registered factory returned a mismatched adapter")
        except Exception as exc:
            raise TrustedAdapterFactoryError from exc
        return adapter

    def list_public_definitions(self) -> tuple[PublicTrustedAdapterDefinition, ...]:
        return tuple(
            PublicTrustedAdapterDefinition(
                adapter_id=definition.adapter_id,
                display_name=definition.display_name,
                tool_name=definition.tool_name,
                tool_version=definition.tool_version,
                backend=definition.backend,
                policy_fingerprint=definition.policy.fingerprint(),
            )
            for definition in sorted(
                self._definitions.values(),
                key=lambda candidate: candidate.adapter_id,
            )
        )


@dataclass(frozen=True, slots=True)
class TrustedAdapterResolver:
    registry: TrustedAdapterRegistry

    def __post_init__(self) -> None:
        if not isinstance(self.registry, TrustedAdapterRegistry):
            raise InvalidTrustedAdapterDefinitionError

    def resolve(
        self,
        adapter_id: str,
    ) -> WorkerAdapter | ControllableWorkerAdapter:
        try:
            adapter = self.registry.create_adapter(adapter_id)
            if not isinstance(adapter, (WorkerAdapter, ControllableWorkerAdapter)):
                raise TrustedAdapterFactoryError
        except TrustedAdapterRegistryError as exc:
            raise WorkerAdapterResolutionError(
                "The configured worker adapter could not be resolved"
            ) from exc
        return adapter
