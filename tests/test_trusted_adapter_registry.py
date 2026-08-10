from __future__ import annotations

from dataclasses import asdict

import pytest

from securescan.adapters.fake_scanner import FakeScannerAdapter
from securescan.adapters.sandbox_policy import (
    SandboxExecutionBackend,
    SandboxExecutionPolicy,
)
from securescan.adapters.trusted_registry import (
    DuplicateTrustedAdapterError,
    InvalidTrustedAdapterDefinitionError,
    TrustedAdapterDefinition,
    TrustedAdapterFactoryError,
    TrustedAdapterRegistry,
    UnknownTrustedAdapterError,
)

_VALID_DIGEST = "registry.example/securescan/tool@sha256:" + "a" * 64


def _test_policy() -> SandboxExecutionPolicy:
    return SandboxExecutionPolicy(backend=SandboxExecutionBackend.TEST_ONLY)


def _test_definition(
    *,
    adapter_id: str = "fake-scanner",
    factory=FakeScannerAdapter,
) -> TrustedAdapterDefinition:
    return TrustedAdapterDefinition(
        adapter_id=adapter_id,
        display_name="Fake scanner",
        tool_name="fake-scanner",
        tool_version="1.0.0",
        backend=SandboxExecutionBackend.TEST_ONLY,
        policy=_test_policy(),
        factory=factory,
        test_only=True,
    )


def _docker_definition(
    *,
    image_reference: str | None = _VALID_DIGEST,
    command_prefix: tuple[str, ...] = ("scanner", "--json"),
) -> TrustedAdapterDefinition:
    return TrustedAdapterDefinition(
        adapter_id="docker-scanner",
        display_name="Docker scanner",
        tool_name="docker-scanner",
        tool_version="1.2.3",
        backend=SandboxExecutionBackend.DOCKER_SANDBOX,
        policy=SandboxExecutionPolicy(),
        factory=FakeScannerAdapter,
        image_reference=image_reference,
        command_prefix=command_prefix,
    )


def test_registry_resolves_explicit_definition_and_lists_safe_metadata() -> None:
    definition = _test_definition()
    registry = TrustedAdapterRegistry((definition,))

    assert registry.resolve_definition("fake-scanner") is definition
    assert isinstance(registry.create_adapter("fake-scanner"), FakeScannerAdapter)
    public = registry.list_public_definitions()
    assert len(public) == 1
    metadata = asdict(public[0])
    assert metadata["adapter_id"] == "fake-scanner"
    assert metadata["policy_fingerprint"] == definition.policy.fingerprint()
    forbidden = {
        "factory",
        "image_reference",
        "command_prefix",
        "run_as_uid",
        "run_as_gid",
        "allowed_environment_names",
        "writable_tmp_paths",
        "policy",
    }
    assert forbidden.isdisjoint(metadata)


def test_registry_rejects_duplicate_adapter_ids() -> None:
    definition = _test_definition()

    with pytest.raises(DuplicateTrustedAdapterError):
        TrustedAdapterRegistry((definition, definition))


def test_registry_rejects_invalid_adapter_ids() -> None:
    invalid_ids = (
        "Uppercase",
        "../scanner",
        "scanner/path",
        " scanner",
        "scanner ",
        "scannеr",
        "a" * 65,
    )

    for adapter_id in invalid_ids:
        with pytest.raises(InvalidTrustedAdapterDefinitionError):
            _test_definition(adapter_id=adapter_id)


def test_docker_adapter_requires_digest_pinned_image() -> None:
    assert _docker_definition().image_reference == _VALID_DIGEST
    invalid_images = (
        "latest",
        "registry.example/tool:1.2.3",
        "registry.example/tool",
        "registry.example/tool@sha256:" + "A" * 64,
        "registry.example/tool@sha256:" + "a" * 63,
    )

    for image_reference in invalid_images:
        with pytest.raises(InvalidTrustedAdapterDefinitionError):
            _docker_definition(image_reference=image_reference)
    with pytest.raises(InvalidTrustedAdapterDefinitionError):
        _docker_definition(command_prefix=())


def test_registry_rejects_backend_policy_mismatch() -> None:
    with pytest.raises(InvalidTrustedAdapterDefinitionError):
        TrustedAdapterDefinition(
            adapter_id="mismatch",
            display_name="Mismatch",
            tool_name="mismatch",
            tool_version="1",
            backend=SandboxExecutionBackend.TEST_ONLY,
            policy=SandboxExecutionPolicy(),
            factory=FakeScannerAdapter,
            test_only=True,
        )
    with pytest.raises(InvalidTrustedAdapterDefinitionError):
        TrustedAdapterDefinition(
            adapter_id="mismatch",
            display_name="Mismatch",
            tool_name="mismatch",
            tool_version="1",
            backend=SandboxExecutionBackend.DOCKER_SANDBOX,
            policy=_test_policy(),
            factory=FakeScannerAdapter,
            image_reference=_VALID_DIGEST,
            command_prefix=("scanner",),
        )


def test_unknown_adapter_error_is_fixed_and_sanitized() -> None:
    submitted = "token=secret/path; command=sh image=private:latest"
    registry = TrustedAdapterRegistry(())

    with pytest.raises(UnknownTrustedAdapterError) as error:
        registry.resolve_definition(submitted)

    message = str(error.value)
    assert message == "Trusted adapter is not registered"
    for sensitive in (submitted, "secret", "path", "command", "private", "latest"):
        assert sensitive not in message


def test_factory_failure_preserves_cause_but_hides_exception_message() -> None:
    sensitive = RuntimeError(
        "postgresql://admin:password@database token=fake repository=https://user:secret@repo"
    )

    def failing_factory() -> object:
        raise sensitive

    registry = TrustedAdapterRegistry((_test_definition(factory=failing_factory),))

    with pytest.raises(TrustedAdapterFactoryError) as error:
        registry.create_adapter("fake-scanner")

    assert error.value.__cause__ is sensitive
    message = str(error.value)
    assert message == "Trusted adapter could not be created"
    for secret in ("postgresql", "password", "token", "repository", "user", "secret"):
        assert secret not in message
