from __future__ import annotations

import inspect
import os
import shutil
import subprocess
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from securescan.adapters.sandbox_policy import (
    SandboxExecutionBackend,
    SandboxExecutionPolicy,
)
from securescan.adapters.trusted_registry import (
    InvalidTrustedAdapterDefinitionError,
    TrustedAdapterDefinition,
    TrustedAdapterRegistry,
)
from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.execution.docker_sandbox import (
    DockerControlCommandResult,
    DockerSandboxExecutor,
)
from securescan.scanners.semgrep import (
    PRODUCTION_SEMGREP_BINDING_DIGEST,
    PRODUCTION_SEMGREP_IMAGE_REFERENCE,
    InvalidSemgrepSourceBindingError,
    TrustedSemgrepSourceBinding,
    build_semgrep_source_analyzer_snapshot,
    create_production_semgrep_source_binding,
    create_semgrep_trusted_definition,
    load_source_ruleset,
)
from securescan.scanners.semgrep.adapter import SemgrepScannerAdapter
from securescan.source import (
    AnalysisCapability,
    AnalysisSurface,
    CapabilitySupportRule,
    FileContentKind,
    InvalidSourcePlanningRequestError,
    RepositoryProfile,
    SourceFileRecord,
    SourceFileRole,
    SourcePlanAction,
    SourcePlanningPolicy,
    SourceSupportPolicy,
    SourceSupportState,
    TrustedSourceAnalyzerRegistry,
    build_source_analysis_plan,
)
from securescan.workspaces.intake import RepositoryWorkspaceManager
from securescan.workspaces.models import (
    RepositoryManifestEntry,
    repository_content_digest,
)

IMAGE = PRODUCTION_SEMGREP_IMAGE_REFERENCE
OLD_PLACEHOLDER_IMAGE = "registry.example/securescan/semgrep@sha256:" + "4" * 64
TOOL_VERSION = "1.171.0"
BINDING_GOLDEN_DIGEST = PRODUCTION_SEMGREP_BINDING_DIGEST
REGISTRY_GOLDEN_DIGEST = "205b72c7866ee9ea08ceebb7654c18176bbf3a5cd4cbf9f59e20da0e94085ada"


def _definition(
    *,
    adapter_id: str = "semgrep-ce",
    tool_version: str = TOOL_VERSION,
    image_reference: str = IMAGE,
    policy: SandboxExecutionPolicy | None = None,
) -> TrustedAdapterDefinition:
    return TrustedAdapterDefinition(
        adapter_id=adapter_id,
        display_name="Semgrep Community Edition",
        tool_name="semgrep",
        tool_version=tool_version,
        backend=SandboxExecutionBackend.DOCKER_SANDBOX,
        policy=policy or SandboxExecutionPolicy(allowed_environment_names=("HOME",)),
        factory=lambda: object(),
        image_reference=image_reference,
        command_prefix=("semgrep",),
    )


class _RuntimeRunner:
    def __init__(self, *, docker_available: bool = True, image_available: bool = True):
        self.docker_available = docker_available
        self.image_available = image_available
        self.commands: list[tuple[str, ...]] = []

    def run_control_command(
        self,
        argv: tuple[str, ...],
        timeout_seconds: float,
    ) -> DockerControlCommandResult:
        self.commands.append(argv)
        assert timeout_seconds == 5.0
        if argv[1] == "version":
            return DockerControlCommandResult(
                0 if self.docker_available else 1,
                b"27.0.0\n" if self.docker_available else b"",
                b"",
            )
        if argv[1:3] == ("image", "inspect"):
            return DockerControlCommandResult(
                0 if self.image_available else 1,
                b"sha256:local\n" if self.image_available else b"",
                b"",
            )
        raise AssertionError("availability probe attempted a mutating Docker command")

    def start_attached(self, *_args: object, **_kwargs: object) -> None:
        raise AssertionError("availability probe attempted container execution")


def _binding(
    definition: TrustedAdapterDefinition | None = None,
) -> TrustedSemgrepSourceBinding:
    return create_production_semgrep_source_binding(
        definition=definition or _definition(),
        ruleset=load_source_ruleset(),
    )


def _snapshot(
    *,
    docker_available: bool = True,
    image_available: bool = True,
):
    definition = _definition()
    binding = _binding(definition)
    runner = _RuntimeRunner(
        docker_available=docker_available,
        image_available=image_available,
    )
    snapshot = build_semgrep_source_analyzer_snapshot(
        binding,
        TrustedAdapterRegistry((definition,)),
        DockerSandboxExecutor(runner=runner),
    )
    return binding, snapshot, runner


def _profile(support_state: SourceSupportState) -> RepositoryProfile:
    entry = RepositoryManifestEntry(
        relative_path="app.py",
        size_bytes=12,
        sha256="7" * 64,
    )
    file = SourceFileRecord(
        entry=entry,
        content_kind=FileContentKind.TEXT,
        role=SourceFileRole.SOURCE,
        eligible_capabilities=(
            AnalysisCapability.REPOSITORY_PROFILING,
            AnalysisCapability.SOURCE_SAST,
        ),
    )
    paths = (file.relative_path,)
    return RepositoryProfile(
        repository_digest=repository_content_digest((entry,)),
        files=(file,),
        surfaces=tuple(
            sorted(
                (
                    AnalysisSurface(
                        capability=AnalysisCapability.REPOSITORY_PROFILING,
                        support_state=SourceSupportState.DETECTED,
                        eligible_paths=paths,
                    ),
                    AnalysisSurface(
                        capability=AnalysisCapability.SOURCE_SAST,
                        support_state=support_state,
                        eligible_paths=paths,
                    ),
                ),
                key=lambda surface: surface.capability.value,
            )
        ),
    )


def _python_entry(plan):
    return next(
        entry for entry in plan.entries if entry.capability is AnalysisCapability.SOURCE_SAST
    )


def test_trusted_semgrep_source_binding_retains_exact_provenance() -> None:
    definition = _definition()
    ruleset = load_source_ruleset()
    binding = create_production_semgrep_source_binding(
        definition=definition,
        ruleset=ruleset,
    )

    assert binding.source_analyzer_id == "semgrep-source-v1"
    assert binding.capability is AnalysisCapability.SOURCE_SAST
    assert binding.core_adapter_id == "semgrep-ce"
    assert binding.tool_family == "semgrep"
    assert binding.declared_tool_version == TOOL_VERSION
    assert binding.execution_backend is SandboxExecutionBackend.DOCKER_SANDBOX
    assert binding.sandbox_policy_fingerprint == definition.policy.fingerprint()
    assert binding.ruleset_id == ruleset.ruleset_id
    assert binding.ruleset_version == ruleset.version
    assert binding.ruleset_sha256 == ruleset.sha256
    assert binding.image_reference == IMAGE
    assert binding.binding_digest() == BINDING_GOLDEN_DIGEST
    assert binding.binding_digest() == _binding().binding_digest()
    with pytest.raises(FrozenInstanceError):
        binding.core_adapter_id = "other"  # type: ignore[misc]


def test_production_binding_rejects_old_placeholder_contract() -> None:
    with pytest.raises(InvalidSemgrepSourceBindingError):
        create_production_semgrep_source_binding(
            definition=_definition(image_reference=OLD_PLACEHOLDER_IMAGE),
            ruleset=load_source_ruleset(),
        )


def test_binding_uses_the_same_ruleset_as_core_semgrep_configuration(
    tmp_path: Path,
) -> None:
    ruleset = load_source_ruleset()
    definition = create_semgrep_trusted_definition(
        image_reference=IMAGE,
        tool_version=TOOL_VERSION,
        docker_executor=object(),  # type: ignore[arg-type]
        workspace_manager=RepositoryWorkspaceManager(tmp_path / "workspaces"),
        ruleset=ruleset,
        artifact_store=ContentAddressedArtifactStore(tmp_path / "artifacts"),
        source_resolver=lambda _run_id: tmp_path,
    )
    binding = TrustedSemgrepSourceBinding(
        definition=definition,
        ruleset=ruleset,
    )
    adapter = definition.factory()

    assert isinstance(adapter, SemgrepScannerAdapter)
    assert adapter.scan_plan.ruleset is ruleset
    assert binding.ruleset_id == adapter.scan_plan.ruleset.ruleset_id
    assert binding.ruleset_version == adapter.scan_plan.ruleset.version
    assert binding.ruleset_sha256 == adapter.scan_plan.ruleset.sha256


def test_binding_rejects_wrong_adapter_and_invalid_or_unpinned_image() -> None:
    with pytest.raises(InvalidSemgrepSourceBindingError):
        _binding(_definition(adapter_id="other-semgrep"))

    for image_reference in ("semgrep:latest", "semgrep:1.0", "semgrep"):
        with pytest.raises(InvalidTrustedAdapterDefinitionError):
            _definition(image_reference=image_reference)


def test_binding_revalidates_ruleset_content_digest() -> None:
    ruleset = load_source_ruleset()
    object.__setattr__(ruleset, "sha256", "0" * 64)

    with pytest.raises(InvalidSemgrepSourceBindingError):
        TrustedSemgrepSourceBinding(
            definition=_definition(),
            ruleset=ruleset,
        )


def test_snapshot_rejects_unknown_mismatched_or_corrupted_binding() -> None:
    definition = _definition()
    binding = _binding(definition)
    executor = DockerSandboxExecutor(runner=_RuntimeRunner())

    with pytest.raises(InvalidSemgrepSourceBindingError):
        build_semgrep_source_analyzer_snapshot(
            binding,
            TrustedAdapterRegistry(()),
            executor,
        )

    mismatched = _definition(tool_version="1.172.0")
    with pytest.raises(InvalidSemgrepSourceBindingError):
        build_semgrep_source_analyzer_snapshot(
            binding,
            TrustedAdapterRegistry((mismatched,)),
            executor,
        )

    object.__setattr__(binding, "capability", AnalysisCapability.SECRET_DETECTION)
    with pytest.raises(InvalidSemgrepSourceBindingError):
        build_semgrep_source_analyzer_snapshot(
            binding,
            TrustedAdapterRegistry((definition,)),
            executor,
        )


def test_available_snapshot_is_deterministic_and_uses_read_only_probes() -> None:
    binding, first, first_runner = _snapshot()
    _, second, second_runner = _snapshot()
    registry = TrustedSourceAnalyzerRegistry(analyzers=(first,))

    assert first == second
    assert first.analyzer_id == "semgrep-source-v1"
    assert first.capabilities == (AnalysisCapability.SOURCE_SAST,)
    assert first.available is True
    assert first.unavailable_reason_code is None
    assert registry.registry_digest() == REGISTRY_GOLDEN_DIGEST
    assert binding.binding_digest() == BINDING_GOLDEN_DIGEST
    expected = [
        ("docker", "version", "--format", "{{.Server.Version}}"),
        (
            "docker",
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            IMAGE,
        ),
    ]
    assert first_runner.commands == expected
    assert second_runner.commands == expected


@pytest.mark.parametrize(
    ("docker_available", "image_available", "reason_code"),
    (
        (False, True, "SEMGREP_DOCKER_UNAVAILABLE"),
        (True, False, "SEMGREP_IMAGE_UNAVAILABLE"),
    ),
)
def test_unavailable_snapshot_has_fixed_runtime_reason(
    docker_available: bool,
    image_available: bool,
    reason_code: str,
) -> None:
    _, snapshot, runner = _snapshot(
        docker_available=docker_available,
        image_available=image_available,
    )

    assert snapshot.available is False
    assert snapshot.unavailable_reason_code == reason_code
    assert all(command[1] in {"version", "image"} for command in runner.commands)


def test_existing_registry_rejects_duplicate_source_declaration() -> None:
    _, snapshot, _ = _snapshot()

    with pytest.raises(InvalidSourcePlanningRequestError):
        TrustedSourceAnalyzerRegistry(analyzers=(snapshot, snapshot))


def test_binding_api_accepts_only_trusted_configuration_inputs() -> None:
    binding_parameters = inspect.signature(TrustedSemgrepSourceBinding).parameters
    snapshot_parameters = inspect.signature(build_semgrep_source_analyzer_snapshot).parameters

    assert tuple(binding_parameters) == ("definition", "ruleset")
    assert tuple(snapshot_parameters) == (
        "binding",
        "adapter_registry",
        "docker_executor",
    )


def test_snapshot_drives_existing_planner_without_mutating_source_truth() -> None:
    _, available, _ = _snapshot()
    _, unavailable, _ = _snapshot(image_available=False)
    scannable = _profile(SourceSupportState.SCANNABLE)
    detected = _profile(SourceSupportState.DETECTED)
    support_policy = SourceSupportPolicy(
        capability_rules=(
            CapabilitySupportRule(
                AnalysisCapability.SOURCE_SAST,
                SourceSupportState.SCANNABLE,
            ),
        )
    )
    profile_before = scannable.canonical_data()
    support_before = support_policy.canonical_data()

    runnable = _python_entry(
        build_source_analysis_plan(
            scannable,
            TrustedSourceAnalyzerRegistry(analyzers=(available,)),
            SourcePlanningPolicy(),
        )
    )
    unavailable_entry = _python_entry(
        build_source_analysis_plan(
            scannable,
            TrustedSourceAnalyzerRegistry(analyzers=(unavailable,)),
            SourcePlanningPolicy(),
        )
    )
    missing = _python_entry(
        build_source_analysis_plan(
            scannable,
            TrustedSourceAnalyzerRegistry(),
            SourcePlanningPolicy(),
        )
    )
    detected_only = _python_entry(
        build_source_analysis_plan(
            detected,
            TrustedSourceAnalyzerRegistry(analyzers=(available,)),
            SourcePlanningPolicy(),
        )
    )

    assert runnable.action is SourcePlanAction.RUN
    assert runnable.analyzer_id == "semgrep-source-v1"
    assert runnable.support_state is SourceSupportState.SCANNABLE
    assert unavailable_entry.action is SourcePlanAction.SKIP
    assert unavailable_entry.reason_code == "ANALYZER_UNAVAILABLE"
    assert missing.action is SourcePlanAction.SKIP
    assert missing.reason_code == "NO_ANALYZER_REGISTERED"
    assert detected_only.action is SourcePlanAction.SKIP
    assert detected_only.reason_code == "CAPABILITY_DETECTED_ONLY"
    assert scannable.canonical_data() == profile_before
    assert support_policy.canonical_data() == support_before


def test_planner_does_not_repeat_runtime_discovery_or_execute(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, snapshot, _ = _snapshot()

    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("planner attempted runtime discovery or execution")

    monkeypatch.setattr(os, "system", fail)
    monkeypatch.setattr(os, "getenv", fail)
    monkeypatch.setattr(shutil, "which", fail)
    monkeypatch.setattr(subprocess, "run", fail)
    monkeypatch.setattr(subprocess, "Popen", fail)
    monkeypatch.setattr(DockerSandboxExecutor, "verify_runtime_prerequisites", fail)
    monkeypatch.setattr(DockerSandboxExecutor, "start", fail)
    monkeypatch.setattr(DockerSandboxExecutor, "execute", fail)
    monkeypatch.setattr(SemgrepScannerAdapter, "execute", fail)

    entry = _python_entry(
        build_source_analysis_plan(
            _profile(SourceSupportState.SCANNABLE),
            TrustedSourceAnalyzerRegistry(analyzers=(snapshot,)),
            SourcePlanningPolicy(),
        )
    )

    assert entry.action is SourcePlanAction.RUN
    assert not hasattr(entry, "command")
    assert not hasattr(entry, "execution_status")
