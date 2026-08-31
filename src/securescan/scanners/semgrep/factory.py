from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import datetime

from securescan.adapters.sandbox_policy import (
    InvalidSandboxPolicyError,
    SandboxExecutionBackend,
    SandboxExecutionPolicy,
)
from securescan.adapters.trusted_registry import TrustedAdapterDefinition
from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.scanners.semgrep.adapter import (
    SemgrepDockerExecutor,
    SemgrepJobInputResolver,
    SemgrepScannerAdapter,
    SemgrepSourceResolver,
)
from securescan.scanners.semgrep.models import InvalidSemgrepScanPlanError, SemgrepScanPlan
from securescan.scanners.semgrep.ruleset import TrustedSemgrepRuleset
from securescan.scanners.semgrep.source_binding import TrustedSemgrepSourceBinding
from securescan.scanners.semgrep.source_execution import (
    InvalidSourceSemgrepExecutionRequestError,
    SourceAwareSemgrepJobInputResolver,
    SourceSemgrepExecutionContextResolver,
    SourceSemgrepExecutionResolver,
)
from securescan.source.projection import SourceProjectionManager
from securescan.workspaces.intake import RepositoryWorkspaceManager


def create_semgrep_trusted_definition(
    *,
    image_reference: str,
    tool_version: str,
    docker_executor: SemgrepDockerExecutor,
    workspace_manager: RepositoryWorkspaceManager,
    ruleset: TrustedSemgrepRuleset,
    artifact_store: ContentAddressedArtifactStore,
    source_resolver: SemgrepSourceResolver,
    job_input_resolver: SemgrepJobInputResolver | None = None,
    plan: SemgrepScanPlan | None = None,
    policy: SandboxExecutionPolicy | None = None,
    clock: Callable[[], datetime] | None = None,
) -> TrustedAdapterDefinition:
    if policy is None:
        trusted_policy = SandboxExecutionPolicy(
            allowed_environment_names=("HOME",),
        )
    elif policy.allowed_environment_names == ():
        trusted_policy = replace(
            policy,
            allowed_environment_names=("HOME",),
        )
    elif policy.allowed_environment_names == ("HOME",):
        trusted_policy = policy
    else:
        raise InvalidSandboxPolicyError
    trusted_plan = plan or SemgrepScanPlan(ruleset=ruleset)
    if trusted_plan.ruleset != ruleset:
        raise InvalidSemgrepScanPlanError
    definition: TrustedAdapterDefinition

    def factory() -> SemgrepScannerAdapter:
        if clock is None:
            return SemgrepScannerAdapter(
                definition=definition,
                docker_executor=docker_executor,
                workspace_manager=workspace_manager,
                ruleset=ruleset,
                artifact_store=artifact_store,
                source_resolver=source_resolver,
                job_input_resolver=job_input_resolver,
                plan=trusted_plan,
            )
        return SemgrepScannerAdapter(
            definition=definition,
            docker_executor=docker_executor,
            workspace_manager=workspace_manager,
            ruleset=ruleset,
            artifact_store=artifact_store,
            source_resolver=source_resolver,
            job_input_resolver=job_input_resolver,
            plan=trusted_plan,
            clock=clock,
        )

    definition = TrustedAdapterDefinition(
        adapter_id="semgrep-ce",
        display_name="Semgrep Community Edition",
        tool_name="semgrep",
        tool_version=tool_version,
        backend=SandboxExecutionBackend.DOCKER_SANDBOX,
        policy=trusted_policy,
        factory=factory,
        image_reference=image_reference,
        command_prefix=("semgrep",),
        test_only=False,
    )
    return definition


def create_source_aware_semgrep_trusted_definition(
    *,
    image_reference: str,
    tool_version: str,
    docker_executor: SemgrepDockerExecutor,
    workspace_manager: RepositoryWorkspaceManager,
    ruleset: TrustedSemgrepRuleset,
    artifact_store: ContentAddressedArtifactStore,
    source_resolver: SemgrepSourceResolver,
    projection_manager: SourceProjectionManager,
    binding: TrustedSemgrepSourceBinding,
    plan: SemgrepScanPlan | None = None,
    policy: SandboxExecutionPolicy | None = None,
    clock: Callable[[], datetime] | None = None,
) -> TrustedAdapterDefinition:
    if (
        not isinstance(projection_manager, SourceProjectionManager)
        or not isinstance(binding, TrustedSemgrepSourceBinding)
    ):
        raise InvalidSourceSemgrepExecutionRequestError
    context_resolver = SourceSemgrepExecutionContextResolver(
        artifact_store,
        binding,
    )
    source_execution_resolver = SourceSemgrepExecutionResolver(
        context_resolver,
        projection_manager,
        binding,
    )
    job_input_resolver = SourceAwareSemgrepJobInputResolver(
        source_resolver,
        source_execution_resolver,
    )
    definition = create_semgrep_trusted_definition(
        image_reference=image_reference,
        tool_version=tool_version,
        docker_executor=docker_executor,
        workspace_manager=workspace_manager,
        ruleset=ruleset,
        artifact_store=artifact_store,
        source_resolver=source_resolver,
        job_input_resolver=job_input_resolver,
        plan=plan,
        policy=policy,
        clock=clock,
    )
    try:
        matches_binding = binding.matches_definition(definition)
    except Exception as exc:
        raise InvalidSourceSemgrepExecutionRequestError from exc
    if not matches_binding:
        raise InvalidSourceSemgrepExecutionRequestError
    return definition
