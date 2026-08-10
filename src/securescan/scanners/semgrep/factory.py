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
    SemgrepScannerAdapter,
    SemgrepSourceResolver,
)
from securescan.scanners.semgrep.models import InvalidSemgrepScanPlanError, SemgrepScanPlan
from securescan.scanners.semgrep.ruleset import TrustedSemgrepRuleset
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
                plan=trusted_plan,
            )
        return SemgrepScannerAdapter(
            definition=definition,
            docker_executor=docker_executor,
            workspace_manager=workspace_manager,
            ruleset=ruleset,
            artifact_store=artifact_store,
            source_resolver=source_resolver,
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
