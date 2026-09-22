"""Public orchestration facade with helper-safe lazy imports."""

from __future__ import annotations

from importlib import import_module
from typing import Any

_MODULE_EXPORTS = {
    "dependency_evaluation": {
        "DEPENDENCY_EVALUATION_MEDIA_TYPE",
        "DEPENDENCY_EVALUATION_SCHEMA_VERSION",
        "DependencyEvaluationDecision",
        "PackageScopeClassification",
        "SourceDependencyEvaluation",
        "SourceDependencyEvaluationConflictError",
        "SourceDependencyEvaluationError",
        "SourceDependencyEvaluationRecord",
        "SourceDependencyEvaluationService",
    },
    "execution": {
        "AcceptedSourceNativeResult",
        "SourceScannerAttemptBlockedError",
        "SourceScannerAttemptRecord",
        "SourceScannerAttemptService",
        "SourceScannerExecutionConflictError",
        "SourceScannerExecutionError",
        "SourceScannerJobRecord",
        "SourceScannerJobService",
        "SourceScannerLeaseReconciliationService",
        "SourceScannerResultRejectedError",
        "source_scanner_job_id",
    },
    "execution_models": {
        "CLEANUP_RECEIPT_SCHEMA_VERSION",
        "SAFE_NATIVE_RESULT_MEDIA_TYPE",
        "SAFE_NATIVE_RESULT_SCHEMA_VERSION",
        "SANDBOX_CLEANUP_RECEIPT_SCHEMA_VERSION",
        "AttemptContainmentOutcome",
        "SafeSourceNativeResult",
        "SourceAttemptCleanupReceipt",
        "SourceSandboxCleanupReceipt",
        "SourceScannerExecutionIntegrityError",
        "SourceScannerFailureCode",
    },
    "models": {
        "AUTHORITY_ROSTER_SCHEMA_VERSION",
        "PLANNING_SNAPSHOT_MEDIA_TYPE",
        "PLANNING_SNAPSHOT_SCHEMA_VERSION",
        "SOURCE_V1_AUTHORITY_ROSTER_DIGEST",
        "OrchestrationContainmentState",
        "OrchestrationLifecycleState",
        "OrchestrationNodeDisposition",
        "OrchestrationNodeLifecycleState",
        "OrchestrationTerminalOutcome",
        "PlannedSourceDependency",
        "PlannedSourceNode",
        "SourceAuthority",
        "SourceOrchestrationIntegrityError",
        "SourcePlanningSnapshot",
        "TrustedSourceAuthority",
        "TrustedSourceAuthorityRoster",
        "build_source_v1_topology",
        "frozen_source_v1_authority_roster",
        "source_node_id",
    },
    "sandbox_execution": {
        "AttemptBoundDockerExecutionHandle",
        "AttemptBoundDockerExecutor",
        "SourceSandboxReconciliationService",
    },
    "service": {
        "SourceOrchestrationConflictError",
        "SourceOrchestrationCreateRequest",
        "SourceOrchestrationError",
        "SourceOrchestrationNotFoundError",
        "SourceOrchestrationRecord",
        "SourceOrchestrationService",
        "SourceOrchestrationStaleVersionError",
        "SourceOrchestrationStateError",
        "SourcePlanningSnapshotStore",
    },
}
_EXPORT_MODULE = {
    name: module_name for module_name, names in _MODULE_EXPORTS.items() for name in names
}


def __getattr__(name: str) -> Any:
    module_name = _EXPORT_MODULE.get(name)
    if module_name is None:
        raise AttributeError(name)
    value = getattr(import_module(f"{__name__}.{module_name}"), name)
    globals()[name] = value
    return value


__all__ = sorted(_EXPORT_MODULE)
