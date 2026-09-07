from enum import StrEnum


class TargetType(StrEnum):
    SOURCE_REPOSITORY = "source_repository"
    LIVE_WEB_APPLICATION = "live_web_application"
    LIVE_API = "live_api"
    ANDROID_APK = "android_apk"
    WINDOWS_PE = "windows_pe"
    CONTAINER_IMAGE = "container_image"


class RunStatus(StrEnum):
    SUBMITTED = "submitted"
    VALIDATING = "validating"
    QUEUED = "queued"
    RUNNING = "running"
    CAPTURING_OUTPUT = "capturing_output"
    VALIDATING_OUTPUT = "validating_output"
    SANITIZING = "sanitizing"
    PARSING = "parsing"
    PERSISTING = "persisting"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ExecutionOutcome(StrEnum):
    SUCCEEDED_NO_OBSERVATIONS = "succeeded_no_observations"
    SUCCEEDED_WITH_OBSERVATIONS = "succeeded_with_observations"
    SUCCEEDED_WITH_WARNINGS = "succeeded_with_warnings"
    PARTIAL_ANALYSIS = "partial_analysis"
    UNSUPPORTED_TARGET = "unsupported_target"
    UNSUPPORTED_CONFIGURATION = "unsupported_configuration"
    TOOL_NOT_AVAILABLE = "tool_not_available"
    TOOL_VERSION_REJECTED = "tool_version_rejected"
    NETWORK_REQUIRED = "network_required"
    AUTHORIZATION_REQUIRED = "authorization_required"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    RESOURCE_LIMIT_EXCEEDED = "resource_limit_exceeded"
    OUTPUT_LIMIT_EXCEEDED = "output_limit_exceeded"
    INVALID_OUTPUT = "invalid_output"
    PARSER_INCOMPATIBLE = "parser_incompatible"
    SECURITY_POLICY_BLOCKED = "security_policy_blocked"
    INTERNAL_ERROR = "internal_error"


class JobFailureCategory(StrEnum):
    RETRYABLE_INFRASTRUCTURE = "retryable_infrastructure"
    NON_RETRYABLE_INPUT = "non_retryable_input"
    NON_RETRYABLE_PARSER = "non_retryable_parser"
    NON_RETRYABLE_POLICY = "non_retryable_policy"
    TIMEOUT = "timeout"
    OUTPUT_LIMIT = "output_limit"
    WORKER_CRASH = "worker_crash"
    CANCELLED = "cancelled"


class ObservationType(StrEnum):
    SOURCE_RULE_MATCH = "source_rule_match"
    SECRET_CANDIDATE = "secret_candidate"
    DEPENDENCY_VULNERABILITY = "dependency_vulnerability"
    CONFIGURATION_POLICY_VIOLATION = "configuration_policy_violation"
    TEST_OBSERVATION = "test_observation"


class ArtifactKind(StrEnum):
    SOURCE_EXECUTION_CONTEXT = "source_execution_context"
    ORCHESTRATION_PLANNING_SNAPSHOT = "orchestration_planning_snapshot"
    SANITIZED_NATIVE_REPORT = "sanitized_native_report"
    STDOUT = "stdout"
    STDERR = "stderr"
    SECURESCAN_REPORT = "securescan_report"
    SARIF = "sarif"
    SBOM = "sbom"
class JobStatus(StrEnum):
    SUBMITTED = "submitted"
    QUEUED = "queued"
    LEASED = "leased"
    RUNNING = "running"
    RETRY_PENDING = "retry_pending"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"
