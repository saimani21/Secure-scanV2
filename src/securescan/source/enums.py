from enum import StrEnum


class SourceInputType(StrEnum):
    LOCAL_DIRECTORY = "local_directory"


class SourceSupportState(StrEnum):
    DETECTED = "detected"
    SCANNABLE = "scannable"
    BENCHMARKED = "benchmarked"
    PRODUCT_SUPPORTED = "product_supported"
    UNSUPPORTED = "unsupported"


class SourceExecutionStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class CoverageStatus(StrEnum):
    FULL_FOR_DECLARED_SCOPE = "full_for_declared_scope"
    PARTIAL = "partial"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class AssessmentStatus(StrEnum):
    OBSERVATIONS_ONLY = "observations_only"
    TRIAGE_REQUIRED = "triage_required"
    HUMAN_REVIEWED = "human_reviewed"
    VALIDATED = "validated"


class FileContentKind(StrEnum):
    TEXT = "text"
    BINARY = "binary"
    UNKNOWN = "unknown"


class SourceFileRole(StrEnum):
    SOURCE = "source"
    MANIFEST = "manifest"
    LOCKFILE = "lockfile"
    TERRAFORM = "terraform"
    DOCKERFILE = "dockerfile"
    CONFIGURATION = "configuration"
    DOCUMENTATION = "documentation"
    BINARY = "binary"
    OTHER = "other"


class SourceFileFlag(StrEnum):
    BINARY = "binary"
    GENERATED = "generated"
    TEST = "test"
    UNSUPPORTED = "unsupported"
    VENDORED = "vendored"


class AnalysisCapability(StrEnum):
    REPOSITORY_PROFILING = "repository_profiling"
    PYTHON_SAST = "python_sast"
    SECRET_DETECTION = "secret_detection"
    DEPENDENCY_ADVISORY_MATCHING = "dependency_advisory_matching"
    TERRAFORM_SOURCE_POLICY = "terraform_source_policy"
    DOCKERFILE_POLICY = "dockerfile_policy"
    PACKAGE_INVENTORY = "package_inventory"
