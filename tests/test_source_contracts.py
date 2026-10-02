from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError

import pytest

from securescan.source import (
    AnalysisCapability,
    AnalysisSurface,
    AssessmentStatus,
    CoverageStatus,
    FileContentKind,
    LanguageSupport,
    RepositoryComponent,
    RepositoryProfile,
    SourceExecutionStatus,
    SourceFileFlag,
    SourceFileRecord,
    SourceFileRole,
    SourceStatusSummary,
    SourceSupportState,
)
from securescan.workspaces.models import (
    RepositoryManifestEntry,
    repository_content_digest,
)


def _entry(relative_path: str, content: bytes) -> RepositoryManifestEntry:
    return RepositoryManifestEntry(
        relative_path=relative_path,
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
    )


def _valid_profile() -> RepositoryProfile:
    files = (
        SourceFileRecord(
            entry=_entry("main.tf", b'resource "x" "y" {}\n'),
            content_kind=FileContentKind.TEXT,
            role=SourceFileRole.TERRAFORM,
            language="HCL",
            component_id="root",
            eligible_capabilities=(AnalysisCapability.TERRAFORM_SOURCE_POLICY,),
        ),
        SourceFileRecord(
            entry=_entry("poetry.lock", b"package = []\n"),
            content_kind=FileContentKind.TEXT,
            role=SourceFileRole.LOCKFILE,
            component_id="root",
            eligible_capabilities=(AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING,),
        ),
        SourceFileRecord(
            entry=_entry("pyproject.toml", b"[project]\nname='demo'\n"),
            content_kind=FileContentKind.TEXT,
            role=SourceFileRole.MANIFEST,
            component_id="root",
        ),
        SourceFileRecord(
            entry=_entry("src/app.py", b"print('hello')\n"),
            content_kind=FileContentKind.TEXT,
            role=SourceFileRole.SOURCE,
            language="Python",
            component_id="root",
            eligible_capabilities=(
                AnalysisCapability.SECRET_DETECTION,
                AnalysisCapability.SOURCE_SAST,
            ),
        ),
    )
    return RepositoryProfile(
        repository_digest=repository_content_digest(tuple(file.entry for file in files)),
        files=files,
        components=(
            RepositoryComponent(
                component_id="root",
                display_name="Repository root",
                root_path=".",
                manifest_paths=("pyproject.toml",),
                lockfile_paths=("poetry.lock",),
            ),
        ),
        languages=(
            LanguageSupport(
                language="HCL",
                file_count=1,
                eligible_file_count=1,
                support_state=SourceSupportState.PRODUCT_SUPPORTED,
            ),
            LanguageSupport(
                language="Python",
                file_count=1,
                eligible_file_count=1,
                support_state=SourceSupportState.PRODUCT_SUPPORTED,
            ),
        ),
        surfaces=(
            AnalysisSurface(
                capability=AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING,
                support_state=SourceSupportState.PRODUCT_SUPPORTED,
                component_id="root",
                eligible_paths=("poetry.lock",),
            ),
            AnalysisSurface(
                capability=AnalysisCapability.SOURCE_SAST,
                support_state=SourceSupportState.PRODUCT_SUPPORTED,
                component_id="root",
                eligible_paths=("src/app.py",),
            ),
            AnalysisSurface(
                capability=AnalysisCapability.TERRAFORM_SOURCE_POLICY,
                support_state=SourceSupportState.PRODUCT_SUPPORTED,
                component_id="root",
                eligible_paths=("main.tf",),
            ),
        ),
    )


def test_source_file_record_is_immutable_and_canonical() -> None:
    file = SourceFileRecord(
        entry=_entry("src/app.py", b"print('hello')\n"),
        content_kind=FileContentKind.TEXT,
        role=SourceFileRole.SOURCE,
        language="Python",
        eligible_capabilities=(
            AnalysisCapability.SECRET_DETECTION,
            AnalysisCapability.SOURCE_SAST,
        ),
    )

    assert file.relative_path == "src/app.py"
    assert file.canonical_data()["language"] == "Python"
    with pytest.raises(FrozenInstanceError):
        file.language = "Java"  # type: ignore[misc]


def test_source_file_record_rejects_noncanonical_flags_and_capabilities() -> None:
    entry = _entry("src/app.py", b"print('hello')\n")

    with pytest.raises(ValueError, match="Source file record is invalid"):
        SourceFileRecord(
            entry=entry,
            content_kind=FileContentKind.TEXT,
            role=SourceFileRole.SOURCE,
            flags=(
                SourceFileFlag.VENDORED,
                SourceFileFlag.GENERATED,
            ),
        )

    with pytest.raises(ValueError, match="Source file record is invalid"):
        SourceFileRecord(
            entry=entry,
            content_kind=FileContentKind.BINARY,
            role=SourceFileRole.BINARY,
        )

    with pytest.raises(ValueError, match="Source file record is invalid"):
        SourceFileRecord(
            entry=entry,
            content_kind=FileContentKind.TEXT,
            role=SourceFileRole.SOURCE,
            eligible_capabilities=(
                AnalysisCapability.SOURCE_SAST,
                AnalysisCapability.SECRET_DETECTION,
            ),
        )


def test_repository_component_rejects_escape_and_unsorted_paths() -> None:
    with pytest.raises(ValueError, match="Repository component is invalid"):
        RepositoryComponent(
            component_id="api",
            display_name="API",
            root_path="services/api",
            manifest_paths=("outside/pyproject.toml",),
        )

    with pytest.raises(ValueError, match="Repository component is invalid"):
        RepositoryComponent(
            component_id="api",
            display_name="API",
            root_path=".",
            manifest_paths=("z.toml", "a.toml"),
        )


def test_unsupported_surface_requires_reason_and_has_no_eligible_paths() -> None:
    with pytest.raises(ValueError, match="Analysis surface is invalid"):
        AnalysisSurface(
            capability=AnalysisCapability.SOURCE_SAST,
            support_state=SourceSupportState.UNSUPPORTED,
        )

    with pytest.raises(ValueError, match="Analysis surface is invalid"):
        AnalysisSurface(
            capability=AnalysisCapability.SOURCE_SAST,
            support_state=SourceSupportState.UNSUPPORTED,
            eligible_paths=("src/app.py",),
            reason_code="LANGUAGE_UNSUPPORTED",
        )

    surface = AnalysisSurface(
        capability=AnalysisCapability.SOURCE_SAST,
        support_state=SourceSupportState.UNSUPPORTED,
        reason_code="LANGUAGE_UNSUPPORTED",
    )

    assert surface.eligible_paths == ()


def test_repository_profile_is_coherent_and_deterministic() -> None:
    profile = _valid_profile()

    assert profile.file_count == 4
    assert profile.total_bytes > 0
    assert len(profile.profile_digest()) == 64
    assert profile.profile_digest() == profile.profile_digest()

    canonical = profile.canonical_data()
    serialized = json.dumps(canonical, sort_keys=True)

    assert canonical["files"][0]["relative_path"] == "main.tf"
    assert "/home/" not in serialized
    assert canonical["components"][0]["root_path"] == "."


def test_repository_profile_rejects_wrong_repository_digest() -> None:
    profile = _valid_profile()

    with pytest.raises(
        ValueError,
        match="Repository profile digest does not match its files",
    ):
        RepositoryProfile(
            repository_digest="a" * 64,
            files=profile.files,
            components=profile.components,
            languages=profile.languages,
            surfaces=profile.surfaces,
        )


def test_repository_profile_rejects_unknown_component() -> None:
    file = SourceFileRecord(
        entry=_entry("src/app.py", b"print('hello')\n"),
        content_kind=FileContentKind.TEXT,
        role=SourceFileRole.SOURCE,
        language="Python",
        component_id="missing",
    )
    files = (file,)

    with pytest.raises(
        ValueError,
        match="Repository profile references an unknown component",
    ):
        RepositoryProfile(
            repository_digest=repository_content_digest(tuple(item.entry for item in files)),
            files=files,
            languages=(
                LanguageSupport(
                    language="Python",
                    file_count=1,
                    eligible_file_count=0,
                    support_state=SourceSupportState.DETECTED,
                ),
            ),
        )


def test_repository_profile_rejects_incorrect_language_summary() -> None:
    profile = _valid_profile()

    with pytest.raises(
        ValueError,
        match="Repository language count is inconsistent",
    ):
        RepositoryProfile(
            repository_digest=profile.repository_digest,
            files=profile.files,
            components=profile.components,
            languages=(
                LanguageSupport(
                    language="HCL",
                    file_count=1,
                    eligible_file_count=1,
                    support_state=SourceSupportState.PRODUCT_SUPPORTED,
                ),
                LanguageSupport(
                    language="Python",
                    file_count=2,
                    eligible_file_count=1,
                    support_state=SourceSupportState.PRODUCT_SUPPORTED,
                ),
            ),
            surfaces=profile.surfaces,
        )


def test_status_dimensions_remain_independent() -> None:
    incomplete = SourceStatusSummary(
        execution_status=SourceExecutionStatus.COMPLETE,
        coverage_status=CoverageStatus.PARTIAL,
        assessment_status=AssessmentStatus.OBSERVATIONS_ONLY,
    )

    assert not incomplete.automated_scope_completed
    assert not incomplete.human_validated

    validated = SourceStatusSummary(
        execution_status=SourceExecutionStatus.COMPLETE,
        coverage_status=CoverageStatus.FULL_FOR_DECLARED_SCOPE,
        assessment_status=AssessmentStatus.VALIDATED,
    )

    assert validated.automated_scope_completed
    assert validated.human_validated
    assert validated.canonical_data() == {
        "assessment_status": "validated",
        "coverage_status": "full_for_declared_scope",
        "execution_status": "complete",
    }
