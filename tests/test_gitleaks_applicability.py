from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from securescan.scanners.gitleaks.applicability import (
    GITLEAKS_APPLICABILITY_SCHEMA_VERSION,
    GITLEAKS_CONFIGURATION_UNAVAILABLE,
    GITLEAKS_EXECUTABLE_UNAVAILABLE,
    GITLEAKS_SCANNABLE_REASON,
    GITLEAKS_V04C_BASELINE_COMMIT,
    GITLEAKS_VERSION_UNAVAILABLE,
    GitleaksApplicabilityError,
    apply_gitleaks_source_applicability,
    build_gitleaks_source_analyzer_snapshot,
    with_gitleaks_planning_policy,
    with_gitleaks_source_support,
)
from securescan.scanners.gitleaks.binding import (
    GitleaksConfigurationIntegrityError,
    GitleaksExecutableIntegrityError,
    GitleaksVersionVerificationError,
    TrustedGitleaksBinding,
)
from securescan.scanners.gitleaks.source_execution import (
    GITLEAKS_SOURCE_ANALYZER_ID,
)
from securescan.source.components import (
    ComponentizedRepositoryInventory,
)
from securescan.source.coverage import build_repository_profile
from securescan.source.enums import (
    AnalysisCapability,
    FileContentKind,
    SourceFileFlag,
    SourceFileRole,
    SourceSupportState,
)
from securescan.source.models import (
    AnalysisSurface,
    RepositoryProfile,
    SourceFileRecord,
)
from securescan.source.planning import (
    CapabilityPathSelectionRule,
    SourcePlanAction,
    SourcePlanningPolicy,
    TrustedSourceAnalyzerRegistry,
    build_source_analysis_plan,
)
from securescan.source.support import (
    CapabilitySupportRule,
    SourceSupportPolicy,
    assess_repository_language_support,
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


def _record(
    relative_path: str,
    *,
    content: bytes = b"value\n",
    binary: bool = False,
    flags: tuple[SourceFileFlag, ...] = (),
) -> SourceFileRecord:
    effective_flags = set(flags)
    if binary:
        effective_flags.add(SourceFileFlag.BINARY)

    return SourceFileRecord(
        entry=_entry(relative_path, content),
        content_kind=(
            FileContentKind.BINARY
            if binary
            else FileContentKind.TEXT
        ),
        role=(
            SourceFileRole.BINARY
            if binary
            else SourceFileRole.SOURCE
        ),
        language=None,
        component_id=None,
        flags=tuple(
            sorted(
                effective_flags,
                key=lambda flag: flag.value,
            )
        ),
        eligible_capabilities=(
            AnalysisCapability.REPOSITORY_PROFILING,
        ),
    )


def _profile(
    *files: SourceFileRecord,
) -> RepositoryProfile:
    ordered = tuple(
        sorted(
            files,
            key=lambda file: file.relative_path,
        )
    )
    paths = tuple(file.relative_path for file in ordered)

    return RepositoryProfile(
        repository_digest=repository_content_digest(
            tuple(file.entry for file in ordered)
        ),
        files=ordered,
        components=(),
        languages=(),
        surfaces=(
            AnalysisSurface(
                capability=AnalysisCapability.REPOSITORY_PROFILING,
                support_state=SourceSupportState.DETECTED,
                eligible_paths=paths,
            ),
        ),
    )


def _secret_surface(profile: RepositoryProfile) -> AnalysisSurface:
    return next(
        surface
        for surface in profile.surfaces
        if surface.capability is AnalysisCapability.SECRET_DETECTION
    )


def _gitleaks_support_policy(
    reason_code: str = GITLEAKS_SCANNABLE_REASON,
) -> SourceSupportPolicy:
    return SourceSupportPolicy(
        capability_rules=(
            CapabilitySupportRule(
                AnalysisCapability.SECRET_DETECTION,
                SourceSupportState.SCANNABLE,
                reason_code,
            ),
        )
    )


def _apply_gitleaks(
    profile: RepositoryProfile,
    policy: SourceSupportPolicy | None = None,
) -> RepositoryProfile:
    return apply_gitleaks_source_applicability(
        profile,
        _gitleaks_support_policy() if policy is None else policy,
    )


def _trusted_binding() -> TrustedGitleaksBinding:
    return TrustedGitleaksBinding(
        executable_path=Path("/opt/securescan/bin/gitleaks"),
        executable_sha256="a" * 64,
        config_path=Path(
            "/opt/securescan/config/securescan-gitleaks-v1.toml"
        ),
        config_sha256="b" * 64,
        ignore_path=Path(
            "/opt/securescan/config/securescan-gitleaks-v1.ignore"
        ),
        ignore_sha256="c" * 64,
    )


def test_schema_and_v04c_baseline_are_frozen() -> None:
    assert GITLEAKS_APPLICABILITY_SCHEMA_VERSION == (
        "securescan-gitleaks-applicability-v0.4D"
    )
    assert GITLEAKS_V04C_BASELINE_COMMIT == (
        "d488fd96eb573687d9887c829d4d5bf26b31fc9a"
    )


def test_support_policy_promotes_only_secret_detection() -> None:
    original = SourceSupportPolicy(
        capability_rules=(
            CapabilitySupportRule(
                AnalysisCapability.PYTHON_SAST,
                SourceSupportState.SCANNABLE,
                "PYTHON_SCANNABLE_BY_POLICY",
            ),
        )
    )

    updated = with_gitleaks_source_support(original)

    secret = updated.capability_rule_for(
        AnalysisCapability.SECRET_DETECTION
    )

    assert secret == CapabilitySupportRule(
        AnalysisCapability.SECRET_DETECTION,
        SourceSupportState.SCANNABLE,
        GITLEAKS_SCANNABLE_REASON,
    )
    assert updated.language_rules == original.language_rules
    assert updated.default_language_state is original.default_language_state
    assert updated.default_capability_state is original.default_capability_state
    assert original.capability_rule_for(
        AnalysisCapability.SECRET_DETECTION
    ).support_state is SourceSupportState.DETECTED


def test_identical_gitleaks_support_rule_is_idempotent() -> None:
    once = with_gitleaks_source_support(SourceSupportPolicy())
    twice = with_gitleaks_source_support(once)

    assert once == twice
    assert once.policy_digest() == twice.policy_digest()


def test_conflicting_explicit_secret_support_rule_fails_closed() -> None:
    policy = SourceSupportPolicy(
        capability_rules=(
            CapabilitySupportRule(
                AnalysisCapability.SECRET_DETECTION,
                SourceSupportState.DETECTED,
                "SECRET_DETECTION_STILL_DETECTED",
            ),
        )
    )

    with pytest.raises(GitleaksApplicabilityError):
        with_gitleaks_source_support(policy)


def test_planning_policy_freezes_zero_secret_exclusions() -> None:
    updated = with_gitleaks_planning_policy(SourcePlanningPolicy())

    assert updated.excluded_flags_for(
        AnalysisCapability.SECRET_DETECTION
    ) == ()

    rule = next(
        rule
        for rule in updated.path_rules
        if rule.capability is AnalysisCapability.SECRET_DETECTION
    )
    assert rule == CapabilityPathSelectionRule(
        AnalysisCapability.SECRET_DETECTION,
        (),
    )


def test_conflicting_secret_path_exclusion_fails_closed() -> None:
    policy = SourcePlanningPolicy(
        path_rules=(
            CapabilityPathSelectionRule(
                AnalysisCapability.SECRET_DETECTION,
                (SourceFileFlag.BINARY,),
            ),
        )
    )

    with pytest.raises(GitleaksApplicabilityError):
        with_gitleaks_planning_policy(policy)


def test_repository_wide_surface_includes_all_file_classes() -> None:
    profile = _profile(
        _record("README.md"),
        _record(
            "generated/client.py",
            flags=(SourceFileFlag.GENERATED,),
        ),
        _record(
            "tests/fixture.py",
            flags=(SourceFileFlag.TEST,),
        ),
        _record(
            "vendor/sdk.py",
            flags=(SourceFileFlag.VENDORED,),
        ),
        _record(
            "certificates/client.p12",
            content=b"\x00\x01\x02",
            binary=True,
        ),
    )

    enriched = _apply_gitleaks(profile)
    surface = _secret_surface(enriched)

    assert surface.support_state is SourceSupportState.SCANNABLE
    assert surface.component_id is None
    assert surface.reason_code == GITLEAKS_SCANNABLE_REASON
    assert surface.eligible_paths == (
        "README.md",
        "certificates/client.p12",
        "generated/client.py",
        "tests/fixture.py",
        "vendor/sdk.py",
    )


def test_path_only_binary_candidate_remains_secret_eligible() -> None:
    profile = _apply_gitleaks(
        _profile(
            _record(
                "identity/client.pfx",
                content=b"\x00\x01\x02\x03",
                binary=True,
            )
        )
    )

    file = profile.files[0]
    surface = _secret_surface(profile)

    assert SourceFileFlag.BINARY in file.flags
    assert AnalysisCapability.SECRET_DETECTION in file.eligible_capabilities
    assert surface.eligible_paths == ("identity/client.pfx",)


def test_applicability_does_not_filter_generated_vendor_or_tests() -> None:
    profile = _apply_gitleaks(
        _profile(
            _record(
                "generated/generated.py",
                flags=(SourceFileFlag.GENERATED,),
            ),
            _record(
                "tests/test_config.py",
                flags=(SourceFileFlag.TEST,),
            ),
            _record(
                "vendor/config.py",
                flags=(SourceFileFlag.VENDORED,),
            ),
        )
    )

    assert _secret_surface(profile).eligible_paths == (
        "generated/generated.py",
        "tests/test_config.py",
        "vendor/config.py",
    )


def test_empty_repository_has_no_secret_detection_surface() -> None:
    enriched = _apply_gitleaks(_profile())

    assert all(
        surface.capability is not AnalysisCapability.SECRET_DETECTION
        for surface in enriched.surfaces
    )


def test_profile_enrichment_is_deterministic_and_non_mutating() -> None:
    original = _profile(
        _record("app.py"),
        _record("certificate.p12", binary=True),
    )
    before = original.canonical_data()

    first = _apply_gitleaks(original)
    second = _apply_gitleaks(original)

    assert first == second
    assert first.profile_digest() == second.profile_digest()
    assert original.canonical_data() == before
    assert original.profile_digest() != first.profile_digest()


def test_existing_other_surfaces_are_preserved() -> None:
    original = _profile(_record("app.py"))
    extra = AnalysisSurface(
        capability=AnalysisCapability.PYTHON_SAST,
        support_state=SourceSupportState.SCANNABLE,
        eligible_paths=("app.py",),
    )
    original = replace(
        original,
        surfaces=tuple(
            sorted(
                (*original.surfaces, extra),
                key=lambda surface: (
                    surface.capability.value,
                    surface.component_id or "",
                ),
            )
        ),
    )

    enriched = _apply_gitleaks(original)

    python = next(
        surface
        for surface in enriched.surfaces
        if surface.capability is AnalysisCapability.PYTHON_SAST
    )

    assert python == extra


def test_component_scoped_secret_surface_is_rejected() -> None:
    profile = _profile(_record("app.py"))

    hostile = AnalysisSurface(
        capability=AnalysisCapability.SECRET_DETECTION,
        support_state=SourceSupportState.DETECTED,
        component_id="component-a",
        eligible_paths=("app.py",),
    )

    object.__setattr__(
        profile,
        "surfaces",
        tuple(
            sorted(
                (*profile.surfaces, hostile),
                key=lambda surface: (
                    surface.capability.value,
                    surface.component_id or "",
                ),
            )
        ),
    )

    with pytest.raises(GitleaksApplicabilityError):
        _apply_gitleaks(profile)


def test_available_analyzer_snapshot_registers_secret_detection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _trusted_binding()

    monkeypatch.setattr(
        TrustedGitleaksBinding,
        "verify_runtime",
        lambda self, executor=None: None,
    )

    analyzer = build_gitleaks_source_analyzer_snapshot(binding)

    assert analyzer.analyzer_id == GITLEAKS_SOURCE_ANALYZER_ID
    assert analyzer.capabilities == (
        AnalysisCapability.SECRET_DETECTION,
    )
    assert analyzer.available is True
    assert analyzer.unavailable_reason_code is None


@pytest.mark.parametrize(
    ("error_type", "expected_reason"),
    (
        (
            GitleaksExecutableIntegrityError,
            GITLEAKS_EXECUTABLE_UNAVAILABLE,
        ),
        (
            GitleaksVersionVerificationError,
            GITLEAKS_VERSION_UNAVAILABLE,
        ),
        (
            GitleaksConfigurationIntegrityError,
            GITLEAKS_CONFIGURATION_UNAVAILABLE,
        ),
    ),
)
def test_known_runtime_unavailability_is_planner_visible(
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[Exception],
    expected_reason: str,
) -> None:
    binding = _trusted_binding()

    def fail(self, executor=None):
        raise error_type()

    monkeypatch.setattr(
        TrustedGitleaksBinding,
        "verify_runtime",
        fail,
    )

    analyzer = build_gitleaks_source_analyzer_snapshot(binding)

    assert analyzer.available is False
    assert analyzer.unavailable_reason_code == expected_reason


def test_available_analyzer_plans_repository_wide_secret_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _apply_gitleaks(
        _profile(
            _record("app.py"),
            _record(
                "certificate.p12",
                content=b"\x00\x01",
                binary=True,
            ),
            _record(
                "tests/fixture.py",
                flags=(SourceFileFlag.TEST,),
            ),
            _record(
                "vendor/config.py",
                flags=(SourceFileFlag.VENDORED,),
            ),
        )
    )

    binding = _trusted_binding()

    monkeypatch.setattr(
        TrustedGitleaksBinding,
        "verify_runtime",
        lambda self, executor=None: None,
    )

    analyzer = build_gitleaks_source_analyzer_snapshot(binding)
    registry = TrustedSourceAnalyzerRegistry(
        analyzers=(analyzer,)
    )

    plan = build_source_analysis_plan(
        profile,
        registry,
        with_gitleaks_planning_policy(SourcePlanningPolicy()),
    )

    secret = next(
        entry
        for entry in plan.entries
        if entry.capability is AnalysisCapability.SECRET_DETECTION
    )

    assert secret.action is SourcePlanAction.RUN
    assert secret.reason_code == "PLANNED"
    assert secret.analyzer_id == GITLEAKS_SOURCE_ANALYZER_ID
    assert secret.selected_paths == (
        "app.py",
        "certificate.p12",
        "tests/fixture.py",
        "vendor/config.py",
    )
    assert secret.excluded_paths == ()


def test_missing_analyzer_is_explicit_skip() -> None:
    profile = _apply_gitleaks(
        _profile(_record("app.py"))
    )

    plan = build_source_analysis_plan(
        profile,
        TrustedSourceAnalyzerRegistry(),
        with_gitleaks_planning_policy(SourcePlanningPolicy()),
    )

    secret = next(
        entry
        for entry in plan.entries
        if entry.capability is AnalysisCapability.SECRET_DETECTION
    )

    assert secret.action is SourcePlanAction.SKIP
    assert secret.reason_code == "NO_ANALYZER_REGISTERED"


def test_unavailable_analyzer_is_explicit_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _apply_gitleaks(
        _profile(_record("app.py"))
    )

    binding = _trusted_binding()

    def unavailable(self, executor=None):
        raise GitleaksExecutableIntegrityError()

    monkeypatch.setattr(
        TrustedGitleaksBinding,
        "verify_runtime",
        unavailable,
    )

    registry = TrustedSourceAnalyzerRegistry(
        analyzers=(
            build_gitleaks_source_analyzer_snapshot(binding),
        )
    )

    plan = build_source_analysis_plan(
        profile,
        registry,
        with_gitleaks_planning_policy(SourcePlanningPolicy()),
    )

    secret = next(
        entry
        for entry in plan.entries
        if entry.capability is AnalysisCapability.SECRET_DETECTION
    )

    assert secret.action is SourcePlanAction.SKIP
    assert secret.reason_code == "ANALYZER_UNAVAILABLE"
    assert secret.analyzer_id == GITLEAKS_SOURCE_ANALYZER_ID


def test_existing_equivalent_scannable_support_rule_is_preserved() -> None:
    existing = CapabilitySupportRule(
        AnalysisCapability.SECRET_DETECTION,
        SourceSupportState.SCANNABLE,
        "EXISTING_SECRET_SCANNABLE_POLICY",
    )
    policy = SourceSupportPolicy(
        capability_rules=(existing,),
    )

    updated = with_gitleaks_source_support(policy)

    assert updated is policy
    assert updated.capability_rule_for(
        AnalysisCapability.SECRET_DETECTION
    ) is existing


@pytest.mark.parametrize(
    "state",
    (
        SourceSupportState.UNSUPPORTED,
        SourceSupportState.BENCHMARKED,
        SourceSupportState.PRODUCT_SUPPORTED,
    ),
)
def test_scanner_overlay_never_overrides_explicit_incompatible_support_state(
    state: SourceSupportState,
) -> None:
    profile = _profile(_record("app.py"))

    reason = (
        "SECRET_DETECTION_EXPLICITLY_UNSUPPORTED"
        if state is SourceSupportState.UNSUPPORTED
        else "SECRET_DETECTION_STRONGER_MATURITY"
    )

    surface = AnalysisSurface(
        capability=AnalysisCapability.SECRET_DETECTION,
        support_state=state,
        eligible_paths=(
            ()
            if state is SourceSupportState.UNSUPPORTED
            else ("app.py",)
        ),
        reason_code=reason,
    )

    profile = replace(
        profile,
        surfaces=tuple(
            sorted(
                (*profile.surfaces, surface),
                key=lambda item: (
                    item.capability.value,
                    item.component_id or "",
                ),
            )
        ),
    )

    with pytest.raises(GitleaksApplicabilityError):
        _apply_gitleaks(profile)


def test_existing_scannable_surface_keeps_its_policy_reason() -> None:
    profile = _profile(
        _record("app.py"),
        _record("client.p12", content=b"\x00\x01", binary=True),
    )

    existing = AnalysisSurface(
        capability=AnalysisCapability.SECRET_DETECTION,
        support_state=SourceSupportState.SCANNABLE,
        eligible_paths=("app.py",),
        reason_code="EXISTING_SECRET_SCANNABLE_POLICY",
    )

    profile = replace(
        profile,
        surfaces=tuple(
            sorted(
                (*profile.surfaces, existing),
                key=lambda item: (
                    item.capability.value,
                    item.component_id or "",
                ),
            )
        ),
    )

    enriched = _apply_gitleaks(
        profile,
        _gitleaks_support_policy(
            "EXISTING_SECRET_SCANNABLE_POLICY"
        ),
    )
    secret = _secret_surface(enriched)

    assert secret.support_state is SourceSupportState.SCANNABLE
    assert secret.reason_code == "EXISTING_SECRET_SCANNABLE_POLICY"
    assert secret.eligible_paths == (
        "app.py",
        "client.p12",
    )


def test_detected_surface_cannot_bypass_scannable_support_policy() -> None:
    profile = _profile(_record("app.py"))

    detected = AnalysisSurface(
        capability=AnalysisCapability.SECRET_DETECTION,
        support_state=SourceSupportState.DETECTED,
        eligible_paths=("app.py",),
        reason_code="CAPABILITY_DETECTED_NO_DECLARED_SUPPORT",
    )

    profile = replace(
        profile,
        surfaces=tuple(
            sorted(
                (*profile.surfaces, detected),
                key=lambda item: (
                    item.capability.value,
                    item.component_id or "",
                ),
            )
        ),
    )

    with pytest.raises(GitleaksApplicabilityError):
        _apply_gitleaks(profile)


def test_default_detected_support_policy_cannot_authorize_overlay() -> None:
    profile = _profile(_record("app.py"))

    with pytest.raises(GitleaksApplicabilityError):
        apply_gitleaks_source_applicability(
            profile,
            SourceSupportPolicy(),
        )




def test_real_generic_profile_then_gitleaks_overlay_expands_binary_scope() -> None:
    text_file = replace(
        _record("app.py"),
        eligible_capabilities=tuple(
            sorted(
                (
                    AnalysisCapability.REPOSITORY_PROFILING,
                    AnalysisCapability.SECRET_DETECTION,
                ),
                key=lambda capability: capability.value,
            )
        ),
    )
    path_only_candidate = _record(
        "certificates/client.p12",
        content=b"\x00\x01\x02\x03",
        binary=True,
    )

    files = tuple(
        sorted(
            (text_file, path_only_candidate),
            key=lambda file: file.relative_path,
        )
    )

    inventory = ComponentizedRepositoryInventory(
        repository_digest=repository_content_digest(
            tuple(file.entry for file in files)
        ),
        files=files,
        components=(),
    )

    policy = with_gitleaks_source_support(
        SourceSupportPolicy()
    )

    assessment = assess_repository_language_support(
        inventory,
        policy,
    )

    generic_profile = build_repository_profile(
        inventory,
        assessment,
        policy,
    )

    generic_secret = _secret_surface(generic_profile)

    # Generic frozen inventory eligibility is text-oriented.
    assert generic_secret.support_state is SourceSupportState.SCANNABLE
    assert generic_secret.eligible_paths == ("app.py",)
    assert (
        AnalysisCapability.SECRET_DETECTION
        not in generic_profile.files[1].eligible_capabilities
    )

    enriched = apply_gitleaks_source_applicability(
        generic_profile,
        policy,
    )

    secret = _secret_surface(enriched)

    # Gitleaks Source policy deliberately expands current-snapshot scope
    # so path-only detectors remain reachable.
    assert secret.support_state is SourceSupportState.SCANNABLE
    assert secret.eligible_paths == (
        "app.py",
        "certificates/client.p12",
    )

    binary = next(
        file
        for file in enriched.files
        if file.relative_path == "certificates/client.p12"
    )

    assert SourceFileFlag.BINARY in binary.flags
    assert (
        AnalysisCapability.SECRET_DETECTION
        in binary.eligible_capabilities
    )
