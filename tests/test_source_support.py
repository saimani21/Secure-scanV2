from __future__ import annotations

import builtins
import hashlib
import json
import os
import socket
import subprocess
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
import sqlalchemy

from securescan.adapters.fake_scanner import FakeScannerAdapter
from securescan.execution import DockerSandboxExecutor
from securescan.scanners.semgrep.adapter import SemgrepScannerAdapter
from securescan.source import (
    AnalysisCapability,
    CapabilitySupportRule,
    ComponentizedRepositoryInventory,
    EnrichedRepositoryInventory,
    EnryClient,
    FileContentKind,
    InvalidSourceSupportPolicyError,
    LanguageSupportRule,
    RepositoryLanguageDecision,
    RepositoryLanguageSupportAssessment,
    SourceFileFlag,
    SourceFileRecord,
    SourceFileRole,
    SourceLanguageProfilingPolicy,
    SourceSupportCorrelationError,
    SourceSupportPolicy,
    SourceSupportPolicyError,
    SourceSupportState,
    TrustedEnryHelper,
    assess_repository_language_support,
    build_repository_inventory,
    detect_repository_components,
    enrich_repository_inventory,
    profile_repository_languages,
)
from securescan.workspaces import RepositoryManifestEntry, RepositoryWorkspaceManager
from securescan.workspaces.models import repository_content_digest

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_LOCAL_HELPER = _PROJECT_ROOT / "tools/enry-helper/bin/securescan-enry-helper"
_POLICY_GOLDEN_DIGEST = (
    "22fc4aba9c6f9309fcf89b67412e6070a47e38141a9ee24218f7378e55c1c69a"
)
_ASSESSMENT_GOLDEN_DIGEST = (
    "1ec06aa19bbdbbe163b95fa598e693b6f615ba1039e39496dca4d92c12ffcb0b"
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
    language: str | None = None,
    role: SourceFileRole = SourceFileRole.SOURCE,
    flags: tuple[SourceFileFlag, ...] = (),
    component_id: str | None = None,
    content: bytes = b"content\n",
    content_kind: FileContentKind = FileContentKind.TEXT,
) -> SourceFileRecord:
    return SourceFileRecord(
        entry=_entry(relative_path, content),
        content_kind=content_kind,
        role=role,
        language=language,
        component_id=component_id,
        flags=flags,
    )


def _componentized(
    *records: SourceFileRecord,
) -> ComponentizedRepositoryInventory:
    files = tuple(sorted(records, key=lambda record: record.relative_path))
    return ComponentizedRepositoryInventory(
        repository_digest=repository_content_digest(
            tuple(record.entry for record in files)
        ),
        files=files,
        components=(),
    )


def _enriched(*records: SourceFileRecord) -> EnrichedRepositoryInventory:
    files = tuple(sorted(records, key=lambda record: record.relative_path))
    return EnrichedRepositoryInventory(
        repository_digest=repository_content_digest(
            tuple(record.entry for record in files)
        ),
        files=files,
    )


def _decision(
    language: str = "Python",
    *,
    file_count: int = 1,
    source_file_count: int = 1,
    generated_file_count: int = 0,
    vendored_file_count: int = 0,
    test_file_count: int = 0,
    support_state: SourceSupportState = SourceSupportState.DETECTED,
    reason_code: str | None = "LANGUAGE_DETECTED_NO_DECLARED_SUPPORT",
) -> RepositoryLanguageDecision:
    return RepositoryLanguageDecision(
        language=language,
        file_count=file_count,
        source_file_count=source_file_count,
        generated_file_count=generated_file_count,
        vendored_file_count=vendored_file_count,
        test_file_count=test_file_count,
        support_state=support_state,
        reason_code=reason_code,
    )


@pytest.mark.parametrize("support_state", tuple(SourceSupportState))
def test_language_rule_accepts_every_support_state(
    support_state: SourceSupportState,
) -> None:
    reason = "LANGUAGE_NOT_SUPPORTED" if support_state is SourceSupportState.UNSUPPORTED else None

    rule = LanguageSupportRule("Python", support_state, reason)

    assert rule.support_state is support_state
    assert rule.reason_code == reason


def test_language_rule_is_immutable() -> None:
    rule = LanguageSupportRule("Python", SourceSupportState.DETECTED)

    with pytest.raises(FrozenInstanceError):
        rule.language = "Go"  # type: ignore[misc]


@pytest.mark.parametrize(
    "language",
    ["", " Python", "Python ", "Py\x00thon", "Py\x85thon", "\ud800", "x" * 101, 1],
)
def test_language_rule_rejects_invalid_language(language: object) -> None:
    with pytest.raises(InvalidSourceSupportPolicyError):
        LanguageSupportRule(
            language,  # type: ignore[arg-type]
            SourceSupportState.DETECTED,
        )


@pytest.mark.parametrize(
    "reason_code",
    ["", "A", "lowercase", "1STARTS_WITH_NUMBER", "HAS-DASH", "A" * 129],
)
def test_language_rule_rejects_invalid_reason(reason_code: str) -> None:
    with pytest.raises(InvalidSourceSupportPolicyError):
        LanguageSupportRule(
            "Python",
            SourceSupportState.DETECTED,
            reason_code,
        )


def test_language_rule_requires_reason_for_unsupported() -> None:
    with pytest.raises(InvalidSourceSupportPolicyError):
        LanguageSupportRule("Python", SourceSupportState.UNSUPPORTED)


@pytest.mark.parametrize("support_state", tuple(SourceSupportState))
def test_capability_rule_accepts_every_support_state(
    support_state: SourceSupportState,
) -> None:
    reason = "CAPABILITY_NOT_SUPPORTED" if support_state is SourceSupportState.UNSUPPORTED else None

    rule = CapabilitySupportRule(
        AnalysisCapability.PYTHON_SAST,
        support_state,
        reason,
    )

    assert rule.support_state is support_state


def test_capability_rule_rejects_invalid_capability_and_reason() -> None:
    with pytest.raises(InvalidSourceSupportPolicyError):
        CapabilitySupportRule(
            "python_sast",  # type: ignore[arg-type]
            SourceSupportState.DETECTED,
        )
    with pytest.raises(InvalidSourceSupportPolicyError):
        CapabilitySupportRule(
            AnalysisCapability.PYTHON_SAST,
            SourceSupportState.DETECTED,
            "invalid",
        )


def test_capability_rule_requires_reason_for_unsupported() -> None:
    with pytest.raises(InvalidSourceSupportPolicyError):
        CapabilitySupportRule(
            AnalysisCapability.PYTHON_SAST,
            SourceSupportState.UNSUPPORTED,
        )


def test_empty_policy_is_conservative_and_canonical() -> None:
    policy = SourceSupportPolicy()

    assert policy.language_rules == ()
    assert policy.capability_rules == ()
    assert policy.default_language_state is SourceSupportState.DETECTED
    assert policy.default_capability_state is SourceSupportState.DETECTED
    assert "product_supported" not in json.dumps(policy.canonical_data())
    assert policy.policy_digest() == _POLICY_GOLDEN_DIGEST


def test_policy_rejects_wrong_schema_and_non_tuple_rules() -> None:
    with pytest.raises(InvalidSourceSupportPolicyError):
        SourceSupportPolicy(schema_version="0.2.4")
    with pytest.raises(InvalidSourceSupportPolicyError):
        SourceSupportPolicy(language_rules=[])  # type: ignore[arg-type]
    with pytest.raises(InvalidSourceSupportPolicyError):
        SourceSupportPolicy(capability_rules=[])  # type: ignore[arg-type]


def test_policy_requires_sorted_unique_language_rules() -> None:
    go = LanguageSupportRule("Go", SourceSupportState.DETECTED)
    python = LanguageSupportRule("Python", SourceSupportState.DETECTED)

    with pytest.raises(InvalidSourceSupportPolicyError):
        SourceSupportPolicy(language_rules=(python, go))
    with pytest.raises(InvalidSourceSupportPolicyError):
        SourceSupportPolicy(
            language_rules=(
                LanguageSupportRule("Python", SourceSupportState.DETECTED),
                LanguageSupportRule("python", SourceSupportState.SCANNABLE),
            )
        )


def test_policy_requires_sorted_unique_capability_rules() -> None:
    repository = CapabilitySupportRule(
        AnalysisCapability.REPOSITORY_PROFILING,
        SourceSupportState.DETECTED,
    )
    python = CapabilitySupportRule(
        AnalysisCapability.PYTHON_SAST,
        SourceSupportState.SCANNABLE,
    )

    with pytest.raises(InvalidSourceSupportPolicyError):
        SourceSupportPolicy(capability_rules=(repository, python))
    with pytest.raises(InvalidSourceSupportPolicyError):
        SourceSupportPolicy(capability_rules=(python, python))


def test_policy_rejects_invalid_default_states() -> None:
    with pytest.raises(InvalidSourceSupportPolicyError):
        SourceSupportPolicy(default_language_state="detected")  # type: ignore[arg-type]
    with pytest.raises(InvalidSourceSupportPolicyError):
        SourceSupportPolicy(default_capability_state="detected")  # type: ignore[arg-type]


def test_policy_default_unsupported_requires_reason() -> None:
    with pytest.raises(InvalidSourceSupportPolicyError):
        SourceSupportPolicy(
            default_language_state=SourceSupportState.UNSUPPORTED,
            default_language_reason_code=None,
        )
    with pytest.raises(InvalidSourceSupportPolicyError):
        SourceSupportPolicy(
            default_capability_state=SourceSupportState.UNSUPPORTED,
            default_capability_reason_code=None,
        )


def test_policy_rejects_invalid_default_reason_codes() -> None:
    with pytest.raises(InvalidSourceSupportPolicyError):
        SourceSupportPolicy(default_language_reason_code="invalid")
    with pytest.raises(InvalidSourceSupportPolicyError):
        SourceSupportPolicy(default_capability_reason_code="invalid")


def test_policy_digest_is_stable_and_changes_with_semantics() -> None:
    policy = SourceSupportPolicy()
    changed = SourceSupportPolicy(
        default_language_state=SourceSupportState.SCANNABLE,
        default_language_reason_code="LANGUAGE_SCANNABLE_BY_POLICY",
    )

    assert policy.canonical_data() == SourceSupportPolicy().canonical_data()
    assert policy.policy_digest() == SourceSupportPolicy().policy_digest()
    assert policy.policy_digest() != changed.policy_digest()


def test_language_lookup_is_case_insensitive_and_returns_explicit_rule() -> None:
    rule = LanguageSupportRule(
        "python",
        SourceSupportState.SCANNABLE,
        "PYTHON_SCANNABLE_BY_POLICY",
    )
    policy = SourceSupportPolicy(language_rules=(rule,))

    assert policy.language_rule_for("Python") is rule


@pytest.mark.parametrize(
    ("support_state", "reason_code"),
    [
        (SourceSupportState.UNSUPPORTED, "LANGUAGE_NOT_SUPPORTED"),
        (SourceSupportState.PRODUCT_SUPPORTED, "LANGUAGE_PRODUCT_SUPPORTED"),
    ],
)
def test_language_lookup_preserves_explicit_policy_state(
    support_state: SourceSupportState,
    reason_code: str,
) -> None:
    policy = SourceSupportPolicy(
        language_rules=(
            LanguageSupportRule("Python", support_state, reason_code),
        )
    )

    result = policy.language_rule_for("Python")

    assert result.support_state is support_state
    assert result.reason_code == reason_code


def test_language_fallback_preserves_requested_spelling_and_policy() -> None:
    policy = SourceSupportPolicy()
    before = policy.canonical_data()

    first = policy.language_rule_for("PyThOn")
    second = policy.language_rule_for("PyThOn")

    assert first == LanguageSupportRule(
        "PyThOn",
        SourceSupportState.DETECTED,
        "LANGUAGE_DETECTED_NO_DECLARED_SUPPORT",
    )
    assert first is not second
    assert policy.canonical_data() == before


def test_capability_lookup_explicit_and_fallback_are_declarative() -> None:
    rule = CapabilitySupportRule(
        AnalysisCapability.PYTHON_SAST,
        SourceSupportState.BENCHMARKED,
        "PYTHON_SAST_BENCHMARKED",
    )
    policy = SourceSupportPolicy(capability_rules=(rule,))
    before = policy.canonical_data()

    assert policy.capability_rule_for(AnalysisCapability.PYTHON_SAST) is rule
    assert policy.capability_rule_for(
        AnalysisCapability.SECRET_DETECTION
    ) == CapabilitySupportRule(
        AnalysisCapability.SECRET_DETECTION,
        SourceSupportState.DETECTED,
        "CAPABILITY_DETECTED_NO_DECLARED_SUPPORT",
    )
    assert policy.canonical_data() == before


def test_lookup_rejects_invalid_identity_with_sanitized_error() -> None:
    policy = SourceSupportPolicy()
    sensitive = " secret-language "

    with pytest.raises(InvalidSourceSupportPolicyError) as language_error:
        policy.language_rule_for(sensitive)
    with pytest.raises(InvalidSourceSupportPolicyError) as capability_error:
        policy.capability_rule_for("python_sast")  # type: ignore[arg-type]

    assert str(language_error.value) == "Source support policy is invalid"
    assert sensitive not in str(language_error.value)
    assert str(capability_error.value) == "Source support policy is invalid"


def test_repository_language_decision_accepts_valid_overlapping_counts() -> None:
    decision = _decision(
        file_count=2,
        source_file_count=2,
        generated_file_count=2,
        vendored_file_count=2,
        test_file_count=2,
    )

    assert decision.generated_file_count + decision.test_file_count > decision.file_count


@pytest.mark.parametrize(
    "changes",
    [
        {"file_count": 0},
        {"file_count": True},
        {"source_file_count": 2},
        {"generated_file_count": 2},
        {"vendored_file_count": 2},
        {"test_file_count": 2},
        {"source_file_count": -1},
    ],
)
def test_repository_language_decision_rejects_invalid_counts(
    changes: dict[str, object],
) -> None:
    arguments: dict[str, object] = {
        "language": "Python",
        "file_count": 1,
        "source_file_count": 1,
        "generated_file_count": 0,
        "vendored_file_count": 0,
        "test_file_count": 0,
        "support_state": SourceSupportState.DETECTED,
        "reason_code": None,
    }
    arguments.update(changes)

    with pytest.raises(ValueError, match="Repository language decision is invalid"):
        RepositoryLanguageDecision(**arguments)  # type: ignore[arg-type]


def test_repository_language_decision_rejects_invalid_state_and_unsupported_reason() -> None:
    with pytest.raises(ValueError, match="Repository language decision is invalid"):
        _decision(support_state="detected")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="Repository language decision is invalid"):
        _decision(
            support_state=SourceSupportState.UNSUPPORTED,
            reason_code=None,
        )


def test_empty_assessment_is_valid_canonical_and_golden() -> None:
    policy = SourceSupportPolicy()
    assessment = RepositoryLanguageSupportAssessment(
        repository_digest="a" * 64,
        languages=(),
        policy_digest=policy.policy_digest(),
    )

    assert assessment.language_count == 0
    assert assessment.canonical_data()["languages"] == []
    assert assessment.assessment_digest() == _ASSESSMENT_GOLDEN_DIGEST
    assert assessment.assessment_digest() == assessment.assessment_digest()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "0.2.4"),
        ("repository_digest", "A" * 64),
        ("repository_digest", "a" * 63),
        ("policy_digest", "g" * 64),
        ("policy_digest", b"a" * 64),
        ("languages", []),
    ],
)
def test_assessment_rejects_invalid_contract(field: str, value: object) -> None:
    arguments: dict[str, object] = {
        "repository_digest": "a" * 64,
        "languages": (),
        "policy_digest": "b" * 64,
    }
    arguments[field] = value

    with pytest.raises(
        ValueError,
        match="Repository language support assessment is invalid",
    ):
        RepositoryLanguageSupportAssessment(**arguments)  # type: ignore[arg-type]


def test_assessment_requires_sorted_unique_language_identities() -> None:
    go = _decision("Go")
    python = _decision("Python")

    with pytest.raises(ValueError):
        RepositoryLanguageSupportAssessment(
            repository_digest="a" * 64,
            languages=(python, go),
            policy_digest="b" * 64,
        )
    with pytest.raises(ValueError):
        RepositoryLanguageSupportAssessment(
            repository_digest="a" * 64,
            languages=(python, _decision("python")),
            policy_digest="b" * 64,
        )


def test_assessment_digest_changes_with_semantics() -> None:
    first = RepositoryLanguageSupportAssessment(
        repository_digest="a" * 64,
        languages=(_decision(),),
        policy_digest="b" * 64,
    )
    second = RepositoryLanguageSupportAssessment(
        repository_digest="a" * 64,
        languages=(_decision(file_count=2, source_file_count=2),),
        policy_digest="b" * 64,
    )

    assert first.canonical_data() == first.canonical_data()
    assert first.assessment_digest() != second.assessment_digest()


def test_empty_and_unknown_language_inventories_have_no_decisions() -> None:
    empty = assess_repository_language_support(_componentized(), SourceSupportPolicy())
    unknown = assess_repository_language_support(
        _componentized(
            _record("README", role=SourceFileRole.DOCUMENTATION),
            _record(
                "asset.bin",
                role=SourceFileRole.BINARY,
                content=b"\x00\x01",
                content_kind=FileContentKind.BINARY,
                flags=(SourceFileFlag.BINARY,),
            ),
        ),
        SourceSupportPolicy(),
    )

    assert empty.languages == ()
    assert unknown.languages == ()


def test_repository_assessment_aggregates_languages_and_all_count_categories() -> None:
    inventory = _componentized(
        _record(
            "generated_test.py",
            language="Python",
            flags=(SourceFileFlag.GENERATED, SourceFileFlag.TEST),
        ),
        _record("main.go", language="Go"),
        _record("main.py", language="Python"),
        _record(
            "vendor.py",
            language="Python",
            flags=(SourceFileFlag.VENDORED,),
        ),
    )

    assessment = assess_repository_language_support(inventory, SourceSupportPolicy())

    assert tuple(language.language for language in assessment.languages) == ("Go", "Python")
    assert assessment.languages[0].file_count == 1
    assert assessment.languages[1] == _decision(
        file_count=3,
        source_file_count=3,
        generated_file_count=1,
        vendored_file_count=1,
        test_file_count=1,
    )


@pytest.mark.parametrize(
    "role",
    [
        SourceFileRole.CONFIGURATION,
        SourceFileRole.DOCUMENTATION,
        SourceFileRole.MANIFEST,
    ],
)
def test_only_source_role_contributes_to_source_file_count(
    role: SourceFileRole,
) -> None:
    assessment = assess_repository_language_support(
        _componentized(_record("file.txt", language="Text", role=role)),
        SourceSupportPolicy(),
    )

    assert assessment.languages[0].file_count == 1
    assert assessment.languages[0].source_file_count == 0


@pytest.mark.parametrize(
    ("support_state", "reason_code"),
    [
        (SourceSupportState.SCANNABLE, "LANGUAGE_SCANNABLE_BY_POLICY"),
        (SourceSupportState.BENCHMARKED, "LANGUAGE_BENCHMARKED_BY_POLICY"),
        (SourceSupportState.PRODUCT_SUPPORTED, "LANGUAGE_PRODUCT_SUPPORTED"),
        (SourceSupportState.UNSUPPORTED, "LANGUAGE_NOT_SUPPORTED"),
    ],
)
def test_repository_support_state_and_reason_come_only_from_policy(
    support_state: SourceSupportState,
    reason_code: str,
) -> None:
    policy = SourceSupportPolicy(
        language_rules=(
            LanguageSupportRule("python", support_state, reason_code),
        )
    )
    inventory = _componentized(
        _record(
            "generated.py",
            language="Python",
            flags=(SourceFileFlag.GENERATED, SourceFileFlag.VENDORED),
        ),
        _record("main.py", language="Python"),
        _record("test.py", language="Python", flags=(SourceFileFlag.TEST,)),
    )

    decision = assess_repository_language_support(inventory, policy).languages[0]

    assert decision.language == "Python"
    assert decision.support_state is support_state
    assert decision.reason_code == reason_code
    assert decision.file_count == 3


def test_component_membership_does_not_affect_language_counts() -> None:
    componentized = detect_repository_components(
        _enriched(
            _record("package.json", role=SourceFileRole.MANIFEST),
            _record("src/app.js", language="JavaScript"),
        )
    )

    decision = assess_repository_language_support(
        componentized,
        SourceSupportPolicy(),
    ).languages[0]

    assert componentized.files[1].component_id is not None
    assert decision.language == "JavaScript"
    assert decision.file_count == 1


def test_case_inconsistent_upstream_language_evidence_is_rejected() -> None:
    inventory = _componentized(
        _record("a.py", language="Python"),
        _record("b.py", language="python"),
    )

    with pytest.raises(SourceSupportCorrelationError) as raised:
        assess_repository_language_support(inventory, SourceSupportPolicy())

    assert str(raised.value) == "Source support correlation failed"
    assert "Python" not in str(raised.value)


def test_invalid_upstream_language_is_rejected_as_correlation_failure() -> None:
    inventory = _componentized(_record("a.py", language="Py\x85thon"))

    with pytest.raises(SourceSupportCorrelationError):
        assess_repository_language_support(inventory, SourceSupportPolicy())


def test_assessment_is_repeatable_and_does_not_mutate_inputs() -> None:
    inventory = _componentized(_record("app.py", language="Python"))
    policy = SourceSupportPolicy()
    inventory_before = inventory.canonical_data()
    policy_before = policy.canonical_data()
    original_file = inventory.files[0]

    first = assess_repository_language_support(inventory, policy)
    second = assess_repository_language_support(inventory, policy)

    assert first == second
    assert first.assessment_digest() == second.assessment_digest()
    assert inventory.canonical_data() == inventory_before
    assert policy.canonical_data() == policy_before
    assert inventory.files[0] is original_file
    assert not hasattr(first, "surfaces")
    assert not hasattr(first, "profile")
    assert not hasattr(first, "execution_plan")
    assert "eligible_file_count" not in json.dumps(first.canonical_data())


def test_assessment_rejects_invalid_input_types_with_sanitized_error() -> None:
    inventory = _componentized()

    with pytest.raises(SourceSupportPolicyError) as inventory_error:
        assess_repository_language_support("inventory", SourceSupportPolicy())  # type: ignore[arg-type]
    with pytest.raises(SourceSupportPolicyError) as policy_error:
        assess_repository_language_support(inventory, "policy")  # type: ignore[arg-type]

    assert str(inventory_error.value) == "Source support policy operation failed"
    assert str(policy_error.value) == "Source support policy operation failed"


def test_support_assessment_has_no_external_side_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventory = _componentized(_record("app.py", language="Python"))

    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("external operation attempted")

    monkeypatch.setattr(builtins, "open", fail)
    monkeypatch.setattr(os, "open", fail)
    monkeypatch.setattr(os, "system", fail)
    monkeypatch.setattr(Path, "open", fail)
    monkeypatch.setattr(Path, "read_bytes", fail)
    monkeypatch.setattr(Path, "read_text", fail)
    monkeypatch.setattr(subprocess, "Popen", fail)
    monkeypatch.setattr(subprocess, "run", fail)
    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(sqlalchemy, "create_engine", fail)
    monkeypatch.setattr(DockerSandboxExecutor, "execute", fail)
    monkeypatch.setattr(EnryClient, "classify", fail)
    monkeypatch.setattr(FakeScannerAdapter, "build_plan", fail)
    monkeypatch.setattr(SemgrepScannerAdapter, "execute", fail)

    result = assess_repository_language_support(inventory, SourceSupportPolicy())

    assert result.language_count == 1


def test_assessment_retains_no_paths_source_content_or_runtime_data() -> None:
    sensitive = b"SECURESCAN_TEST_SECRET=private"
    inventory = _componentized(
        _record("private/location/app.py", language="Python", content=sensitive)
    )

    assessment = assess_repository_language_support(inventory, SourceSupportPolicy())
    rendered = json.dumps(assessment.canonical_data(), sort_keys=True)

    assert "private/location" not in rendered
    assert sensitive.decode("ascii") not in rendered
    assert "component" not in rendered
    assert "scanner" not in rendered
    assert "runtime" not in rendered


@pytest.mark.skipif(not _LOCAL_HELPER.exists(), reason="local Enry helper is absent")
def test_real_enry_support_assessment_pipeline(tmp_path: Path) -> None:
    source = tmp_path / "repository"
    files = {
        "README.md": b"# Documentation\n",
        "asset.bin": b"\x00\x01\x02\x03",
        "config.yaml": b"enabled: true\n",
        "frontend/package.json": b'{"name": "frontend"}\n',
        "frontend/src/app.js": b"export const app = true;\n",
        "go.mod": b"module example.test/project\n\ngo 1.22\n",
        "pkg/app_test.go": b"package pkg\n\nfunc TestApp() {}\n",
        "pyproject.toml": b"[project]\nname = 'root'\n",
        "src/root.py": b"ROOT = True\n",
        "src/generated/generated.go": (
            b"// Code generated by SecureScan. DO NOT EDIT.\npackage generated\n"
        ),
        "vendor/example/lib.go": b"package example\n",
    }
    for relative_path, content in files.items():
        path = source / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    manager = RepositoryWorkspaceManager(tmp_path / "managed")
    workspace = manager.prepare_repository(source)
    with _LOCAL_HELPER.open("rb") as helper_stream:
        helper_digest = hashlib.file_digest(helper_stream, "sha256").hexdigest()
    client = EnryClient(
        TrustedEnryHelper(
            helper_path=_LOCAL_HELPER,
            expected_sha256=helper_digest,
        )
    )
    policy = SourceSupportPolicy(
        language_rules=(
            LanguageSupportRule(
                "Go",
                SourceSupportState.UNSUPPORTED,
                "GO_NOT_SUPPORTED",
            ),
            LanguageSupportRule(
                "JavaScript",
                SourceSupportState.DETECTED,
                "JAVASCRIPT_DETECTED_ONLY",
            ),
            LanguageSupportRule(
                "Python",
                SourceSupportState.SCANNABLE,
                "PYTHON_SCANNABLE_BY_POLICY",
            ),
        )
    )

    try:
        base_inventory = build_repository_inventory(workspace)
        language_profile = profile_repository_languages(
            workspace,
            base_inventory,
            client,
            policy=SourceLanguageProfilingPolicy(sample_bytes=1024),
        )
        enriched = enrich_repository_inventory(base_inventory, language_profile)
        componentized = detect_repository_components(enriched)
        result = assess_repository_language_support(componentized, policy)
        decisions = {decision.language: decision for decision in result.languages}

        assert decisions["Python"].support_state is SourceSupportState.SCANNABLE
        assert decisions["Python"].file_count == 1
        assert decisions["Python"].source_file_count == 1
        assert decisions["JavaScript"].support_state is SourceSupportState.DETECTED
        assert decisions["JavaScript"].file_count == 1
        assert decisions["JavaScript"].source_file_count == 1
        assert decisions["Go"].support_state is SourceSupportState.UNSUPPORTED
        assert decisions["Go"].reason_code == "GO_NOT_SUPPORTED"
        assert decisions["Go"].file_count == 3
        assert decisions["Go"].source_file_count == 3
        assert decisions["Go"].generated_file_count == 1
        assert decisions["Go"].vendored_file_count == 1
        assert decisions["Go"].test_file_count == 1
        assert result.repository_digest == componentized.repository_digest
        assert result.policy_digest == policy.policy_digest()
        assert result == assess_repository_language_support(componentized, policy)
        rendered = json.dumps(result.canonical_data(), sort_keys=True)
        assert not any(relative_path in rendered for relative_path in files)
        assert not hasattr(result, "surfaces")
        assert not hasattr(result, "profile")
        assert not hasattr(result, "execution_plan")
    finally:
        manager.cleanup_workspace(workspace)
