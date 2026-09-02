from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

import securescan.benchmarks.python_sast_realworld_evaluation as evaluation_module
from securescan.benchmarks.python_sast import (
    EXPECTED_SCANNER_VERSION,
    FROZEN_RULESET_DIGEST,
    FROZEN_RULESET_ID,
    FROZEN_RULESET_VERSION,
    PRODUCTION_RULE_IDS,
    SCANNER_ID,
)
from securescan.benchmarks.python_sast_realworld_evaluation import (
    ACCEPTED_CASE_SET_DIGEST,
    APPLICABILITY_PROPOSAL_DIGEST,
    APPLICABILITY_REVIEW_DIGEST,
    APPLICABILITY_SUMMARY_DIGEST,
    BASELINE_COMMIT,
    BASELINE_TAG,
    CLAIM_AUDIT_DIGEST,
    CLAIM_AUDIT_FILE_SHA256,
    CLAIM_CONTRACT_DIGEST,
    CLAIM_CONTRACT_FILE_SHA256,
    SOURCE_LOCK_DIGEST,
    FrozenRealWorldInputs,
    ObservedFinding,
    ProjectionEntry,
    RealWorldProjection,
    RevisionExpectation,
    ScanObservations,
    _projection_file,
    build_report,
    build_review,
    canonical_report,
    controlled_environment,
    create_projection,
    evaluate_observations,
    expected_scanner_executable,
    load_frozen_inputs,
    normalize_scanner_output,
    projection_path,
    record_evidence,
    report_digest,
    verify_projection,
    verify_ruleset_identity,
    verify_scanner_identity,
)
from securescan.workspaces.models import (
    RepositoryManifest,
    RepositoryManifestEntry,
    repository_content_digest,
)

ROOT = Path(__file__).parent.parent
BENCHMARK_ROOT = ROOT / "benchmarks/python_sast_realworld"


@pytest.fixture(scope="module")
def frozen_inputs() -> FrozenRealWorldInputs:
    return load_frozen_inputs(ROOT)


def _projection(tmp_path: Path) -> RealWorldProjection:
    scanner_path = "cases/CVE-2024-0001/vulnerable/source.py"
    content = b"value = eval(payload)\n"
    path = tmp_path / scanner_path
    path.parent.mkdir(parents=True)
    path.write_bytes(content)
    source_sha256 = hashlib.sha256(content).hexdigest()
    entry = ProjectionEntry(
        scanner_path=scanner_path,
        case_id="python-realworld/CVE-2024-0001/example",
        cve_id="CVE-2024-0001",
        project="example",
        case_family_id="example-family",
        revision_role="vulnerable",
        original_relative_path="source.py",
        source_sha256=source_sha256,
        size_bytes=len(content),
    )
    manifest_entry = RepositoryManifestEntry(scanner_path, len(content), source_sha256)
    manifest = RepositoryManifest(
        entries=(manifest_entry,),
        file_count=1,
        total_bytes=len(content),
        content_digest=repository_content_digest((manifest_entry,)),
    )
    return RealWorldProjection(tmp_path, (entry,), manifest)


def _semgrep_output(
    findings: list[dict[str, object]],
    *,
    version: str = EXPECTED_SCANNER_VERSION,
    errors: list[dict[str, object]] | None = None,
) -> bytes:
    return json.dumps(
        {"errors": errors or [], "results": findings, "version": version},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _finding(path: str, rule_id: str, start: int = 1, end: int | None = None) -> dict[str, object]:
    return {
        "check_id": rule_id,
        "end": {"col": 2, "line": end or start},
        "extra": {"metadata": {}, "severity": "ERROR"},
        "path": path,
        "start": {"col": 1, "line": start},
    }


def _observations(findings: tuple[ObservedFinding, ...] = ()) -> ScanObservations:
    return ScanObservations(findings, len(findings), len(findings), 0)


def _observed_for(
    expectation: RevisionExpectation, *, rule_id: str | None = None
) -> ObservedFinding:
    region = expectation.evidence_regions[0]
    return ObservedFinding(
        expectation.case_id,
        expectation.cve_id,
        expectation.revision_role,
        region.relative_source_path,
        rule_id or expectation.rule_id,
        region.start_line,
        region.end_line,
    )


def _perfect_findings(inputs: FrozenRealWorldInputs) -> tuple[ObservedFinding, ...]:
    return tuple(_observed_for(item) for item in inputs.expectations if item.expected_match)


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {item for nested in value.values() for item in _all_keys(nested)}
    if isinstance(value, list):
        return {item for nested in value for item in _all_keys(nested)}
    return set()


def _all_strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for nested in value.values() for item in _all_strings(nested)]
    if isinstance(value, list):
        return [item for nested in value for item in _all_strings(nested)]
    return []


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        env=evaluation_module._git_environment(),
        check=True,
        capture_output=True,
        stdin=subprocess.DEVNULL,
        text=True,
    )
    return result.stdout.strip()


def _temporary_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, str]:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "--initial-branch=source/v0.3-semgrep")
    _git(repository, "config", "user.name", "SecureScan Test")
    _git(repository, "config", "user.email", "securescan@example.invalid")
    _git(repository, "commit", "--allow-empty", "-m", "baseline")
    baseline = _git(repository, "rev-parse", "HEAD")
    _git(repository, "tag", "f2e4-baseline", baseline)
    monkeypatch.setattr(evaluation_module, "BASELINE_TAG", "f2e4-baseline")
    monkeypatch.setattr(evaluation_module, "BASELINE_COMMIT", baseline)
    return repository, baseline


def test_exact_f2e1_f2e4_and_baseline_bindings(frozen_inputs: FrozenRealWorldInputs) -> None:
    assert BASELINE_TAG == "source-v0.3F2E4-python-sast-claim-contract-v2"
    assert BASELINE_COMMIT == "7845ad4107a628dc1ab714220b4bc63b6370760a"
    assert SOURCE_LOCK_DIGEST == "0bba4bbe5ce557f1382f61f9af3320adef5cc53ab386d1c63f4983d8cbf48a00"
    assert (
        ACCEPTED_CASE_SET_DIGEST
        == "60d44ea9cf0f174e1488c5b8dbccde2804524fe4d3bfa31b9db0810e52332a92"
    )
    assert (
        APPLICABILITY_PROPOSAL_DIGEST
        == "96267be4d421582b1f9834cf2bd2750096c727a75a2cc39cd139baf7f58bc478"
    )
    assert (
        APPLICABILITY_SUMMARY_DIGEST
        == "b9286a5d601e0815bd68c6cb73052740e4b34e1d155591341a6ed683b140c083"
    )
    assert (
        APPLICABILITY_REVIEW_DIGEST
        == "4b0c7e551ffc3163941a4358ce3de8572505bd6aa2172e6440668e7d2aba0464"
    )
    assert (
        CLAIM_CONTRACT_DIGEST
        == "0e0d9a118a7567049ad26f046b0f097ba8390d74f05f2b721452683ee3c2e62d"
    )
    assert (
        CLAIM_CONTRACT_FILE_SHA256
        == "70b3c50f33526e5db40bbb4ee8c89c561a2ecfaa7cfbb4e01934d9656c7993b3"
    )
    assert (
        CLAIM_AUDIT_DIGEST
        == "d9c6b52c77e6fc8fdd4a8ea8ba9a29274bd7f416622c35904a44d3c4348e7d2a"
    )
    assert (
        CLAIM_AUDIT_FILE_SHA256
        == "d821fd7ca273c7a45e3cd0c548f96d3ad2bf0f7ea54b3ca6054d7c991a0dbf81"
    )
    assert len(frozen_inputs.accepted_cases) == 13
    assert len(frozen_inputs.expectations) == 14


def test_f2e4_tag_resolves_to_the_exact_baseline_commit() -> None:
    assert evaluation_module._git_text(
        ROOT, "rev-parse", f"{BASELINE_TAG}^{{commit}}"
    ) == BASELINE_COMMIT


def test_head_equal_to_baseline_is_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, baseline = _temporary_baseline(tmp_path, monkeypatch)
    assert _git(repository, "rev-parse", "HEAD") == baseline
    evaluation_module.verify_git_baseline(repository)


def test_descendant_head_is_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, baseline = _temporary_baseline(tmp_path, monkeypatch)
    _git(repository, "commit", "--allow-empty", "-m", "f2e5")
    assert _git(repository, "rev-parse", "HEAD") != baseline
    evaluation_module.verify_git_baseline(repository)


def test_divergent_head_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, baseline = _temporary_baseline(tmp_path, monkeypatch)
    tree = _git(repository, "rev-parse", f"{baseline}^{{tree}}")
    divergent = _git(repository, "commit-tree", tree, "-m", "divergent")
    _git(repository, "update-ref", "refs/heads/source/v0.3-semgrep", divergent)
    with pytest.raises(ValueError, match="baseline binding is invalid"):
        evaluation_module.verify_git_baseline(repository)


def test_wrong_baseline_tag_resolution_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def hostile_git_text(_root: Path, *arguments: str) -> str:
        if arguments == ("branch", "--show-current"):
            return "source/v0.3-semgrep"
        return "0" * 40

    monkeypatch.setattr(evaluation_module, "_git_text", hostile_git_text)
    monkeypatch.setattr(
        evaluation_module,
        "_git_is_ancestor",
        lambda *_arguments: pytest.fail("ancestry must not run for a wrong tag target"),
    )
    with pytest.raises(ValueError, match="baseline binding is invalid"):
        evaluation_module.verify_git_baseline(ROOT)


def test_exact_ruleset_and_scanner_contracts() -> None:
    verify_ruleset_identity(ROOT)
    assert (FROZEN_RULESET_ID, FROZEN_RULESET_VERSION, FROZEN_RULESET_DIGEST) == (
        "securescan-python-baseline-v2",
        "2",
        "e10fb04e6b5abb35e0b83bdd718c2e973a8026e3630e420dc398db95e59d01a5",
    )
    assert (SCANNER_ID, EXPECTED_SCANNER_VERSION) == ("semgrep-ce", "1.171.0")
    assert expected_scanner_executable(ROOT) == ROOT / ".venv-semgrep-1.171/bin/semgrep"


def test_v2_case_relation_and_revision_accounting_is_exact(
    frozen_inputs: FrozenRealWorldInputs,
) -> None:
    assert {
        (case["cve_id"], relation["rule_id"])
        for case in frozen_inputs.proposal_cases
        for relation in case["relations"]
    } == {
        ("CVE-2023-24816", "securescan.python.os-system"),
        ("CVE-2023-40581", "securescan.python.subprocess-shell-true"),
        ("CVE-2023-50943", "securescan.python.unsafe-pickle-load"),
        ("CVE-2023-7018", "securescan.python.unsafe-pickle-load"),
        ("CVE-2024-3098", "securescan.python.dangerous-eval"),
        ("CVE-2024-3271", "securescan.python.dangerous-eval"),
        ("CVE-2024-3568", "securescan.python.unsafe-pickle-load"),
    }
    dispositions = {
        value: sum(case["case_disposition"] == value for case in frozen_inputs.proposal_cases)
        for value in (
            "CLAIM_APPLICABLE",
            "OUTSIDE_FROZEN_RULE_CLAIMS",
            "UNRESOLVED",
        )
    }
    assert dispositions == {
        "CLAIM_APPLICABLE": 7,
        "OUTSIDE_FROZEN_RULE_CLAIMS": 6,
        "UNRESOLVED": 0,
    }
    assert sum(item.expected_match for item in frozen_inputs.expectations) == 11
    assert sum(not item.expected_match for item in frozen_inputs.expectations) == 3


def test_yt_dlp_is_a_scoring_relation(frozen_inputs: FrozenRealWorldInputs) -> None:
    relations = [
        item for item in frozen_inputs.expectations if item.cve_id == "CVE-2023-40581"
    ]
    assert [(item.revision_role, item.rule_id, item.expected_match) for item in relations] == [
        ("fixed", "securescan.python.subprocess-shell-true", False),
        ("vulnerable", "securescan.python.subprocess-shell-true", True),
    ]


def test_historical_v1_applicability_is_not_loaded_for_scoring(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loaded: list[str] = []
    original = evaluation_module.load_json

    def tracking_load(path: Path) -> dict[str, object]:
        loaded.append(path.name)
        return original(path)

    monkeypatch.setattr(evaluation_module, "load_json", tracking_load)
    load_frozen_inputs(ROOT)
    assert "rule-claims-v2.json" in loaded
    assert "applicability-proposal-v2.json" in loaded
    assert not {
        "rule-claims.json",
        "applicability-proposal.json",
        "applicability-summary.json",
        "applicability-review.json",
    } & set(loaded)


@pytest.mark.parametrize(
    "name",
    (
        "rule-claims-v2.json",
        "rule-claim-conformance-audit-v2.json",
        "applicability-proposal-v2.json",
        "applicability-summary-v2.json",
        "applicability-review-v2.json",
    ),
)
def test_any_f2e4_evidence_file_identity_mismatch_fails_closed(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = evaluation_module._file_digest

    def hostile_digest(path: Path) -> str:
        return "0" * 64 if path.name == name else original(path)

    monkeypatch.setattr(evaluation_module, "_file_digest", hostile_digest)
    with pytest.raises(ValueError, match="F2E4 .* binding is invalid"):
        load_frozen_inputs(ROOT)


def test_old_provisional_output_filenames_are_forbidden() -> None:
    cli_source = (
        ROOT / "src/securescan/benchmarks/python_sast_realworld_evaluation_cli.py"
    ).read_text(encoding="utf-8")
    assert '"realworld-evaluation-report.json"' not in cli_source
    assert '"realworld-evaluation-review.json"' not in cli_source
    assert not (BENCHMARK_ROOT / "realworld-evaluation-report.json").exists()
    assert not (BENCHMARK_ROOT / "realworld-evaluation-review.json").exists()


def test_wrong_scanner_executable_fails(tmp_path: Path) -> None:
    executable = tmp_path / "semgrep"
    executable.write_text("fixture", encoding="utf-8")
    with pytest.raises(ValueError, match="scanner executable is invalid"):
        verify_scanner_identity(ROOT, executable, tmp_path)


def test_wrong_scanner_version_fails_before_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    executable = repository / ".venv-semgrep-1.171/bin/semgrep"
    executable.parent.mkdir(parents=True)
    executable.write_text("fixture", encoding="utf-8")
    monkeypatch.setattr(
        evaluation_module.subprocess,
        "run",
        lambda arguments, **_kwargs: subprocess.CompletedProcess(arguments, 0, b"1.170.0\n", b""),
    )
    with pytest.raises(ValueError, match="scanner identity is invalid"):
        verify_scanner_identity(repository, executable, tmp_path / "temporary")


def test_controlled_environment_drops_arbitrary_semgrep_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SEMGREP_UNTRUSTED", "value")
    environment = controlled_environment(tmp_path, tmp_path / "bin/semgrep")
    assert "SEMGREP_UNTRUSTED" not in environment
    assert set(environment) == {
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "SEMGREP_LOG_FILE",
        "SEMGREP_SETTINGS_FILE",
    }


def test_projection_path_is_safe_and_deterministic() -> None:
    assert projection_path("CVE-2024-0001", "fixed", "package/source.py") == (
        "cases/CVE-2024-0001/fixed/package/source.py"
    )
    with pytest.raises(ValueError, match="projection path is invalid"):
        projection_path("CVE-2024-0001", "fixed", "../source.py")


def test_projection_rejects_symlink_and_nonregular(tmp_path: Path) -> None:
    target = tmp_path / "target.py"
    target.write_bytes(b"value = 1\n")
    link = tmp_path / "link.py"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="projection is invalid"):
        _projection_file(tmp_path, "link.py")
    directory = tmp_path / "directory.py"
    directory.mkdir()
    with pytest.raises(ValueError, match="projection is invalid"):
        _projection_file(tmp_path, "directory.py")


def test_projection_byte_integrity_fails_closed(tmp_path: Path) -> None:
    projection = _projection(tmp_path)
    (tmp_path / projection.entries[0].scanner_path).write_bytes(b"tampered\n")
    with pytest.raises(ValueError, match="byte identity is invalid"):
        verify_projection(projection)


def test_actual_projection_contains_all_26_logical_revisions(
    tmp_path: Path, frozen_inputs: FrozenRealWorldInputs
) -> None:
    projection = create_projection(
        tmp_path / "projection",
        ROOT / ".cache/securescan-realworld-python",
        frozen_inputs,
    )
    assert {(item.cve_id, item.revision_role) for item in projection.entries} == {
        (case["cve_id"], role)
        for case in frozen_inputs.accepted_cases
        for role in ("vulnerable", "fixed")
    }
    assert all(item.scanner_path.startswith("cases/") for item in projection.entries)


def test_duplicate_finding_normalization(tmp_path: Path) -> None:
    projection = _projection(tmp_path)
    path = projection.entries[0].scanner_path
    rule = "securescan.python.dangerous-eval"
    normalized = normalize_scanner_output(
        _semgrep_output([_finding(path, rule), _finding(path, rule)]), projection
    )
    assert len(normalized.findings) == 1
    assert normalized.raw_result_count == 2
    assert normalized.duplicate_result_count == 1


@pytest.mark.parametrize(
    ("output", "message"),
    (
        (b'{"errors":[],"results":[],"results":[]}', "malformed"),
        (_semgrep_output([], version="1.170.0"), "version is invalid"),
        (
            _semgrep_output([], errors=[{"type": "Parse error", "message": "gap"}]),
            "analysis gaps",
        ),
    ),
)
def test_malformed_wrong_version_and_analysis_gap_fail_closed(
    tmp_path: Path, output: bytes, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        normalize_scanner_output(output, _projection(tmp_path))


def test_unknown_projected_path_and_unknown_rule_fail_closed(tmp_path: Path) -> None:
    projection = _projection(tmp_path)
    path = projection.entries[0].scanner_path
    with pytest.raises(ValueError, match="analysis gaps"):
        normalize_scanner_output(
            _semgrep_output(
                [_finding("cases/CVE-2024-9999/vulnerable/unknown.py", min(PRODUCTION_RULE_IDS))]
            ),
            projection,
        )
    with pytest.raises(ValueError, match="finding is invalid"):
        normalize_scanner_output(_semgrep_output([_finding(path, "unknown.rule")]), projection)


def test_scanner_nonzero_failure_and_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, frozen_inputs: FrozenRealWorldInputs
) -> None:
    projection = _projection(tmp_path / "projection")
    monkeypatch.setattr(evaluation_module, "verify_ruleset_identity", lambda _root: None)
    monkeypatch.setattr(evaluation_module, "verify_scanner_identity", lambda *_args: None)
    monkeypatch.setattr(evaluation_module, "create_projection", lambda *_args: projection)
    monkeypatch.setattr(
        evaluation_module.subprocess,
        "run",
        lambda arguments, **_kwargs: subprocess.CompletedProcess(arguments, 2, b"", b"error"),
    )
    with pytest.raises(RuntimeError, match="execution failed"):
        evaluation_module.execute_controlled_scan(ROOT, frozen_inputs, Path("semgrep"))

    def timeout(*_args: object, **_kwargs: object) -> None:
        raise subprocess.TimeoutExpired("semgrep", 300)

    monkeypatch.setattr(evaluation_module.subprocess, "run", timeout)
    with pytest.raises(RuntimeError, match="timed out"):
        evaluation_module.execute_controlled_scan(ROOT, frozen_inputs, Path("semgrep"))


def test_location_containment_satisfies_only_the_exact_relation(
    frozen_inputs: FrozenRealWorldInputs,
) -> None:
    expectation = next(item for item in frozen_inputs.expectations if item.expected_match)
    finding = _observed_for(expectation)
    result = evaluate_observations(frozen_inputs, _observations((finding,)))
    scored = next(
        item
        for item in result.scored
        if item.case_id == expectation.case_id
        and item.revision_role == expectation.revision_role
        and item.rule_id == expectation.rule_id
    )
    assert scored.observed_match is True


def test_same_rule_outside_region_does_not_satisfy_relation(
    frozen_inputs: FrozenRealWorldInputs,
) -> None:
    expectation = frozen_inputs.expectations[0]
    region = expectation.evidence_regions[0]
    finding = ObservedFinding(
        expectation.case_id,
        expectation.cve_id,
        expectation.revision_role,
        region.relative_source_path,
        expectation.rule_id,
        region.end_line + 1,
        region.end_line + 1,
    )
    result = evaluate_observations(frozen_inputs, _observations((finding,)))
    assert "same-rule-outside-cve-region" in {item.classification for item in result.observations}
    assert not any(
        item.observed_match
        for item in result.scored
        if item.case_id == expectation.case_id
        and item.revision_role == expectation.revision_role
        and item.rule_id == expectation.rule_id
    )


def test_wrong_rule_inside_region_is_cross_rule_and_does_not_satisfy(
    frozen_inputs: FrozenRealWorldInputs,
) -> None:
    expectation = frozen_inputs.expectations[0]
    wrong_rule = next(rule for rule in sorted(PRODUCTION_RULE_IDS) if rule != expectation.rule_id)
    result = evaluate_observations(
        frozen_inputs,
        _observations((_observed_for(expectation, rule_id=wrong_rule),)),
    )
    assert "cross-rule-in-cve-region" in {item.classification for item in result.observations}
    assert not any(
        item.observed_match
        for item in result.scored
        if item.case_id == expectation.case_id
        and item.revision_role == expectation.revision_role
        and item.rule_id == expectation.rule_id
    )


@pytest.mark.parametrize(
    ("expected", "observed", "classification"),
    (
        (True, True, "TP"),
        (True, False, "FN"),
        (False, False, "TN"),
        (False, True, "FP"),
    ),
)
def test_revision_expectation_classifications(
    frozen_inputs: FrozenRealWorldInputs,
    expected: bool,
    observed: bool,
    classification: str,
) -> None:
    expectation = next(
        item for item in frozen_inputs.expectations if item.expected_match is expected
    )
    findings = (_observed_for(expectation),) if observed else ()
    result = evaluate_observations(frozen_inputs, _observations(findings))
    scored = next(
        item
        for item in result.scored
        if (item.case_id, item.revision_role, item.rule_id)
        == (expectation.case_id, expectation.revision_role, expectation.rule_id)
    )
    assert scored.classification == classification


def test_should_discriminate_success_and_failure(frozen_inputs: FrozenRealWorldInputs) -> None:
    perfect = evaluate_observations(frozen_inputs, _observations(_perfect_findings(frozen_inputs)))
    report = build_report(frozen_inputs, perfect)
    assert report["discrimination"]["successes"] == 3
    assert report["discrimination"]["failures"] == 0
    relation = next(
        item
        for item in frozen_inputs.expectations
        if item.discrimination_expectation == "SHOULD_DISCRIMINATE"
        and item.revision_role == "fixed"
    )
    failed_findings = (*_perfect_findings(frozen_inputs), _observed_for(relation))
    failed = build_report(
        frozen_inputs,
        evaluate_observations(frozen_inputs, _observations(failed_findings)),
    )
    assert failed["discrimination"]["failures"] == 1


def test_not_expected_to_discriminate_persistence(frozen_inputs: FrozenRealWorldInputs) -> None:
    report = build_report(
        frozen_inputs,
        evaluate_observations(frozen_inputs, _observations(_perfect_findings(frozen_inputs))),
    )
    assert report["non_discrimination"]["expected_persistent_count"] == 4
    assert report["non_discrimination"]["persisted_as_expected_count"] == 4
    assert report["non_discrimination"]["unexpected_disappearance_count"] == 0


def test_outside_case_observation_remains_non_scoring(
    frozen_inputs: FrozenRealWorldInputs,
) -> None:
    case = next(
        item
        for item in frozen_inputs.proposal_cases
        if item["case_disposition"] == "OUTSIDE_FROZEN_RULE_CLAIMS"
    )
    region = case["evidence"]["vulnerable"][0]
    finding = ObservedFinding(
        case["case_id"],
        case["cve_id"],
        "vulnerable",
        region["relative_source_path"],
        min(PRODUCTION_RULE_IDS),
        region["start_line"],
        region["end_line"],
    )
    evaluation = evaluate_observations(frozen_inputs, _observations((finding,)))
    assert evaluation.observations[0].classification == "outside-case-observation"
    assert len(evaluation.scored) == 14


def test_cve_detection_and_case_family_accounting(frozen_inputs: FrozenRealWorldInputs) -> None:
    report = build_report(
        frozen_inputs,
        evaluate_observations(frozen_inputs, _observations(_perfect_findings(frozen_inputs))),
    )
    assert report["applicable_cve_count"] == 7
    assert report["applicable_unique_case_families"] == 6
    assert report["applicable_unique_projects"] == 5
    assert report["vulnerable_cve_detection"]["detected_count"] == 7
    assert report["vulnerable_cve_detection"]["missed_count"] == 0
    assert report["vulnerable_cve_detection"]["vulnerable_detection_recall"] == "1.0000"


def test_deterministic_claim_metrics_and_per_rule_results(
    frozen_inputs: FrozenRealWorldInputs,
) -> None:
    evaluation = evaluate_observations(
        frozen_inputs, _observations(_perfect_findings(frozen_inputs))
    )
    report = build_report(frozen_inputs, evaluation)
    assert report["claim_conformance"] == {
        "tp": 11,
        "fp": 0,
        "fn": 0,
        "tn": 3,
        "precision": "1.0000",
        "recall": "1.0000",
        "f1": "1.0000",
    }
    assert report["expected_positive_count"] == 11
    assert report["expected_negative_count"] == 3
    assert len(report["per_rule_claim_conformance"]) == 17


def test_report_binds_all_frozen_f2e4_provenance(
    frozen_inputs: FrozenRealWorldInputs,
) -> None:
    report = build_report(
        frozen_inputs,
        evaluate_observations(frozen_inputs, _observations(_perfect_findings(frozen_inputs))),
    )
    assert report["schema_version"] == "securescan-python-sast-realworld-evaluation-v2"
    assert report["baseline_tag"] == BASELINE_TAG
    assert report["baseline_commit"] == BASELINE_COMMIT
    assert report["claim_contract_digest"] == CLAIM_CONTRACT_DIGEST
    assert report["claim_contract_file_sha256"] == CLAIM_CONTRACT_FILE_SHA256
    assert report["claim_audit_digest"] == CLAIM_AUDIT_DIGEST
    assert report["applicability_proposal_digest"] == APPLICABILITY_PROPOSAL_DIGEST
    assert report["applicability_summary_digest"] == APPLICABILITY_SUMMARY_DIGEST
    assert report["applicability_review_digest"] == APPLICABILITY_REVIEW_DIGEST


def test_review_includes_failures_observations_and_successes(
    frozen_inputs: FrozenRealWorldInputs,
) -> None:
    expectation = next(item for item in frozen_inputs.expectations if item.expected_match)
    outside = next(
        item
        for item in frozen_inputs.proposal_cases
        if item["case_disposition"] == "OUTSIDE_FROZEN_RULE_CLAIMS"
    )
    outside_region = outside["evidence"]["fixed"][0]
    outside_finding = ObservedFinding(
        outside["case_id"],
        outside["cve_id"],
        "fixed",
        outside_region["relative_source_path"],
        min(PRODUCTION_RULE_IDS),
        outside_region["start_line"],
        outside_region["end_line"],
    )
    findings = tuple(
        item for item in _perfect_findings(frozen_inputs) if item != _observed_for(expectation)
    ) + (outside_finding,)
    evaluation = evaluate_observations(frozen_inputs, _observations(findings))
    report = build_report(frozen_inputs, evaluation)
    review = build_review(evaluation, report)
    assert review["failures"]
    assert review["outside_case_observations"]
    assert review["representative_successful_relations"]
    assert review["report_digest"] == report_digest(report)


def test_report_has_no_host_paths_source_bodies_snippets_or_timestamps(
    frozen_inputs: FrozenRealWorldInputs,
) -> None:
    evaluation = evaluate_observations(
        frozen_inputs, _observations(_perfect_findings(frozen_inputs))
    )
    report = build_report(frozen_inputs, evaluation)
    review = build_review(evaluation, report)
    keys = {key.casefold() for document in (report, review) for key in _all_keys(document)}
    assert not keys & {"source", "source_body", "snippet", "timestamp"}
    strings = [item for document in (report, review) for item in _all_strings(document)]
    assert not any(item.startswith("/home/") or item.startswith("/tmp/") for item in strings)


def test_repeated_report_and_review_bytes_are_identical(
    frozen_inputs: FrozenRealWorldInputs,
) -> None:
    first_evaluation = evaluate_observations(
        frozen_inputs, _observations(_perfect_findings(frozen_inputs))
    )
    second_evaluation = evaluate_observations(
        frozen_inputs, _observations(tuple(reversed(_perfect_findings(frozen_inputs))))
    )
    first_report = build_report(frozen_inputs, first_evaluation)
    second_report = build_report(frozen_inputs, second_evaluation)
    assert canonical_report(first_report) == canonical_report(second_report)
    assert canonical_report(build_review(first_evaluation, first_report)) == canonical_report(
        build_review(second_evaluation, second_report)
    )


def test_record_requires_explicit_identical_evidence(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    review_path = tmp_path / "review.json"
    assert record_evidence(report_path, review_path, b"report\n", b"review\n") is True
    assert record_evidence(report_path, review_path, b"report\n", b"review\n") is False
    with pytest.raises(FileExistsError, match="already differs"):
        record_evidence(report_path, review_path, b"different\n", b"review\n")


def test_scanner_failure_accounting_never_becomes_clean(
    frozen_inputs: FrozenRealWorldInputs,
) -> None:
    report = build_report(
        frozen_inputs,
        evaluate_observations(frozen_inputs, _observations(_perfect_findings(frozen_inputs))),
    )
    assert report["scan_observation_accounting"]["scanner_failure_count"] == 0
    assert report["scan_observation_accounting"]["scanner_analysis_gap_count"] == 0
