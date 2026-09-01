from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from securescan.benchmarks import python_sast_external_evaluation_cli as cli
from securescan.benchmarks.python_sast import (
    EXPECTED_SCANNER_VERSION,
    SCANNER_ID,
    calculate_metrics,
)
from securescan.benchmarks.python_sast_applicability import (
    RULE_IDS,
    ApplicabilityDecision,
    EvidenceLocation,
    proposal_digest,
)
from securescan.benchmarks.python_sast_external import Candidate
from securescan.benchmarks.python_sast_external_evaluation import (
    EXPECTED_APPLICABILITY_COUNTS,
    EXPECTED_APPLICABILITY_PROPOSAL_DIGEST,
    EXPECTED_CANDIDATE_COUNT,
    EXPECTED_CANDIDATE_INVENTORY_DIGEST,
    EXPECTED_REVIEW_SELECTION_DIGEST,
    EXPECTED_RULE_CLAIM_CATALOG_DIGEST,
    EXPECTED_SCORING_RELATION_COUNT,
    CandidateProjection,
    ObservedRelation,
    ProjectionEntry,
    ScanObservations,
    _projection_file,
    build_external_report,
    build_external_review,
    canonical_report,
    controlled_environment,
    create_projection,
    evaluate_external_relations,
    load_frozen_external_inputs,
    normalize_scanner_output,
    projection_path,
    record_external_evidence,
    report_digest,
    verify_scanner_identity,
)
from securescan.workspaces.models import (
    RepositoryManifest,
    RepositoryManifestEntry,
    repository_content_digest,
)

ROOT = Path(__file__).parent.parent
BENCHMARK_ROOT = ROOT / "benchmarks/python_sast_external"


@pytest.fixture(scope="module")
def frozen_inputs():
    return load_frozen_external_inputs(ROOT)


def _candidate(
    number: int,
    *,
    label: str = "vulnerable",
    excluded: bool = False,
    source: bytes = b"value = 1\n",
) -> Candidate:
    case_id = f"BenchmarkTest{number:05d}"
    return Candidate(
        candidate_id=f"benchproctor-python-quicktest/flask/{case_id}",
        category="cmdi",
        cwe=78,
        external_case_id=case_id,
        external_source_id="benchproctor-python-quicktest",
        framework="flask",
        ground_truth_status="accepted",
        known_issue="cross-category-xss-contamination" if excluded else None,
        license="Apache-2.0",
        provenance="sources.lock.json#benchproctor-python-quicktest",
        relative_source_path=f"flask/testcode/benchmark_test_{number:05d}.py",
        scoring_status=(
            "excluded-known-benchmark-contamination"
            if excluded
            else "pending-applicability-review"
        ),
        source_sha256=hashlib.sha256(source).hexdigest(),
        upstream_label=label,
        upstream_version_id="2026.07.22",
    )


def _decision(
    candidate: Candidate,
    disposition: str,
    rule_id: str | None = None,
) -> ApplicabilityDecision:
    expected = (
        disposition == "APPLICABLE_POSITIVE"
        if disposition in {"APPLICABLE_POSITIVE", "APPLICABLE_NEGATIVE"}
        else None
    )
    return ApplicabilityDecision(
        candidate_id=candidate.candidate_id,
        disposition=disposition,
        expected_rule_id=rule_id,
        expected_match=expected,
        claim_class=("explicit-insecure-pattern" if rule_id is not None else None),
        reason_code="fixture-reason",
        review_state=(
            "fixed-policy-exclusion" if disposition == "EXCLUDED" else "pending-human-approval"
        ),
        possible_rule_ids=((rule_id,) if rule_id is not None else ()),
        evidence=(
            EvidenceLocation(
                relative_source_path=candidate.relative_source_path,
                source_sha256=candidate.source_sha256,
                start_line=1,
                end_line=1,
            ),
        ),
    )


def _observations(*relations: tuple[str, str, int]) -> ScanObservations:
    return ScanObservations(
        scanner_id=SCANNER_ID,
        scanner_version=EXPECTED_SCANNER_VERSION,
        relations=tuple(ObservedRelation(*relation) for relation in relations),
        raw_result_count=sum(relation[2] for relation in relations),
        accepted_result_count=sum(relation[2] for relation in relations),
    )


def _projection(tmp_path: Path) -> CandidateProjection:
    scanner_path = "cases/source/flask/BenchmarkTest00001.py"
    digest = hashlib.sha256(b"value = 1\n").hexdigest()
    manifest_entry = RepositoryManifestEntry(scanner_path, 10, digest)
    manifest_entries = (manifest_entry,)
    manifest = RepositoryManifest(
        entries=manifest_entries,
        file_count=1,
        total_bytes=10,
        content_digest=repository_content_digest(manifest_entries),
    )
    return CandidateProjection(
        root=tmp_path,
        entries=(ProjectionEntry(scanner_path, "candidate-1", digest, 10),),
        manifest=manifest,
    )


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


def _finding(path: str, rule_id: str, line: int = 1) -> dict[str, object]:
    return {
        "check_id": rule_id,
        "end": {"col": 2, "line": line},
        "extra": {"metadata": {}, "severity": "ERROR"},
        "path": path,
        "start": {"col": 1, "line": line},
    }


def test_frozen_f2c_inputs_are_bound_exactly(frozen_inputs) -> None:
    counts: dict[str, int] = {key: 0 for key in EXPECTED_APPLICABILITY_COUNTS}
    for decision in frozen_inputs.decisions:
        counts[decision.disposition] += 1

    assert len(frozen_inputs.candidates) == EXPECTED_CANDIDATE_COUNT
    assert counts == EXPECTED_APPLICABILITY_COUNTS
    assert frozen_inputs.proposal["candidate_inventory_digest"] == (
        EXPECTED_CANDIDATE_INVENTORY_DIGEST
    )
    assert frozen_inputs.proposal["review_selection_digest"] == EXPECTED_REVIEW_SELECTION_DIGEST
    assert frozen_inputs.proposal["rule_claim_catalog_digest"] == (
        EXPECTED_RULE_CLAIM_CATALOG_DIGEST
    )
    assert proposal_digest(frozen_inputs.proposal) == EXPECTED_APPLICABILITY_PROPOSAL_DIGEST
    assert SCANNER_ID == "semgrep-ce"
    assert EXPECTED_SCANNER_VERSION == "1.171.0"


def test_projection_path_is_deterministic_and_one_to_one() -> None:
    candidate = _candidate(1)

    assert projection_path(candidate) == (
        "cases/benchproctor-python-quicktest/flask/BenchmarkTest00001.py"
    )


def test_projection_copies_exact_bytes_without_hardlinks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = b"print('exact bytes')\n"
    candidate = _candidate(1, source=source)
    monkeypatch.setattr(
        "securescan.benchmarks.python_sast_external_evaluation._candidate_source",
        lambda *_args: source,
    )

    projection = create_projection(
        tmp_path / "projection", tmp_path / "cache", (candidate,), object()  # type: ignore[arg-type]
    )
    path = projection.root / projection.entries[0].scanner_path

    assert path.read_bytes() == source
    assert path.stat().st_nlink == 1
    assert projection.entries[0].source_sha256 == hashlib.sha256(source).hexdigest()


def test_projection_rejects_symlink(tmp_path: Path) -> None:
    root = tmp_path / "projection"
    root.mkdir()
    target = tmp_path / "target.py"
    target.write_bytes(b"value = 1\n")
    link = root / "case.py"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="projection is invalid"):
        _projection_file(root, "case.py")


def test_projection_path_rejects_traversal_shape() -> None:
    candidate = _candidate(1)
    object.__setattr__(candidate, "external_case_id", "../escape")

    with pytest.raises(ValueError, match="projection path is invalid"):
        projection_path(candidate)


def test_scanner_output_deduplicates_relation_and_preserves_observation_count(
    tmp_path: Path,
) -> None:
    projection = _projection(tmp_path)
    rule_id = "securescan.python.dangerous-eval"
    path = projection.entries[0].scanner_path
    output = _semgrep_output([_finding(path, rule_id, 1), _finding(path, rule_id, 2)])

    normalized = normalize_scanner_output(output, projection)

    assert normalized.relations == (ObservedRelation("candidate-1", rule_id, 2),)


@pytest.mark.parametrize(
    ("output", "message"),
    (
        (b'{"errors":[],"results":[],"results":[],"version":"1.171.0"}', "malformed"),
        (_semgrep_output([], version="1.170.0"), "version is invalid"),
    ),
)
def test_malformed_or_wrong_version_scanner_output_fails_closed(
    tmp_path: Path, output: bytes, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        normalize_scanner_output(output, _projection(tmp_path))


def test_parser_gap_fails_external_evaluation(tmp_path: Path) -> None:
    output = _semgrep_output(
        [], errors=[{"type": "Parse error", "message": "fixture diagnostic"}]
    )

    with pytest.raises(ValueError, match="analysis gaps"):
        normalize_scanner_output(output, _projection(tmp_path))


def test_unknown_rule_and_scanner_path_fail_closed(tmp_path: Path) -> None:
    projection = _projection(tmp_path)
    path = projection.entries[0].scanner_path
    with pytest.raises(ValueError, match="observation is invalid"):
        output = _semgrep_output([_finding(path, "unknown.rule")])
        normalize_scanner_output(output, projection)
    assert output
    with pytest.raises(ValueError, match="analysis gaps"):
        normalize_scanner_output(
            _semgrep_output(
                [_finding("cases/source/flask/BenchmarkTest99999.py", min(RULE_IDS))]
            ),
            projection,
        )


def test_scanner_identity_is_exact_and_wrong_version_fails_before_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    executable = repository / ".venv-semgrep-1.171/bin/semgrep"
    executable.parent.mkdir(parents=True)
    executable.write_text("fixture", encoding="utf-8")
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    calls: list[list[str]] = []

    def fake_run(arguments, **_kwargs):
        calls.append(arguments)
        return subprocess.CompletedProcess(arguments, 0, b"1.170.0\n", b"")

    monkeypatch.setattr(
        "securescan.benchmarks.python_sast_external_evaluation.subprocess.run", fake_run
    )
    with pytest.raises(ValueError, match="scanner identity is invalid"):
        verify_scanner_identity(repository, executable, temporary)

    assert calls == [[os.fspath(executable), "--disable-version-check", "--version"]]
    assert all("scan" not in arguments for arguments in calls)


@pytest.mark.parametrize(
    ("scanner_id", "scanner_version"),
    (("other-scanner", EXPECTED_SCANNER_VERSION), (SCANNER_ID, "1.170.0")),
)
def test_observation_identity_must_match_frozen_scanner(
    scanner_id: str, scanner_version: str
) -> None:
    with pytest.raises(ValueError, match="scanner observations are invalid"):
        ScanObservations(scanner_id, scanner_version, (), 0, 0)


def test_controlled_environment_does_not_inherit_semgrep_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SEMGREP_FAKE_UNTRUSTED", "value")
    executable = tmp_path / "semgrep-bin/semgrep"

    environment = controlled_environment(tmp_path, executable)

    assert "SEMGREP_FAKE_UNTRUSTED" not in environment
    assert set(environment) == {
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "SEMGREP_LOG_FILE",
        "SEMGREP_SETTINGS_FILE",
    }


def test_tp_fp_fn_tn_mapping_and_non_scoring_boundaries() -> None:
    positive = _candidate(1)
    negative = _candidate(2, label="safe")
    outside = _candidate(3)
    excluded = _candidate(4, excluded=True)
    eval_rule = "securescan.python.dangerous-eval"
    requests_rule = "securescan.python.requests-verify-false"
    decisions = (
        _decision(positive, "APPLICABLE_POSITIVE", eval_rule),
        _decision(negative, "APPLICABLE_NEGATIVE", requests_rule),
        _decision(outside, "OUT_OF_SCOPE"),
        _decision(excluded, "EXCLUDED"),
    )
    candidates = (positive, negative, outside, excluded)
    observations = _observations(
        (positive.candidate_id, eval_rule, 1),
        (negative.candidate_id, requests_rule, 1),
        (outside.candidate_id, eval_rule, 1),
        (excluded.candidate_id, eval_rule, 1),
    )

    evaluation = evaluate_external_relations(decisions, candidates, observations)

    assert evaluation.overall.canonical_data() == {
        "f1": "0.6667",
        "fn": 0,
        "fp": 1,
        "precision": "0.5000",
        "recall": "1.0000",
        "tn": 0,
        "tp": 1,
    }
    assert len(evaluation.out_of_scope) == 1
    assert len(evaluation.excluded) == 1


def test_wrong_rule_neither_satisfies_positive_nor_creates_negative_fp() -> None:
    positive = _candidate(1)
    negative = _candidate(2, label="safe")
    eval_rule = "securescan.python.dangerous-eval"
    expected_negative = "securescan.python.requests-verify-false"
    wrong_rule = "securescan.python.os-system"
    decisions = (
        _decision(positive, "APPLICABLE_POSITIVE", eval_rule),
        _decision(negative, "APPLICABLE_NEGATIVE", expected_negative),
    )
    evaluation = evaluate_external_relations(
        decisions,
        (positive, negative),
        _observations(
            (positive.candidate_id, wrong_rule, 1),
            (negative.candidate_id, wrong_rule, 1),
        ),
    )

    assert [item.classification for item in evaluation.scored_relations] == ["FN", "TN"]
    assert len(evaluation.unexpected_cross_rule) == 2


def test_unknown_candidate_observation_is_rejected() -> None:
    candidate = _candidate(1)
    decision = _decision(candidate, "APPLICABLE_POSITIVE", min(RULE_IDS))

    with pytest.raises(ValueError, match="observation is invalid"):
        evaluate_external_relations(
            (decision,),
            (candidate,),
            _observations(("unknown-candidate", min(RULE_IDS), 1)),
        )


def test_zero_evidence_rules_and_decimal_rounding_remain_explicit() -> None:
    candidate = _candidate(1)
    rule_id = "securescan.python.dangerous-eval"
    evaluation = evaluate_external_relations(
        (_decision(candidate, "APPLICABLE_POSITIVE", rule_id),),
        (candidate,),
        _observations(),
    )
    empty = next(item for item in evaluation.per_rule if item.rule_id != rule_id)

    assert empty.applicable_positive_count == 0
    assert empty.applicable_negative_count == 0
    assert empty.metrics.precision is None
    assert empty.metrics.recall is None
    assert empty.metrics.f1 is None
    assert calculate_metrics(("TP", "FP", "FP")).precision == "0.3333"


def test_frozen_report_is_deterministic_complete_and_contains_no_host_data(
    frozen_inputs,
) -> None:
    observations = _observations()
    first_evaluation = evaluate_external_relations(
        frozen_inputs.decisions, frozen_inputs.candidates, observations
    )
    second_evaluation = evaluate_external_relations(
        frozen_inputs.decisions, frozen_inputs.candidates, observations
    )
    first = build_external_report(frozen_inputs, first_evaluation)
    second = build_external_report(frozen_inputs, second_evaluation)
    encoded = canonical_report(first)

    assert encoded == canonical_report(second)
    assert first["scanned_candidate_count"] == EXPECTED_CANDIDATE_COUNT
    assert first["scored_relation_count"] == EXPECTED_SCORING_RELATION_COUNT
    assert len(first["per_rule"]) == len(RULE_IDS) == 17
    assert str(ROOT).encode() not in encoded
    assert b"timestamp" not in encoded
    assert b"source_body" not in encoded
    assert b"value = 1" not in encoded


def test_review_contains_all_failures_and_three_or_fewer_representatives_per_rule(
    frozen_inputs,
) -> None:
    evaluation = evaluate_external_relations(
        frozen_inputs.decisions, frozen_inputs.candidates, _observations()
    )
    report = build_external_report(frozen_inputs, evaluation)
    review = build_external_review(frozen_inputs, evaluation, report)

    assert len(review["failures"]) == 400
    assert review["report_digest"] == report_digest(report)
    assert len(review["representative_tp_tn"]) <= len(RULE_IDS) * 6
    assert str(ROOT).encode() not in canonical_report(review)


def test_report_mode_prints_only_and_does_not_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "benchmarks/python_sast_external").mkdir(parents=True)
    monkeypatch.setattr(cli, "repository_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "evaluation_payloads", lambda _root: (b'{"report":true}\n', b"{}\n"))

    assert cli.main(["report"]) == 0
    captured = capfd.readouterr()

    assert captured.out == '{"report":true}\n'
    assert list((tmp_path / "benchmarks/python_sast_external").iterdir()) == []


def test_record_refuses_conflict_and_accepts_identical_existing_evidence(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    review_path = tmp_path / "review.json"
    assert record_external_evidence(report_path, review_path, b"report\n", b"review\n")
    assert not record_external_evidence(report_path, review_path, b"report\n", b"review\n")
    report_path.write_bytes(b"different\n")

    with pytest.raises(FileExistsError, match="already exists"):
        record_external_evidence(report_path, review_path, b"report\n", b"review\n")
