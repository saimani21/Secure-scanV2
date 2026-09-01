from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from securescan.benchmarks.python_sast_applicability import (
    EXPECTED_CANDIDATE_COUNT,
    EXPECTED_CANDIDATE_INVENTORY_DIGEST,
    EXPECTED_REVIEW_SELECTION_DIGEST,
    EXPECTED_SOURCE_LOCK_DIGEST,
    FROZEN_RULESET_DIGEST,
    RULE_IDS,
    SourceInspection,
    _decision,
    build_applicability_proposal,
    build_applicability_summary,
    build_audit_sample,
    inspect_python_source,
    load_applicability_proposal,
    load_rule_claim_catalog,
    proposal_digest,
    rule_claim_catalog_digest,
    validate_applicability_proposal,
)
from securescan.benchmarks.python_sast_external import Candidate, canonical_document

ROOT = Path(__file__).parent.parent
BENCHMARK_ROOT = ROOT / "benchmarks/python_sast_external"
CACHE_ROOT = ROOT / ".cache/securescan-benchmarks"
CATALOG_PATH = BENCHMARK_ROOT / "rule-claims.json"
PROPOSAL_PATH = BENCHMARK_ROOT / "applicability-proposal.json"
AUDIT_PATH = BENCHMARK_ROOT / "applicability-audit-sample.json"
SUMMARY_PATH = BENCHMARK_ROOT / "applicability-summary.json"
MODULE_PATH = ROOT / "src/securescan/benchmarks/python_sast_applicability.py"


@pytest.fixture(scope="module")
def built_evidence():
    proposal, candidates, catalog, source_lock = build_applicability_proposal(ROOT, CACHE_ROOT)
    decisions = validate_applicability_proposal(
        proposal, candidates, catalog, CACHE_ROOT, source_lock
    )
    audit = build_audit_sample(proposal, decisions, candidates)
    summary = build_applicability_summary(proposal, decisions, candidates, catalog, audit)
    return proposal, candidates, catalog, source_lock, decisions, audit, summary


def _candidate(*, label: str = "vulnerable", cwe: int = 94, excluded: bool = False) -> Candidate:
    return Candidate(
        candidate_id="benchproctor-python-quicktest/flask/BenchmarkTest00001",
        category="codeinj",
        cwe=cwe,
        external_case_id="BenchmarkTest00001",
        external_source_id="benchproctor-python-quicktest",
        framework="flask",
        ground_truth_status="accepted",
        known_issue="cross-category-xss-contamination" if excluded else None,
        license="Apache-2.0",
        provenance="sources.lock.json#benchproctor-python-quicktest",
        relative_source_path="flask/testcode/benchmark_test_00001.py",
        scoring_status=(
            "excluded-known-benchmark-contamination"
            if excluded
            else "pending-applicability-review"
        ),
        source_sha256="1" * 64,
        upstream_label=label,
        upstream_version_id="2026.07.22",
    )


def _classify(source: str, *, label: str = "vulnerable", cwe: int = 94):
    return _decision(
        _candidate(label=label, cwe=cwe),
        load_rule_claim_catalog(CATALOG_PATH),
        inspect_python_source(source.encode()),
    )


def _relations(source: str) -> set[tuple[str, str, str]]:
    return {
        (item.kind, item.rule_id, item.reason_code)
        for item in inspect_python_source(source.encode()).relations
    }


def test_rule_claim_catalog_is_canonical_complete_and_deterministic() -> None:
    catalog = load_rule_claim_catalog(CATALOG_PATH)

    assert len(catalog.rules) == 17
    assert {rule.rule_id for rule in catalog.rules} == RULE_IDS
    assert CATALOG_PATH.read_bytes() == canonical_document(catalog.canonical_data())
    assert rule_claim_catalog_digest(catalog) == rule_claim_catalog_digest(catalog)
    assert catalog.ruleset_digest == FROZEN_RULESET_DIGEST


def test_ast_recognizes_module_and_from_import_aliases() -> None:
    relations = _relations(
        "import os as operating_system\n"
        "from pickle import loads as restore\n"
        "operating_system.system(command)\n"
        "restore(payload)\n"
    )

    assert ("positive", "securescan.python.os-system", "direct-semantic-api-use") in relations
    assert (
        "positive",
        "securescan.python.unsafe-pickle-load",
        "direct-semantic-api-use",
    ) in relations


def test_builtin_and_import_shadowing_are_unresolved() -> None:
    built_in = _classify("def eval(value): return value\neval(payload)\n")
    imported = _classify("import os\nos = object()\nos.system(command)\n", cwe=78)

    assert built_in.disposition == "UNRESOLVED"
    assert built_in.reason_code == "ambiguous-binding-or-shadowing"
    assert imported.disposition == "UNRESOLVED"
    assert imported.reason_code == "ambiguous-binding-or-shadowing"


def test_reassigned_local_framework_object_is_unresolved() -> None:
    decision = _classify(
        "from flask import Flask\napp = Flask(__name__)\napp = object()\napp.run(debug=True)\n",
        cwe=489,
    )

    assert decision.disposition == "UNRESOLVED"
    assert decision.reason_code == "ambiguous-binding-or-shadowing"


def test_unrelated_methods_and_literal_dynamic_boundaries() -> None:
    assert inspect_python_source(b"client.eval(payload)\n").relations == ()
    assert _classify("eval('2 + 2')\n").disposition == "OUT_OF_SCOPE"
    dynamic = _classify(
        "import subprocess\nsubprocess.run(command, shell=setting)\n", cwe=78
    )
    assert dynamic.disposition == "OUT_OF_SCOPE"
    assert dynamic.reason_code == "dynamic-argument-outside-literal-claim"


def test_safe_counterpart_and_dangerous_api_safe_label_boundary() -> None:
    safe_shell = _classify(
        "import subprocess\nsubprocess.run(command, shell=False)\n",
        label="safe",
        cwe=78,
    )
    safe_but_audited = _classify("eval(validated_value)\n", label="safe")

    assert safe_shell.disposition == "APPLICABLE_NEGATIVE"
    assert safe_shell.expected_match is False
    assert safe_but_audited.disposition == "OUT_OF_SCOPE"
    assert safe_but_audited.reason_code == "dangerous-api-safe-label-not-a-negative"


def test_sql_direct_fstring_boundary() -> None:
    direct = _classify('cursor.execute(f"SELECT {value}")\n', cwe=89)
    indirect = _classify('query = f"SELECT {value}"\ncursor.execute(query)\n', cwe=89)
    parameterized = _classify(
        'cursor.execute("SELECT * FROM t WHERE id = ?", (value,))\n',
        label="safe",
        cwe=89,
    )

    assert direct.disposition == "APPLICABLE_POSITIVE"
    assert indirect.disposition == "OUT_OF_SCOPE"
    assert parameterized.disposition == "APPLICABLE_NEGATIVE"


@pytest.mark.parametrize("loader", ("Loader", "UnsafeLoader", "CLoader"))
def test_yaml_explicit_unsafe_loader_boundaries(loader: str) -> None:
    decision = _classify(
        f"import yaml\nyaml.load(payload, Loader=yaml.{loader})\n", cwe=502
    )
    assert decision.disposition == "APPLICABLE_POSITIVE"


@pytest.mark.parametrize("loader", ("SafeLoader", "CSafeLoader"))
def test_yaml_safe_loaders_are_meaningful_negatives(loader: str) -> None:
    decision = _classify(
        f"import yaml\nyaml.load(payload, yaml.{loader})\n", label="safe", cwe=502
    )
    assert decision.disposition == "APPLICABLE_NEGATIVE"


def test_yaml_full_loader_is_outside_frozen_claim_and_never_applicable() -> None:
    decision = _classify(
        "import yaml\nyaml.load(payload, yaml.FullLoader)\n", label="safe", cwe=502
    )

    assert decision.disposition != "APPLICABLE_NEGATIVE"
    assert decision.disposition != "APPLICABLE_POSITIVE"
    assert decision.disposition == "OUT_OF_SCOPE"
    assert decision.reason_code == "full-loader-outside-frozen-claim"


def test_multiple_claims_remain_unresolved() -> None:
    decision = _classify(
        "import pickle\nimport yaml\npickle.loads(payload)\nyaml.unsafe_load(payload)\n",
        cwe=502,
    )

    assert decision.disposition == "UNRESOLVED"
    assert decision.reason_code == "multiple-claim-relations"
    assert decision.possible_rule_ids == (
        "securescan.python.unsafe-pickle-load",
        "securescan.python.unsafe-yaml-load",
    )


def test_known_contamination_is_excluded_before_source_classification() -> None:
    decision = _decision(
        _candidate(label="safe", cwe=502, excluded=True),
        load_rule_claim_catalog(CATALOG_PATH),
        SourceInspection(relations=()),
    )

    assert decision.disposition == "EXCLUDED"
    assert decision.review_state == "fixed-policy-exclusion"
    assert decision.possible_rule_ids == ()
    assert decision.expected_rule_id is None
    assert decision.expected_match is None
    assert decision.claim_class is None


def test_frozen_inputs_and_all_candidates_are_bound_once(built_evidence) -> None:
    proposal, candidates, catalog, source_lock, decisions, *_ = built_evidence

    assert proposal["source_lock_digest"] == EXPECTED_SOURCE_LOCK_DIGEST
    assert proposal["candidate_inventory_digest"] == EXPECTED_CANDIDATE_INVENTORY_DIGEST
    assert proposal["review_selection_digest"] == EXPECTED_REVIEW_SELECTION_DIGEST
    assert len(candidates) == len(decisions) == EXPECTED_CANDIDATE_COUNT
    assert len({decision.candidate_id for decision in decisions}) == EXPECTED_CANDIDATE_COUNT
    assert all(
        decision.review_state == "pending-human-approval"
        for decision in decisions
        if decision.disposition != "EXCLUDED"
    )
    excluded = [decision for decision in decisions if decision.disposition == "EXCLUDED"]
    assert len(excluded) == 33
    assert all(decision.possible_rule_ids == () for decision in excluded)
    assert all(decision.expected_rule_id is None for decision in excluded)
    assert validate_applicability_proposal(
        proposal, candidates, catalog, CACHE_ROOT, source_lock
    ) == decisions


def test_fixed_exclusions_do_not_contribute_to_rule_or_claim_counts(built_evidence) -> None:
    *_, summary = built_evidence

    assert summary["excluded_known_contamination_count"] == 33
    assert all(counts["EXCLUDED"] == 0 for counts in summary["counts_by_rule"].values())
    assert all(
        counts["EXCLUDED"] == 0 for counts in summary["counts_by_claim_class"].values()
    )


@pytest.mark.parametrize("mutation", ("missing", "duplicate"))
def test_missing_or_duplicate_candidate_decision_fails_closed(
    built_evidence, mutation: str
) -> None:
    proposal, candidates, catalog, source_lock, *_ = built_evidence
    changed = json.loads(json.dumps(proposal))
    if mutation == "missing":
        changed["decisions"].pop()
    else:
        changed["decisions"][-1] = changed["decisions"][0]

    with pytest.raises(ValueError, match="proposal is invalid"):
        validate_applicability_proposal(
            changed, candidates, catalog, CACHE_ROOT, source_lock
        )


def test_committed_proposal_and_summary_reconstruct_identically(built_evidence) -> None:
    proposal, candidates, catalog, source_lock, decisions, audit, summary = built_evidence
    loaded, loaded_decisions = load_applicability_proposal(
        PROPOSAL_PATH, candidates, catalog, CACHE_ROOT, source_lock
    )

    assert loaded == proposal
    assert loaded_decisions == decisions
    assert AUDIT_PATH.read_bytes() == canonical_document(audit)
    assert SUMMARY_PATH.read_bytes() == canonical_document(summary)
    assert json.loads(SUMMARY_PATH.read_bytes())["proposal_digest"] == proposal_digest(proposal)


def test_audit_sample_is_deterministic_and_contains_no_source_body_or_host_path(
    built_evidence,
) -> None:
    proposal, candidates, _, _, decisions, audit, _ = built_evidence

    assert audit == build_audit_sample(proposal, decisions, candidates)
    encoded = canonical_document(audit).decode()
    assert str(ROOT) not in encoded
    assert "source_body" not in encoded
    assert "source_text" not in encoded


def test_applicability_path_has_no_scanner_import_invocation_or_yaml_file_read() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    string_literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }

    assert not any("semgrep" in name.lower() for name in imported)
    assert "subprocess" not in imported
    assert not any(value.endswith((".yaml", ".yml")) for value in string_literals)
    assert "run_frozen_semgrep_benchmark" not in source
    assert "scanner_result" not in source


def test_proposal_contains_no_scanner_fields_or_metrics(built_evidence) -> None:
    proposal, *_ = built_evidence
    encoded = canonical_document(proposal).decode()

    assert not any(
        f'"{name}"' in encoded for name in ("tp", "fp", "fn", "tn", "precision", "recall", "f1")
    )
    assert not any(f'"{name}"' in encoded for name in ("scanner", "semgrep", "finding"))
