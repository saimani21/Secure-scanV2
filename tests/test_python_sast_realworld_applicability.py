from __future__ import annotations

import ast
import copy
import json
import subprocess
from pathlib import Path

import pytest

import securescan.benchmarks.python_sast_realworld_applicability as applicability
from securescan.benchmarks.python_sast_realworld import canonical_document, digest, load_json
from securescan.benchmarks.python_sast_realworld_applicability import (
    ACCEPTED_CASE_SET_DIGEST,
    BASELINE_COMMIT,
    BASELINE_TAG,
    CLAIM_APPLICABLE,
    NOT_EXPECTED_TO_DISCRIMINATE,
    OUTSIDE_FROZEN_RULE_CLAIMS,
    REVIEW_STATE,
    RULE_CLAIM_CATALOG_DIGEST,
    RULE_IDS,
    SHOULD_DISCRIMINATE,
    SOURCE_LOCK_DIGEST,
    UNRESOLVED,
    build_documents,
    classify_frozen_claims,
    verify_documents,
)

ROOT = Path(__file__).parent.parent
BENCHMARK_ROOT = ROOT / "benchmarks/python_sast_realworld"
MODULE_PATH = ROOT / "src/securescan/benchmarks/python_sast_realworld_applicability.py"
CLI_PATH = ROOT / "src/securescan/benchmarks/python_sast_realworld_applicability_cli.py"


@pytest.fixture(scope="module")
def documents() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    return build_documents(ROOT)


def _keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {item for nested in value.values() for item in _keys(nested)}
    if isinstance(value, list):
        return {item for nested in value for item in _keys(nested)}
    return set()


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for nested in value.values() for item in _strings(nested)]
    if isinstance(value, list):
        return [item for nested in value for item in _strings(nested)]
    return []


def _cases(proposal: dict[str, object]) -> list[dict[str, object]]:
    cases = proposal["cases"]
    assert isinstance(cases, list)
    assert all(isinstance(case, dict) for case in cases)
    return cases  # type: ignore[return-value]


def test_exact_f2e1_and_rule_claim_bindings(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    proposal, summary, review = documents
    assert proposal["baseline_tag"] == BASELINE_TAG
    assert proposal["baseline_commit"] == BASELINE_COMMIT
    for document in (proposal, summary, review):
        assert document["source_lock_digest"] == SOURCE_LOCK_DIGEST
        assert document["accepted_case_set_digest"] == ACCEPTED_CASE_SET_DIGEST
        assert document["rule_claim_catalog_digest"] == RULE_CLAIM_CATALOG_DIGEST
    catalog = load_json(ROOT / "benchmarks/python_sast_external/rule-claims.json")
    assert digest(catalog) == RULE_CLAIM_CATALOG_DIGEST


def test_wrong_baseline_commit_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(applicability, "_baseline_commit", lambda _root: "0" * 40)
    with pytest.raises(ValueError, match="baseline tag resolves to the wrong commit"):
        build_documents(ROOT)


def test_wrong_source_lock_binding_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        applicability,
        "verify_realworld_cases",
        lambda _benchmark, _cache: {"source_lock_digest": "0" * 64},
    )
    with pytest.raises(ValueError, match="source-lock digest is not frozen"):
        build_documents(ROOT)


def test_wrong_rule_claim_catalog_binding_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    original = applicability.load_json

    def tampered(path: Path) -> dict[str, object]:
        document = original(path)
        if path.name == "rule-claims.json":
            document = copy.deepcopy(document)
            document["rules"][0]["positive_scope"] = ["tampered"]  # type: ignore[index]
        return document

    monkeypatch.setattr(applicability, "load_json", tampered)
    with pytest.raises(ValueError, match="catalog digest is invalid"):
        build_documents(ROOT)


def test_wrong_accepted_case_set_binding_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(applicability, "accepted_case_set_digest", lambda _document: "0" * 64)
    with pytest.raises(ValueError, match="accepted-case-set digest is not frozen"):
        build_documents(ROOT)


def test_all_13_cases_are_accounted_once(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    cases = _cases(documents[0])
    ids = [case["cve_id"] for case in cases]
    assert len(ids) == 13
    assert ids == sorted(set(ids))
    assert (
        sum(
            case["case_disposition"] == disposition
            for case in cases
            for disposition in (CLAIM_APPLICABLE, OUTSIDE_FROZEN_RULE_CLAIMS, UNRESOLVED)
        )
        == 13
    )


def test_case_disposition_accounting_is_exact(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    summary = documents[1]
    assert summary["case_disposition_counts"] == {
        CLAIM_APPLICABLE: 6,
        OUTSIDE_FROZEN_RULE_CLAIMS: 7,
        UNRESOLVED: 0,
    }


def test_every_decision_remains_pending_human_approval(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    assert {case["review_state"] for case in _cases(documents[0])} == {REVIEW_STATE}


def test_evidence_paths_hashes_lines_and_revision_roles_are_bound_to_f2e1(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    accepted = load_json(BENCHMARK_ROOT / "accepted-cases.json")
    frozen = {case["cve_id"]: case for case in accepted["cases"]}
    for decision in _cases(documents[0]):
        case = frozen[decision["cve_id"]]
        for role in ("vulnerable", "fixed"):
            snapshot = case[f"{role}_source"]
            hashes = {item["path"]: item["sha256"] for item in snapshot["per_file_sha256"]}
            for region in decision["evidence"][role]:
                assert region["revision_role"] == role
                assert region["relative_source_path"] in snapshot["relevant_path_set"]
                assert region["source_sha256"] == hashes[region["relative_source_path"]]
                assert 1 <= region["start_line"] <= region["end_line"]
                assert snapshot["revision"] == case[f"{role}_revision"]


def test_revision_roles_cannot_be_swapped(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    for case in _cases(documents[0]):
        vulnerable_hashes = {item["source_sha256"] for item in case["evidence"]["vulnerable"]}
        fixed_hashes = {item["source_sha256"] for item in case["evidence"]["fixed"]}
        assert vulnerable_hashes
        assert fixed_hashes
        assert all(item["revision_role"] == "vulnerable" for item in case["evidence"]["vulnerable"])
        assert all(item["revision_role"] == "fixed" for item in case["evidence"]["fixed"])


@pytest.mark.parametrize(
    ("source", "rule_id"),
    (
        ("value = eval(payload)", "securescan.python.dangerous-eval"),
        ("exec(payload)", "securescan.python.dangerous-exec"),
        ("import os\nos.system(command)", "securescan.python.os-system"),
        ("from os import popen\npopen(command)", "securescan.python.os-popen"),
        ("import pickle\npickle.loads(data)", "securescan.python.unsafe-pickle-load"),
        ("import tempfile\ntempfile.mktemp()", "securescan.python.insecure-tempfile-mktemp"),
        (
            "import subprocess\nsubprocess.run(command, shell=True)",
            "securescan.python.subprocess-shell-true",
        ),
        ("import yaml\nyaml.load(data, Loader=yaml.Loader)", "securescan.python.unsafe-yaml-load"),
        (
            "import requests\nrequests.get(url, verify=False)",
            "securescan.python.requests-verify-false",
        ),
        (
            "import requests\ns = requests.Session()\ns.verify = False",
            "securescan.python.requests-session-verify-false",
        ),
        (
            "import ssl\nssl._create_unverified_context()",
            "securescan.python.ssl-unverified-context",
        ),
        (
            "import paramiko\nc = paramiko.SSHClient()\n"
            "c.set_missing_host_key_policy(paramiko.AutoAddPolicy())",
            "securescan.python.paramiko-autoaddpolicy",
        ),
        (
            "from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)",
            "securescan.python.flask-debug-enabled",
        ),
        (
            "import jinja2\njinja2.Environment(autoescape=False)",
            "securescan.python.jinja-autoescape-disabled",
        ),
        ("cursor.execute(f'SELECT {value}')", "securescan.python.sql-fstring-execute"),
        (
            "import jwt\njwt.decode(token, options={'verify_signature': False})",
            "securescan.python.jwt-signature-verification-disabled",
        ),
        (
            "from lxml import etree\netree.XMLParser(resolve_entities=True)",
            "securescan.python.lxml-resolve-entities",
        ),
    ),
)
def test_ast_classifier_implements_each_frozen_human_claim(source: str, rule_id: str) -> None:
    assert rule_id in classify_frozen_claims(source)


def test_same_cwe_does_not_imply_claim_applicability(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    by_id = {case["cve_id"]: case for case in _cases(documents[0])}
    assert by_id["CVE-2022-28347"]["case_disposition"] == OUTSIDE_FROZEN_RULE_CLAIMS
    assert by_id["CVE-2022-34265"]["case_disposition"] == OUTSIDE_FROZEN_RULE_CLAIMS
    assert by_id["CVE-2024-7009"]["case_disposition"] == OUTSIDE_FROZEN_RULE_CLAIMS


def test_unsupported_sql_shapes_remain_outside() -> None:
    source = "query = f'SELECT {value}'\ncursor.execute(query)\ncursor.execute('x ' + value)"
    assert "securescan.python.sql-fstring-execute" not in classify_frozen_claims(source)


def test_non_pickle_deserialization_does_not_enter_pickle_claim() -> None:
    source = "import json\nvalue = json.loads(payload)"
    assert "securescan.python.unsafe-pickle-load" not in classify_frozen_claims(source)


def test_built_in_eval_resolution_and_shadowing() -> None:
    assert "securescan.python.dangerous-eval" in classify_frozen_claims("eval(payload)")
    assert "securescan.python.dangerous-eval" not in classify_frozen_claims(
        "def f(eval, payload):\n    return eval(payload)"
    )
    assert "securescan.python.dangerous-eval" not in classify_frozen_claims(
        "eval = handler\neval(payload)"
    )


def test_frozen_yaml_and_subprocess_boundaries() -> None:
    safe = "import yaml\nyaml.safe_load(data)\nyaml.load(data, Loader=yaml.FullLoader)"
    assert "securescan.python.unsafe-yaml-load" not in classify_frozen_claims(safe)
    unsupported = "import subprocess\nsubprocess.call(command, shell=True)"
    assert "securescan.python.subprocess-shell-true" not in classify_frozen_claims(unsupported)


def test_dangerous_api_may_persist_after_fix(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    relations = [
        relation
        for case in _cases(documents[0])
        for relation in case["relations"]
        if relation["discrimination_expectation"] == NOT_EXPECTED_TO_DISCRIMINATE
    ]
    assert len(relations) == 4
    assert all(item["vulnerable"]["expected_match"] is True for item in relations)
    assert all(item["fixed"]["expected_match"] is True for item in relations)


def test_removed_api_should_discriminate(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    relations = [
        relation
        for case in _cases(documents[0])
        for relation in case["relations"]
        if relation["discrimination_expectation"] == SHOULD_DISCRIMINATE
    ]
    assert len(relations) == 2
    assert all(item["vulnerable"]["expected_match"] is True for item in relations)
    assert all(item["fixed"]["expected_match"] is False for item in relations)


def test_no_applicable_relation_has_vulnerable_false(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    relations = [relation for case in _cases(documents[0]) for relation in case["relations"]]
    assert relations
    assert all(relation["vulnerable"]["expected_match"] is True for relation in relations)


def test_multiple_exact_claims_are_not_deduplicated() -> None:
    claims = classify_frozen_claims("import pickle\neval(payload)\npickle.loads(payload)")
    assert claims == {
        "securescan.python.dangerous-eval",
        "securescan.python.unsafe-pickle-load",
    }


def test_case_family_and_project_accounting(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    summary = documents[1]
    assert summary["applicable_unique_project_count"] == 4
    assert summary["applicable_unique_case_family_count"] == 5
    assert summary["relations_by_case_family"]["llama-index-safe-eval-restriction-bypass"] == 2


def test_all_outside_cases_have_reasons_and_no_relations(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    outside = [
        case
        for case in _cases(documents[0])
        if case["case_disposition"] == OUTSIDE_FROZEN_RULE_CLAIMS
    ]
    assert len(outside) == 7
    assert all(case["reason_codes"] for case in outside)
    assert all(case["applicable_rule_ids"] == [] and case["relations"] == [] for case in outside)


def test_summary_rule_accounting_is_complete(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    summary = documents[1]
    represented = set(summary["rules_represented_by_real_world_cases"])
    absent = set(summary["rules_without_real_world_applicable_cve"])
    assert represented == {
        "securescan.python.dangerous-eval",
        "securescan.python.os-system",
        "securescan.python.unsafe-pickle-load",
    }
    assert represented.isdisjoint(absent)
    assert represented | absent == set(RULE_IDS)


def test_committed_documents_are_canonical_and_current(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    proposal, summary, review = documents
    expected = {
        "applicability-proposal.json": proposal,
        "applicability-summary.json": summary,
        "applicability-review.json": review,
    }
    assert verify_documents(ROOT)
    for name, document in expected.items():
        assert (BENCHMARK_ROOT / name).read_bytes() == canonical_document(document)


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value.replace(b'"source_sha256": "', b'"source_sha256": "0', 1),
        lambda value: value.replace(b'"start_line": ', b'"start_line": 999', 1),
        lambda value: value.replace(
            b'"revision_role": "fixed"', b'"revision_role": "vulnerable"', 1
        ),
    ),
)
def test_tampered_evidence_hash_line_or_role_fails_verification(
    monkeypatch: pytest.MonkeyPatch,
    mutation: object,
) -> None:
    target = BENCHMARK_ROOT / "applicability-proposal.json"
    original_read_bytes = Path.read_bytes

    def read_bytes(path: Path) -> bytes:
        value = original_read_bytes(path)
        if path == target:
            return mutation(value)  # type: ignore[operator]
        return value

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    with pytest.raises(ValueError, match="stale or non-canonical"):
        verify_documents(ROOT)


def test_repeated_generation_is_byte_identical(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    second = build_documents(ROOT)
    assert tuple(canonical_document(item) for item in documents) == tuple(
        canonical_document(item) for item in second
    )


def test_evidence_has_no_host_paths_source_bodies_timestamps_or_metrics(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    forbidden = {
        "f1",
        "fn",
        "fp",
        "precision",
        "recall",
        "source_body",
        "source_code",
        "timestamp",
        "tn",
        "tp",
    }
    assert not ({key.casefold() for document in documents for key in _keys(document)} & forbidden)
    strings = [item for document in documents for item in _strings(document)]
    assert not any(item.startswith("/home/") or item.startswith("/tmp/") for item in strings)


def test_applicability_implementation_is_scanner_and_production_yaml_independent() -> None:
    for path in (MODULE_PATH, CLI_PATH):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        assert not any(
            "semgrep" in name.casefold() or "scanner" in name.casefold() for name in imports
        )
        literals = {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        assert not any(value.endswith((".yml", ".yaml")) for value in literals)
        assert "python_sast_external_evaluation" not in source
        assert "initial-v0.3e-baseline" not in source


def test_generation_process_invokes_only_git(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = subprocess.run
    commands: list[object] = []

    def spy(*args: object, **kwargs: object) -> subprocess.CompletedProcess[object]:
        commands.append(args[0])
        return original(*args, **kwargs)  # type: ignore[call-overload,return-value]

    monkeypatch.setattr(subprocess, "run", spy)
    build_documents(ROOT)
    assert commands
    assert all(isinstance(command, list) and command[0] == "git" for command in commands)


def test_review_contains_every_case_not_a_sample(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    proposal, _summary, review = documents
    assert review["case_count"] == 13
    assert [item["cve_id"] for item in review["cases"]] == [
        item["cve_id"] for item in proposal["cases"]
    ]


def test_documents_contain_no_scoring_result_fields(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    serialized = json.dumps(documents, sort_keys=True)
    assert '"expected_match"' in serialized
    for forbidden in ('"tp"', '"fp"', '"fn"', '"tn"', '"precision"', '"recall"', '"f1"'):
        assert forbidden not in serialized
