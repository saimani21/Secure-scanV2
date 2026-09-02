from __future__ import annotations

import ast
import copy
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from securescan.benchmarks.python_sast_realworld import canonical_document, load_json
from securescan.benchmarks.python_sast_realworld_applicability_v2 import (
    ACCEPTED_CASE_SET_DIGEST,
    CLAIM_APPLICABLE,
    F2E1_BASELINE_COMMIT,
    F2E1_BASELINE_TAG,
    F2E2_BASELINE_COMMIT,
    F2E2_BASELINE_TAG,
    HISTORICAL_F2E2_FILE_SHA256,
    NOT_EXPECTED_TO_DISCRIMINATE,
    OUTSIDE_FROZEN_RULE_CLAIMS,
    REVIEW_STATE,
    RULE_CLAIM_CONTRACT_DIGEST,
    RULE_IDS,
    SHOULD_DISCRIMINATE,
    SOURCE_LOCK_DIGEST,
    UNRESOLVED,
    _changed_cases,
    build_documents,
    classify_claim_contract_v2,
    verify_documents,
)

ROOT = Path(__file__).parent.parent
BENCHMARK_ROOT = ROOT / "benchmarks/python_sast_realworld"
MODULE_PATH = ROOT / "src/securescan/benchmarks/python_sast_realworld_applicability_v2.py"
CLI_PATH = ROOT / "src/securescan/benchmarks/python_sast_realworld_applicability_v2_cli.py"


@pytest.fixture(scope="module")
def documents() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    return build_documents(ROOT)


def _cases(proposal: dict[str, object]) -> list[dict[str, object]]:
    cases = proposal["cases"]
    assert isinstance(cases, list)
    assert all(isinstance(case, dict) for case in cases)
    return cases  # type: ignore[return-value]


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


def test_exact_f2e1_f2e2_and_contract_v2_bindings(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    proposal, summary, review = documents
    assert proposal["baseline_tags"] == {
        "F2E1": F2E1_BASELINE_TAG,
        "F2E2": F2E2_BASELINE_TAG,
    }
    assert proposal["baseline_commits"] == {
        "F2E1": F2E1_BASELINE_COMMIT,
        "F2E2": F2E2_BASELINE_COMMIT,
    }
    for document in (proposal, summary, review):
        assert document["source_lock_digest"] == SOURCE_LOCK_DIGEST
        assert document["accepted_case_set_digest"] == ACCEPTED_CASE_SET_DIGEST
        assert document["rule_claim_contract_digest"] == RULE_CLAIM_CONTRACT_DIGEST


def test_historical_f2e2_artifacts_remain_byte_identical() -> None:
    for name, expected in HISTORICAL_F2E2_FILE_SHA256.items():
        assert hashlib.sha256((BENCHMARK_ROOT / name).read_bytes()).hexdigest() == expected


def test_all_13_cases_are_re_reviewed_once(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    cases = _cases(documents[0])
    ids = [case["cve_id"] for case in cases]
    assert len(ids) == 13
    assert ids == sorted(set(ids))
    assert {case["review_state"] for case in cases} == {REVIEW_STATE}


def test_v2_case_disposition_accounting_is_exact(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    assert documents[1]["case_disposition_counts"] == {
        CLAIM_APPLICABLE: 7,
        OUTSIDE_FROZEN_RULE_CLAIMS: 6,
        UNRESOLVED: 0,
    }


def test_corrected_subprocess_methods_are_claim_positive() -> None:
    for method in ("run", "call", "check_call", "check_output", "Popen"):
        claims = classify_claim_contract_v2(
            f"import subprocess\nsubprocess.{method}(command, shell=True)"
        )
        assert "securescan.python.subprocess-shell-true" in claims


def test_subprocess_negative_boundaries_remain_outside() -> None:
    sources = (
        "subprocess.call(command)",
        "subprocess.call(command, shell=False)",
        "subprocess.call(command, shell=choice)",
        "subprocess.getoutput(command, shell=True)",
    )
    assert all(
        "securescan.python.subprocess-shell-true" not in classify_claim_contract_v2(source)
        for source in sources
    )


def test_corrected_requests_methods_are_claim_positive() -> None:
    for method in ("request", "get", "options", "head", "post", "put", "patch", "delete"):
        claims = classify_claim_contract_v2(
            f"import requests\nrequests.{method}(url, verify=False)"
        )
        assert "securescan.python.requests-verify-false" in claims


def test_full_loader_remains_outside_the_v2_claim() -> None:
    source = "import yaml\nyaml.load(data, Loader=yaml.FullLoader)"
    assert "securescan.python.unsafe-yaml-load" not in classify_claim_contract_v2(source)


def test_unimported_bare_yaml_loader_name_remains_outside() -> None:
    source = "yaml.load(data, Loader=Loader)"
    assert "securescan.python.unsafe-yaml-load" not in classify_claim_contract_v2(source)


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        (
            "session = requests.Session()\n\ndef configure():\n    session.verify = False\n",
            False,
        ),
        (
            "def configure():\n    session = requests.Session()\n    session.verify = False\n",
            True,
        ),
        (
            "def construct():\n    session = requests.Session()\n\n"
            "def configure():\n    session.verify = False\n",
            False,
        ),
        ("session.verify = False\nsession = requests.Session()\n", False),
        (
            "def outer():\n    session = requests.Session()\n"
            "    def configure():\n        session.verify = False\n",
            False,
        ),
        (
            "session = requests.Session()\nsession = object()\nsession.verify = False\n",
            True,
        ),
    ),
)
def test_requests_session_lexical_scope_matches_production(source: str, expected: bool) -> None:
    rule_id = "securescan.python.requests-session-verify-false"
    assert (rule_id in classify_claim_contract_v2(source)) is expected


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        (
            "app = flask.Flask(__name__)\n\ndef serve():\n    app.run(debug=True)\n",
            True,
        ),
        (
            "def serve():\n    app = flask.Flask(__name__)\n    app.run(debug=True)\n",
            True,
        ),
        (
            "def construct():\n    app = flask.Flask(__name__)\n\n"
            "def serve():\n    app.run(debug=True)\n",
            False,
        ),
        ("app.run(debug=True)\napp = flask.Flask(__name__)\n", False),
        (
            "def outer():\n    app = flask.Flask(__name__)\n"
            "    def serve():\n        app.run(debug=True)\n",
            True,
        ),
        (
            "app = flask.Flask(__name__)\napp = object()\napp.run(debug=True)\n",
            True,
        ),
    ),
)
def test_flask_lexical_scope_matches_production(source: str, expected: bool) -> None:
    rule_id = "securescan.python.flask-debug-enabled"
    assert (rule_id in classify_claim_contract_v2(source)) is expected


def test_sibling_scope_constructor_cannot_contaminate_requests_or_flask() -> None:
    source = (
        "def construct():\n"
        "    session = requests.Session()\n"
        "    app = flask.Flask(__name__)\n\n"
        "def use():\n"
        "    session.verify = False\n"
        "    app.run(debug=True)\n"
    )
    claims = classify_claim_contract_v2(source)
    assert "securescan.python.requests-session-verify-false" not in claims
    assert "securescan.python.flask-debug-enabled" not in claims


def test_yt_dlp_is_independently_classified_from_source(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    by_cve = {case["cve_id"]: case for case in _cases(documents[0])}
    decision = by_cve["CVE-2023-40581"]
    assert decision["case_disposition"] == CLAIM_APPLICABLE
    assert decision["applicable_rule_ids"] == ["securescan.python.subprocess-shell-true"]
    relation = decision["relations"][0]
    assert relation["vulnerable"]["expected_match"] is True
    assert relation["fixed"]["expected_match"] is False
    assert relation["discrimination_expectation"] == SHOULD_DISCRIMINATE
    assert decision["evidence"]["vulnerable"][0]["source_sha256"] == (
        "ac033013947a65b83f7f6b45cc76ab9bd763a3e5bbd16341a89f5f503a951648"
    )
    assert decision["evidence"]["fixed"][0]["source_sha256"] == (
        "dd070bef54ed99adb908456b450438ffebddf76b38033bbf8b4b2ebb012495c9"
    )


def test_v1_to_v2_delta_is_explicit_and_exact(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    summary = documents[1]
    assert summary["changed_case_count"] == 1
    assert summary["changed_cases"] == [
        {
            "cve_id": "CVE-2023-40581",
            "new_disposition": CLAIM_APPLICABLE,
            "new_rule_ids": ["securescan.python.subprocess-shell-true"],
            "old_disposition": OUTSIDE_FROZEN_RULE_CLAIMS,
            "old_rule_ids": [],
            "reason": (
                "corrected subprocess claim includes subprocess.call with shell=True; "
                "the fixed revision removes that frozen pattern"
            ),
        }
    ]


def test_unreviewed_changed_case_cannot_inherit_the_yt_dlp_reason(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    proposal = copy.deepcopy(documents[0])
    historical = load_json(BENCHMARK_ROOT / "applicability-proposal.json")
    unexpected = next(case for case in proposal["cases"] if case["cve_id"] == "CVE-2022-24065")
    unexpected["case_disposition"] = CLAIM_APPLICABLE
    unexpected["applicable_rule_ids"] = ["securescan.python.os-system"]
    with pytest.raises(ValueError, match="unreviewed v1-to-v2 applicability delta"):
        _changed_cases(proposal, historical)


def test_relation_and_discrimination_accounting_is_exact(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    proposal, summary, _review = documents
    relations = [relation for case in _cases(proposal) for relation in case["relations"]]
    assert len(relations) == 7
    assert all(relation["vulnerable"]["expected_match"] is True for relation in relations)
    assert sum(relation["fixed"]["expected_match"] is True for relation in relations) == 4
    assert sum(relation["fixed"]["expected_match"] is False for relation in relations) == 3
    assert summary["discrimination_expectation_counts"] == {
        SHOULD_DISCRIMINATE: 3,
        NOT_EXPECTED_TO_DISCRIMINATE: 4,
    }


def test_applicable_project_family_and_rule_accounting(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    summary = documents[1]
    assert summary["applicable_unique_project_count"] == 5
    assert summary["applicable_unique_case_family_count"] == 6
    assert summary["relations_by_project"] == {
        "airflow": 1,
        "ipython": 1,
        "llama-index": 2,
        "transformers": 2,
        "yt-dlp": 1,
    }
    assert summary["relations_by_rule"] == {
        "securescan.python.dangerous-eval": 2,
        "securescan.python.os-system": 1,
        "securescan.python.subprocess-shell-true": 1,
        "securescan.python.unsafe-pickle-load": 3,
    }


def test_evidence_paths_hashes_lines_and_roles_remain_bound_to_f2e1(
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


def test_same_cwe_still_does_not_imply_applicability(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    by_cve = {case["cve_id"]: case for case in _cases(documents[0])}
    for cve in ("CVE-2022-28347", "CVE-2022-34265", "CVE-2024-7009"):
        assert by_cve[cve]["case_disposition"] == OUTSIDE_FROZEN_RULE_CLAIMS
        assert by_cve[cve]["relations"] == []


def test_applicability_v2_does_not_import_or_name_provisional_evaluation_inputs() -> None:
    for path in (MODULE_PATH, CLI_PATH):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        assert not any("python_sast_realworld_evaluation" in name for name in imported)
        assert "realworld-evaluation-report.json" not in source
        assert "realworld-evaluation-review.json" not in source
        assert "python_sast_realworld_evaluation" not in source


def test_provisional_evaluation_reads_are_hostilely_forbidden(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_read_bytes = Path.read_bytes
    original_read_text = Path.read_text

    def read_bytes(path: Path) -> bytes:
        if path.name.startswith("realworld-evaluation-"):
            raise AssertionError("provisional evaluation input was read")
        return original_read_bytes(path)

    def read_text(path: Path, *args: object, **kwargs: object) -> str:
        if path.name.startswith("realworld-evaluation-"):
            raise AssertionError("provisional evaluation input was read")
        return original_read_text(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    monkeypatch.setattr(Path, "read_text", read_text)
    assert build_documents(ROOT)[1]["changed_case_count"] == 1


def test_generation_process_invokes_only_git(monkeypatch: pytest.MonkeyPatch) -> None:
    original = subprocess.run
    commands: list[object] = []

    def spy(*args: object, **kwargs: object) -> subprocess.CompletedProcess[object]:
        commands.append(args[0])
        return original(*args, **kwargs)  # type: ignore[call-overload,return-value]

    monkeypatch.setattr(subprocess, "run", spy)
    build_documents(ROOT)
    assert commands
    assert all(isinstance(command, list) and command[0] == "git" for command in commands)


def test_repeated_generation_is_byte_identical(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    second = build_documents(ROOT)
    assert tuple(canonical_document(item) for item in documents) == tuple(
        canonical_document(item) for item in second
    )


def test_recorded_v2_documents_are_canonical_and_current(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    proposal, summary, review = documents
    expected = {
        "applicability-proposal-v2.json": proposal,
        "applicability-summary-v2.json": summary,
        "applicability-review-v2.json": review,
    }
    assert verify_documents(ROOT)
    for name, document in expected.items():
        assert (BENCHMARK_ROOT / name).read_bytes() == canonical_document(document)


def test_documents_contain_no_scanner_observations_metrics_or_host_data(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    forbidden = {
        "f1",
        "findings",
        "fn",
        "fp",
        "precision",
        "recall",
        "scanner_findings",
        "timestamp",
        "tn",
        "tp",
    }
    assert not ({key.casefold() for document in documents for key in _keys(document)} & forbidden)
    strings = [item for document in documents for item in _strings(document)]
    assert not any(item.startswith("/home/") or item.startswith("/tmp/") for item in strings)
    serialized = json.dumps(documents, sort_keys=True)
    assert '"expected_match"' in serialized
    assert '"scanner_execution": "forbidden"' in serialized


def test_rule_accounting_remains_complete(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    represented = set(documents[1]["rules_represented_by_real_world_cases"])
    absent = set(documents[1]["rules_without_real_world_applicable_cve"])
    assert represented.isdisjoint(absent)
    assert represented | absent == set(RULE_IDS)
