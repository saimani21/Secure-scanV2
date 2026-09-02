from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Final

from securescan.benchmarks.python_sast_realworld import (
    canonical_document,
    digest,
    load_json,
)
from securescan.scanners.semgrep import load_baseline_ruleset

CONTRACT_SCHEMA_VERSION: Final = "securescan-python-sast-rule-claims-v2"
AUDIT_SCHEMA_VERSION: Final = "securescan-python-sast-rule-claim-conformance-audit-v2"
CONTRACT_VERSION: Final = 2
PRODUCTION_RULESET_ID: Final = "securescan-python-baseline-v2"
PRODUCTION_RULESET_VERSION: Final = "2"
PRODUCTION_RULESET_DIGEST: Final = (
    "e10fb04e6b5abb35e0b83bdd718c2e973a8026e3630e420dc398db95e59d01a5"
)
HISTORICAL_CLAIM_CATALOG_DIGEST: Final = (
    "02741b7745a8d61648eb67d0132923599c7fb110d8cedbc05bb311b2601befc9"
)
HISTORICAL_CLAIM_FILE_SHA256: Final = (
    "d9b719b3ea74070a9e02273c24eedebc3b0084ebec58dda107531251986fece0"
)

ALIGNED: Final = "ALIGNED"
CLAIM_NARROWER_THAN_PRODUCTION: Final = "CLAIM_NARROWER_THAN_PRODUCTION"
CLAIM_BROADER_THAN_PRODUCTION: Final = "CLAIM_BROADER_THAN_PRODUCTION"
SEMANTICALLY_AMBIGUOUS: Final = "SEMANTICALLY_AMBIGUOUS"

RULE_IDS: Final = (
    "securescan.python.dangerous-eval",
    "securescan.python.dangerous-exec",
    "securescan.python.os-system",
    "securescan.python.os-popen",
    "securescan.python.subprocess-shell-true",
    "securescan.python.unsafe-pickle-load",
    "securescan.python.unsafe-yaml-load",
    "securescan.python.requests-verify-false",
    "securescan.python.requests-session-verify-false",
    "securescan.python.ssl-unverified-context",
    "securescan.python.paramiko-autoaddpolicy",
    "securescan.python.insecure-tempfile-mktemp",
    "securescan.python.flask-debug-enabled",
    "securescan.python.jinja-autoescape-disabled",
    "securescan.python.sql-fstring-execute",
    "securescan.python.jwt-signature-verification-disabled",
    "securescan.python.lxml-resolve-entities",
)

_NO_BINDING_GUARANTEE: Final = (
    "Semgrep Python import equivalence may normalize direct imports and aliases, but the "
    "rule does not establish runtime binding identity"
)


def _scope(
    *targets: str,
    required_literals: dict[str, object] | None = None,
    argument_shape: str = "any arguments accepted by the pattern ellipses",
    lexical_context: list[str] | None = None,
    name_resolution: str = _NO_BINDING_GUARANTEE,
) -> dict[str, object]:
    return {
        "argument_shape": argument_shape,
        "canonical_call_targets": list(targets),
        "lexical_context": lexical_context or [],
        "name_resolution": name_resolution,
        "required_literals": required_literals or {},
    }


def _claim(
    rule_id: str,
    claim_class: str,
    relevant_cwes: list[int],
    positive_scope: dict[str, object],
    exclusions: list[str],
    safe_counterparts: list[str],
    analysis_boundary: list[str],
    differences: list[str],
) -> dict[str, object]:
    return {
        "analysis_boundary": analysis_boundary,
        "claim_class": claim_class,
        "explicit_exclusions": exclusions,
        "external_label_scoring": {
            "safe": claim_class != "dangerous-api-observation",
            "vulnerable": True,
        },
        "positive_scope": positive_scope,
        "reconciliation": {
            "alignment_state": ALIGNED if not differences else CLAIM_NARROWER_THAN_PRODUCTION,
            "differences_from_v1": differences,
        },
        "relevant_cwes": relevant_cwes,
        "rule_id": rule_id,
        "safe_counterparts": safe_counterparts,
    }


_CLAIMS: Final = (
    _claim(
        "securescan.python.dangerous-eval",
        "dangerous-api-observation",
        [94, 95],
        _scope(
            "eval",
            argument_shape='first argument is not a static string matched by eval("...")',
            name_resolution="direct call spelling; no built-in or shadowing identity guarantee",
        ),
        ["a direct eval call whose first argument is a static string", "object methods named eval"],
        ["a direct eval call with a static string is outside this rule"],
        [
            "syntactic call and static-string exclusion only",
            "no binding, taint, or reachability claim",
        ],
        [
            "v1 excluded shadowed eval bindings, but the production pattern does not "
            "prove built-in identity"
        ],
    ),
    _claim(
        "securescan.python.dangerous-exec",
        "dangerous-api-observation",
        [94, 95],
        _scope(
            "exec",
            argument_shape='first argument is not a static string matched by exec("...")',
            name_resolution="direct call spelling; no built-in or shadowing identity guarantee",
        ),
        ["a direct exec call whose first argument is a static string", "object methods named exec"],
        ["a direct exec call with a static string is outside this rule"],
        [
            "syntactic call and static-string exclusion only",
            "no binding, taint, or reachability claim",
        ],
        [
            "v1 excluded shadowed exec bindings, but the production pattern does not "
            "prove built-in identity"
        ],
    ),
    _claim(
        "securescan.python.os-system",
        "dangerous-api-observation",
        [78],
        _scope("os.system"),
        ["system methods not normalized to or spelled as os.system"],
        [],
        [
            "canonical call surface plus Semgrep import equivalence",
            "no binding, taint, or reachability claim",
        ],
        [
            "v1 required unambiguous os identity, while the production pattern also "
            "matches the canonical surface without proving that binding"
        ],
    ),
    _claim(
        "securescan.python.os-popen",
        "dangerous-api-observation",
        [78],
        _scope("os.popen"),
        ["popen methods not normalized to or spelled as os.popen"],
        [],
        [
            "canonical call surface plus Semgrep import equivalence",
            "no binding, taint, or reachability claim",
        ],
        [
            "v1 required unambiguous os identity, while the production pattern does "
            "not prove that binding"
        ],
    ),
    _claim(
        "securescan.python.subprocess-shell-true",
        "explicit-insecure-pattern",
        [78],
        _scope(
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "subprocess.Popen",
            required_literals={"shell": True},
        ),
        ["shell omitted", "shell=False", "dynamic shell value", "other subprocess APIs"],
        ["the same five-call API family with shell=False"],
        [
            "literal shell keyword and five-name call family only",
            "no binding, command taint, or reachability claim",
        ],
        [
            "v1 omitted subprocess.call and subprocess.check_call",
            "v1 asserted semantic binding identity that the production pattern does not establish",
        ],
    ),
    _claim(
        "securescan.python.unsafe-pickle-load",
        "dangerous-api-observation",
        [502],
        _scope("pickle.load", "pickle.loads"),
        ["load or loads methods not normalized to or spelled as pickle.load or pickle.loads"],
        [],
        [
            "canonical call surface plus Semgrep import equivalence",
            "no binding, serialized-data taint, or reachability claim",
        ],
        [
            "v1 required unambiguous pickle identity, while the production pattern "
            "does not prove that binding"
        ],
    ),
    _claim(
        "securescan.python.unsafe-yaml-load",
        "explicit-insecure-pattern",
        [502],
        _scope(
            "yaml.unsafe_load",
            "yaml.load",
            required_literals={"loader_names": ["Loader", "UnsafeLoader", "CLoader"]},
            argument_shape=(
                "yaml.load accepts the listed loader in keyword or second-positional "
                "form; bare loader names require the corresponding from-yaml import context"
            ),
        ),
        [
            "yaml.safe_load",
            "SafeLoader",
            "CSafeLoader",
            "FullLoader",
            "unlisted or dynamic loader values",
        ],
        ["yaml.safe_load", "yaml.load with SafeLoader or CSafeLoader"],
        [
            "enumerated call and loader shapes only",
            "no binding, deserialization taint, or object-flow claim",
            "FullLoader remains outside the frozen claim",
        ],
        [
            "v1 asserted semantic YAML binding integrity, while module-qualified "
            "production alternatives do not prove that binding"
        ],
    ),
    _claim(
        "securescan.python.requests-verify-false",
        "explicit-insecure-pattern",
        [295],
        _scope(
            "requests.request",
            "requests.get",
            "requests.options",
            "requests.head",
            "requests.post",
            "requests.put",
            "requests.patch",
            "requests.delete",
            required_literals={"verify": False},
        ),
        ["verify omitted", "verify=True", "dynamic verify value", "other requests APIs"],
        ["the same eight-call API family with verify=True"],
        [
            "literal verify keyword and eight-name call family only",
            "no binding, TLS reachability, or transport claim",
        ],
        [
            "v1 omitted requests.options, requests.head, requests.put, requests.patch, "
            "and requests.delete",
            "v1 asserted semantic requests binding identity that the production pattern "
            "does not establish",
        ],
    ),
    _claim(
        "securescan.python.requests-session-verify-false",
        "explicit-insecure-pattern",
        [295],
        _scope(
            "requests.Session",
            required_literals={"verify_assignment": False},
            lexical_context=[
                "a name is assigned from requests.Session()",
                "the same name later receives .verify = False in the same lexical scope",
            ],
        ),
        [
            "verify=True",
            "dynamic verify assignment",
            "absence of the preceding Session assignment pattern",
            "constructor assignment in an ancestor or sibling lexical scope",
        ],
        ["the same lexical Session assignment sequence with verify=True"],
        [
            "same-scope lexical assignment sequence and literal false only",
            "no binding, alias-flow, or interprocedural object-identity claim",
        ],
        [
            "v1 described verified requests.Session object identity, while production "
            "establishes only a lexical constructor-and-assignment sequence"
        ],
    ),
    _claim(
        "securescan.python.ssl-unverified-context",
        "explicit-insecure-pattern",
        [295],
        _scope("ssl._create_unverified_context"),
        ["constructors not normalized to or spelled as ssl._create_unverified_context"],
        ["ssl.create_default_context"],
        [
            "canonical call surface plus Semgrep import equivalence",
            "no binding, TLS reachability, or transport claim",
        ],
        [
            "v1 required unambiguous ssl identity, while the production pattern does "
            "not prove that binding"
        ],
    ),
    _claim(
        "securescan.python.paramiko-autoaddpolicy",
        "explicit-insecure-pattern",
        [295],
        _scope(
            "<any-receiver>.set_missing_host_key_policy",
            argument_shape=(
                "first argument is a zero-argument paramiko.AutoAddPolicy() construction"
            ),
        ),
        ["a policy other than paramiko.AutoAddPolicy()", "a different method name"],
        ["set_missing_host_key_policy(paramiko.RejectPolicy())"],
        [
            "method name and policy-constructor surface only",
            "no SSHClient receiver identity, binding, or object-flow claim",
        ],
        [
            "v1 required a Paramiko SSHClient receiver identity, but production permits "
            "any receiver metavariable"
        ],
    ),
    _claim(
        "securescan.python.insecure-tempfile-mktemp",
        "dangerous-api-observation",
        [377],
        _scope("tempfile.mktemp"),
        [
            "NamedTemporaryFile",
            "TemporaryFile",
            "mktemp methods not normalized to or spelled as tempfile.mktemp",
        ],
        ["tempfile.NamedTemporaryFile", "tempfile.TemporaryFile"],
        [
            "canonical call surface plus Semgrep import equivalence",
            "no binding, race exploitability, or attacker-control claim",
        ],
        [
            "v1 required unambiguous tempfile identity, while the production pattern "
            "does not prove that binding"
        ],
    ),
    _claim(
        "securescan.python.flask-debug-enabled",
        "explicit-insecure-pattern",
        [489],
        _scope(
            "<assigned-name>.run",
            required_literals={"debug": True},
            lexical_context=[
                "the same name is assigned from flask.Flask(...) or Flask(...)",
                "the run call occurs later in the same or a descendant lexical scope",
            ],
        ),
        [
            "debug omitted",
            "debug=False",
            "dynamic debug value",
            "absence of the preceding Flask-constructor assignment pattern",
            "constructor assignment in a sibling lexical scope",
        ],
        ["the same lexical Flask assignment sequence with debug=False"],
        [
            "same-or-ancestor-scope constructor sequence and literal true only",
            "no binding, deployment, alias-flow, or interprocedural identity claim",
        ],
        [
            "v1 described established Flask application identity, while production "
            "establishes only a lexical constructor-and-call sequence"
        ],
    ),
    _claim(
        "securescan.python.jinja-autoescape-disabled",
        "explicit-insecure-pattern",
        [79],
        _scope("jinja2.Environment", required_literals={"autoescape": False}),
        ["autoescape omitted", "autoescape=True", "select_autoescape", "dynamic autoescape value"],
        ["jinja2.Environment with autoescape=True or select_autoescape"],
        [
            "canonical constructor surface and literal false only",
            "no binding, template-flow, or rendering-context claim",
        ],
        [
            "v1 required semantic Jinja identity, while the production pattern does not "
            "prove that binding"
        ],
    ),
    _claim(
        "securescan.python.sql-fstring-execute",
        "direct-interpolation-sink",
        [89],
        _scope(
            "<any-receiver>.execute",
            argument_shape="direct first argument is an f-string expression",
            name_resolution="receiver is intentionally unconstrained",
        ),
        [
            "f-string assigned before execute",
            "concatenation",
            "percent formatting",
            "format call",
            "non-f-string direct argument",
        ],
        ["execute with a non-f-string query and separate parameters"],
        [
            "direct call argument shape only",
            "no SQL sink identity, taint, variable tracking, or interprocedural claim",
        ],
        [],
    ),
    _claim(
        "securescan.python.jwt-signature-verification-disabled",
        "explicit-insecure-pattern",
        [347],
        _scope(
            "jwt.decode",
            required_literals={"options.verify_signature": False},
            argument_shape=(
                "options is an inline dictionary containing the literal verify_signature "
                "false entry"
            ),
        ),
        [
            "verify_signature omitted or true",
            "dynamic options dictionary",
            "other validation-option keys",
            "decode calls not normalized to or spelled as jwt.decode",
        ],
        ["jwt.decode without disabling signature verification"],
        [
            "canonical call surface and inline literal dictionary entry only",
            "no binding, token-flow, or unrelated validation-option claim",
        ],
        [
            "v1 asserted semantic PyJWT identity, while the production pattern does not "
            "prove that binding"
        ],
    ),
    _claim(
        "securescan.python.lxml-resolve-entities",
        "explicit-insecure-pattern",
        [611],
        _scope("lxml.etree.XMLParser", required_literals={"resolve_entities": True}),
        [
            "resolve_entities omitted",
            "resolve_entities=False",
            "dynamic resolve_entities value",
            "XMLParser surfaces not normalized to or spelled as lxml.etree.XMLParser",
        ],
        [
            "lxml.etree.XMLParser with resolve_entities=False",
            "defused or standard-library XML parsers",
        ],
        [
            "canonical constructor surface and literal true only",
            "no binding, XML source-flow, or parser-object dataflow claim",
        ],
        [
            "v1 required semantic lxml identity, while the production pattern does not "
            "prove that binding"
        ],
    ),
)


def _verify_production_ruleset() -> None:
    ruleset = load_baseline_ruleset()
    if (
        ruleset.ruleset_id != PRODUCTION_RULESET_ID
        or ruleset.version != PRODUCTION_RULESET_VERSION
        or ruleset.sha256 != PRODUCTION_RULESET_DIGEST
    ):
        raise ValueError("production Semgrep ruleset identity is not frozen")
    ids = tuple(
        re.findall(
            rb"^  - id: ([a-z0-9._-]+)$",
            ruleset.content,
            flags=re.MULTILINE,
        )
    )
    if tuple(item.decode("ascii") for item in ids) != RULE_IDS:
        raise ValueError("production Semgrep rule membership or order is not frozen")


def _load_historical_claims(repository_root: Path) -> dict[str, object]:
    path = repository_root / "benchmarks/python_sast_external/rule-claims.json"
    if hashlib.sha256(path.read_bytes()).hexdigest() != HISTORICAL_CLAIM_FILE_SHA256:
        raise ValueError("historical v1 claim file bytes changed")
    document = load_json(path)
    if digest(document) != HISTORICAL_CLAIM_CATALOG_DIGEST:
        raise ValueError("historical v1 claim catalog identity changed")
    rules = document.get("rules")
    if not isinstance(rules, list) or {
        item.get("rule_id") for item in rules if isinstance(item, dict)
    } != set(RULE_IDS):
        raise ValueError("historical v1 claim membership is invalid")
    return document


def _with_self_digest(document: dict[str, object], field: str) -> dict[str, object]:
    result = dict(document)
    result[field] = digest(document)
    return result


def build_contract(repository_root: Path) -> dict[str, object]:
    _verify_production_ruleset()
    _load_historical_claims(repository_root)
    document = {
        "contract_version": CONTRACT_VERSION,
        "production_ruleset_digest": PRODUCTION_RULESET_DIGEST,
        "production_ruleset_id": PRODUCTION_RULESET_ID,
        "production_ruleset_version": PRODUCTION_RULESET_VERSION,
        "rules": [dict(item) for item in _CLAIMS],
        "schema_version": CONTRACT_SCHEMA_VERSION,
    }
    return _with_self_digest(document, "contract_digest")


def build_audit(repository_root: Path) -> dict[str, object]:
    contract = build_contract(repository_root)
    historical = _load_historical_claims(repository_root)
    historical_by_id = {str(item["rule_id"]): item for item in historical["rules"]}  # type: ignore[index]
    entries: list[dict[str, object]] = []
    for claim in contract["rules"]:  # type: ignore[assignment]
        assert isinstance(claim, dict)
        rule_id = str(claim["rule_id"])
        old = historical_by_id[rule_id]
        reconciliation = claim["reconciliation"]
        assert isinstance(reconciliation, dict)
        differences = reconciliation["differences_from_v1"]
        assert isinstance(differences, list)
        state = str(reconciliation["alignment_state"])
        entries.append(
            {
                "alignment_state": state,
                "corrected_analysis_boundary": claim["analysis_boundary"],
                "corrected_exclusions": claim["explicit_exclusions"],
                "corrected_safe_counterparts": claim["safe_counterparts"],
                "correction_required": state != ALIGNED,
                "differences": differences,
                "existing_production_test_coverage": {
                    "fixture_directory": (
                        f"tests/fixtures/semgrep/rules/python/{rule_id.rsplit('.', maxsplit=1)[-1]}"
                    ),
                    "fixture_roles": ["near_miss", "safe", "vulnerable"],
                },
                "historical_analysis_boundary": old["analysis_boundary"],
                "historical_claim_identity": {
                    "catalog_digest": HISTORICAL_CLAIM_CATALOG_DIGEST,
                    "component_digest": digest(old),
                },
                "historical_exclusions": old["explicit_exclusions"],
                "historical_positive_scope": old["positive_scope"],
                "historical_safe_counterparts": old["safe_counterparts"],
                "import_alias_behavior": claim["positive_scope"]["name_resolution"],
                "production_positive_scope": claim["positive_scope"],
                "production_ruleset_digest": PRODUCTION_RULESET_DIGEST,
                "review_reason": (
                    "production rule and v1 claim describe the same boundary"
                    if state == ALIGNED
                    else "; ".join(str(item) for item in differences)
                ),
                "rule_id": rule_id,
            }
        )
    counts = Counter(str(item["alignment_state"]) for item in entries)
    document = {
        "contract_digest": contract["contract_digest"],
        "historical_claim_catalog_digest": HISTORICAL_CLAIM_CATALOG_DIGEST,
        "production_ruleset_digest": PRODUCTION_RULESET_DIGEST,
        "rules": entries,
        "schema_version": AUDIT_SCHEMA_VERSION,
        "summary": {
            "alignment_state_counts": {
                ALIGNED: counts[ALIGNED],
                CLAIM_NARROWER_THAN_PRODUCTION: counts[CLAIM_NARROWER_THAN_PRODUCTION],
                CLAIM_BROADER_THAN_PRODUCTION: counts[CLAIM_BROADER_THAN_PRODUCTION],
                SEMANTICALLY_AMBIGUOUS: counts[SEMANTICALLY_AMBIGUOUS],
            },
            "correction_required_count": sum(bool(item["correction_required"]) for item in entries),
            "rule_count": len(entries),
        },
    }
    return _with_self_digest(document, "audit_digest")


def _validate_self_digest(document: dict[str, object], field: str) -> None:
    expected = document.get(field)
    payload = {key: value for key, value in document.items() if key != field}
    if not isinstance(expected, str) or digest(payload) != expected:
        raise ValueError(f"{field} is invalid")


def write_documents(repository_root: Path) -> dict[str, str]:
    output_root = repository_root / "benchmarks/python_sast_external"
    documents = {
        "rule-claim-conformance-audit-v2.json": build_audit(repository_root),
        "rule-claims-v2.json": build_contract(repository_root),
    }
    for name, document in documents.items():
        (output_root / name).write_bytes(canonical_document(document))
    return {
        name: hashlib.sha256(canonical_document(value)).hexdigest()
        for name, value in documents.items()
    }


def verify_documents(repository_root: Path) -> dict[str, str]:
    output_root = repository_root / "benchmarks/python_sast_external"
    expected = {
        "rule-claim-conformance-audit-v2.json": build_audit(repository_root),
        "rule-claims-v2.json": build_contract(repository_root),
    }
    for name, document in expected.items():
        recorded = load_json(output_root / name)
        _validate_self_digest(recorded, "audit_digest" if "audit" in name else "contract_digest")
        if recorded != document:
            raise ValueError(f"rule-claim v2 evidence is stale: {name}")
    return {
        name: hashlib.sha256(canonical_document(value)).hexdigest()
        for name, value in expected.items()
    }


def canonical_stdout(value: object) -> str:
    return json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    )
