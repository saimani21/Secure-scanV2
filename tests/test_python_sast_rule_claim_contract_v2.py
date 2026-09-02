from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from securescan.benchmarks.python_sast_realworld import canonical_document, load_json
from securescan.benchmarks.python_sast_rule_claim_contract_v2 import (
    ALIGNED,
    CLAIM_BROADER_THAN_PRODUCTION,
    CLAIM_NARROWER_THAN_PRODUCTION,
    CONTRACT_VERSION,
    HISTORICAL_CLAIM_FILE_SHA256,
    PRODUCTION_RULESET_DIGEST,
    RULE_IDS,
    SEMANTICALLY_AMBIGUOUS,
    build_audit,
    build_contract,
    verify_documents,
)

ROOT = Path(__file__).parent.parent
EXTERNAL_ROOT = ROOT / "benchmarks/python_sast_external"
RULESET_PATH = ROOT / "src/securescan/scanners/semgrep/rules/securescan-python-baseline-v2.yml"
SEMGREP = ROOT / ".venv-semgrep-1.171/bin/semgrep"

MICROFIXTURES = {
    "securescan.python.dangerous-eval": (
        "def eval(value):\n    return value\neval(payload)\n",
        "eval('fixed expression')\n",
    ),
    "securescan.python.dangerous-exec": (
        "def exec(value):\n    return value\nexec(payload)\n",
        "exec('value = 1')\n",
    ),
    "securescan.python.os-system": (
        "class Local:\n    def system(self, value): pass\nos = Local()\nos.system(command)\n",
        "platform.system()\n",
    ),
    "securescan.python.os-popen": (
        "class Local:\n    def popen(self, value): pass\nos = Local()\nos.popen(command)\n",
        "subprocess.Popen(command, shell=False)\n",
    ),
    "securescan.python.subprocess-shell-true": (
        "subprocess.run(command, shell=True)\n"
        "subprocess.call(command, shell=True)\n"
        "subprocess.check_call(command, shell=True)\n"
        "subprocess.check_output(command, shell=True)\n"
        "subprocess.Popen(command, shell=True)\n",
        "subprocess.run(command, shell=False)\nsubprocess.call(command, shell=choice)\n",
    ),
    "securescan.python.unsafe-pickle-load": (
        "class Local:\n    def loads(self, value): pass\npickle = Local()\npickle.loads(data)\n",
        "json.loads(data)\n",
    ),
    "securescan.python.unsafe-yaml-load": (
        "class Local:\n    class Loader: pass\n    def load(self, *args, **kwargs): pass\n"
        "yaml = Local()\nyaml.load(data, Loader=yaml.Loader)\n",
        "yaml.safe_load(data)\nyaml.load(data, Loader=yaml.FullLoader)\n"
        "yaml.load(data, Loader=Loader)\n",
    ),
    "securescan.python.requests-verify-false": (
        "requests.request(url, verify=False)\n"
        "requests.get(url, verify=False)\n"
        "requests.options(url, verify=False)\n"
        "requests.head(url, verify=False)\n"
        "requests.post(url, verify=False)\n"
        "requests.put(url, verify=False)\n"
        "requests.patch(url, verify=False)\n"
        "requests.delete(url, verify=False)\n",
        "requests.get(url, verify=True)\nrequests.head(url, verify=choice)\n",
    ),
    "securescan.python.requests-session-verify-false": (
        "class Local:\n    def Session(self): return object()\nrequests = Local()\n"
        "session = requests.Session()\nsession.verify = False\n",
        "session = requests.Session()\nsession.verify = True\n",
    ),
    "securescan.python.ssl-unverified-context": (
        "class Local:\n    def _create_unverified_context(self): pass\n"
        "ssl = Local()\nssl._create_unverified_context()\n",
        "ssl.create_default_context()\n",
    ),
    "securescan.python.paramiko-autoaddpolicy": (
        "client.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n",
        "client.set_missing_host_key_policy(paramiko.RejectPolicy())\n",
    ),
    "securescan.python.insecure-tempfile-mktemp": (
        "class Local:\n    def mktemp(self): pass\ntempfile = Local()\ntempfile.mktemp()\n",
        "tempfile.NamedTemporaryFile()\n",
    ),
    "securescan.python.flask-debug-enabled": (
        "class Local:\n    def Flask(self, value): return app\nflask = Local()\n"
        "app = flask.Flask(__name__)\napp.run(debug=True)\n",
        "app = flask.Flask(__name__)\napp.run(debug=False)\n",
    ),
    "securescan.python.jinja-autoescape-disabled": (
        "class Local:\n    def Environment(self, **kwargs): pass\n"
        "jinja2 = Local()\njinja2.Environment(autoescape=False)\n",
        "jinja2.Environment(autoescape=jinja2.select_autoescape())\n",
    ),
    "securescan.python.sql-fstring-execute": (
        "object_with_any_identity.execute(f'SELECT {value}')\n",
        "query = f'SELECT {value}'\nobject_with_any_identity.execute(query)\n",
    ),
    "securescan.python.jwt-signature-verification-disabled": (
        "jwt.decode(token, options={'verify_signature': False})\n",
        "jwt.decode(token, options={'verify_aud': False})\n",
    ),
    "securescan.python.lxml-resolve-entities": (
        "lxml.etree.XMLParser(resolve_entities=True)\n",
        "lxml.etree.XMLParser(resolve_entities=False)\n",
    ),
}

EXPECTED_POSITIVE_FINDING_COUNTS = {
    "securescan.python.dangerous-eval": 1,
    "securescan.python.dangerous-exec": 1,
    "securescan.python.os-system": 1,
    "securescan.python.os-popen": 1,
    "securescan.python.subprocess-shell-true": 5,
    "securescan.python.unsafe-pickle-load": 1,
    "securescan.python.unsafe-yaml-load": 1,
    "securescan.python.requests-verify-false": 8,
    "securescan.python.requests-session-verify-false": 1,
    "securescan.python.ssl-unverified-context": 1,
    "securescan.python.paramiko-autoaddpolicy": 1,
    "securescan.python.insecure-tempfile-mktemp": 1,
    "securescan.python.flask-debug-enabled": 1,
    "securescan.python.jinja-autoescape-disabled": 1,
    "securescan.python.sql-fstring-execute": 1,
    "securescan.python.jwt-signature-verification-disabled": 1,
    "securescan.python.lxml-resolve-entities": 1,
}

LEXICAL_MICROFIXTURES = {
    "module-constructor-to-later-function": (
        "session = requests.Session()\n\ndef configure():\n    session.verify = False\n",
        "app = flask.Flask(__name__)\n\ndef serve():\n    app.run(debug=True)\n",
    ),
    "same-function": (
        "def configure():\n    session = requests.Session()\n    session.verify = False\n",
        "def serve():\n    app = flask.Flask(__name__)\n    app.run(debug=True)\n",
    ),
    "sibling-functions": (
        "def construct():\n    session = requests.Session()\n\n"
        "def configure():\n    session.verify = False\n",
        "def construct():\n    app = flask.Flask(__name__)\n\n"
        "def serve():\n    app.run(debug=True)\n",
    ),
    "use-before-constructor": (
        "session.verify = False\nsession = requests.Session()\n",
        "app.run(debug=True)\napp = flask.Flask(__name__)\n",
    ),
    "outer-constructor-to-nested-function": (
        "def outer():\n    session = requests.Session()\n"
        "    def configure():\n        session.verify = False\n",
        "def outer():\n    app = flask.Flask(__name__)\n"
        "    def serve():\n        app.run(debug=True)\n",
    ),
    "intervening-reassignment": (
        "session = requests.Session()\nsession = object()\nsession.verify = False\n",
        "app = flask.Flask(__name__)\napp = object()\napp.run(debug=True)\n",
    ),
}

EXPECTED_LEXICAL_MATCHES = {
    "securescan.python.requests-session-verify-false": {
        "intervening-reassignment",
        "same-function",
    },
    "securescan.python.flask-debug-enabled": {
        "intervening-reassignment",
        "module-constructor-to-later-function",
        "outer-constructor-to-nested-function",
        "same-function",
    },
}


@pytest.fixture(scope="module")
def documents() -> tuple[dict[str, object], dict[str, object]]:
    return build_contract(ROOT), build_audit(ROOT)


@pytest.fixture(scope="module")
def semgrep_observation(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[dict[str, object], Path]:
    tmp_path = tmp_path_factory.mktemp("claim-contract-v2")
    assert SEMGREP.is_file()
    environment = {
        "HOME": str(tmp_path),
        "PATH": f"{SEMGREP.parent}:/usr/bin:/bin",
        "SEMGREP_LOG_FILE": str(tmp_path / "semgrep.log"),
        "SEMGREP_SETTINGS_FILE": str(tmp_path / "settings.yml"),
    }
    assert (
        subprocess.run(
            [str(SEMGREP), "--version"],
            check=True,
            capture_output=True,
            env=environment,
            stdin=subprocess.DEVNULL,
            text=True,
        ).stdout.strip()
        == "1.171.0"
    )
    paths: list[Path] = []
    for rule_id, (positive, negative) in MICROFIXTURES.items():
        slug = rule_id.rsplit(".", maxsplit=1)[-1]
        directory = tmp_path / "contract" / slug
        directory.mkdir(parents=True)
        for role, source in (("positive", positive), ("negative", negative)):
            path = directory / f"{role}.py"
            path.write_text(source, encoding="utf-8")
            paths.append(path)
    for scenario, (session_source, flask_source) in LEXICAL_MICROFIXTURES.items():
        for slug, source in (
            ("requests-session-verify-false", session_source),
            ("flask-debug-enabled", flask_source),
        ):
            directory = tmp_path / "lexical" / slug
            directory.mkdir(parents=True, exist_ok=True)
            path = directory / f"{scenario}.py"
            path.write_text(source, encoding="utf-8")
            paths.append(path)
    result = subprocess.run(
        [
            str(SEMGREP),
            "scan",
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--quiet",
            "--no-git-ignore",
            "--jobs=1",
            "--no-rewrite-rule-ids",
            f"--config={RULESET_PATH}",
            *(str(path) for path in paths),
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        stdin=subprocess.DEVNULL,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    output = json.loads(result.stdout)
    assert isinstance(output, dict)
    assert output["version"] == "1.171.0"
    assert output["errors"] == []
    return output, tmp_path


def test_contract_is_exactly_bound_to_the_frozen_production_ruleset(
    documents: tuple[dict[str, object], dict[str, object]],
) -> None:
    contract, audit = documents
    assert contract["contract_version"] == CONTRACT_VERSION == 2
    assert contract["production_ruleset_digest"] == PRODUCTION_RULESET_DIGEST
    assert audit["production_ruleset_digest"] == PRODUCTION_RULESET_DIGEST
    assert hashlib.sha256(RULESET_PATH.read_bytes()).hexdigest() == PRODUCTION_RULESET_DIGEST
    assert tuple(item["rule_id"] for item in contract["rules"]) == RULE_IDS


def test_audit_accounts_for_all_rules_and_every_alignment_state(
    documents: tuple[dict[str, object], dict[str, object]],
) -> None:
    _contract, audit = documents
    assert tuple(item["rule_id"] for item in audit["rules"]) == RULE_IDS
    assert audit["summary"] == {
        "alignment_state_counts": {
            ALIGNED: 1,
            CLAIM_BROADER_THAN_PRODUCTION: 0,
            CLAIM_NARROWER_THAN_PRODUCTION: 16,
            SEMANTICALLY_AMBIGUOUS: 0,
        },
        "correction_required_count": 16,
        "rule_count": 17,
    }
    aligned = [item["rule_id"] for item in audit["rules"] if not item["correction_required"]]
    assert aligned == ["securescan.python.sql-fstring-execute"]


def test_historical_claim_catalog_is_immutable() -> None:
    path = EXTERNAL_ROOT / "rule-claims.json"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == HISTORICAL_CLAIM_FILE_SHA256


def test_known_subprocess_scope_drift_is_corrected(
    documents: tuple[dict[str, object], dict[str, object]],
) -> None:
    contract, _audit = documents
    rule = next(
        item
        for item in contract["rules"]
        if item["rule_id"] == "securescan.python.subprocess-shell-true"
    )
    assert rule["positive_scope"]["canonical_call_targets"] == [
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
    ]
    assert rule["positive_scope"]["required_literals"] == {"shell": True}


def test_known_requests_scope_drift_is_corrected(
    documents: tuple[dict[str, object], dict[str, object]],
) -> None:
    contract, _audit = documents
    rule = next(
        item
        for item in contract["rules"]
        if item["rule_id"] == "securescan.python.requests-verify-false"
    )
    assert rule["positive_scope"]["canonical_call_targets"] == [
        "requests.request",
        "requests.get",
        "requests.options",
        "requests.head",
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
    ]
    assert rule["positive_scope"]["required_literals"] == {"verify": False}


def test_every_rule_has_positive_and_negative_semantic_microfixtures() -> None:
    assert tuple(MICROFIXTURES) == RULE_IDS
    assert all(
        positive.strip() and negative.strip() for positive, negative in MICROFIXTURES.values()
    )


def test_microfixtures_have_exact_rule_specific_finding_counts(
    semgrep_observation: tuple[dict[str, object], Path],
) -> None:
    output, tmp_path = semgrep_observation
    counts = {rule_id: 0 for rule_id in RULE_IDS}
    for finding in output["results"]:
        path = Path(finding["path"]).relative_to(tmp_path)
        if path.parts[0] != "contract":
            continue
        expected_rule = f"securescan.python.{path.parts[1]}"
        assert path.name == "positive.py"
        assert finding["check_id"] == expected_rule
        counts[expected_rule] += 1
    assert counts == EXPECTED_POSITIVE_FINDING_COUNTS
    assert sum(counts.values()) == 28


def test_lexical_pattern_inside_behavior_matches_frozen_semgrep(
    semgrep_observation: tuple[dict[str, object], Path],
) -> None:
    output, tmp_path = semgrep_observation
    observed = {rule_id: set() for rule_id in EXPECTED_LEXICAL_MATCHES}
    for finding in output["results"]:
        path = Path(finding["path"]).relative_to(tmp_path)
        if path.parts[0] != "lexical":
            continue
        expected_rule = f"securescan.python.{path.parts[1]}"
        assert finding["check_id"] == expected_rule
        observed[expected_rule].add(path.stem)
    assert observed == EXPECTED_LEXICAL_MATCHES


def test_recorded_contract_and_audit_are_canonical_and_current(
    documents: tuple[dict[str, object], dict[str, object]],
) -> None:
    contract, audit = documents
    assert verify_documents(ROOT)
    assert (EXTERNAL_ROOT / "rule-claims-v2.json").read_bytes() == canonical_document(contract)
    assert (
        EXTERNAL_ROOT / "rule-claim-conformance-audit-v2.json"
    ).read_bytes() == canonical_document(audit)
    assert load_json(EXTERNAL_ROOT / "rule-claims-v2.json") == contract
