from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import stat
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

from securescan.benchmarks.python_sast_external import (
    Candidate,
    SourceLock,
    candidate_inventory_digest,
    canonical_document,
    load_candidate_inventory,
    load_source_lock,
    source_lock_digest,
    verify_external_sources,
)

CLAIM_CATALOG_SCHEMA_VERSION: Final = "securescan-python-sast-rule-claims-v1"
PROPOSAL_SCHEMA_VERSION: Final = "securescan-python-sast-applicability-proposal-v1"
AUDIT_SAMPLE_SCHEMA_VERSION: Final = "securescan-python-sast-applicability-audit-v1"
SUMMARY_SCHEMA_VERSION: Final = "securescan-python-sast-applicability-summary-v1"
EXPECTED_SOURCE_LOCK_DIGEST: Final = (
    "ded3352210520814c03532686096a834c0fac95de51cdb13b02bda4a6aeefd23"
)
EXPECTED_CANDIDATE_INVENTORY_DIGEST: Final = (
    "84e60a1e411ed2f517356e2a6a11bf1fe03fc4945672d120cdb50ead9d4dd60b"
)
EXPECTED_REVIEW_SELECTION_DIGEST: Final = (
    "81cb5657d9501bfd0f5aa41125813168bf811788d02d8603ade43e6482384534"
)
EXPECTED_CANDIDATE_COUNT: Final = 1460
FROZEN_RULESET_ID: Final = "securescan-python-baseline-v2"
FROZEN_RULESET_VERSION: Final = "2"
FROZEN_RULESET_DIGEST: Final = (
    "e10fb04e6b5abb35e0b83bdd718c2e973a8026e3630e420dc398db95e59d01a5"
)
CLAIM_CLASSES: Final = frozenset(
    {"dangerous-api-observation", "explicit-insecure-pattern", "direct-interpolation-sink"}
)
DISPOSITIONS: Final = frozenset(
    {"APPLICABLE_POSITIVE", "APPLICABLE_NEGATIVE", "OUT_OF_SCOPE", "EXCLUDED", "UNRESOLVED"}
)
RULE_IDS: Final = frozenset(
    {
        "securescan.python.dangerous-eval",
        "securescan.python.dangerous-exec",
        "securescan.python.flask-debug-enabled",
        "securescan.python.insecure-tempfile-mktemp",
        "securescan.python.jinja-autoescape-disabled",
        "securescan.python.jwt-signature-verification-disabled",
        "securescan.python.lxml-resolve-entities",
        "securescan.python.os-popen",
        "securescan.python.os-system",
        "securescan.python.paramiko-autoaddpolicy",
        "securescan.python.requests-session-verify-false",
        "securescan.python.requests-verify-false",
        "securescan.python.sql-fstring-execute",
        "securescan.python.ssl-unverified-context",
        "securescan.python.subprocess-shell-true",
        "securescan.python.unsafe-pickle-load",
        "securescan.python.unsafe-yaml-load",
    }
)
RULE_CLASS_BY_ID: Final = {
    rule_id: (
        "dangerous-api-observation"
        if rule_id
        in {
            "securescan.python.dangerous-eval",
            "securescan.python.dangerous-exec",
            "securescan.python.insecure-tempfile-mktemp",
            "securescan.python.os-popen",
            "securescan.python.os-system",
            "securescan.python.unsafe-pickle-load",
        }
        else "direct-interpolation-sink"
        if rule_id == "securescan.python.sql-fstring-execute"
        else "explicit-insecure-pattern"
    )
    for rule_id in RULE_IDS
}
_CATALOG_FIELDS = frozenset({"frozen_ruleset", "rules", "schema_version"})
_RULE_FIELDS = frozenset(
    {
        "analysis_boundary",
        "claim_class",
        "explicit_exclusions",
        "external_label_scoring",
        "positive_scope",
        "relevant_cwes",
        "rule_id",
        "safe_counterparts",
    }
)
_RULESET_FIELDS = frozenset({"digest", "id", "version"})
_SCORING_FIELDS = frozenset({"safe", "vulnerable"})
_DECISION_FIELDS = frozenset(
    {
        "candidate_id",
        "claim_class",
        "disposition",
        "evidence",
        "expected_match",
        "expected_rule_id",
        "possible_rule_ids",
        "reason_code",
        "review_state",
    }
)
_EVIDENCE_FIELDS = frozenset(
    {"end_line", "relative_source_path", "source_sha256", "start_line"}
)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _load_json(path: Path) -> object:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {value}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("Python SAST applicability JSON is invalid") from exc


@dataclass(frozen=True, slots=True, order=True)
class RuleClaim:
    rule_id: str
    claim_class: str
    relevant_cwes: tuple[int, ...]
    positive_scope: tuple[str, ...]
    explicit_exclusions: tuple[str, ...]
    safe_counterparts: tuple[str, ...]
    analysis_boundary: tuple[str, ...]
    vulnerable_label_scoring: bool
    safe_label_scoring: bool

    def canonical_data(self) -> dict[str, object]:
        return {
            "analysis_boundary": list(self.analysis_boundary),
            "claim_class": self.claim_class,
            "explicit_exclusions": list(self.explicit_exclusions),
            "external_label_scoring": {
                "safe": self.safe_label_scoring,
                "vulnerable": self.vulnerable_label_scoring,
            },
            "positive_scope": list(self.positive_scope),
            "relevant_cwes": list(self.relevant_cwes),
            "rule_id": self.rule_id,
            "safe_counterparts": list(self.safe_counterparts),
        }


@dataclass(frozen=True, slots=True)
class RuleClaimCatalog:
    schema_version: str
    ruleset_id: str
    ruleset_version: str
    ruleset_digest: str
    rules: tuple[RuleClaim, ...]

    def canonical_data(self) -> dict[str, object]:
        return {
            "frozen_ruleset": {
                "digest": self.ruleset_digest,
                "id": self.ruleset_id,
                "version": self.ruleset_version,
            },
            "rules": [rule.canonical_data() for rule in self.rules],
            "schema_version": self.schema_version,
        }

    def rule(self, rule_id: str) -> RuleClaim:
        try:
            return next(rule for rule in self.rules if rule.rule_id == rule_id)
        except StopIteration as exc:
            raise ValueError("Python SAST applicability rule is unknown") from exc


def _text_list(value: object, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise ValueError
    result = tuple(value)
    if any(not isinstance(item, str) or not item or item != item.strip() for item in result):
        raise ValueError
    return result


def load_rule_claim_catalog(path: Path) -> RuleClaimCatalog:
    try:
        raw = _load_json(path)
        if not isinstance(raw, dict) or set(raw) != _CATALOG_FIELDS:
            raise ValueError
        ruleset = raw["frozen_ruleset"]
        raw_rules = raw["rules"]
        if (
            not isinstance(ruleset, dict)
            or set(ruleset) != _RULESET_FIELDS
            or not isinstance(raw_rules, list)
        ):
            raise ValueError
        rules: list[RuleClaim] = []
        for item in raw_rules:
            if not isinstance(item, dict) or set(item) != _RULE_FIELDS:
                raise ValueError
            scoring = item["external_label_scoring"]
            cwes = item["relevant_cwes"]
            if (
                not isinstance(scoring, dict)
                or set(scoring) != _SCORING_FIELDS
                or any(not isinstance(value, bool) for value in scoring.values())
                or not isinstance(cwes, list)
                or not cwes
                or any(not isinstance(cwe, int) or isinstance(cwe, bool) for cwe in cwes)
            ):
                raise ValueError
            rules.append(
                RuleClaim(
                    rule_id=item["rule_id"],
                    claim_class=item["claim_class"],
                    relevant_cwes=tuple(cwes),
                    positive_scope=_text_list(item["positive_scope"]),
                    explicit_exclusions=_text_list(item["explicit_exclusions"]),
                    safe_counterparts=_text_list(item["safe_counterparts"], allow_empty=True),
                    analysis_boundary=_text_list(item["analysis_boundary"]),
                    vulnerable_label_scoring=scoring["vulnerable"],
                    safe_label_scoring=scoring["safe"],
                )
            )
        catalog = RuleClaimCatalog(
            schema_version=raw["schema_version"],
            ruleset_id=ruleset["id"],
            ruleset_version=ruleset["version"],
            ruleset_digest=ruleset["digest"],
            rules=tuple(rules),
        )
        if (
            catalog.schema_version != CLAIM_CATALOG_SCHEMA_VERSION
            or catalog.ruleset_id != FROZEN_RULESET_ID
            or catalog.ruleset_version != FROZEN_RULESET_VERSION
            or catalog.ruleset_digest != FROZEN_RULESET_DIGEST
            or len(catalog.rules) != len(RULE_IDS)
            or {rule.rule_id for rule in catalog.rules} != RULE_IDS
            or {rule.claim_class for rule in catalog.rules} - CLAIM_CLASSES
            or any(RULE_CLASS_BY_ID[rule.rule_id] != rule.claim_class for rule in catalog.rules)
            or path.read_bytes() != canonical_document(catalog.canonical_data())
        ):
            raise ValueError
        return catalog
    except (KeyError, OSError, TypeError, ValueError) as exc:
        raise ValueError("Python SAST rule-claim catalog is invalid") from exc


def rule_claim_catalog_digest(catalog: RuleClaimCatalog) -> str:
    return hashlib.sha256(_canonical_json(catalog.canonical_data())).hexdigest()


@dataclass(frozen=True, slots=True, order=True)
class Relation:
    kind: str
    rule_id: str
    reason_code: str
    start_line: int
    end_line: int


@dataclass(frozen=True, slots=True)
class SourceInspection:
    relations: tuple[Relation, ...]
    parse_uncertainty: bool = False


def _bound_names(tree: ast.AST) -> set[str]:
    result: set[str] = set()

    def add_target(target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            result.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                add_target(element)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            result.add(node.name)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                result.update(argument.arg for argument in node.args.posonlyargs)
                result.update(argument.arg for argument in node.args.args)
                result.update(argument.arg for argument in node.args.kwonlyargs)
                if node.args.vararg is not None:
                    result.add(node.args.vararg.arg)
                if node.args.kwarg is not None:
                    result.add(node.args.kwarg.arg)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                add_target(target)
        elif isinstance(node, (ast.AugAssign, ast.For, ast.AsyncFor)):
            add_target(node.target)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    add_target(item.optional_vars)
        elif isinstance(node, ast.ExceptHandler) and node.name is not None:
            result.add(node.name)
    return result


class _SemanticInspector(ast.NodeVisitor):
    def __init__(self, tree: ast.AST) -> None:
        self.relations: list[Relation] = []
        self.module_aliases: dict[str, str] = {}
        self.symbol_aliases: dict[str, str] = {}
        self.imported_names: set[str] = set()
        self.ambiguous_aliases: set[str] = set()
        self.bound_names = _bound_names(tree)
        self.sessions: set[str] = set()
        self.flask_apps: set[str] = set()
        self.paramiko_clients: set[str] = set()
        self.ambiguous_objects: dict[str, str] = {}
        self._collect_imports(tree)
        self.ambiguous_aliases.update(self.imported_names & self.bound_names)
        self._collect_objects(tree)

    def _collect_imports(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name.split(".")[0]
                    path = alias.name if alias.asname else alias.name.split(".")[0]
                    self._record_alias(name, path, module=True)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    name = alias.asname or alias.name
                    self._record_alias(name, f"{node.module}.{alias.name}", module=False)

    def _record_alias(self, name: str, path: str, *, module: bool) -> None:
        mapping = self.module_aliases if module else self.symbol_aliases
        other = self.symbol_aliases if module else self.module_aliases
        if (name in mapping and mapping[name] != path) or name in other:
            self.ambiguous_aliases.add(name)
        mapping[name] = path
        self.imported_names.add(name)

    def _collect_objects(self, tree: ast.AST) -> None:
        assignment_counts: Counter[str] = Counter()
        recognized: dict[str, str] = {}
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = [target.id for target in targets if isinstance(target, ast.Name)]
            for name in names:
                assignment_counts[name] += 1
            value = node.value
            if not isinstance(value, ast.Call):
                continue
            path = self._path(value.func)
            for name in names:
                if path == "requests.Session":
                    recognized[name] = "securescan.python.requests-session-verify-false"
                elif path == "flask.Flask":
                    recognized[name] = "securescan.python.flask-debug-enabled"
                elif path == "paramiko.SSHClient":
                    recognized[name] = "securescan.python.paramiko-autoaddpolicy"
        for name, rule_id in recognized.items():
            if assignment_counts[name] != 1:
                self.ambiguous_objects[name] = rule_id
            elif rule_id == "securescan.python.requests-session-verify-false":
                self.sessions.add(name)
            elif rule_id == "securescan.python.flask-debug-enabled":
                self.flask_apps.add(name)
            else:
                self.paramiko_clients.add(name)

    def _path(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            if node.id in self.ambiguous_aliases:
                return None
            if node.id in self.symbol_aliases:
                return self.symbol_aliases[node.id]
            if node.id in self.module_aliases:
                return self.module_aliases[node.id]
            return node.id
        if isinstance(node, ast.Attribute):
            parent = self._path(node.value)
            return f"{parent}.{node.attr}" if parent is not None else None
        return None

    def _ambiguous_path(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name) and node.id in self.ambiguous_aliases:
            return self.symbol_aliases.get(node.id) or self.module_aliases.get(node.id)
        if isinstance(node, ast.Attribute):
            parent = self._ambiguous_path(node.value)
            return f"{parent}.{node.attr}" if parent is not None else None
        return None

    def _add(self, kind: str, rule_id: str, reason: str, node: ast.AST) -> None:
        self.relations.append(
            Relation(
                kind=kind,
                rule_id=rule_id,
                reason_code=reason,
                start_line=getattr(node, "lineno", 1),
                end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
            )
        )

    @staticmethod
    def _keyword(call: ast.Call, name: str) -> ast.AST | None:
        return next((keyword.value for keyword in call.keywords if keyword.arg == name), None)

    @staticmethod
    def _literal_bool(node: ast.AST | None) -> bool | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, bool):
            return node.value
        return None

    def _literal_option(self, node: ast.AST | None, key: str) -> bool | None | str:
        if node is None:
            return None
        if not isinstance(node, ast.Dict):
            return "dynamic"
        for raw_key, raw_value in zip(node.keys, node.values, strict=True):
            if isinstance(raw_key, ast.Constant) and raw_key.value == key:
                value = self._literal_bool(raw_value)
                return value if value is not None else "dynamic"
        return None

    def visit_Assign(self, node: ast.Assign) -> None:
        self._session_verify_assignment(node.targets, node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._session_verify_assignment([node.target], node.value, node)
        self.generic_visit(node)

    def _session_verify_assignment(
        self, targets: list[ast.expr], value: ast.AST, node: ast.AST
    ) -> None:
        for target in targets:
            if (
                isinstance(target, ast.Attribute)
                and target.attr == "verify"
                and isinstance(target.value, ast.Name)
                and self.ambiguous_objects.get(target.value.id)
                == "securescan.python.requests-session-verify-false"
            ):
                self._add(
                    "ambiguous",
                    "securescan.python.requests-session-verify-false",
                    "ambiguous-object-identity",
                    node,
                )
                continue
            if (
                isinstance(target, ast.Attribute)
                and target.attr == "verify"
                and isinstance(target.value, ast.Name)
                and target.value.id in self.sessions
            ):
                literal = self._literal_bool(value)
                kind = "positive" if literal is False else "safe" if literal is True else "outside"
                self._add(
                    kind,
                    "securescan.python.requests-session-verify-false",
                    "session-verify-literal-false"
                    if literal is False
                    else "session-verify-literal-true"
                    if literal is True
                    else "dynamic-argument-outside-literal-claim",
                    node,
                )

    def visit_Call(self, node: ast.Call) -> None:
        path = self._path(node.func)
        ambiguous_path = self._ambiguous_path(node.func)
        ambiguous_rules = {
            "flask.Flask": "securescan.python.flask-debug-enabled",
            "jinja2.Environment": "securescan.python.jinja-autoescape-disabled",
            "jwt.decode": "securescan.python.jwt-signature-verification-disabled",
            "lxml.etree.XMLParser": "securescan.python.lxml-resolve-entities",
            "os.popen": "securescan.python.os-popen",
            "os.system": "securescan.python.os-system",
            "paramiko.SSHClient": "securescan.python.paramiko-autoaddpolicy",
            "pickle.load": "securescan.python.unsafe-pickle-load",
            "pickle.loads": "securescan.python.unsafe-pickle-load",
            "requests.Session": "securescan.python.requests-session-verify-false",
            "requests.get": "securescan.python.requests-verify-false",
            "requests.post": "securescan.python.requests-verify-false",
            "requests.request": "securescan.python.requests-verify-false",
            "ssl._create_unverified_context": "securescan.python.ssl-unverified-context",
            "subprocess.Popen": "securescan.python.subprocess-shell-true",
            "subprocess.check_output": "securescan.python.subprocess-shell-true",
            "subprocess.run": "securescan.python.subprocess-shell-true",
            "tempfile.mktemp": "securescan.python.insecure-tempfile-mktemp",
            "yaml.load": "securescan.python.unsafe-yaml-load",
            "yaml.safe_load": "securescan.python.unsafe-yaml-load",
            "yaml.unsafe_load": "securescan.python.unsafe-yaml-load",
        }
        if ambiguous_path in ambiguous_rules:
            self._add(
                "ambiguous",
                ambiguous_rules[ambiguous_path],
                "ambiguous-import-shadowing",
                node,
            )
        self._inspect_builtin(node, path)
        self._inspect_direct_apis(node, path)
        self._inspect_subprocess(node, path)
        self._inspect_yaml(node, path)
        self._inspect_requests(node, path)
        self._inspect_framework_patterns(node, path)
        self._inspect_sql(node)
        self._inspect_jwt(node, path)
        self._inspect_lxml(node, path)
        self.generic_visit(node)

    def _inspect_builtin(self, call: ast.Call, path: str | None) -> None:
        if not isinstance(call.func, ast.Name) or call.func.id not in {"eval", "exec"}:
            return
        rule_id = f"securescan.python.dangerous-{call.func.id}"
        if call.func.id in self.bound_names - self.imported_names:
            self._add("ambiguous", rule_id, "ambiguous-built-in-shadowing", call)
        elif path == call.func.id and call.args:
            if isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
                self._add("outside", rule_id, "literal-only-outside-claim", call)
            else:
                self._add("positive", rule_id, "nonliteral-built-in-source", call)

    def _inspect_direct_apis(self, call: ast.Call, path: str | None) -> None:
        positive_paths = {
            "os.system": "securescan.python.os-system",
            "os.popen": "securescan.python.os-popen",
            "pickle.load": "securescan.python.unsafe-pickle-load",
            "pickle.loads": "securescan.python.unsafe-pickle-load",
            "ssl._create_unverified_context": "securescan.python.ssl-unverified-context",
            "tempfile.mktemp": "securescan.python.insecure-tempfile-mktemp",
        }
        safe_paths = {
            "ssl.create_default_context": "securescan.python.ssl-unverified-context",
            "tempfile.NamedTemporaryFile": "securescan.python.insecure-tempfile-mktemp",
            "tempfile.TemporaryFile": "securescan.python.insecure-tempfile-mktemp",
        }
        if path in positive_paths:
            self._add("positive", positive_paths[path], "direct-semantic-api-use", call)
        elif path in safe_paths:
            self._add("safe", safe_paths[path], "explicit-safe-counterpart", call)

    def _inspect_subprocess(self, call: ast.Call, path: str | None) -> None:
        if path not in {"subprocess.Popen", "subprocess.check_output", "subprocess.run"}:
            return
        shell = self._literal_bool(self._keyword(call, "shell"))
        if shell is True:
            self._add(
                "positive",
                "securescan.python.subprocess-shell-true",
                "literal-shell-true",
                call,
            )
        elif shell is False:
            self._add(
                "safe",
                "securescan.python.subprocess-shell-true",
                "literal-shell-false",
                call,
            )
        elif self._keyword(call, "shell") is not None:
            self._add(
                "outside",
                "securescan.python.subprocess-shell-true",
                "dynamic-argument-outside-literal-claim",
                call,
            )

    def _inspect_yaml(self, call: ast.Call, path: str | None) -> None:
        rule_id = "securescan.python.unsafe-yaml-load"
        if path == "yaml.unsafe_load":
            self._add("positive", rule_id, "yaml-unsafe-load", call)
            return
        if path == "yaml.safe_load":
            self._add("safe", rule_id, "yaml-safe-load", call)
            return
        if path != "yaml.load":
            return
        loader = self._keyword(call, "Loader")
        if loader is None and len(call.args) >= 2:
            loader = call.args[1]
        loader_path = self._path(loader) if loader is not None else None
        if loader_path in {"yaml.CLoader", "yaml.Loader", "yaml.UnsafeLoader"}:
            self._add("positive", rule_id, "yaml-explicit-unsafe-loader", call)
        elif loader_path in {"yaml.CSafeLoader", "yaml.SafeLoader"}:
            self._add("safe", rule_id, "yaml-explicit-safe-loader", call)
        elif loader_path == "yaml.FullLoader":
            self._add("outside", rule_id, "full-loader-outside-frozen-claim", call)
        else:
            self._add("ambiguous", rule_id, "ambiguous-loader-binding", call)

    def _inspect_requests(self, call: ast.Call, path: str | None) -> None:
        if path not in {"requests.get", "requests.post", "requests.request"}:
            return
        verify = self._keyword(call, "verify")
        if verify is None:
            return
        literal = self._literal_bool(verify)
        self._add(
            "positive" if literal is False else "safe" if literal is True else "outside",
            "securescan.python.requests-verify-false",
            "requests-verify-literal-false"
            if literal is False
            else "requests-verify-literal-true"
            if literal is True
            else "dynamic-argument-outside-literal-claim",
            call,
        )

    def _inspect_framework_patterns(self, call: ast.Call, path: str | None) -> None:
        if (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "run"
            and isinstance(call.func.value, ast.Name)
        ):
            name = call.func.value.id
            debug = self._keyword(call, "debug")
            if (
                debug is not None
                and self.ambiguous_objects.get(name)
                == "securescan.python.flask-debug-enabled"
            ):
                self._add(
                    "ambiguous",
                    "securescan.python.flask-debug-enabled",
                    "ambiguous-object-identity",
                    call,
                )
            elif debug is not None and name in self.flask_apps:
                literal = self._literal_bool(debug)
                kind = "positive" if literal is True else "safe" if literal is False else "outside"
                self._add(
                    kind,
                    "securescan.python.flask-debug-enabled",
                    "flask-debug-literal-true"
                    if literal is True
                    else "flask-debug-literal-false"
                    if literal is False
                    else "dynamic-argument-outside-literal-claim",
                    call,
                )
        if path == "jinja2.Environment":
            autoescape = self._keyword(call, "autoescape")
            if autoescape is not None:
                literal = self._literal_bool(autoescape)
                autoescape_path = self._path(autoescape)
                kind = (
                    "positive"
                    if literal is False
                    else "safe"
                    if literal is True or autoescape_path == "jinja2.select_autoescape"
                    else "outside"
                )
                self._add(
                    kind,
                    "securescan.python.jinja-autoescape-disabled",
                    "jinja-autoescape-literal-false"
                    if kind == "positive"
                    else "jinja-safe-autoescape"
                    if kind == "safe"
                    else "dynamic-argument-outside-literal-claim",
                    call,
                )
        if (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "set_missing_host_key_policy"
            and isinstance(call.func.value, ast.Name)
            and call.args
            and isinstance(call.args[0], ast.Call)
        ):
            client_name = call.func.value.id
            if (
                self.ambiguous_objects.get(client_name)
                == "securescan.python.paramiko-autoaddpolicy"
            ):
                self._add(
                    "ambiguous",
                    "securescan.python.paramiko-autoaddpolicy",
                    "ambiguous-object-identity",
                    call,
                )
                return
            if client_name not in self.paramiko_clients:
                return
            policy_path = self._path(call.args[0].func)
            if policy_path == "paramiko.AutoAddPolicy":
                self._add(
                    "positive",
                    "securescan.python.paramiko-autoaddpolicy",
                    "paramiko-auto-add-policy",
                    call,
                )
            elif policy_path == "paramiko.RejectPolicy":
                self._add(
                    "safe",
                    "securescan.python.paramiko-autoaddpolicy",
                    "paramiko-reject-policy",
                    call,
                )
            else:
                self._add(
                    "ambiguous",
                    "securescan.python.paramiko-autoaddpolicy",
                    "ambiguous-policy-binding",
                    call,
                )

    def _inspect_sql(self, call: ast.Call) -> None:
        if not isinstance(call.func, ast.Attribute) or call.func.attr != "execute" or not call.args:
            return
        first = call.args[0]
        if isinstance(first, ast.JoinedStr):
            self._add(
                "positive",
                "securescan.python.sql-fstring-execute",
                "direct-fstring-execute",
                call,
            )
        elif isinstance(first, ast.Constant) and isinstance(first.value, str) and (
            len(call.args) >= 2
            or any(keyword.arg in {"parameters", "params"} for keyword in call.keywords)
        ):
            self._add(
                "safe",
                "securescan.python.sql-fstring-execute",
                "parameterized-execute",
                call,
            )

    def _inspect_jwt(self, call: ast.Call, path: str | None) -> None:
        if path != "jwt.decode":
            return
        option = self._literal_option(self._keyword(call, "options"), "verify_signature")
        if option is False:
            kind, reason = "positive", "jwt-verify-signature-literal-false"
        elif option in {True, None}:
            kind, reason = "safe", "jwt-signature-verification-preserved"
        else:
            kind, reason = "outside", "dynamic-argument-outside-literal-claim"
        self._add(
            kind,
            "securescan.python.jwt-signature-verification-disabled",
            reason,
            call,
        )

    def _inspect_lxml(self, call: ast.Call, path: str | None) -> None:
        rule_id = "securescan.python.lxml-resolve-entities"
        if path == "lxml.etree.XMLParser":
            value = self._keyword(call, "resolve_entities")
            literal = self._literal_bool(value)
            if literal is True:
                kind, reason = "positive", "lxml-resolve-entities-literal-true"
            elif value is None or literal is False:
                kind, reason = "safe", "lxml-entities-disabled-or-default"
            else:
                kind, reason = "outside", "dynamic-argument-outside-literal-claim"
            self._add(kind, rule_id, reason, call)
        elif path is not None and (
            path.startswith("defusedxml.") or path.startswith("xml.etree.")
        ):
            self._add("safe", rule_id, "safe-or-standard-library-xml-parser", call)


def inspect_python_source(source: bytes) -> SourceInspection:
    try:
        text = source.decode("utf-8")
        tree = ast.parse(text)
    except (UnicodeError, SyntaxError, ValueError):
        return SourceInspection(relations=(), parse_uncertainty=True)
    inspector = _SemanticInspector(tree)
    inspector.visit(tree)
    return SourceInspection(relations=tuple(sorted(set(inspector.relations))))


@dataclass(frozen=True, slots=True, order=True)
class EvidenceLocation:
    relative_source_path: str
    source_sha256: str
    start_line: int
    end_line: int

    def canonical_data(self) -> dict[str, object]:
        return {
            "end_line": self.end_line,
            "relative_source_path": self.relative_source_path,
            "source_sha256": self.source_sha256,
            "start_line": self.start_line,
        }


@dataclass(frozen=True, slots=True)
class ApplicabilityDecision:
    candidate_id: str
    disposition: str
    expected_rule_id: str | None
    expected_match: bool | None
    claim_class: str | None
    reason_code: str
    review_state: str
    possible_rule_ids: tuple[str, ...]
    evidence: tuple[EvidenceLocation, ...]

    def canonical_data(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "claim_class": self.claim_class,
            "disposition": self.disposition,
            "evidence": [item.canonical_data() for item in self.evidence],
            "expected_match": self.expected_match,
            "expected_rule_id": self.expected_rule_id,
            "possible_rule_ids": list(self.possible_rule_ids),
            "reason_code": self.reason_code,
            "review_state": self.review_state,
        }


def _valid_relative_path(value: str) -> bool:
    if not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and path.as_posix() == value
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _candidate_source(
    cache_root: Path, source_lock: SourceLock, candidate: Candidate
) -> bytes:
    if not _valid_relative_path(candidate.relative_source_path):
        raise ValueError("applicability candidate path is invalid")
    root = cache_root / source_lock.source(candidate.external_source_id).cache_path
    path = root.joinpath(*PurePosixPath(candidate.relative_source_path).parts)
    try:
        resolved_root = root.resolve(strict=True)
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
        resolved.relative_to(resolved_root)
        data = path.read_bytes()
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("applicability candidate source is invalid") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or resolved != path.absolute()
        or hashlib.sha256(data).hexdigest() != candidate.source_sha256
    ):
        raise ValueError("applicability candidate source is invalid")
    return data


def _line_count(source: bytes) -> int:
    return max(1, len(source.splitlines()))


def _evidence(
    candidate: Candidate, relations: tuple[Relation, ...]
) -> tuple[EvidenceLocation, ...]:
    if not relations:
        return (
            EvidenceLocation(
                relative_source_path=candidate.relative_source_path,
                source_sha256=candidate.source_sha256,
                start_line=1,
                end_line=1,
            ),
        )
    return tuple(
        sorted(
            {
                EvidenceLocation(
                    relative_source_path=candidate.relative_source_path,
                    source_sha256=candidate.source_sha256,
                    start_line=relation.start_line,
                    end_line=relation.end_line,
                )
                for relation in relations
            }
        )
    )


def _relevant_rules(catalog: RuleClaimCatalog, cwe: int) -> tuple[str, ...]:
    return tuple(sorted(rule.rule_id for rule in catalog.rules if cwe in rule.relevant_cwes))


def _decision(
    candidate: Candidate,
    catalog: RuleClaimCatalog,
    inspection: SourceInspection,
) -> ApplicabilityDecision:
    if candidate.scoring_status == "excluded-known-benchmark-contamination":
        return ApplicabilityDecision(
            candidate_id=candidate.candidate_id,
            disposition="EXCLUDED",
            expected_rule_id=None,
            expected_match=None,
            claim_class=None,
            reason_code="known-benchmark-cross-category-contamination",
            review_state="fixed-policy-exclusion",
            possible_rule_ids=(),
            evidence=_evidence(candidate, ()),
        )
    relevant = frozenset(_relevant_rules(catalog, candidate.cwe))
    aligned = tuple(relation for relation in inspection.relations if relation.rule_id in relevant)
    possible = tuple(sorted({relation.rule_id for relation in aligned} or relevant))
    evidence = _evidence(candidate, aligned)

    def result(
        disposition: str,
        reason: str,
        *,
        rule_id: str | None = None,
        expected_match: bool | None = None,
        possible_rules: tuple[str, ...] = possible,
        selected_evidence: tuple[EvidenceLocation, ...] = evidence,
        review_state: str = "pending-human-approval",
    ) -> ApplicabilityDecision:
        return ApplicabilityDecision(
            candidate_id=candidate.candidate_id,
            disposition=disposition,
            expected_rule_id=rule_id,
            expected_match=expected_match,
            claim_class=RULE_CLASS_BY_ID[rule_id] if rule_id is not None else None,
            reason_code=reason,
            review_state=review_state,
            possible_rule_ids=possible_rules,
            evidence=selected_evidence,
        )

    if inspection.parse_uncertainty:
        return result("UNRESOLVED", "syntax-or-decoding-uncertainty")

    positive = tuple(relation for relation in aligned if relation.kind == "positive")
    safe = tuple(relation for relation in aligned if relation.kind == "safe")
    ambiguous = tuple(relation for relation in aligned if relation.kind == "ambiguous")
    outside = tuple(relation for relation in aligned if relation.kind == "outside")
    strong_rule_ids = {relation.rule_id for relation in positive + safe}
    if len(strong_rule_ids) > 1:
        return result(
            "UNRESOLVED",
            "multiple-claim-relations",
            possible_rules=tuple(sorted(strong_rule_ids)),
            selected_evidence=_evidence(candidate, positive + safe),
        )
    if positive and safe:
        return result(
            "UNRESOLVED",
            "contradictory-claim-relations",
            possible_rules=tuple(sorted(strong_rule_ids)),
            selected_evidence=_evidence(candidate, positive + safe),
        )
    if ambiguous:
        return result(
            "UNRESOLVED",
            "ambiguous-binding-or-shadowing",
            possible_rules=tuple(sorted({relation.rule_id for relation in ambiguous})),
            selected_evidence=_evidence(candidate, ambiguous),
        )
    if positive:
        relation = positive[0]
        claim = catalog.rule(relation.rule_id)
        selected = _evidence(candidate, positive)
        if candidate.upstream_label == "vulnerable" and claim.vulnerable_label_scoring:
            return result(
                "APPLICABLE_POSITIVE",
                relation.reason_code,
                rule_id=relation.rule_id,
                expected_match=True,
                possible_rules=(relation.rule_id,),
                selected_evidence=selected,
            )
        reason = (
            "dangerous-api-safe-label-not-a-negative"
            if claim.claim_class == "dangerous-api-observation"
            else "upstream-safe-label-requires-contextual-mitigation-review"
        )
        return result("OUT_OF_SCOPE", reason, selected_evidence=selected)
    if safe:
        relation = safe[0]
        claim = catalog.rule(relation.rule_id)
        selected = _evidence(candidate, safe)
        if candidate.upstream_label == "safe" and claim.safe_label_scoring:
            return result(
                "APPLICABLE_NEGATIVE",
                relation.reason_code,
                rule_id=relation.rule_id,
                expected_match=False,
                possible_rules=(relation.rule_id,),
                selected_evidence=selected,
            )
        reason = (
            "dangerous-api-safe-label-not-a-negative"
            if claim.claim_class == "dangerous-api-observation"
            else "vulnerable-label-uses-safe-counterpart-outside-claim"
        )
        return result("OUT_OF_SCOPE", reason, selected_evidence=selected)
    if outside:
        reasons = {relation.reason_code for relation in outside}
        reason = next(iter(reasons)) if len(reasons) == 1 else "multiple-out-of-scope-relations"
        return result("OUT_OF_SCOPE", reason, selected_evidence=_evidence(candidate, outside))
    reason_by_cwe = {
        78: "requires-taint-or-dataflow-analysis",
        79: "unrelated-framework-or-output-encoding-pattern",
        89: "not-direct-fstring-execute",
        94: "requires-taint-or-dataflow-analysis",
        95: "requires-taint-or-dataflow-analysis",
        295: "different-api-or-configuration-family",
        347: "different-api-or-configuration-family",
        377: "different-temporary-file-pattern",
        489: "different-debug-or-stack-trace-pattern",
        502: "different-deserialization-api-family",
        611: "different-xml-parser-family",
    }
    return result("OUT_OF_SCOPE", reason_by_cwe[candidate.cwe])


def _review_selection_digest(candidates: tuple[Candidate, ...]) -> str:
    return hashlib.sha256(
        _canonical_json(sorted(candidate.candidate_id for candidate in candidates))
    ).hexdigest()


def proposal_digest(proposal: dict[str, object]) -> str:
    return hashlib.sha256(_canonical_json(proposal)).hexdigest()


def build_applicability_proposal(
    repository_root: Path,
    cache_root: Path,
) -> tuple[dict[str, object], tuple[Candidate, ...], RuleClaimCatalog, SourceLock]:
    benchmark_root = repository_root / "benchmarks/python_sast_external"
    source_lock = load_source_lock(benchmark_root / "sources.lock.json")
    source_digest = source_lock_digest(source_lock)
    if source_digest != EXPECTED_SOURCE_LOCK_DIGEST:
        raise ValueError("applicability source-lock binding mismatch")
    inventory_path = benchmark_root / "candidates.json"
    candidates = load_candidate_inventory(inventory_path, source_digest)
    inventory_raw = _load_json(inventory_path)
    if (
        not isinstance(inventory_raw, dict)
        or candidate_inventory_digest(inventory_raw) != EXPECTED_CANDIDATE_INVENTORY_DIGEST
        or len(candidates) != EXPECTED_CANDIDATE_COUNT
        or _review_selection_digest(candidates) != EXPECTED_REVIEW_SELECTION_DIGEST
    ):
        raise ValueError("applicability candidate-inventory binding mismatch")
    catalog = load_rule_claim_catalog(benchmark_root / "rule-claims.json")
    verify_external_sources(cache_root, source_lock)
    decisions = tuple(
        _decision(
            candidate,
            catalog,
            inspect_python_source(_candidate_source(cache_root, source_lock, candidate)),
        )
        for candidate in candidates
    )
    proposal: dict[str, object] = {
        "candidate_inventory_digest": EXPECTED_CANDIDATE_INVENTORY_DIGEST,
        "decisions": [decision.canonical_data() for decision in decisions],
        "proposal_state": "IMPLEMENTED-PENDING-HUMAN-APPROVAL",
        "review_selection_digest": EXPECTED_REVIEW_SELECTION_DIGEST,
        "rule_claim_catalog_digest": rule_claim_catalog_digest(catalog),
        "ruleset": {
            "digest": FROZEN_RULESET_DIGEST,
            "id": FROZEN_RULESET_ID,
            "version": FROZEN_RULESET_VERSION,
        },
        "schema_version": PROPOSAL_SCHEMA_VERSION,
        "source_lock_digest": EXPECTED_SOURCE_LOCK_DIGEST,
        "total_candidate_count": EXPECTED_CANDIDATE_COUNT,
    }
    validate_applicability_proposal(proposal, candidates, catalog, cache_root, source_lock)
    return proposal, candidates, catalog, source_lock


def _parse_decision(raw: object) -> ApplicabilityDecision:
    if not isinstance(raw, dict) or set(raw) != _DECISION_FIELDS:
        raise ValueError
    evidence_raw = raw["evidence"]
    possible = raw["possible_rule_ids"]
    if not isinstance(evidence_raw, list) or not evidence_raw or not isinstance(possible, list):
        raise ValueError
    evidence: list[EvidenceLocation] = []
    for item in evidence_raw:
        if not isinstance(item, dict) or set(item) != _EVIDENCE_FIELDS:
            raise ValueError
        evidence.append(EvidenceLocation(**item))
    return ApplicabilityDecision(
        candidate_id=raw["candidate_id"],
        disposition=raw["disposition"],
        expected_rule_id=raw["expected_rule_id"],
        expected_match=raw["expected_match"],
        claim_class=raw["claim_class"],
        reason_code=raw["reason_code"],
        review_state=raw["review_state"],
        possible_rule_ids=tuple(possible),
        evidence=tuple(evidence),
    )


def validate_applicability_proposal(
    proposal: dict[str, object],
    candidates: tuple[Candidate, ...],
    catalog: RuleClaimCatalog,
    cache_root: Path,
    source_lock: SourceLock,
) -> tuple[ApplicabilityDecision, ...]:
    expected_fields = {
        "candidate_inventory_digest",
        "decisions",
        "proposal_state",
        "review_selection_digest",
        "rule_claim_catalog_digest",
        "ruleset",
        "schema_version",
        "source_lock_digest",
        "total_candidate_count",
    }
    try:
        if (
            not isinstance(proposal, dict)
            or set(proposal) != expected_fields
            or proposal["schema_version"] != PROPOSAL_SCHEMA_VERSION
            or proposal["proposal_state"] != "IMPLEMENTED-PENDING-HUMAN-APPROVAL"
            or proposal["source_lock_digest"] != EXPECTED_SOURCE_LOCK_DIGEST
            or proposal["candidate_inventory_digest"] != EXPECTED_CANDIDATE_INVENTORY_DIGEST
            or proposal["review_selection_digest"] != EXPECTED_REVIEW_SELECTION_DIGEST
            or proposal["rule_claim_catalog_digest"] != rule_claim_catalog_digest(catalog)
            or proposal["total_candidate_count"] != EXPECTED_CANDIDATE_COUNT
            or proposal["ruleset"]
            != {
                "digest": FROZEN_RULESET_DIGEST,
                "id": FROZEN_RULESET_ID,
                "version": FROZEN_RULESET_VERSION,
            }
            or not isinstance(proposal["decisions"], list)
        ):
            raise ValueError
        decisions = tuple(_parse_decision(item) for item in proposal["decisions"])
        candidate_by_id = {candidate.candidate_id: candidate for candidate in candidates}
        if (
            len(decisions) != EXPECTED_CANDIDATE_COUNT
            or tuple(item.candidate_id for item in decisions)
            != tuple(candidate.candidate_id for candidate in candidates)
            or len({item.candidate_id for item in decisions}) != len(decisions)
        ):
            raise ValueError
        excluded = 0
        for decision in decisions:
            candidate = candidate_by_id[decision.candidate_id]
            source = _candidate_source(cache_root, source_lock, candidate)
            lines = _line_count(source)
            if (
                decision.disposition not in DISPOSITIONS
                or not isinstance(decision.reason_code, str)
                or not decision.reason_code
                or decision.possible_rule_ids != tuple(sorted(set(decision.possible_rule_ids)))
                or any(rule_id not in RULE_IDS for rule_id in decision.possible_rule_ids)
                or decision.evidence != tuple(sorted(set(decision.evidence)))
                or (
                    candidate.scoring_status == "excluded-known-benchmark-contamination"
                )
                != (decision.disposition == "EXCLUDED")
                or any(
                    item.relative_source_path != candidate.relative_source_path
                    or item.source_sha256 != candidate.source_sha256
                    or not isinstance(item.start_line, int)
                    or isinstance(item.start_line, bool)
                    or not isinstance(item.end_line, int)
                    or isinstance(item.end_line, bool)
                    or not 1 <= item.start_line <= item.end_line <= lines
                    for item in decision.evidence
                )
            ):
                raise ValueError
            if decision.disposition in {"APPLICABLE_POSITIVE", "APPLICABLE_NEGATIVE"}:
                expected_match = decision.disposition == "APPLICABLE_POSITIVE"
                if (
                    decision.review_state != "pending-human-approval"
                    or decision.expected_rule_id not in RULE_IDS
                    or decision.expected_match is not expected_match
                    or decision.claim_class != RULE_CLASS_BY_ID[decision.expected_rule_id]
                    or decision.possible_rule_ids != (decision.expected_rule_id,)
                ):
                    raise ValueError
            elif (
                decision.expected_rule_id is not None
                or decision.expected_match is not None
                or decision.claim_class is not None
                or (
                    decision.disposition == "EXCLUDED"
                    and (
                        candidate.scoring_status
                        != "excluded-known-benchmark-contamination"
                        or decision.review_state != "fixed-policy-exclusion"
                        or decision.possible_rule_ids
                        or decision.reason_code
                        != "known-benchmark-cross-category-contamination"
                    )
                )
                or (
                    decision.disposition != "EXCLUDED"
                    and decision.review_state != "pending-human-approval"
                )
            ):
                raise ValueError
            excluded += decision.disposition == "EXCLUDED"
        if excluded != 33:
            raise ValueError
        return decisions
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Python SAST applicability proposal is invalid") from exc


def load_applicability_proposal(
    path: Path,
    candidates: tuple[Candidate, ...],
    catalog: RuleClaimCatalog,
    cache_root: Path,
    source_lock: SourceLock,
) -> tuple[dict[str, object], tuple[ApplicabilityDecision, ...]]:
    raw = _load_json(path)
    if not isinstance(raw, dict) or path.read_bytes() != canonical_document(raw):
        raise ValueError("Python SAST applicability proposal is invalid")
    decisions = validate_applicability_proposal(raw, candidates, catalog, cache_root, source_lock)
    return raw, decisions


def _rank(candidate_id: str, dimension: str) -> tuple[str, str]:
    return hashlib.sha256(f"{dimension}\0{candidate_id}".encode()).hexdigest(), candidate_id


def build_audit_sample(
    proposal: dict[str, object],
    decisions: tuple[ApplicabilityDecision, ...],
    candidates: tuple[Candidate, ...],
) -> dict[str, object]:
    candidate_by_id = {candidate.candidate_id: candidate for candidate in candidates}
    decision_by_id = {decision.candidate_id: decision for decision in decisions}
    selected: set[str] = set()
    for rule_id in sorted(RULE_IDS):
        for disposition in ("APPLICABLE_POSITIVE", "APPLICABLE_NEGATIVE", "OUT_OF_SCOPE"):
            eligible = [
                decision
                for decision in decisions
                if decision.disposition == disposition
                and rule_id
                in (
                    (decision.expected_rule_id,)
                    if decision.expected_rule_id is not None
                    else decision.possible_rule_ids
                )
            ]
            selected.update(
                decision.candidate_id
                for decision in sorted(
                    eligible, key=lambda item: _rank(item.candidate_id, f"{rule_id}:{disposition}")
                )[:3]
            )
    selected.update(
        decision.candidate_id for decision in decisions if decision.disposition == "UNRESOLVED"
    )
    for attribute in ("external_source_id", "framework"):
        values = sorted({getattr(candidate, attribute) for candidate in candidates})
        for value in values:
            eligible_ids = [
                candidate.candidate_id
                for candidate in candidates
                if getattr(candidate, attribute) == value
            ]
            selected.add(min(eligible_ids, key=lambda item: _rank(item, f"{attribute}:{value}")))
    excluded = [item for item in decisions if item.disposition == "EXCLUDED"]
    selected.update(
        item.candidate_id
        for item in sorted(excluded, key=lambda item: _rank(item.candidate_id, "excluded"))[:3]
    )
    cases = []
    for candidate_id in sorted(selected):
        candidate = candidate_by_id[candidate_id]
        decision = decision_by_id[candidate_id]
        cases.append(
            {
                "candidate_id": candidate_id,
                "cwe": candidate.cwe,
                "decision": decision.canonical_data(),
                "external_source_id": candidate.external_source_id,
                "framework": candidate.framework,
                "upstream_label": candidate.upstream_label,
            }
        )
    return {
        "cases": cases,
        "proposal_digest": proposal_digest(proposal),
        "sampling": {
            "per_rule_and_disposition_limit": 3,
            "ranking": "SHA-256 of dimension, NUL, and immutable candidate ID",
            "required": [
                "all unresolved decisions",
                "source and framework representatives",
                "excluded known-contamination representatives",
            ],
        },
        "schema_version": AUDIT_SAMPLE_SCHEMA_VERSION,
    }


def _nested_counts(
    decisions: tuple[ApplicabilityDecision, ...],
    candidates: tuple[Candidate, ...],
    attribute: str,
) -> dict[str, dict[str, int]]:
    candidate_by_id = {candidate.candidate_id: candidate for candidate in candidates}
    grouped: dict[str, Counter[str]] = defaultdict(Counter)
    for decision in decisions:
        grouped[str(getattr(candidate_by_id[decision.candidate_id], attribute))][
            decision.disposition
        ] += 1
    return {
        key: {disposition: counts.get(disposition, 0) for disposition in sorted(DISPOSITIONS)}
        for key, counts in sorted(grouped.items())
    }


def build_applicability_summary(
    proposal: dict[str, object],
    decisions: tuple[ApplicabilityDecision, ...],
    candidates: tuple[Candidate, ...],
    catalog: RuleClaimCatalog,
    audit: dict[str, object],
) -> dict[str, object]:
    disposition_counts = Counter(decision.disposition for decision in decisions)
    reason_counts = Counter(decision.reason_code for decision in decisions)
    per_rule: dict[str, dict[str, int]] = {}
    for rule_id in sorted(RULE_IDS):
        relevant = [
            decision
            for decision in decisions
            if decision.expected_rule_id == rule_id or rule_id in decision.possible_rule_ids
        ]
        per_rule[rule_id] = {
            disposition: sum(item.disposition == disposition for item in relevant)
            for disposition in sorted(DISPOSITIONS)
        }
    claim_counts: dict[str, Counter[str]] = defaultdict(Counter)
    for decision in decisions:
        classes = (
            (decision.claim_class,)
            if decision.claim_class is not None
            else tuple({RULE_CLASS_BY_ID[rule_id] for rule_id in decision.possible_rule_ids})
        )
        for claim_class in classes:
            claim_counts[claim_class][decision.disposition] += 1
    return {
        "audit_sample_count": len(audit["cases"]),
        "candidate_inventory_digest": EXPECTED_CANDIDATE_INVENTORY_DIGEST,
        "counts_by_claim_class": {
            key: {item: value.get(item, 0) for item in sorted(DISPOSITIONS)}
            for key, value in sorted(claim_counts.items())
        },
        "counts_by_disposition": {
            item: disposition_counts.get(item, 0) for item in sorted(DISPOSITIONS)
        },
        "counts_by_external_source": _nested_counts(decisions, candidates, "external_source_id"),
        "counts_by_framework": _nested_counts(decisions, candidates, "framework"),
        "counts_by_rule": per_rule,
        "counts_by_upstream_label": _nested_counts(decisions, candidates, "upstream_label"),
        "excluded_known_contamination_count": disposition_counts.get("EXCLUDED", 0),
        "out_of_scope_reason_counts": dict(
            sorted(
                Counter(
                    decision.reason_code
                    for decision in decisions
                    if decision.disposition == "OUT_OF_SCOPE"
                ).items()
            )
        ),
        "proposal_digest": proposal_digest(proposal),
        "proposal_state": proposal["proposal_state"],
        "reason_counts": dict(sorted(reason_counts.items())),
        "review_selection_digest": EXPECTED_REVIEW_SELECTION_DIGEST,
        "rule_claim_catalog_digest": rule_claim_catalog_digest(catalog),
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "source_lock_digest": EXPECTED_SOURCE_LOCK_DIGEST,
        "total_candidate_count": len(decisions),
        "unresolved_reason_counts": dict(
            sorted(
                Counter(
                    decision.reason_code
                    for decision in decisions
                    if decision.disposition == "UNRESOLVED"
                ).items()
            )
        ),
    }


def write_applicability_evidence(
    proposal_path: Path,
    audit_path: Path,
    summary_path: Path,
    proposal: dict[str, object],
    audit: dict[str, object],
    summary: dict[str, object],
) -> None:
    for path, value in (
        (proposal_path, proposal),
        (audit_path, audit),
        (summary_path, summary),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(canonical_document(value))
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary_path, 0o644)
            os.replace(temporary_path, path)
        finally:
            temporary_path.unlink(missing_ok=True)
