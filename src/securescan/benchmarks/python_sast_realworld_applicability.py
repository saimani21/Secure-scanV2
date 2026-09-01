from __future__ import annotations

import ast
import hashlib
import json
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from securescan.benchmarks.python_sast_realworld import (
    _blob,
    accepted_case_set_digest,
    canonical_document,
    digest,
    load_json,
)
from securescan.benchmarks.python_sast_realworld import (
    verify as verify_realworld_cases,
)

SCHEMA_VERSION: Final = "securescan-python-sast-realworld-applicability-v1"
SUMMARY_SCHEMA_VERSION: Final = "securescan-python-sast-realworld-applicability-summary-v1"
REVIEW_SCHEMA_VERSION: Final = "securescan-python-sast-realworld-applicability-review-v1"
BASELINE_TAG: Final = "source-v0.3F2E1-python-sast-realworld-cases"
BASELINE_COMMIT: Final = "8b0a6ca6ac2ae659723425f21aaafcbfe11ef5f2"
SOURCE_LOCK_DIGEST: Final = "0bba4bbe5ce557f1382f61f9af3320adef5cc53ab386d1c63f4983d8cbf48a00"
ACCEPTED_CASE_SET_DIGEST: Final = "60d44ea9cf0f174e1488c5b8dbccde2804524fe4d3bfa31b9db0810e52332a92"
RULE_CLAIM_CATALOG_DIGEST: Final = (
    "02741b7745a8d61648eb67d0132923599c7fb110d8cedbc05bb311b2601befc9"
)
REVIEW_STATE: Final = "pending-human-approval"
CLAIM_APPLICABLE: Final = "CLAIM_APPLICABLE"
OUTSIDE_FROZEN_RULE_CLAIMS: Final = "OUTSIDE_FROZEN_RULE_CLAIMS"
UNRESOLVED: Final = "UNRESOLVED"
SHOULD_DISCRIMINATE: Final = "SHOULD_DISCRIMINATE"
NOT_EXPECTED_TO_DISCRIMINATE: Final = "NOT_EXPECTED_TO_DISCRIMINATE"

RULE_IDS: Final = (
    "securescan.python.dangerous-eval",
    "securescan.python.dangerous-exec",
    "securescan.python.os-system",
    "securescan.python.os-popen",
    "securescan.python.unsafe-pickle-load",
    "securescan.python.insecure-tempfile-mktemp",
    "securescan.python.subprocess-shell-true",
    "securescan.python.unsafe-yaml-load",
    "securescan.python.requests-verify-false",
    "securescan.python.requests-session-verify-false",
    "securescan.python.ssl-unverified-context",
    "securescan.python.paramiko-autoaddpolicy",
    "securescan.python.flask-debug-enabled",
    "securescan.python.jinja-autoescape-disabled",
    "securescan.python.sql-fstring-execute",
    "securescan.python.jwt-signature-verification-disabled",
    "securescan.python.lxml-resolve-entities",
)


@dataclass(frozen=True, slots=True)
class RegionSpec:
    path: str
    qualified_symbol: str | None = None
    occurrence: int = 0
    call_attribute: str | None = None
    first_arg_name: str | None = None


@dataclass(frozen=True, slots=True)
class CaseSpec:
    disposition: str
    vulnerable_regions: tuple[RegionSpec, ...]
    fixed_regions: tuple[RegionSpec, ...]
    rule_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]


_SPECS: Final = {
    "CVE-2022-24065": CaseSpec(
        OUTSIDE_FROZEN_RULE_CLAIMS,
        (RegionSpec("cookiecutter/vcs.py", "clone"),),
        (RegionSpec("cookiecutter/vcs.py", "clone"),),
        (),
        ("literal-shell-true-absent", "security-fix-outside-rule-semantics"),
    ),
    "CVE-2022-28347": CaseSpec(
        OUTSIDE_FROZEN_RULE_CLAIMS,
        (
            RegionSpec(
                "django/db/backends/postgresql/operations.py",
                "DatabaseOperations.explain_query_prefix",
            ),
            RegionSpec("django/db/models/sql/query.py", "Query.explain"),
        ),
        (
            RegionSpec(
                "django/db/backends/postgresql/operations.py",
                "DatabaseOperations.explain_query_prefix",
            ),
            RegionSpec("django/db/models/sql/query.py", "Query.explain"),
        ),
        (),
        ("same-cwe-unsupported-pattern", "different-interpolation-shape"),
    ),
    "CVE-2022-34265": CaseSpec(
        OUTSIDE_FROZEN_RULE_CLAIMS,
        (
            RegionSpec("django/db/models/functions/datetime.py", "Extract.as_sql"),
            RegionSpec("django/db/models/functions/datetime.py", "TruncBase.as_sql"),
        ),
        (
            RegionSpec("django/db/models/functions/datetime.py", "Extract.as_sql"),
            RegionSpec("django/db/models/functions/datetime.py", "TruncBase.as_sql"),
        ),
        (),
        ("same-cwe-unsupported-pattern", "different-interpolation-shape"),
    ),
    "CVE-2023-24816": CaseSpec(
        CLAIM_APPLICABLE,
        (RegionSpec("IPython/utils/terminal.py", "_set_term_title", 2),),
        (RegionSpec("IPython/utils/terminal.py", "_set_term_title", 1),),
        ("securescan.python.os-system",),
        ("exact-frozen-claim-overlap", "dangerous-api-removed-by-fix"),
    ),
    "CVE-2023-40581": CaseSpec(
        OUTSIDE_FROZEN_RULE_CLAIMS,
        (RegionSpec("yt_dlp/postprocessor/exec.py", "ExecPP.run"),),
        (RegionSpec("yt_dlp/postprocessor/exec.py", "ExecPP.run"),),
        (),
        ("different-sink-api", "security-fix-outside-rule-semantics"),
    ),
    "CVE-2023-50943": CaseSpec(
        CLAIM_APPLICABLE,
        (RegionSpec("airflow/models/xcom.py", "BaseXCom._deserialize_value"),),
        (RegionSpec("airflow/models/xcom.py", "BaseXCom._deserialize_value"),),
        ("securescan.python.unsafe-pickle-load",),
        ("exact-frozen-claim-overlap", "dangerous-api-persists-after-fix"),
    ),
    "CVE-2023-6940": CaseSpec(
        OUTSIDE_FROZEN_RULE_CLAIMS,
        (RegionSpec("mlflow/utils/file_utils.py", "render_and_merge_yaml"),),
        (RegionSpec("mlflow/utils/file_utils.py", "render_and_merge_yaml"),),
        (),
        ("same-cwe-unsupported-pattern", "security-fix-outside-rule-semantics"),
    ),
    "CVE-2023-7018": CaseSpec(
        CLAIM_APPLICABLE,
        (
            RegionSpec(
                "src/transformers/models/rag/retrieval_rag.py", "LegacyIndex._load_passages"
            ),
            RegionSpec(
                "src/transformers/models/transfo_xl/tokenization_transfo_xl.py",
                "TransfoXLTokenizer.__init__",
            ),
            RegionSpec(
                "src/transformers/models/transfo_xl/tokenization_transfo_xl.py",
                "get_lm_corpus",
            ),
        ),
        (
            RegionSpec(
                "src/transformers/models/rag/retrieval_rag.py", "LegacyIndex._load_passages"
            ),
            RegionSpec(
                "src/transformers/models/deprecated/transfo_xl/tokenization_transfo_xl.py",
                "TransfoXLTokenizer.__init__",
            ),
            RegionSpec(
                "src/transformers/models/deprecated/transfo_xl/tokenization_transfo_xl.py",
                "get_lm_corpus",
            ),
        ),
        ("securescan.python.unsafe-pickle-load",),
        ("exact-frozen-claim-overlap", "dangerous-api-persists-after-fix"),
    ),
    "CVE-2024-22423": CaseSpec(
        OUTSIDE_FROZEN_RULE_CLAIMS,
        (
            RegionSpec("yt_dlp/YoutubeDL.py", "YoutubeDL.prepare_outtmpl"),
            RegionSpec("yt_dlp/utils/_utils.py", "shell_quote"),
        ),
        (
            RegionSpec("yt_dlp/YoutubeDL.py", "YoutubeDL.prepare_outtmpl"),
            RegionSpec("yt_dlp/utils/_utils.py", "shell_quote"),
        ),
        (),
        ("different-sink-api", "security-fix-outside-rule-semantics"),
    ),
    "CVE-2024-3098": CaseSpec(
        CLAIM_APPLICABLE,
        (RegionSpec("llama-index-core/llama_index/core/exec_utils.py", "safe_eval"),),
        (RegionSpec("llama-index-core/llama_index/core/exec_utils.py", "safe_eval"),),
        ("securescan.python.dangerous-eval",),
        ("exact-frozen-claim-overlap", "dangerous-api-persists-after-fix"),
    ),
    "CVE-2024-3271": CaseSpec(
        CLAIM_APPLICABLE,
        (RegionSpec("llama-index-core/llama_index/core/exec_utils.py", "safe_eval"),),
        (RegionSpec("llama-index-core/llama_index/core/exec_utils.py", "safe_eval"),),
        ("securescan.python.dangerous-eval",),
        ("exact-frozen-claim-overlap", "dangerous-api-persists-after-fix"),
    ),
    "CVE-2024-3568": CaseSpec(
        CLAIM_APPLICABLE,
        (
            RegionSpec(
                "src/transformers/modeling_tf_utils.py",
                "TFPreTrainedModel.load_repo_checkpoint",
            ),
        ),
        (RegionSpec("src/transformers/modeling_tf_utils.py"),),
        ("securescan.python.unsafe-pickle-load",),
        ("exact-frozen-claim-overlap", "dangerous-api-removed-by-fix"),
    ),
    "CVE-2024-7009": CaseSpec(
        OUTSIDE_FROZEN_RULE_CLAIMS,
        (
            RegionSpec(
                "src/calibre/db/backend.py",
                "DB.search_annotations",
                call_attribute="execute",
                first_arg_name="query",
            ),
            RegionSpec(
                "src/calibre/db/fts/connect.py",
                "FTS.search",
                call_attribute="execute",
                first_arg_name="query",
            ),
            RegionSpec(
                "src/calibre/db/notes/connect.py",
                "Notes.search",
                call_attribute="execute",
                first_arg_name="query",
            ),
        ),
        (
            RegionSpec(
                "src/calibre/db/backend.py",
                "DB.search_annotations",
                call_attribute="execute",
                first_arg_name="query",
            ),
            RegionSpec(
                "src/calibre/db/fts/connect.py",
                "FTS.search",
                call_attribute="execute",
                first_arg_name="query",
            ),
            RegionSpec(
                "src/calibre/db/notes/connect.py",
                "Notes.search",
                call_attribute="execute",
                first_arg_name="query",
            ),
        ),
        (),
        ("same-cwe-unsupported-pattern", "different-interpolation-shape"),
    ),
}


def _qualified_nodes(tree: ast.AST) -> dict[str, list[ast.AST]]:
    result: dict[str, list[ast.AST]] = {}

    def visit(node: ast.AST, parents: tuple[str, ...]) -> None:
        nested_parents = parents
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            qualified = ".".join((*parents, node.name))
            result.setdefault(qualified, []).append(node)
            nested_parents = (*parents, node.name)
        for child in ast.iter_child_nodes(node):
            visit(child, nested_parents)

    visit(tree, ())
    return result


def _literal_bool(node: ast.AST | None, expected: bool) -> bool:
    return isinstance(node, ast.Constant) and node.value is expected


def _keyword(call: ast.Call, name: str) -> ast.AST | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


def _imports(tree: ast.AST) -> dict[str, str]:
    result: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                result[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                result[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return result


def _bound_names(region: ast.AST) -> set[str]:
    names: set[str] = set()
    if isinstance(region, (ast.FunctionDef, ast.AsyncFunctionDef)):
        arguments = (*region.args.posonlyargs, *region.args.args, *region.args.kwonlyargs)
        names.update(item.arg for item in arguments)
        if region.args.vararg:
            names.add(region.args.vararg.arg)
        if region.args.kwarg:
            names.add(region.args.kwarg.arg)
    for node in ast.walk(region):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            names.add(node.id)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node is not region
        ):
            names.add(node.name)
    return names


def _semantic_name(node: ast.AST, imports: dict[str, str], bound: set[str]) -> str | None:
    if isinstance(node, ast.Name):
        if node.id in bound:
            return None
        return imports.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = _semantic_name(node.value, imports, bound)
        if parent:
            return f"{parent}.{node.attr}"
    return None


def _literal_loader_name(node: ast.AST, imports: dict[str, str], bound: set[str]) -> str | None:
    value = _semantic_name(node, imports, bound)
    if value is None:
        return None
    return value.rsplit(".", maxsplit=1)[-1]


def _session_and_app_identities(region: ast.AST, imports: dict[str, str]) -> dict[str, str]:
    result: dict[str, str] = {}
    bound = _bound_names(region)
    for node in ast.walk(region):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not isinstance(value, ast.Call):
            continue
        semantic = _semantic_name(value.func, imports, bound)
        identity = {
            "requests.Session": "requests-session",
            "paramiko.SSHClient": "paramiko-client",
            "flask.Flask": "flask-app",
        }.get(str(semantic))
        if identity:
            for target in targets:
                if isinstance(target, ast.Name):
                    result[target.id] = identity
    return result


def classify_frozen_claims(source: str, region: ast.AST | None = None) -> set[str]:
    """Classify only the frozen human-readable claims using Python AST semantics."""
    tree = ast.parse(source)
    region = region or tree
    imports = _imports(tree)
    bound = _bound_names(region)
    identities = _session_and_app_identities(region, imports)
    found: set[str] = set()
    for node in ast.walk(region):
        if isinstance(node, ast.Call):
            semantic = _semantic_name(node.func, imports, bound)
            if (
                semantic in {"eval", "exec"}
                and node.args
                and not isinstance(node.args[0], ast.Constant)
            ):
                found.add(f"securescan.python.dangerous-{semantic}")
            direct_calls = {
                "os.system": "securescan.python.os-system",
                "os.popen": "securescan.python.os-popen",
                "pickle.load": "securescan.python.unsafe-pickle-load",
                "pickle.loads": "securescan.python.unsafe-pickle-load",
                "tempfile.mktemp": "securescan.python.insecure-tempfile-mktemp",
                "ssl._create_unverified_context": "securescan.python.ssl-unverified-context",
            }
            if semantic in direct_calls:
                found.add(direct_calls[semantic])
            if semantic in {
                "subprocess.run",
                "subprocess.Popen",
                "subprocess.check_output",
            } and _literal_bool(_keyword(node, "shell"), True):
                found.add("securescan.python.subprocess-shell-true")
            if semantic == "yaml.unsafe_load":
                found.add("securescan.python.unsafe-yaml-load")
            if semantic == "yaml.load":
                loader = _keyword(node, "Loader")
                if loader is None and len(node.args) > 1:
                    loader = node.args[1]
                if loader is not None and _literal_loader_name(loader, imports, bound) in {
                    "Loader",
                    "UnsafeLoader",
                    "CLoader",
                }:
                    found.add("securescan.python.unsafe-yaml-load")
            if semantic in {
                "requests.get",
                "requests.post",
                "requests.request",
            } and _literal_bool(_keyword(node, "verify"), False):
                found.add("securescan.python.requests-verify-false")
            if isinstance(node.func, ast.Attribute) and node.func.attr == "run":
                receiver = node.func.value
                if (
                    isinstance(receiver, ast.Name)
                    and identities.get(receiver.id) == "flask-app"
                    and _literal_bool(_keyword(node, "debug"), True)
                ):
                    found.add("securescan.python.flask-debug-enabled")
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "set_missing_host_key_policy"
            ):
                receiver = node.func.value
                policy = node.args[0] if node.args else None
                if isinstance(policy, ast.Call):
                    policy = policy.func
                if (
                    isinstance(receiver, ast.Name)
                    and identities.get(receiver.id) == "paramiko-client"
                    and policy is not None
                    and _semantic_name(policy, imports, bound) == "paramiko.AutoAddPolicy"
                ):
                    found.add("securescan.python.paramiko-autoaddpolicy")
            if semantic == "jinja2.Environment" and _literal_bool(
                _keyword(node, "autoescape"), False
            ):
                found.add("securescan.python.jinja-autoescape-disabled")
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "execute"
                and node.args
                and isinstance(node.args[0], ast.JoinedStr)
            ):
                found.add("securescan.python.sql-fstring-execute")
            if semantic in {"jwt.decode", "PyJWT.decode"}:
                options = _keyword(node, "options")
                if isinstance(options, ast.Dict) and any(
                    isinstance(key, ast.Constant)
                    and key.value == "verify_signature"
                    and _literal_bool(value, False)
                    for key, value in zip(options.keys, options.values, strict=True)
                ):
                    found.add("securescan.python.jwt-signature-verification-disabled")
            if semantic == "lxml.etree.XMLParser" and _literal_bool(
                _keyword(node, "resolve_entities"), True
            ):
                found.add("securescan.python.lxml-resolve-entities")
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if not _literal_bool(value, False):
                continue
            for target in targets:
                if (
                    isinstance(target, ast.Attribute)
                    and target.attr == "verify"
                    and isinstance(target.value, ast.Name)
                    and identities.get(target.value.id) == "requests-session"
                ):
                    found.add("securescan.python.requests-session-verify-false")
    return found


def _baseline_commit(repository_root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", f"{BASELINE_TAG}^{{commit}}"],
            cwd=repository_root,
            check=True,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError("required F2E1 baseline tag is unavailable") from exc
    return result.stdout.strip()


def _source_hash(case: dict[str, object], role: str, path: str) -> str:
    snapshot = case.get(f"{role}_source")
    if not isinstance(snapshot, dict):
        raise ValueError("frozen source snapshot is invalid")
    files = snapshot.get("per_file_sha256")
    if not isinstance(files, list):
        raise ValueError("frozen per-file identities are invalid")
    matches = [
        item.get("sha256") for item in files if isinstance(item, dict) and item.get("path") == path
    ]
    if len(matches) != 1 or not isinstance(matches[0], str):
        raise ValueError("evidence path is outside the frozen relevant path set")
    return matches[0]


def _region(
    case: dict[str, object],
    role: str,
    spec: RegionSpec,
    repository: Path,
) -> tuple[dict[str, object], set[str]]:
    revision = case.get(f"{role}_revision")
    snapshot = case.get(f"{role}_source")
    if not isinstance(revision, str) or not isinstance(snapshot, dict):
        raise ValueError("frozen revision evidence is invalid")
    if snapshot.get("revision") != revision:
        raise ValueError("revision role does not match the frozen source snapshot")
    raw = _blob(repository, revision, spec.path, offline=True)
    expected_hash = _source_hash(case, role, spec.path)
    if hashlib.sha256(raw).hexdigest() != expected_hash:
        raise ValueError("evidence source hash does not match F2E1")
    try:
        source = raw.decode("utf-8")
        tree = ast.parse(source)
    except (UnicodeError, SyntaxError) as exc:
        raise ValueError("bounded evidence source is not valid UTF-8 Python") from exc
    lines = source.splitlines()
    if not lines:
        raise ValueError("bounded evidence source is empty")
    node: ast.AST = tree
    symbol = spec.qualified_symbol
    region_kind = "bounded-relevant-file-absence"
    if symbol is not None:
        matches = _qualified_nodes(tree).get(symbol, [])
        if spec.occurrence >= len(matches):
            raise ValueError(f"frozen evidence symbol is missing: {symbol}")
        node = matches[spec.occurrence]
        region_kind = "cve-relevant-symbol"
    if spec.call_attribute is not None:
        call_matches = [
            candidate
            for candidate in ast.walk(node)
            if isinstance(candidate, ast.Call)
            and isinstance(candidate.func, ast.Attribute)
            and candidate.func.attr == spec.call_attribute
            and candidate.args
            and isinstance(candidate.args[0], ast.Name)
            and candidate.args[0].id == spec.first_arg_name
        ]
        if len(call_matches) != 1:
            raise ValueError("CVE-relevant call evidence is missing or ambiguous")
        node = call_matches[0]
        region_kind = "cve-relevant-call"
    start = getattr(node, "lineno", 1)
    end = getattr(node, "end_lineno", len(lines))
    if (
        not isinstance(start, int)
        or not isinstance(end, int)
        or not (1 <= start <= end <= len(lines))
    ):
        raise ValueError("evidence line range is invalid")
    evidence = {
        "end_line": end,
        "region_kind": region_kind,
        "relative_source_path": spec.path,
        "revision_role": role,
        "source_sha256": expected_hash,
        "start_line": start,
        "symbol_name": symbol,
    }
    return evidence, classify_frozen_claims(source, node)


def _validate_inputs(repository_root: Path) -> tuple[dict[str, object], dict[str, object]]:
    if _baseline_commit(repository_root) != BASELINE_COMMIT:
        raise ValueError("required F2E1 baseline tag resolves to the wrong commit")
    benchmark_root = repository_root / "benchmarks/python_sast_realworld"
    cache_root = repository_root / ".cache/securescan-realworld-python"
    f2e1_summary = verify_realworld_cases(benchmark_root, cache_root)
    if f2e1_summary.get("source_lock_digest") != SOURCE_LOCK_DIGEST:
        raise ValueError("F2E1 source-lock digest is not frozen")
    accepted = load_json(benchmark_root / "accepted-cases.json")
    if accepted_case_set_digest(accepted) != ACCEPTED_CASE_SET_DIGEST:
        raise ValueError("F2E1 accepted-case-set digest is not frozen")
    if accepted.get("accepted_case_set_digest") != ACCEPTED_CASE_SET_DIGEST:
        raise ValueError("F2E1 accepted-case-set identity is invalid")
    claim_catalog = load_json(repository_root / "benchmarks/python_sast_external/rule-claims.json")
    if digest(claim_catalog) != RULE_CLAIM_CATALOG_DIGEST:
        raise ValueError("frozen rule-claim catalog digest is invalid")
    rules = claim_catalog.get("rules")
    if (
        not isinstance(rules, list)
        or tuple(item.get("rule_id") for item in rules if isinstance(item, dict)) != RULE_IDS
    ):
        raise ValueError("frozen rule-claim catalog membership or order is invalid")
    return accepted, claim_catalog


def build_documents(
    repository_root: Path,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    accepted, _claim_catalog = _validate_inputs(repository_root)
    raw_cases = accepted.get("cases")
    if not isinstance(raw_cases, list) or len(raw_cases) != 13:
        raise ValueError("F2E1 accepted case count is not frozen")
    cve_ids = [case.get("cve_id") for case in raw_cases if isinstance(case, dict)]
    if cve_ids != sorted(_SPECS) or set(cve_ids) != set(_SPECS):
        raise ValueError("F2E1 accepted case set is not exact")
    cache_root = repository_root / ".cache/securescan-realworld-python/repositories"
    decisions: list[dict[str, object]] = []
    for case in raw_cases:
        if not isinstance(case, dict):
            raise ValueError("F2E1 accepted case is invalid")
        cve = str(case["cve_id"])
        spec = _SPECS[cve]
        repository_id = case.get("repository_id")
        if not isinstance(repository_id, str):
            raise ValueError("F2E1 repository identity is invalid")
        repository = cache_root / repository_id
        evidence: dict[str, list[dict[str, object]]] = {"fixed": [], "vulnerable": []}
        observed: dict[str, set[str]] = {"fixed": set(), "vulnerable": set()}
        for role, region_specs in (
            ("vulnerable", spec.vulnerable_regions),
            ("fixed", spec.fixed_regions),
        ):
            for region_spec in region_specs:
                item, claims = _region(case, role, region_spec, repository)
                evidence[role].append(item)
                observed[role].update(claims)
        if spec.disposition == CLAIM_APPLICABLE:
            if set(spec.rule_ids) - observed["vulnerable"]:
                raise ValueError(f"applicable vulnerable claim is not present: {cve}")
            unrelated = (observed["vulnerable"] | observed["fixed"]) - set(spec.rule_ids)
            if unrelated:
                raise ValueError(f"unreviewed claim occurs in a CVE evidence region: {cve}")
        elif observed["vulnerable"] or observed["fixed"]:
            raise ValueError(f"outside case contains an exact frozen claim overlap: {cve}")
        relations = []
        for rule_id in spec.rule_ids:
            vulnerable_match = rule_id in observed["vulnerable"]
            fixed_match = rule_id in observed["fixed"]
            if not vulnerable_match:
                raise ValueError(
                    "a CVE-applicable relation requires vulnerable expected_match true"
                )
            discrimination = (
                SHOULD_DISCRIMINATE if not fixed_match else NOT_EXPECTED_TO_DISCRIMINATE
            )
            relations.append(
                {
                    "discrimination_expectation": discrimination,
                    "fixed": {
                        "evidence_regions": evidence["fixed"],
                        "expected_match": fixed_match,
                    },
                    "reason_codes": list(spec.reason_codes),
                    "rule_id": rule_id,
                    "vulnerable": {
                        "evidence_regions": evidence["vulnerable"],
                        "expected_match": vulnerable_match,
                    },
                }
            )
        decisions.append(
            {
                "applicable_rule_ids": list(spec.rule_ids),
                "case_disposition": spec.disposition,
                "case_family_id": case["case_family_id"],
                "case_id": case["immutable_case_id"],
                "cve_id": cve,
                "cwe_ids": case["cwe_ids"],
                "evidence": evidence,
                "project": repository_id,
                "reason_codes": list(spec.reason_codes),
                "relations": relations,
                "review_state": REVIEW_STATE,
            }
        )
    proposal = {
        "accepted_case_set_digest": ACCEPTED_CASE_SET_DIGEST,
        "baseline_commit": BASELINE_COMMIT,
        "baseline_tag": BASELINE_TAG,
        "case_count": len(decisions),
        "cases": decisions,
        "rule_claim_catalog_digest": RULE_CLAIM_CATALOG_DIGEST,
        "schema_version": SCHEMA_VERSION,
        "scientific_boundary": {
            "applicability_only": True,
            "human_approval": "pending",
            "metrics": "not-calculated",
            "scanner_execution": "forbidden",
        },
        "source_lock_digest": SOURCE_LOCK_DIGEST,
    }
    summary = build_summary(proposal)
    review = build_review(proposal)
    return proposal, summary, review


def build_summary(proposal: dict[str, object]) -> dict[str, object]:
    cases = proposal["cases"]
    assert isinstance(cases, list)
    dispositions = Counter(str(case["case_disposition"]) for case in cases)
    applicable = [case for case in cases if case["case_disposition"] == CLAIM_APPLICABLE]
    relations = [relation for case in applicable for relation in case["relations"]]
    by_rule = Counter(str(relation["rule_id"]) for relation in relations)
    by_cwe = Counter(str(cwe) for case in applicable for cwe in case["cwe_ids"])
    by_project = Counter(str(case["project"]) for case in applicable)
    by_family = Counter(str(case["case_family_id"]) for case in applicable)
    discrimination = Counter(str(item["discrimination_expectation"]) for item in relations)
    represented = sorted(by_rule)
    return {
        "accepted_case_set_digest": ACCEPTED_CASE_SET_DIGEST,
        "accepted_cve_count": len(cases),
        "applicable_relation_count": len(relations),
        "applicable_unique_case_family_count": len(by_family),
        "applicable_unique_project_count": len(by_project),
        "case_disposition_counts": {
            CLAIM_APPLICABLE: dispositions[CLAIM_APPLICABLE],
            OUTSIDE_FROZEN_RULE_CLAIMS: dispositions[OUTSIDE_FROZEN_RULE_CLAIMS],
            UNRESOLVED: dispositions[UNRESOLVED],
        },
        "discrimination_expectation_counts": {
            SHOULD_DISCRIMINATE: discrimination[SHOULD_DISCRIMINATE],
            NOT_EXPECTED_TO_DISCRIMINATE: discrimination[NOT_EXPECTED_TO_DISCRIMINATE],
        },
        "relations_by_case_family": dict(sorted(by_family.items())),
        "relations_by_cwe": dict(sorted(by_cwe.items())),
        "relations_by_project": dict(sorted(by_project.items())),
        "relations_by_rule": dict(sorted(by_rule.items())),
        "rule_claim_catalog_digest": RULE_CLAIM_CATALOG_DIGEST,
        "rules_represented_by_real_world_cases": represented,
        "rules_without_real_world_applicable_cve": sorted(set(RULE_IDS) - set(represented)),
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "source_lock_digest": SOURCE_LOCK_DIGEST,
    }


def build_review(proposal: dict[str, object]) -> dict[str, object]:
    cases = proposal["cases"]
    assert isinstance(cases, list)
    return {
        "accepted_case_set_digest": ACCEPTED_CASE_SET_DIGEST,
        "case_count": len(cases),
        "cases": [
            {
                "applicable_rule_ids": case["applicable_rule_ids"],
                "case_disposition": case["case_disposition"],
                "case_family_id": case["case_family_id"],
                "cve_id": case["cve_id"],
                "cwe_ids": case["cwe_ids"],
                "discrimination_expectations": [
                    {
                        "discrimination_expectation": relation["discrimination_expectation"],
                        "rule_id": relation["rule_id"],
                    }
                    for relation in case["relations"]
                ],
                "fixed_evidence": case["evidence"]["fixed"],
                "project": case["project"],
                "reason_codes": case["reason_codes"],
                "review_state": case["review_state"],
                "vulnerable_evidence": case["evidence"]["vulnerable"],
            }
            for case in cases
        ],
        "rule_claim_catalog_digest": RULE_CLAIM_CATALOG_DIGEST,
        "schema_version": REVIEW_SCHEMA_VERSION,
        "source_lock_digest": SOURCE_LOCK_DIGEST,
    }


def write_documents(repository_root: Path) -> dict[str, str]:
    proposal, summary, review = build_documents(repository_root)
    output_root = repository_root / "benchmarks/python_sast_realworld"
    documents = {
        "applicability-proposal.json": proposal,
        "applicability-review.json": review,
        "applicability-summary.json": summary,
    }
    for name, document in documents.items():
        (output_root / name).write_bytes(canonical_document(document))
    return {
        name: hashlib.sha256(canonical_document(document)).hexdigest()
        for name, document in documents.items()
    }


def verify_documents(repository_root: Path) -> dict[str, str]:
    proposal, summary, review = build_documents(repository_root)
    output_root = repository_root / "benchmarks/python_sast_realworld"
    expected = {
        "applicability-proposal.json": proposal,
        "applicability-review.json": review,
        "applicability-summary.json": summary,
    }
    for name, document in expected.items():
        path = output_root / name
        if path.read_bytes() != canonical_document(document):
            raise ValueError(f"applicability evidence is stale or non-canonical: {name}")
    return {
        name: hashlib.sha256(canonical_document(document)).hexdigest()
        for name, document in expected.items()
    }


def canonical_stdout(value: object) -> str:
    return json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    )
