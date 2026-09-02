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
    load_json,
)
from securescan.benchmarks.python_sast_realworld import (
    verify as verify_realworld_cases,
)
from securescan.benchmarks.python_sast_rule_claim_contract_v2 import (
    PRODUCTION_RULESET_DIGEST,
    RULE_IDS,
    build_contract,
)

SCHEMA_VERSION: Final = "securescan-python-sast-realworld-applicability-v2"
SUMMARY_SCHEMA_VERSION: Final = "securescan-python-sast-realworld-applicability-summary-v2"
REVIEW_SCHEMA_VERSION: Final = "securescan-python-sast-realworld-applicability-review-v2"
F2E1_BASELINE_TAG: Final = "source-v0.3F2E1-python-sast-realworld-cases"
F2E1_BASELINE_COMMIT: Final = "8b0a6ca6ac2ae659723425f21aaafcbfe11ef5f2"
F2E2_BASELINE_TAG: Final = "source-v0.3F2E2-python-sast-realworld-applicability"
F2E2_BASELINE_COMMIT: Final = "e957afb582bf03d6b6ebc20ad018c7c49092f092"
SOURCE_LOCK_DIGEST: Final = "0bba4bbe5ce557f1382f61f9af3320adef5cc53ab386d1c63f4983d8cbf48a00"
ACCEPTED_CASE_SET_DIGEST: Final = "60d44ea9cf0f174e1488c5b8dbccde2804524fe4d3bfa31b9db0810e52332a92"
RULE_CLAIM_CONTRACT_DIGEST: Final = (
    "0e0d9a118a7567049ad26f046b0f097ba8390d74f05f2b721452683ee3c2e62d"
)
HISTORICAL_F2E2_FILE_SHA256: Final = {
    "applicability-proposal.json": (
        "35310583c35ccad335e6e99945b62a0a750026b45e66aabb49c52a803a8e0243"
    ),
    "applicability-review.json": "5341490a298090d02f4d171c9d2e892207a9d1d6dc44179390682583a3405627",
    "applicability-summary.json": (
        "f79db3de59cc3a0dad7d1615d540fd8717abe6b99cb876de9ff4b27e90abe189"
    ),
}
REVIEW_STATE: Final = "pending-human-approval"
CLAIM_APPLICABLE: Final = "CLAIM_APPLICABLE"
OUTSIDE_FROZEN_RULE_CLAIMS: Final = "OUTSIDE_FROZEN_RULE_CLAIMS"
UNRESOLVED: Final = "UNRESOLVED"
SHOULD_DISCRIMINATE: Final = "SHOULD_DISCRIMINATE"
NOT_EXPECTED_TO_DISCRIMINATE: Final = "NOT_EXPECTED_TO_DISCRIMINATE"


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
        CLAIM_APPLICABLE,
        (RegionSpec("yt_dlp/postprocessor/exec.py", "ExecPP.run"),),
        (RegionSpec("yt_dlp/postprocessor/exec.py", "ExecPP.run"),),
        ("securescan.python.subprocess-shell-true",),
        ("exact-corrected-claim-overlap", "literal-shell-true-removed-by-fix"),
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
                "src/transformers/modeling_tf_utils.py", "TFPreTrainedModel.load_repo_checkpoint"
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

_REVIEWED_DELTA_REASONS: Final = {
    (
        "CVE-2023-40581",
        OUTSIDE_FROZEN_RULE_CLAIMS,
        CLAIM_APPLICABLE,
        (),
        ("securescan.python.subprocess-shell-true",),
    ): (
        "corrected subprocess claim includes subprocess.call with shell=True; "
        "the fixed revision removes that frozen pattern"
    ),
}


def _qualified_nodes(tree: ast.AST) -> dict[str, list[ast.AST]]:
    result: dict[str, list[ast.AST]] = {}

    def visit(node: ast.AST, parents: tuple[str, ...]) -> None:
        nested = parents
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            qualified = ".".join((*parents, node.name))
            result.setdefault(qualified, []).append(node)
            nested = (*parents, node.name)
        for child in ast.iter_child_nodes(node):
            visit(child, nested)

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


def _surface_name(node: ast.AST, imports: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return imports.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = _surface_name(node.value, imports)
        if parent:
            return f"{parent}.{node.attr}"
    return None


_LEXICAL_SCOPE_NODES: Final = (
    ast.Module,
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.Lambda,
    ast.ClassDef,
)


def _lexical_scope_chains(region: ast.AST) -> dict[int, tuple[int, ...]]:
    result: dict[int, tuple[int, ...]] = {}

    def visit(node: ast.AST, scopes: tuple[int, ...]) -> None:
        nested = (*scopes, id(node)) if isinstance(node, _LEXICAL_SCOPE_NODES) else scopes
        result[id(node)] = nested
        for child in ast.iter_child_nodes(node):
            visit(child, nested)

    visit(region, ())
    return result


def _assigned_constructors(
    region: ast.AST,
    imports: dict[str, str],
    scope_chains: dict[int, tuple[int, ...]],
) -> dict[tuple[str, str], list[tuple[int, tuple[int, ...]]]]:
    result: dict[tuple[str, str], list[tuple[int, tuple[int, ...]]]] = {}
    for node in ast.walk(region):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or not isinstance(
            node.value, ast.Call
        ):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        semantic = _surface_name(node.value.func, imports)
        identity = {
            "requests.Session": "requests-session",
            "flask.Flask": "flask-app",
            "Flask": "flask-app",
        }.get(str(semantic))
        if identity:
            for target in targets:
                if isinstance(target, ast.Name):
                    result.setdefault((target.id, identity), []).append(
                        (node.lineno, scope_chains[id(node)])
                    )
    return result


def _assigned_before(
    assignments: dict[tuple[str, str], list[tuple[int, tuple[int, ...]]]],
    name: str,
    identity: str,
    line: int,
    use_scope: tuple[int, ...],
    *,
    allow_ancestor_scope: bool,
) -> bool:
    return any(
        candidate_line < line
        and (
            candidate_scope == use_scope
            or (
                allow_ancestor_scope
                and len(candidate_scope) <= len(use_scope)
                and use_scope[: len(candidate_scope)] == candidate_scope
            )
        )
        for candidate_line, candidate_scope in assignments.get((name, identity), [])
    )


def classify_claim_contract_v2(source: str, region: ast.AST | None = None) -> set[str]:
    """Classify the frozen production surface without claiming runtime binding identity."""
    tree = ast.parse(source)
    region = region or tree
    imports = _imports(tree)
    scope_chains = _lexical_scope_chains(region)
    assignments = _assigned_constructors(region, imports, scope_chains)
    found: set[str] = set()
    for node in ast.walk(region):
        if isinstance(node, ast.Call):
            semantic = _surface_name(node.func, imports)
            if (
                semantic in {"eval", "exec"}
                and node.args
                and not (
                    isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)
                )
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
                "subprocess.call",
                "subprocess.check_call",
                "subprocess.check_output",
                "subprocess.Popen",
            } and _literal_bool(_keyword(node, "shell"), True):
                found.add("securescan.python.subprocess-shell-true")
            if semantic == "yaml.unsafe_load":
                found.add("securescan.python.unsafe-yaml-load")
            if semantic == "yaml.load":
                loader = _keyword(node, "Loader")
                if loader is None and len(node.args) > 1:
                    loader = node.args[1]
                loader_name = _surface_name(loader, imports) if loader is not None else None
                if loader_name in {
                    "yaml.Loader",
                    "yaml.UnsafeLoader",
                    "yaml.CLoader",
                }:
                    found.add("securescan.python.unsafe-yaml-load")
            if semantic in {
                "requests.request",
                "requests.get",
                "requests.options",
                "requests.head",
                "requests.post",
                "requests.put",
                "requests.patch",
                "requests.delete",
            } and _literal_bool(_keyword(node, "verify"), False):
                found.add("securescan.python.requests-verify-false")
            if isinstance(node.func, ast.Attribute) and node.func.attr == "run":
                receiver = node.func.value
                if (
                    isinstance(receiver, ast.Name)
                    and _assigned_before(
                        assignments,
                        receiver.id,
                        "flask-app",
                        node.lineno,
                        scope_chains[id(node)],
                        allow_ancestor_scope=True,
                    )
                    and _literal_bool(_keyword(node, "debug"), True)
                ):
                    found.add("securescan.python.flask-debug-enabled")
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "set_missing_host_key_policy"
            ):
                policy = node.args[0] if node.args else None
                if isinstance(policy, ast.Call):
                    policy = policy.func
                if (
                    policy is not None
                    and _surface_name(policy, imports) == "paramiko.AutoAddPolicy"
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
            if semantic == "jwt.decode":
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
            if not _literal_bool(node.value, False):
                continue
            for target in targets:
                if (
                    isinstance(target, ast.Attribute)
                    and target.attr == "verify"
                    and isinstance(target.value, ast.Name)
                    and _assigned_before(
                        assignments,
                        target.value.id,
                        "requests-session",
                        node.lineno,
                        scope_chains[id(node)],
                        allow_ancestor_scope=False,
                    )
                ):
                    found.add("securescan.python.requests-session-verify-false")
    return found


def _tag_commit(repository_root: Path, tag: str) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", f"{tag}^{{commit}}"],
            cwd=repository_root,
            check=True,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError(f"required baseline tag is unavailable: {tag}") from exc
    return result.stdout.strip()


def _source_hash(case: dict[str, object], role: str, path: str) -> str:
    snapshot = case.get(f"{role}_source")
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("per_file_sha256"), list):
        raise ValueError("frozen source snapshot is invalid")
    matches = [
        item.get("sha256")
        for item in snapshot["per_file_sha256"]
        if isinstance(item, dict) and item.get("path") == path
    ]
    if len(matches) != 1 or not isinstance(matches[0], str):
        raise ValueError("evidence path is outside the frozen relevant path set")
    return matches[0]


def _region(
    case: dict[str, object], role: str, spec: RegionSpec, repository: Path
) -> tuple[dict[str, object], set[str]]:
    revision = case.get(f"{role}_revision")
    snapshot = case.get(f"{role}_source")
    if (
        not isinstance(revision, str)
        or not isinstance(snapshot, dict)
        or snapshot.get("revision") != revision
    ):
        raise ValueError("frozen revision evidence is invalid")
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
    region_kind = "bounded-relevant-file-absence"
    if spec.qualified_symbol is not None:
        matches = _qualified_nodes(tree).get(spec.qualified_symbol, [])
        if spec.occurrence >= len(matches):
            raise ValueError(f"frozen evidence symbol is missing: {spec.qualified_symbol}")
        node = matches[spec.occurrence]
        region_kind = "cve-relevant-symbol"
    if spec.call_attribute is not None:
        calls = [
            candidate
            for candidate in ast.walk(node)
            if isinstance(candidate, ast.Call)
            and isinstance(candidate.func, ast.Attribute)
            and candidate.func.attr == spec.call_attribute
            and candidate.args
            and isinstance(candidate.args[0], ast.Name)
            and candidate.args[0].id == spec.first_arg_name
        ]
        if len(calls) != 1:
            raise ValueError("CVE-relevant call evidence is missing or ambiguous")
        node = calls[0]
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
        "symbol_name": spec.qualified_symbol,
    }
    return evidence, classify_claim_contract_v2(source, node)


def _verify_historical_f2e2(repository_root: Path) -> dict[str, object]:
    root = repository_root / "benchmarks/python_sast_realworld"
    for name, expected in HISTORICAL_F2E2_FILE_SHA256.items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != expected:
            raise ValueError(f"historical F2E2 artifact changed: {name}")
    return load_json(root / "applicability-proposal.json")


def _validate_inputs(repository_root: Path) -> tuple[dict[str, object], dict[str, object]]:
    if _tag_commit(repository_root, F2E1_BASELINE_TAG) != F2E1_BASELINE_COMMIT:
        raise ValueError("required F2E1 baseline tag resolves to the wrong commit")
    if _tag_commit(repository_root, F2E2_BASELINE_TAG) != F2E2_BASELINE_COMMIT:
        raise ValueError("required F2E2 baseline tag resolves to the wrong commit")
    benchmark_root = repository_root / "benchmarks/python_sast_realworld"
    f2e1_summary = verify_realworld_cases(
        benchmark_root, repository_root / ".cache/securescan-realworld-python"
    )
    if f2e1_summary.get("source_lock_digest") != SOURCE_LOCK_DIGEST:
        raise ValueError("F2E1 source-lock digest is not frozen")
    accepted = load_json(benchmark_root / "accepted-cases.json")
    if (
        accepted_case_set_digest(accepted) != ACCEPTED_CASE_SET_DIGEST
        or accepted.get("accepted_case_set_digest") != ACCEPTED_CASE_SET_DIGEST
    ):
        raise ValueError("F2E1 accepted-case-set identity is invalid")
    contract = build_contract(repository_root)
    if contract.get("contract_digest") != RULE_CLAIM_CONTRACT_DIGEST:
        raise ValueError("rule-claim v2 contract identity is invalid")
    recorded_contract = load_json(
        repository_root / "benchmarks/python_sast_external/rule-claims-v2.json"
    )
    if recorded_contract != contract:
        raise ValueError("recorded rule-claim v2 contract is stale")
    return accepted, _verify_historical_f2e2(repository_root)


def build_documents(
    repository_root: Path,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    accepted, historical_proposal = _validate_inputs(repository_root)
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
            raise ValueError(f"outside case contains an exact corrected claim overlap: {cve}")
        relations: list[dict[str, object]] = []
        for rule_id in spec.rule_ids:
            vulnerable_match = rule_id in observed["vulnerable"]
            fixed_match = rule_id in observed["fixed"]
            if not vulnerable_match:
                raise ValueError(
                    "a CVE-applicable relation requires vulnerable expected_match true"
                )
            relations.append(
                {
                    "discrimination_expectation": SHOULD_DISCRIMINATE
                    if not fixed_match
                    else NOT_EXPECTED_TO_DISCRIMINATE,
                    "fixed": {"evidence_regions": evidence["fixed"], "expected_match": fixed_match},
                    "reason_codes": list(spec.reason_codes),
                    "rule_id": rule_id,
                    "vulnerable": {
                        "evidence_regions": evidence["vulnerable"],
                        "expected_match": True,
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
        "baseline_commits": {"F2E1": F2E1_BASELINE_COMMIT, "F2E2": F2E2_BASELINE_COMMIT},
        "baseline_tags": {"F2E1": F2E1_BASELINE_TAG, "F2E2": F2E2_BASELINE_TAG},
        "case_count": len(decisions),
        "cases": decisions,
        "production_ruleset_digest": PRODUCTION_RULESET_DIGEST,
        "rule_claim_contract_digest": RULE_CLAIM_CONTRACT_DIGEST,
        "schema_version": SCHEMA_VERSION,
        "scientific_boundary": {
            "applicability_only": True,
            "human_approval": "pending",
            "metrics": "not-calculated",
            "scanner_execution": "forbidden",
            "source_inspection": "bounded-frozen-git-blobs-only",
        },
        "source_lock_digest": SOURCE_LOCK_DIGEST,
    }
    return proposal, build_summary(proposal, historical_proposal), build_review(proposal)


def _changed_cases(
    proposal: dict[str, object], historical_proposal: dict[str, object]
) -> list[dict[str, object]]:
    current = {str(item["cve_id"]): item for item in proposal["cases"]}  # type: ignore[index]
    historical = {str(item["cve_id"]): item for item in historical_proposal["cases"]}  # type: ignore[index]
    changes = []
    for cve in sorted(current):
        old = historical[cve]
        new = current[cve]
        if (
            old["case_disposition"] == new["case_disposition"]
            and old["applicable_rule_ids"] == new["applicable_rule_ids"]
        ):
            continue
        old_rules = tuple(str(item) for item in old["applicable_rule_ids"])
        new_rules = tuple(str(item) for item in new["applicable_rule_ids"])
        delta_identity = (
            cve,
            str(old["case_disposition"]),
            str(new["case_disposition"]),
            old_rules,
            new_rules,
        )
        reason = _REVIEWED_DELTA_REASONS.get(delta_identity)
        if reason is None:
            raise ValueError(f"unreviewed v1-to-v2 applicability delta: {cve}")
        changes.append(
            {
                "cve_id": cve,
                "new_disposition": new["case_disposition"],
                "new_rule_ids": new["applicable_rule_ids"],
                "old_disposition": old["case_disposition"],
                "old_rule_ids": old["applicable_rule_ids"],
                "reason": reason,
            }
        )
    return changes


def build_summary(
    proposal: dict[str, object], historical_proposal: dict[str, object]
) -> dict[str, object]:
    cases = proposal["cases"]
    assert isinstance(cases, list)
    dispositions = Counter(str(case["case_disposition"]) for case in cases)
    applicable = [case for case in cases if case["case_disposition"] == CLAIM_APPLICABLE]
    relations = [relation for case in applicable for relation in case["relations"]]
    by_rule = Counter(str(item["rule_id"]) for item in relations)
    by_cwe = Counter(str(cwe) for case in applicable for cwe in case["cwe_ids"])
    by_project = Counter(str(case["project"]) for case in applicable)
    by_family = Counter(str(case["case_family_id"]) for case in applicable)
    discrimination = Counter(str(item["discrimination_expectation"]) for item in relations)
    changes = _changed_cases(proposal, historical_proposal)
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
        "changed_case_count": len(changes),
        "changed_cases": changes,
        "discrimination_expectation_counts": {
            SHOULD_DISCRIMINATE: discrimination[SHOULD_DISCRIMINATE],
            NOT_EXPECTED_TO_DISCRIMINATE: discrimination[NOT_EXPECTED_TO_DISCRIMINATE],
        },
        "relations_by_case_family": dict(sorted(by_family.items())),
        "relations_by_cwe": dict(sorted(by_cwe.items())),
        "relations_by_project": dict(sorted(by_project.items())),
        "relations_by_rule": dict(sorted(by_rule.items())),
        "rule_claim_contract_digest": RULE_CLAIM_CONTRACT_DIGEST,
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
        "rule_claim_contract_digest": RULE_CLAIM_CONTRACT_DIGEST,
        "schema_version": REVIEW_SCHEMA_VERSION,
        "source_lock_digest": SOURCE_LOCK_DIGEST,
    }


def write_documents(repository_root: Path) -> dict[str, str]:
    proposal, summary, review = build_documents(repository_root)
    output_root = repository_root / "benchmarks/python_sast_realworld"
    documents = {
        "applicability-proposal-v2.json": proposal,
        "applicability-review-v2.json": review,
        "applicability-summary-v2.json": summary,
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
        "applicability-proposal-v2.json": proposal,
        "applicability-review-v2.json": review,
        "applicability-summary-v2.json": summary,
    }
    for name, document in expected.items():
        if (output_root / name).read_bytes() != canonical_document(document):
            raise ValueError(f"applicability v2 evidence is stale or non-canonical: {name}")
    return {
        name: hashlib.sha256(canonical_document(document)).hexdigest()
        for name, document in expected.items()
    }


def canonical_stdout(value: object) -> str:
    return json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    )
