from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import subprocess
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final
from urllib.parse import urlparse

DISCOVERY_SCHEMA_VERSION: Final = "securescan-python-sast-realworld-discovery-v1"
LEDGER_SCHEMA_VERSION: Final = "securescan-python-sast-realworld-ledger-v1"
ACCEPTED_SCHEMA_VERSION: Final = "securescan-python-sast-realworld-cases-v1"
SUMMARY_SCHEMA_VERSION: Final = "securescan-python-sast-realworld-summary-v1"
PYSASTBENCH_SOURCE_ID: Final = "pysastbench-realworld-index"
PYSASTBENCH_ALLOWED_COLUMNS: Final = (
    "CVE",
    "CWE Type",
    "Type",
    "vul position",
    "project",
    "Project Type",
    "Version",
)
PYSASTBENCH_FORBIDDEN_COLUMNS: Final = (
    "Bearer_reason",
    "DevSkim_reason",
    "Dlint_reason",
    "Bandit_reason",
    "Semgrep_reason",
    "Codeql_reason",
    "Pysa_reason",
)
SELECTION_STATES: Final = frozenset(
    {
        "ACCEPTED_FOR_APPLICABILITY_REVIEW",
        "DEFER_NO_VERIFIED_FIX",
        "DEFER_AMBIGUOUS_REVISION",
        "DEFER_LICENSE_UNCLEAR",
        "DEFER_REPOSITORY_UNAVAILABLE",
        "DEFER_NON_PYTHON_FIX",
        "DEFER_INSUFFICIENT_GROUND_TRUTH",
        "OUTSIDE_FROZEN_CWE_CANDIDATE_FAMILIES",
    }
)
FORBIDDEN_EVIDENCE_KEYS: Final = frozenset(
    {
        "expected_match",
        "expected_rule_id",
        "f1",
        "fn",
        "fp",
        "precision",
        "recall",
        "scanner_findings",
        "tn",
        "tp",
    }
)

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}\Z", re.ASCII)
_CVE_SEARCH_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.ASCII)
_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_REPOSITORY_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z", re.ASCII)


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_document(value: object) -> bytes:
    return (
        json.dumps(value, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant: {value}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"invalid canonical evidence: {path.name}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"invalid canonical evidence: {path.name}")
    if path.read_bytes() != canonical_document(value):
        raise ValueError(f"non-canonical evidence: {path.name}")
    return value


def _valid_relative_python_path(value: object) -> bool:
    if not isinstance(value, str) or not value.endswith(".py") or "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and path.as_posix() == value
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _valid_repository_url(value: object) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlparse(value)
    return (
        parsed.scheme == "https"
        and parsed.hostname == "github.com"
        and parsed.username is None
        and parsed.password is None
        and parsed.query == ""
        and parsed.fragment == ""
        and parsed.path.endswith(".git")
        and len(PurePosixPath(parsed.path).parts) == 3
    )


@dataclass(frozen=True, slots=True)
class PySASTBenchDiscovery:
    cve: str
    cwe_type: str
    vulnerability_type: str
    vulnerable_position: str
    project: str
    project_type: str
    version: str

    def canonical_data(self) -> dict[str, str]:
        return {
            "cve": self.cve,
            "cwe_type": self.cwe_type,
            "project": self.project,
            "project_type": self.project_type,
            "version": self.version,
            "vulnerability_type": self.vulnerability_type,
            "vulnerable_position": self.vulnerable_position,
        }


def parse_pysastbench_discovery_csv(content: bytes) -> tuple[PySASTBenchDiscovery, ...]:
    """Parse only the seven discovery columns into the selection model."""
    try:
        reader = csv.reader(io.StringIO(content.decode("utf-8-sig"), newline=""))
        header = next(reader)
        indexes = tuple(header.index(column) for column in PYSASTBENCH_ALLOWED_COLUMNS)
    except (UnicodeError, ValueError, StopIteration) as exc:
        raise ValueError("PySASTBench discovery CSV is invalid") from exc
    discoveries: list[PySASTBenchDiscovery] = []
    seen: set[str] = set()
    for raw_row in reader:
        if not raw_row or all(not item for item in raw_row):
            continue
        if max(indexes) >= len(raw_row):
            raise ValueError("PySASTBench discovery CSV row is invalid")
        selected = tuple(raw_row[index] for index in indexes)
        match = _CVE_SEARCH_PATTERN.search(selected[0])
        if match is None:
            raise ValueError("PySASTBench discovery CVE is invalid")
        cve = match.group(0)
        if cve in seen:
            raise ValueError("duplicate PySASTBench discovery CVE")
        seen.add(cve)
        discoveries.append(
            PySASTBenchDiscovery(
                cve=cve,
                cwe_type=selected[1],
                vulnerability_type=selected[2],
                vulnerable_position=selected[3],
                project=selected[4],
                project_type=selected[5],
                version=selected[6],
            )
        )
    return tuple(sorted(discoveries, key=lambda item: item.cve))


def _git_environment(*, offline: bool) -> dict[str, str]:
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    if offline:
        environment["GIT_NO_LAZY_FETCH"] = "1"
    return environment


def _git(
    repository: Path,
    arguments: Iterable[str],
    *,
    offline: bool,
    text: bool = False,
) -> bytes | str:
    try:
        result = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", *arguments],
            cwd=repository,
            env=_git_environment(offline=offline),
            check=True,
            capture_output=True,
            shell=False,
            stdin=subprocess.DEVNULL,
            text=text,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError("Git evidence operation failed") from exc
    return result.stdout


def _clone(repository_url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "clone",
            "--filter=blob:none",
            "--no-checkout",
            "--no-tags",
            repository_url,
            str(destination),
        ],
        cwd=destination.parent,
        env=_git_environment(offline=False),
        check=True,
        shell=False,
        stdin=subprocess.DEVNULL,
    )


def _normalized_remote(value: str) -> str:
    return value.removesuffix("/")


def _ensure_repository(
    cache_path: Path, repository_url: str, *, allow_clone: bool = False
) -> None:
    if not cache_path.exists():
        if not allow_clone:
            raise ValueError("cached upstream repository is missing")
        _clone(repository_url, cache_path)
    remote = str(_git(cache_path, ("remote", "get-url", "origin"), offline=True, text=True)).strip()
    if _normalized_remote(remote) != _normalized_remote(repository_url):
        raise ValueError("cached upstream repository remote is invalid")


def _fetch_revision(repository: Path, revision: str) -> None:
    _git(
        repository,
        ("fetch", "--no-recurse-submodules", "--no-write-fetch-head", "origin", revision),
        offline=False,
    )


def _require_commit(value: object) -> str:
    if not isinstance(value, str) or _COMMIT_PATTERN.fullmatch(value) is None:
        raise ValueError("exact Git revision is invalid")
    return value


def _require_sha256(value: object) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError("SHA-256 identity is invalid")
    return value


def _blob(repository: Path, revision: str, path: str, *, offline: bool) -> bytes:
    mode_and_type = str(
        _git(repository, ("ls-tree", revision, "--", path), offline=offline, text=True)
    ).strip()
    if not mode_and_type:
        raise ValueError(f"relevant source is missing: {path}")
    mode, object_type, _rest = mode_and_type.split(maxsplit=2)
    if mode == "120000":
        raise ValueError(f"relevant source is a symlink: {path}")
    if mode not in {"100644", "100755"} or object_type != "blob":
        raise ValueError(f"relevant source is not a regular file: {path}")
    value = _git(repository, ("cat-file", "blob", f"{revision}:{path}"), offline=offline)
    assert isinstance(value, bytes)
    return value


def source_snapshot(
    repository: Path, revision: str, paths: Iterable[str], *, offline: bool
) -> dict[str, object]:
    revision = _require_commit(revision)
    resolved = str(
        _git(repository, ("rev-parse", f"{revision}^{{commit}}"), offline=offline, text=True)
    ).strip()
    if resolved != revision:
        raise ValueError("cached revision does not resolve exactly")
    unique_paths = tuple(sorted(set(paths)))
    if not unique_paths or any(not _valid_relative_python_path(path) for path in unique_paths):
        raise ValueError("relevant Python path set is invalid")
    files = [
        {
            "path": path,
            "sha256": hashlib.sha256(
                _blob(repository, revision, path, offline=offline)
            ).hexdigest(),
        }
        for path in unique_paths
    ]
    return {
        "per_file_sha256": files,
        "relevant_path_set": list(unique_paths),
        "relevant_tree_digest": digest(files),
        "revision": revision,
    }


def _walk_keys(value: object) -> Iterable[str]:
    if isinstance(value, dict):
        for key, nested in value.items():
            yield key
            yield from _walk_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk_keys(nested)


def _validate_case_metadata(case: dict[str, object]) -> None:
    cve = case.get("cve_id")
    if not isinstance(cve, str) or _CVE_PATTERN.fullmatch(cve) is None:
        raise ValueError("accepted CVE ID is invalid")
    if not isinstance(case.get("repository_license"), str) or not case["repository_license"]:
        raise ValueError("accepted repository license is missing")
    if not _valid_repository_url(case.get("upstream_repository")):
        raise ValueError("accepted repository URL is invalid")
    vulnerable = _require_commit(case.get("vulnerable_revision"))
    fixed = _require_commit(case.get("fixed_revision"))
    if vulnerable == fixed:
        raise ValueError("vulnerable and fixed revisions must differ")
    paths = case.get("affected_paths")
    if not isinstance(paths, list) or not paths or any(
        not _valid_relative_python_path(path) for path in paths
    ):
        raise ValueError("accepted affected paths are invalid")
    if paths != sorted(set(paths)):
        raise ValueError("accepted affected paths are not canonical")
    for field in ("vulnerable_relevant_paths", "fixed_relevant_paths"):
        relevant_paths = case.get(field, paths)
        if not isinstance(relevant_paths, list) or not relevant_paths or any(
            not _valid_relative_python_path(path) for path in relevant_paths
        ):
            raise ValueError(f"accepted {field} are invalid")
        if relevant_paths != sorted(set(relevant_paths)):
            raise ValueError(f"accepted {field} are not canonical")
    for field in ("advisory_urls", "ground_truth_evidence"):
        values = case.get(field)
        if not isinstance(values, list) or not values or any(
            not isinstance(value, str) or not value for value in values
        ):
            raise ValueError(f"accepted {field} is invalid")


def accepted_case_set_digest(document: dict[str, object]) -> str:
    cases = document.get("cases")
    if not isinstance(cases, list):
        raise ValueError("accepted case document is invalid")
    return digest({"schema_version": document.get("schema_version"), "cases": cases})


def _source_lock_digest(document: dict[str, object]) -> str:
    without_digest = {key: value for key, value in document.items() if key != "source_lock_digest"}
    return digest(without_digest)


def acquire(benchmark_root: Path, cache_root: Path) -> dict[str, object]:
    source_lock = load_json(benchmark_root / "discovery-source-lock.json")
    accepted = load_json(benchmark_root / "accepted-cases.json")
    if source_lock.get("schema_version") != DISCOVERY_SCHEMA_VERSION:
        raise ValueError("discovery source lock schema is invalid")
    if source_lock.get("source_lock_digest") != _source_lock_digest(source_lock):
        raise ValueError("discovery source lock digest is invalid")
    pysastbench = source_lock.get("pysastbench")
    if not isinstance(pysastbench, dict):
        raise ValueError("PySASTBench source lock is invalid")
    discovery_repository = cache_root / "discovery" / "pysastbench"
    repository_url = pysastbench.get("repository_url")
    if not _valid_repository_url(repository_url):
        raise ValueError("PySASTBench repository URL is invalid")
    _ensure_repository(discovery_repository, repository_url, allow_clone=True)
    discovery_revision = _require_commit(pysastbench.get("commit"))
    _fetch_revision(discovery_repository, discovery_revision)
    csv_path = pysastbench.get("csv_path")
    if csv_path != "RealworldDataset.csv":
        raise ValueError("PySASTBench CSV path is invalid")
    csv_bytes = _blob(discovery_repository, discovery_revision, csv_path, offline=False)
    if hashlib.sha256(csv_bytes).hexdigest() != _require_sha256(pysastbench.get("csv_sha256")):
        raise ValueError("PySASTBench discovery CSV identity is invalid")
    discovered = {item.cve for item in parse_pysastbench_discovery_csv(csv_bytes)}

    cases = accepted.get("cases")
    if not isinstance(cases, list):
        raise ValueError("accepted case document is invalid")
    for raw_case in cases:
        if not isinstance(raw_case, dict):
            raise ValueError("accepted case is invalid")
        _validate_case_metadata(raw_case)
        if raw_case.get("pysastbench_indexed") is True and raw_case.get("cve_id") not in discovered:
            raise ValueError("accepted CVE is absent from the pinned discovery index")
        repository_id = raw_case.get("repository_id")
        if (
            not isinstance(repository_id, str)
            or _REPOSITORY_ID_PATTERN.fullmatch(repository_id) is None
        ):
            raise ValueError("accepted repository ID is invalid")
        repository = cache_root / "repositories" / repository_id
        upstream = raw_case["upstream_repository"]
        assert isinstance(upstream, str)
        _ensure_repository(repository, upstream, allow_clone=True)
        required_revisions = {
            _require_commit(raw_case["vulnerable_revision"]),
            _require_commit(raw_case["fixed_revision"]),
        }
        fix_diff = raw_case.get("fix_diff_evidence")
        if not isinstance(fix_diff, dict):
            raise ValueError("accepted fix-diff evidence is invalid")
        security_commits = fix_diff.get("security_fix_commits")
        if not isinstance(security_commits, list) or not security_commits:
            raise ValueError("accepted security-fix commits are invalid")
        required_revisions.update(_require_commit(item) for item in security_commits)
        for revision in sorted(required_revisions):
            _fetch_revision(repository, revision)
        license_path = raw_case.get("license_path")
        if not isinstance(license_path, str):
            raise ValueError("accepted license path is invalid")
        _blob(repository, raw_case["vulnerable_revision"], license_path, offline=False)
        raw_case["license_file_sha256"] = hashlib.sha256(
            _blob(repository, raw_case["vulnerable_revision"], license_path, offline=False)
        ).hexdigest()
        raw_case["vulnerable_source"] = source_snapshot(
            repository,
            raw_case["vulnerable_revision"],
            raw_case.get("vulnerable_relevant_paths", raw_case["affected_paths"]),
            offline=False,
        )
        raw_case["fixed_source"] = source_snapshot(
            repository,
            raw_case["fixed_revision"],
            raw_case.get("fixed_relevant_paths", raw_case["affected_paths"]),
            offline=False,
        )
    cases.sort(key=lambda item: str(item.get("cve_id")))
    accepted["accepted_case_set_digest"] = accepted_case_set_digest(accepted)
    (benchmark_root / "accepted-cases.json").write_bytes(canonical_document(accepted))
    summary = build_summary(benchmark_root)
    (benchmark_root / "acquisition-summary.json").write_bytes(canonical_document(summary))
    return verify(benchmark_root, cache_root)


def build_summary(benchmark_root: Path) -> dict[str, object]:
    source_lock = load_json(benchmark_root / "discovery-source-lock.json")
    ledger = load_json(benchmark_root / "candidate-ledger.json")
    accepted = load_json(benchmark_root / "accepted-cases.json")
    reviewed = ledger.get("reviewed_candidates")
    cases = accepted.get("cases")
    if not isinstance(reviewed, list) or not isinstance(cases, list):
        raise ValueError("real-world evidence documents are invalid")
    cwe_counts: Counter[str] = Counter()
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("accepted case is invalid")
        cwes = case.get("cwe_ids")
        if not isinstance(cwes, list):
            raise ValueError("accepted CWE list is invalid")
        cwe_counts.update(str(cwe) for cwe in cwes)
    accepted_ids = sorted(str(case["cve_id"]) for case in cases)
    deferred = sorted(
        (
            {
                "cve_id": item["cve_id"],
                "reason": item["reason"],
                "selection_state": item["selection_state"],
            }
            for item in reviewed
            if isinstance(item, dict)
            and item.get("selection_state") != "ACCEPTED_FOR_APPLICABILITY_REVIEW"
        ),
        key=lambda item: str(item["cve_id"]),
    )
    return {
        "accepted_case_count": len(cases),
        "accepted_case_set_digest": accepted.get("accepted_case_set_digest"),
        "accepted_cve_ids": accepted_ids,
        "counts_by_cwe": dict(sorted(cwe_counts.items())),
        "deferred_candidate_count": len(deferred),
        "deferred_candidates": deferred,
        "independent_search_outcomes": ledger.get("independent_search_outcomes"),
        "reviewed_candidate_count": len(reviewed),
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "scientific_boundary": {
            "applicability_review": "not-started",
            "benchmark_metrics": "not-calculated",
            "real_world_scanning": "not-performed",
        },
        "source_lock_digest": source_lock.get("source_lock_digest"),
        "unique_case_family_count": len({case["case_family_id"] for case in cases}),
        "unique_project_count": len({case["repository_id"] for case in cases}),
    }


def verify(benchmark_root: Path, cache_root: Path) -> dict[str, object]:
    source_lock = load_json(benchmark_root / "discovery-source-lock.json")
    ledger = load_json(benchmark_root / "candidate-ledger.json")
    accepted = load_json(benchmark_root / "accepted-cases.json")
    summary = load_json(benchmark_root / "acquisition-summary.json")
    if source_lock.get("schema_version") != DISCOVERY_SCHEMA_VERSION:
        raise ValueError("discovery source lock schema is invalid")
    if source_lock.get("source_lock_digest") != _source_lock_digest(source_lock):
        raise ValueError("discovery source lock digest is invalid")
    if ledger.get("schema_version") != LEDGER_SCHEMA_VERSION:
        raise ValueError("candidate ledger schema is invalid")
    if accepted.get("schema_version") != ACCEPTED_SCHEMA_VERSION:
        raise ValueError("accepted case schema is invalid")
    if summary.get("schema_version") != SUMMARY_SCHEMA_VERSION:
        raise ValueError("acquisition summary schema is invalid")
    pysastbench = source_lock.get("pysastbench")
    if not isinstance(pysastbench, dict):
        raise ValueError("PySASTBench source lock is invalid")
    repository_url = pysastbench.get("repository_url")
    if not _valid_repository_url(repository_url):
        raise ValueError("PySASTBench repository URL is invalid")
    discovery_repository = cache_root / "discovery" / "pysastbench"
    _ensure_repository(discovery_repository, repository_url)
    discovery_revision = _require_commit(pysastbench.get("commit"))
    _git(
        discovery_repository,
        ("cat-file", "-e", f"{discovery_revision}^{{commit}}"),
        offline=True,
    )
    csv_path = pysastbench.get("csv_path")
    if csv_path != "RealworldDataset.csv":
        raise ValueError("PySASTBench CSV path is invalid")
    csv_bytes = _blob(discovery_repository, discovery_revision, csv_path, offline=True)
    if hashlib.sha256(csv_bytes).hexdigest() != _require_sha256(
        pysastbench.get("csv_sha256")
    ):
        raise ValueError("PySASTBench discovery CSV identity is invalid")
    parse_pysastbench_discovery_csv(csv_bytes)
    forbidden = {
        key.casefold() for key in _walk_keys((ledger, accepted, summary))
    } & FORBIDDEN_EVIDENCE_KEYS
    if forbidden:
        raise ValueError("scanner or metric fields are forbidden")
    reviewed = ledger.get("reviewed_candidates")
    cases = accepted.get("cases")
    if not isinstance(reviewed, list) or not isinstance(cases, list):
        raise ValueError("real-world evidence documents are invalid")
    reviewed_ids: list[str] = []
    accepted_ledger_ids: set[str] = set()
    for item in reviewed:
        if not isinstance(item, dict):
            raise ValueError("candidate ledger entry is invalid")
        cve = item.get("cve_id")
        state = item.get("selection_state")
        if not isinstance(cve, str) or _CVE_PATTERN.fullmatch(cve) is None:
            raise ValueError("candidate CVE is invalid")
        if state not in SELECTION_STATES:
            raise ValueError("candidate selection state is invalid")
        reviewed_ids.append(cve)
        if state == "ACCEPTED_FOR_APPLICABILITY_REVIEW":
            accepted_ledger_ids.add(cve)
    if reviewed_ids != sorted(set(reviewed_ids)):
        raise ValueError("candidate ledger CVEs are duplicated or unsorted")
    accepted_ids: set[str] = set()
    families: Counter[str] = Counter()
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("accepted case is invalid")
        _validate_case_metadata(case)
        cve = str(case["cve_id"])
        if cve in accepted_ids:
            raise ValueError("duplicate accepted CVE")
        accepted_ids.add(cve)
        family = case.get("case_family_id")
        if not isinstance(family, str) or not family:
            raise ValueError("accepted case family is invalid")
        families[family] += 1
        repository_id = case.get("repository_id")
        if (
            not isinstance(repository_id, str)
            or _REPOSITORY_ID_PATTERN.fullmatch(repository_id) is None
        ):
            raise ValueError("accepted repository ID is invalid")
        repository = cache_root / "repositories" / repository_id
        upstream = case["upstream_repository"]
        assert isinstance(upstream, str)
        _ensure_repository(repository, upstream)
        for revision in (case["vulnerable_revision"], case["fixed_revision"]):
            _require_commit(revision)
            _git(repository, ("cat-file", "-e", f"{revision}^{{commit}}"), offline=True)
        fix_diff = case.get("fix_diff_evidence")
        if not isinstance(fix_diff, dict):
            raise ValueError("accepted fix-diff evidence is invalid")
        security_commits = fix_diff.get("security_fix_commits")
        if not isinstance(security_commits, list) or not security_commits:
            raise ValueError("accepted security-fix commits are invalid")
        for revision in security_commits:
            revision = _require_commit(revision)
            _git(repository, ("cat-file", "-e", f"{revision}^{{commit}}"), offline=True)
        if case.get("revision_relationship_kind") in {
            "ancestor-patched-release",
            "ancestor-security-fix",
        }:
            _git(
                repository,
                (
                    "merge-base",
                    "--is-ancestor",
                    case["vulnerable_revision"],
                    case["fixed_revision"],
                ),
                offline=True,
            )
        expected_license = _require_sha256(case.get("license_file_sha256"))
        license_path = case.get("license_path")
        if not isinstance(license_path, str):
            raise ValueError("accepted license path is invalid")
        if hashlib.sha256(
            _blob(repository, case["vulnerable_revision"], license_path, offline=True)
        ).hexdigest() != expected_license:
            raise ValueError("accepted license identity is invalid")
        vulnerable = source_snapshot(
            repository,
            case["vulnerable_revision"],
            case.get("vulnerable_relevant_paths", case["affected_paths"]),
            offline=True,
        )
        fixed = source_snapshot(
            repository,
            case["fixed_revision"],
            case.get("fixed_relevant_paths", case["affected_paths"]),
            offline=True,
        )
        if case.get("vulnerable_source") != vulnerable or case.get("fixed_source") != fixed:
            raise ValueError("accepted source identity is invalid")
    if accepted_ids != accepted_ledger_ids:
        raise ValueError("accepted cases are not exactly the accepted ledger subset")
    if [case["cve_id"] for case in cases] != sorted(accepted_ids):
        raise ValueError("accepted cases are not sorted by CVE")
    if accepted.get("accepted_case_set_digest") != accepted_case_set_digest(accepted):
        raise ValueError("accepted case-set digest is invalid")
    expected_summary = build_summary(benchmark_root)
    if summary != expected_summary:
        raise ValueError("acquisition summary is invalid")
    return expected_summary
