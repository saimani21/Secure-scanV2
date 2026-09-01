from __future__ import annotations

import ast
import hashlib
import subprocess
from pathlib import Path

import pytest

from securescan.benchmarks.python_sast_realworld import (
    ACCEPTED_SCHEMA_VERSION,
    FORBIDDEN_EVIDENCE_KEYS,
    PYSASTBENCH_ALLOWED_COLUMNS,
    PYSASTBENCH_FORBIDDEN_COLUMNS,
    PySASTBenchDiscovery,
    _ensure_repository,
    _git_environment,
    _valid_repository_url,
    accepted_case_set_digest,
    canonical_document,
    load_json,
    parse_pysastbench_discovery_csv,
    source_snapshot,
    verify,
)

ROOT = Path(__file__).parent.parent
BENCHMARK_ROOT = ROOT / "benchmarks/python_sast_realworld"
CACHE_ROOT = ROOT / ".cache/securescan-realworld-python"
MODULE_PATH = ROOT / "src/securescan/benchmarks/python_sast_realworld.py"
CLI_PATH = ROOT / "src/securescan/benchmarks/python_sast_realworld_cli.py"
RUNNER_PATH = ROOT / "scripts/setup-python-sast-realworld-cases.sh"
EXPECTED_PYSASTBENCH_COMMIT = "3ad04b72c516d0533a5dc9c8042c9808e69e0f40"
EXPECTED_PYSASTBENCH_CSV_SHA256 = (
    "06ae70387ba9eaf6696409fc7ee7d08a387b7e14ed4524130cfc6eccb4ccefd4"
)
EXPECTED_CASE_SET_DIGEST = "60d44ea9cf0f174e1488c5b8dbccde2804524fe4d3bfa31b9db0810e52332a92"


def _discovery_csv(*, semgrep_reason: str, bearer_reason: str = "ignored") -> bytes:
    header = [
        "CVE",
        "CWE Type",
        "Type",
        "vul position",
        "project",
        "Bearer_reason",
        "DevSkim_reason",
        "Dlint_reason",
        "Bandit_reason",
        "Semgrep_reason",
        "Codeql_reason",
        "Pysa_reason",
        "Project Type",
        "Version",
    ]
    row = [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-7009",
        "89;707",
        "sql injection",
        "src/calibre/db/backend.py:DB.search_annotations",
        "https://github.com/kovidgoyal/calibre",
        bearer_reason,
        "ignored",
        "ignored",
        "ignored",
        semgrep_reason,
        "ignored",
        "ignored",
        "manage/monitor platform",
        "Calibre <= 7.15.0",
    ]
    return (",".join(header) + "\n" + ",".join(row) + "\n").encode()


def _load(name: str) -> dict[str, object]:
    return load_json(BENCHMARK_ROOT / name)


def _cases() -> list[dict[str, object]]:
    cases = _load("accepted-cases.json")["cases"]
    assert isinstance(cases, list)
    assert all(isinstance(case, dict) for case in cases)
    return cases  # type: ignore[return-value]


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for item in value.values() for key in _all_keys(item)}
    if isinstance(value, list):
        return {key for item in value for key in _all_keys(item)}
    return set()


def _all_strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for nested in value.values() for item in _all_strings(nested)]
    if isinstance(value, list):
        return [item for nested in value for item in _all_strings(nested)]
    return []


def _git(repository: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )


def _local_repository(tmp_path: Path) -> tuple[Path, str, str]:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "SecureScan Test")
    _git(repository, "config", "user.email", "test@example.invalid")
    (repository / "case.py").write_text("value = 1\n", encoding="utf-8")
    _git(repository, "add", "case.py")
    _git(repository, "commit", "-qm", "vulnerable")
    vulnerable = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repository, text=True
    ).strip()
    (repository / "case.py").write_text("value = 2\n", encoding="utf-8")
    _git(repository, "commit", "-qam", "fixed")
    fixed = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repository, text=True
    ).strip()
    return repository, vulnerable, fixed


def test_discovery_model_contains_only_the_seven_allowed_columns() -> None:
    expected = (
        "CVE",
        "CWE Type",
        "Type",
        "vul position",
        "project",
        "Project Type",
        "Version",
    )
    assert expected == PYSASTBENCH_ALLOWED_COLUMNS
    assert set(PySASTBenchDiscovery.__dataclass_fields__) == {
        "cve",
        "cwe_type",
        "project",
        "project_type",
        "version",
        "vulnerability_type",
        "vulnerable_position",
    }
    assert not set(PYSASTBENCH_FORBIDDEN_COLUMNS) & set(
        PySASTBenchDiscovery.__dataclass_fields__
    )


def test_prior_tool_columns_cannot_influence_discovery_selection_model() -> None:
    first = parse_pysastbench_discovery_csv(
        _discovery_csv(semgrep_reason="reported match", bearer_reason="reported miss")
    )
    second = parse_pysastbench_discovery_csv(
        _discovery_csv(semgrep_reason="opposite result", bearer_reason="opposite result")
    )
    assert first == second
    assert first[0].canonical_data()["cve"] == "CVE-2024-7009"


def test_cve_parsing_is_deterministic_and_duplicate_cves_fail_closed() -> None:
    content = _discovery_csv(semgrep_reason="ignored")
    assert parse_pysastbench_discovery_csv(content) == parse_pysastbench_discovery_csv(
        content
    )
    with pytest.raises(ValueError, match="duplicate PySASTBench discovery CVE"):
        parse_pysastbench_discovery_csv(content + content.splitlines(keepends=True)[1])


def test_committed_source_lock_is_exact_and_canonical() -> None:
    document = _load("discovery-source-lock.json")
    source = document["pysastbench"]
    assert isinstance(source, dict)
    assert source["commit"] == EXPECTED_PYSASTBENCH_COMMIT
    assert source["csv_sha256"] == EXPECTED_PYSASTBENCH_CSV_SHA256
    assert source["allowed_discovery_columns"] == list(PYSASTBENCH_ALLOWED_COLUMNS)
    assert source["forbidden_prior_tool_columns"] == list(
        PYSASTBENCH_FORBIDDEN_COLUMNS
    )


def test_candidate_ledger_is_complete_and_accepted_subset_is_exact() -> None:
    ledger = _load("candidate-ledger.json")
    reviewed = ledger["reviewed_candidates"]
    assert isinstance(reviewed, list)
    assert len(reviewed) == 18
    assert [item["cve_id"] for item in reviewed] == sorted(
        item["cve_id"] for item in reviewed
    )
    accepted_ledger = {
        item["cve_id"]
        for item in reviewed
        if item["selection_state"] == "ACCEPTED_FOR_APPLICABILITY_REVIEW"
    }
    assert accepted_ledger == {case["cve_id"] for case in _cases()}
    assert [case["cve_id"] for case in _cases()] == sorted(accepted_ledger)
    assert len(accepted_ledger) == 13


def test_ambiguous_or_unfixed_candidates_remain_explicit_deferrals() -> None:
    reviewed = _load("candidate-ledger.json")["reviewed_candidates"]
    assert isinstance(reviewed, list)
    by_cve = {item["cve_id"]: item for item in reviewed}
    assert by_cve["CVE-2024-37059"]["selection_state"] == "DEFER_NO_VERIFIED_FIX"
    assert by_cve["CVE-2023-6730"]["selection_state"] == (
        "DEFER_INSUFFICIENT_GROUND_TRUTH"
    )


def test_accepted_cases_have_exact_revisions_license_paths_and_provenance() -> None:
    document = _load("accepted-cases.json")
    assert document["schema_version"] == ACCEPTED_SCHEMA_VERSION
    cases = _cases()
    for case in cases:
        assert len(case["vulnerable_revision"]) == 40
        assert len(case["fixed_revision"]) == 40
        assert case["vulnerable_revision"] != case["fixed_revision"]
        assert _valid_repository_url(case["upstream_repository"])
        assert case["repository_license"]
        assert case["license_path"]
        assert case["advisory_urls"]
        assert case["ground_truth_evidence"]
        assert case["discovery_source_revision"] == EXPECTED_PYSASTBENCH_COMMIT
        assert case["selection_state"] == "ACCEPTED_FOR_APPLICABILITY_REVIEW"


@pytest.mark.parametrize(
    "url",
    (
        "http://github.com/owner/repository.git",
        "https://example.com/owner/repository.git",
        "https://github.com/owner/repository",
        "https://github.com/owner/repository.git?ref=main",
        "file:///tmp/repository.git",
    ),
)
def test_untrusted_repository_urls_fail_validation(url: str) -> None:
    assert not _valid_repository_url(url)


def test_duplicate_case_families_are_counted_without_fake_diversity() -> None:
    summary = _load("acquisition-summary.json")
    assert summary["accepted_case_count"] == 13
    assert summary["unique_project_count"] == 9
    assert summary["unique_case_family_count"] == 11
    families = [case["case_family_id"] for case in _cases()]
    assert families.count("yt-dlp-exec-shell-quoting") == 2


def test_case_set_digest_and_summary_are_frozen() -> None:
    accepted = _load("accepted-cases.json")
    assert accepted_case_set_digest(accepted) == EXPECTED_CASE_SET_DIGEST
    assert accepted["accepted_case_set_digest"] == EXPECTED_CASE_SET_DIGEST
    summary = _load("acquisition-summary.json")
    assert summary["accepted_case_set_digest"] == EXPECTED_CASE_SET_DIGEST
    assert summary["counts_by_cwe"] == {
        "502": 3,
        "77": 2,
        "78": 4,
        "89": 3,
        "94": 3,
    }


def test_no_scanner_metric_host_path_or_source_body_enters_evidence() -> None:
    documents = [
        _load("discovery-source-lock.json"),
        _load("candidate-ledger.json"),
        _load("accepted-cases.json"),
        _load("acquisition-summary.json"),
    ]
    keys = {key.casefold() for document in documents for key in _all_keys(document)}
    assert not keys & FORBIDDEN_EVIDENCE_KEYS
    assert not keys & {"source_body", "source_code", "patch", "excerpt"}
    strings = [item for document in documents for item in _all_strings(document)]
    assert not any(item.startswith("/home/") or item.startswith("/tmp/") for item in strings)


def test_acquisition_module_has_no_scanner_or_prior_evidence_dependency() -> None:
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not any("semgrep" in name.casefold() for name in imports)
    source = MODULE_PATH.read_text(encoding="utf-8")
    assert "python_sast_external_evaluation" not in source
    assert "initial-v0.3e-baseline" not in source
    assert "rules/python" not in source
    assert ".yaml" not in source and ".yml" not in source
    assert "semgrep" not in CLI_PATH.read_text(encoding="utf-8").casefold()
    assert "semgrep" not in RUNNER_PATH.read_text(encoding="utf-8").casefold()


def test_relative_source_snapshot_is_deterministic_and_content_addressed(
    tmp_path: Path,
) -> None:
    repository, vulnerable, fixed = _local_repository(tmp_path)
    first = source_snapshot(repository, vulnerable, ["case.py"], offline=True)
    second = source_snapshot(repository, vulnerable, ["case.py"], offline=True)
    assert first == second
    expected = hashlib.sha256(b"value = 1\n").hexdigest()
    assert first["per_file_sha256"] == [{"path": "case.py", "sha256": expected}]
    assert source_snapshot(repository, fixed, ["case.py"], offline=True) != first


@pytest.mark.parametrize(
    "path",
    ("/absolute.py", "../escape.py", "nested/../escape.py", "windows\\case.py", "case.txt"),
)
def test_unsafe_or_non_python_relevant_paths_fail_closed(
    tmp_path: Path, path: str
) -> None:
    repository, vulnerable, _fixed = _local_repository(tmp_path)
    with pytest.raises(ValueError, match="relevant Python path set is invalid"):
        source_snapshot(repository, vulnerable, [path], offline=True)


def test_symlink_and_missing_revisions_fail_closed(tmp_path: Path) -> None:
    repository, vulnerable, _fixed = _local_repository(tmp_path)
    (repository / "link.py").symlink_to("case.py")
    _git(repository, "add", "link.py")
    _git(repository, "commit", "-qm", "symlink")
    symlink_revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repository, text=True
    ).strip()
    with pytest.raises(ValueError, match="relevant source is a symlink"):
        source_snapshot(repository, symlink_revision, ["link.py"], offline=True)
    with pytest.raises(ValueError, match="Git evidence operation failed"):
        source_snapshot(repository, "0" * 40, ["case.py"], offline=True)
    with pytest.raises(ValueError, match="relevant source is missing"):
        source_snapshot(repository, vulnerable, ["missing.py"], offline=True)


@pytest.mark.parametrize("revision_role", ("vulnerable", "fixed"))
def test_missing_vulnerable_or_fixed_revision_fails_closed(
    tmp_path: Path, revision_role: str
) -> None:
    repository, vulnerable, fixed = _local_repository(tmp_path)
    revisions = {"vulnerable": vulnerable, "fixed": fixed}
    revisions[revision_role] = "0" * 40
    with pytest.raises(ValueError, match="Git evidence operation failed"):
        source_snapshot(repository, revisions[revision_role], ["case.py"], offline=True)


def test_offline_repository_check_never_clones(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected_clone(_repository_url: str, _destination: Path) -> None:
        raise AssertionError("offline verification attempted a clone")

    monkeypatch.setattr(
        "securescan.benchmarks.python_sast_realworld._clone", unexpected_clone
    )
    with pytest.raises(ValueError, match="cached upstream repository is missing"):
        _ensure_repository(
            tmp_path / "missing",
            "https://github.com/example/repository.git",
        )


def test_noncanonical_and_duplicate_json_fail_closed(tmp_path: Path) -> None:
    noncanonical = tmp_path / "noncanonical.json"
    noncanonical.write_text('{"b": 1, "a": 2}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="non-canonical evidence"):
        load_json(noncanonical)
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"a":1,"a":2}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="invalid canonical evidence"):
        load_json(duplicate)
    canonical = tmp_path / "canonical.json"
    canonical.write_bytes(canonical_document({"a": 2, "b": 1}))
    assert load_json(canonical) == {"a": 2, "b": 1}


def test_offline_verify_reproduces_all_committed_source_identities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not CACHE_ROOT.is_dir():
        pytest.skip("run acquire before the offline integration check")
    import securescan.benchmarks.python_sast_realworld as realworld

    original = realworld._git
    offline_flags: list[bool] = []

    def recording_git(
        repository: Path,
        arguments: tuple[str, ...],
        *,
        offline: bool,
        text: bool = False,
    ) -> bytes | str:
        offline_flags.append(offline)
        return original(repository, arguments, offline=offline, text=text)

    monkeypatch.setattr(realworld, "_git", recording_git)
    first = verify(BENCHMARK_ROOT, CACHE_ROOT)
    second = verify(BENCHMARK_ROOT, CACHE_ROOT)
    assert first == second
    assert first["accepted_case_set_digest"] == EXPECTED_CASE_SET_DIGEST
    assert offline_flags and all(offline_flags)
    assert _git_environment(offline=True)["GIT_NO_LAZY_FETCH"] == "1"
