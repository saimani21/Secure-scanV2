from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

from securescan.benchmarks.python_sast import (
    EXPECTED_SCANNER_VERSION,
    FROZEN_RULESET_DIGEST,
    FROZEN_RULESET_ID,
    FROZEN_RULESET_VERSION,
    PRODUCTION_RULE_IDS,
    SCANNER_ID,
    BenchmarkMetrics,
    calculate_metrics,
    classify_case,
)
from securescan.benchmarks.python_sast_realworld import (
    _blob,
    load_json,
)
from securescan.benchmarks.python_sast_realworld import (
    verify as verify_realworld_cases,
)
from securescan.scanners.semgrep import (
    SemgrepAdapterError,
    load_baseline_ruleset,
    parse_semgrep_output,
)
from securescan.workspaces.models import (
    RepositoryManifest,
    RepositoryManifestEntry,
    repository_content_digest,
)

REPORT_SCHEMA_VERSION: Final = "securescan-python-sast-realworld-evaluation-v2"
REVIEW_SCHEMA_VERSION: Final = "securescan-python-sast-realworld-evaluation-review-v2"
BASELINE_TAG: Final = "source-v0.3F2E4-python-sast-claim-contract-v2"
BASELINE_COMMIT: Final = "7845ad4107a628dc1ab714220b4bc63b6370760a"
SOURCE_LOCK_DIGEST: Final = "0bba4bbe5ce557f1382f61f9af3320adef5cc53ab386d1c63f4983d8cbf48a00"
ACCEPTED_CASE_SET_DIGEST: Final = "60d44ea9cf0f174e1488c5b8dbccde2804524fe4d3bfa31b9db0810e52332a92"
CLAIM_CONTRACT_DIGEST: Final = (
    "0e0d9a118a7567049ad26f046b0f097ba8390d74f05f2b721452683ee3c2e62d"
)
CLAIM_CONTRACT_FILE_SHA256: Final = (
    "70b3c50f33526e5db40bbb4ee8c89c561a2ecfaa7cfbb4e01934d9656c7993b3"
)
CLAIM_AUDIT_DIGEST: Final = (
    "d9c6b52c77e6fc8fdd4a8ea8ba9a29274bd7f416622c35904a44d3c4348e7d2a"
)
CLAIM_AUDIT_FILE_SHA256: Final = (
    "d821fd7ca273c7a45e3cd0c548f96d3ad2bf0f7ea54b3ca6054d7c991a0dbf81"
)
APPLICABILITY_PROPOSAL_DIGEST: Final = (
    "96267be4d421582b1f9834cf2bd2750096c727a75a2cc39cd139baf7f58bc478"
)
APPLICABILITY_SUMMARY_DIGEST: Final = (
    "b9286a5d601e0815bd68c6cb73052740e4b34e1d155591341a6ed683b140c083"
)
APPLICABILITY_REVIEW_DIGEST: Final = (
    "4b0c7e551ffc3163941a4358ce3de8572505bd6aa2172e6440668e7d2aba0464"
)
EXPECTED_CASE_COUNT: Final = 13
EXPECTED_REVISION_COUNT: Final = 26
EXPECTED_APPLICABLE_CVE_COUNT: Final = 7
EXPECTED_RELATION_COUNT: Final = 7
EXPECTED_EXPECTATION_COUNT: Final = 14
EXPECTED_POSITIVE_COUNT: Final = 11
EXPECTED_NEGATIVE_COUNT: Final = 3
MAXIMUM_RESULT_BYTES: Final = 64 * 1024 * 1024
MAXIMUM_STDERR_BYTES: Final = 1024 * 1024
SCAN_TIMEOUT_SECONDS: Final = 300
_RULESET_RELATIVE_PATH: Final = Path(
    "src/securescan/scanners/semgrep/rules/securescan-python-baseline-v2.yml"
)
_BENCHMARK_RELATIVE_ROOT: Final = Path("benchmarks/python_sast_realworld")
_CACHE_RELATIVE_ROOT: Final = Path(".cache/securescan-realworld-python")

def canonical_report(value: dict[str, object]) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def report_digest(value: dict[str, object]) -> str:
    return hashlib.sha256(canonical_report(value)).hexdigest()


def _file_digest(path: Path) -> str:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise OSError
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise ValueError(f"frozen evidence file is invalid: {path.name}") from exc


def _git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _git_text(repository_root: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=repository_root,
            env=_git_environment(),
            check=True,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("F2E5 Git baseline check failed") from exc
    return result.stdout.strip()


def _git_is_ancestor(repository_root: Path, ancestor: str, descendant: str) -> bool:
    try:
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", ancestor, descendant],
            cwd=repository_root,
            env=_git_environment(),
            check=False,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("F2E5 Git baseline check failed") from exc
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise ValueError("F2E5 Git baseline check failed")


def verify_git_baseline(repository_root: Path) -> None:
    if _git_text(repository_root, "branch", "--show-current") != "source/v0.3-semgrep":
        raise ValueError("F2E5 branch binding is invalid")
    baseline = _git_text(repository_root, "rev-parse", f"{BASELINE_TAG}^{{commit}}")
    if baseline != BASELINE_COMMIT:
        raise ValueError("F2E5 baseline binding is invalid")
    if not _git_is_ancestor(repository_root, baseline, "HEAD"):
        raise ValueError("F2E5 baseline binding is invalid")


@dataclass(frozen=True, slots=True, order=True)
class EvidenceRegion:
    relative_source_path: str
    source_sha256: str
    start_line: int
    end_line: int
    revision_role: str

    @classmethod
    def from_data(cls, value: object, role: str) -> EvidenceRegion:
        if not isinstance(value, dict):
            raise ValueError("F2E4 evidence region is invalid")
        path = value.get("relative_source_path")
        source_sha256 = value.get("source_sha256")
        start = value.get("start_line")
        end = value.get("end_line")
        if (
            not isinstance(path, str)
            or not path
            or PurePosixPath(path).is_absolute()
            or PurePosixPath(path).as_posix() != path
            or any(part in {"", ".", ".."} for part in PurePosixPath(path).parts)
            or not isinstance(source_sha256, str)
            or len(source_sha256) != 64
            or not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(end, int)
            or isinstance(end, bool)
            or not 1 <= start <= end
            or value.get("revision_role") != role
        ):
            raise ValueError("F2E4 evidence region is invalid")
        return cls(path, source_sha256, start, end, role)


@dataclass(frozen=True, slots=True, order=True)
class RevisionExpectation:
    case_id: str
    cve_id: str
    project: str
    case_family_id: str
    rule_id: str
    revision_role: str
    expected_match: bool
    discrimination_expectation: str
    evidence_regions: tuple[EvidenceRegion, ...]


@dataclass(frozen=True, slots=True)
class FrozenRealWorldInputs:
    accepted_cases: tuple[dict[str, object], ...]
    proposal_cases: tuple[dict[str, object], ...]
    expectations: tuple[RevisionExpectation, ...]


def _parse_expectations(
    proposal_cases: tuple[dict[str, object], ...],
) -> tuple[RevisionExpectation, ...]:
    expectations: list[RevisionExpectation] = []
    relation_count = 0
    discrimination_counts: Counter[str] = Counter()
    for case in proposal_cases:
        relations = case.get("relations")
        if not isinstance(relations, list):
            raise ValueError("F2E4 applicability relation list is invalid")
        disposition = case.get("case_disposition")
        if (disposition == "CLAIM_APPLICABLE") != bool(relations):
            raise ValueError("F2E4 applicability relation accounting is invalid")
        for relation in relations:
            if not isinstance(relation, dict):
                raise ValueError("F2E4 applicability relation is invalid")
            rule_id = relation.get("rule_id")
            discrimination = relation.get("discrimination_expectation")
            if rule_id not in PRODUCTION_RULE_IDS or discrimination not in {
                "SHOULD_DISCRIMINATE",
                "NOT_EXPECTED_TO_DISCRIMINATE",
            }:
                raise ValueError("F2E4 applicability relation identity is invalid")
            relation_count += 1
            discrimination_counts[str(discrimination)] += 1
            for role in ("vulnerable", "fixed"):
                raw_role = relation.get(role)
                if not isinstance(raw_role, dict) or not isinstance(
                    raw_role.get("expected_match"), bool
                ):
                    raise ValueError("F2E4 revision expectation is invalid")
                raw_regions = raw_role.get("evidence_regions")
                if not isinstance(raw_regions, list) or not raw_regions:
                    raise ValueError("F2E4 revision evidence is invalid")
                regions = tuple(EvidenceRegion.from_data(item, role) for item in raw_regions)
                expectations.append(
                    RevisionExpectation(
                        case_id=str(case["case_id"]),
                        cve_id=str(case["cve_id"]),
                        project=str(case["project"]),
                        case_family_id=str(case["case_family_id"]),
                        rule_id=str(rule_id),
                        revision_role=role,
                        expected_match=raw_role["expected_match"],
                        discrimination_expectation=str(discrimination),
                        evidence_regions=regions,
                    )
                )
    result = tuple(sorted(expectations))
    if (
        relation_count != EXPECTED_RELATION_COUNT
        or len(result) != EXPECTED_EXPECTATION_COUNT
        or len({(item.case_id, item.revision_role, item.rule_id) for item in result})
        != len(result)
        or len({item.cve_id for item in result}) != EXPECTED_APPLICABLE_CVE_COUNT
        or sum(item.expected_match for item in result) != EXPECTED_POSITIVE_COUNT
        or sum(not item.expected_match for item in result) != EXPECTED_NEGATIVE_COUNT
        or any(
            not item.expected_match
            for item in result
            if item.revision_role == "vulnerable"
        )
        or discrimination_counts
        != Counter(
            {
                "SHOULD_DISCRIMINATE": 3,
                "NOT_EXPECTED_TO_DISCRIMINATE": 4,
            }
        )
    ):
        raise ValueError("F2E4 revision expectation accounting is invalid")
    return result


def load_frozen_inputs(repository_root: Path) -> FrozenRealWorldInputs:
    verify_git_baseline(repository_root)
    benchmark_root = repository_root / _BENCHMARK_RELATIVE_ROOT
    f2e1 = verify_realworld_cases(
        benchmark_root,
        repository_root / _CACHE_RELATIVE_ROOT,
    )
    if (
        f2e1.get("source_lock_digest") != SOURCE_LOCK_DIGEST
        or f2e1.get("accepted_case_set_digest") != ACCEPTED_CASE_SET_DIGEST
    ):
        raise ValueError("F2E1 real-world input binding is invalid")
    evidence_identities = {
        "applicability-proposal-v2.json": APPLICABILITY_PROPOSAL_DIGEST,
        "applicability-summary-v2.json": APPLICABILITY_SUMMARY_DIGEST,
        "applicability-review-v2.json": APPLICABILITY_REVIEW_DIGEST,
    }
    for name, expected in evidence_identities.items():
        if _file_digest(benchmark_root / name) != expected:
            raise ValueError("F2E4 applicability evidence binding is invalid")
    claim_root = repository_root / "benchmarks/python_sast_external"
    contract_path = claim_root / "rule-claims-v2.json"
    audit_path = claim_root / "rule-claim-conformance-audit-v2.json"
    if (
        _file_digest(contract_path) != CLAIM_CONTRACT_FILE_SHA256
        or _file_digest(audit_path) != CLAIM_AUDIT_FILE_SHA256
    ):
        raise ValueError("F2E4 claim evidence file binding is invalid")
    contract = load_json(contract_path)
    audit = load_json(audit_path)
    if (
        contract.get("contract_digest") != CLAIM_CONTRACT_DIGEST
        or contract.get("contract_version") != 2
        or contract.get("production_ruleset_id") != FROZEN_RULESET_ID
        or contract.get("production_ruleset_version") != FROZEN_RULESET_VERSION
        or contract.get("production_ruleset_digest") != FROZEN_RULESET_DIGEST
        or audit.get("audit_digest") != CLAIM_AUDIT_DIGEST
        or audit.get("contract_digest") != CLAIM_CONTRACT_DIGEST
    ):
        raise ValueError("F2E4 claim evidence binding is invalid")
    accepted = load_json(benchmark_root / "accepted-cases.json")
    proposal = load_json(benchmark_root / "applicability-proposal-v2.json")
    summary = load_json(benchmark_root / "applicability-summary-v2.json")
    review = load_json(benchmark_root / "applicability-review-v2.json")
    raw_accepted = accepted.get("cases")
    raw_proposal = proposal.get("cases")
    if (
        not isinstance(raw_accepted, list)
        or not isinstance(raw_proposal, list)
        or len(raw_accepted) != EXPECTED_CASE_COUNT
        or len(raw_proposal) != EXPECTED_CASE_COUNT
        or proposal.get("source_lock_digest") != SOURCE_LOCK_DIGEST
        or proposal.get("accepted_case_set_digest") != ACCEPTED_CASE_SET_DIGEST
        or proposal.get("rule_claim_contract_digest") != CLAIM_CONTRACT_DIGEST
        or proposal.get("production_ruleset_digest") != FROZEN_RULESET_DIGEST
    ):
        raise ValueError("F2E4 applicability proposal binding is invalid")
    if not all(isinstance(item, dict) for item in (*raw_accepted, *raw_proposal)):
        raise ValueError("frozen real-world case data is invalid")
    accepted_cases = tuple(raw_accepted)  # type: ignore[arg-type]
    proposal_cases = tuple(raw_proposal)  # type: ignore[arg-type]
    accepted_ids = [item.get("cve_id") for item in accepted_cases]
    proposal_ids = [item.get("cve_id") for item in proposal_cases]
    dispositions = Counter(item.get("case_disposition") for item in proposal_cases)
    if (
        accepted_ids != proposal_ids
        or accepted_ids != sorted(set(accepted_ids))
        or dispositions
        != Counter(
            {
                "CLAIM_APPLICABLE": 7,
                "OUTSIDE_FROZEN_RULE_CLAIMS": 6,
            }
        )
        or summary.get("accepted_cve_count") != EXPECTED_CASE_COUNT
        or summary.get("applicable_relation_count") != EXPECTED_RELATION_COUNT
        or summary.get("applicable_unique_case_family_count") != 6
        or summary.get("applicable_unique_project_count") != 5
        or summary.get("discrimination_expectation_counts")
        != {
            "NOT_EXPECTED_TO_DISCRIMINATE": 4,
            "SHOULD_DISCRIMINATE": 3,
        }
        or summary.get("case_disposition_counts")
        != {
            "CLAIM_APPLICABLE": 7,
            "OUTSIDE_FROZEN_RULE_CLAIMS": 6,
            "UNRESOLVED": 0,
        }
        or summary.get("rule_claim_contract_digest") != CLAIM_CONTRACT_DIGEST
        or review.get("case_count") != EXPECTED_CASE_COUNT
        or review.get("rule_claim_contract_digest") != CLAIM_CONTRACT_DIGEST
    ):
        raise ValueError("F2E4 case accounting is invalid")
    return FrozenRealWorldInputs(
        accepted_cases=accepted_cases,
        proposal_cases=proposal_cases,
        expectations=_parse_expectations(proposal_cases),
    )


@dataclass(frozen=True, slots=True, order=True)
class ProjectionEntry:
    scanner_path: str
    case_id: str
    cve_id: str
    project: str
    case_family_id: str
    revision_role: str
    original_relative_path: str
    source_sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class RealWorldProjection:
    root: Path
    entries: tuple[ProjectionEntry, ...]
    manifest: RepositoryManifest

    def entry_for_path(self, scanner_path: str) -> ProjectionEntry:
        matches = [entry for entry in self.entries if entry.scanner_path == scanner_path]
        if len(matches) != 1:
            raise ValueError("real-world scanner path is unknown")
        return matches[0]


def projection_path(cve_id: str, revision_role: str, original_path: str) -> str:
    value = f"cases/{cve_id}/{revision_role}/{original_path}"
    path = PurePosixPath(value)
    if (
        path.as_posix() != value
        or path.is_absolute()
        or revision_role not in {"vulnerable", "fixed"}
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("real-world projection path is invalid")
    return value


def _projection_file(root: Path, relative_path: str) -> Path:
    path = root.joinpath(*PurePosixPath(relative_path).parts)
    try:
        root_resolved = root.resolve(strict=True)
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
        resolved.relative_to(root_resolved)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("real-world projection is invalid") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or resolved != path.absolute()
    ):
        raise ValueError("real-world projection is invalid")
    return path


def verify_projection(projection: RealWorldProjection) -> None:
    expected_paths = {entry.scanner_path for entry in projection.entries}
    observed_files: set[str] = set()
    try:
        for path in projection.root.rglob("*"):
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError
            if stat.S_ISREG(metadata.st_mode):
                observed_files.add(path.relative_to(projection.root).as_posix())
            elif not stat.S_ISDIR(metadata.st_mode):
                raise ValueError
    except (OSError, ValueError) as exc:
        raise ValueError("real-world projection is invalid") from exc
    if observed_files != expected_paths:
        raise ValueError("real-world projection is invalid")
    for entry in projection.entries:
        data = _projection_file(projection.root, entry.scanner_path).read_bytes()
        if len(data) != entry.size_bytes or hashlib.sha256(data).hexdigest() != entry.source_sha256:
            raise ValueError("real-world projection byte identity is invalid")


def create_projection(
    projection_root: Path,
    cache_root: Path,
    inputs: FrozenRealWorldInputs,
) -> RealWorldProjection:
    try:
        projection_root.mkdir(mode=0o700)
        if projection_root.is_symlink() or not projection_root.is_dir():
            raise ValueError
    except (OSError, ValueError) as exc:
        raise ValueError("real-world projection root is invalid") from exc
    proposal_by_cve = {item["cve_id"]: item for item in inputs.proposal_cases}
    entries: list[ProjectionEntry] = []
    for case in inputs.accepted_cases:
        cve_id = str(case["cve_id"])
        proposal_case = proposal_by_cve[cve_id]
        repository = cache_root / "repositories" / str(case["repository_id"])
        for role in ("vulnerable", "fixed"):
            revision = case.get(f"{role}_revision")
            snapshot = case.get(f"{role}_source")
            if not isinstance(revision, str) or not isinstance(snapshot, dict):
                raise ValueError("F2E1 revision snapshot is invalid")
            if snapshot.get("revision") != revision:
                raise ValueError("F2E1 revision role binding is invalid")
            raw_files = snapshot.get("per_file_sha256")
            relevant_paths = snapshot.get("relevant_path_set")
            if not isinstance(raw_files, list) or not isinstance(relevant_paths, list):
                raise ValueError("F2E1 relevant source set is invalid")
            expected_hashes = {
                item["path"]: item["sha256"]
                for item in raw_files
                if isinstance(item, dict)
                and isinstance(item.get("path"), str)
                and isinstance(item.get("sha256"), str)
            }
            if sorted(expected_hashes) != relevant_paths:
                raise ValueError("F2E1 relevant source identity is invalid")
            for original_path in relevant_paths:
                if not isinstance(original_path, str):
                    raise ValueError("F2E1 relevant source path is invalid")
                source = _blob(repository, revision, original_path, offline=True)
                source_sha256 = hashlib.sha256(source).hexdigest()
                if source_sha256 != expected_hashes[original_path]:
                    raise ValueError("F2E1 relevant source bytes are invalid")
                scanner_path = projection_path(cve_id, role, original_path)
                destination = projection_root.joinpath(*PurePosixPath(scanner_path).parts)
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                try:
                    with destination.open("xb") as output:
                        output.write(source)
                        output.flush()
                        os.fsync(output.fileno())
                    os.chmod(destination, 0o600)
                except OSError as exc:
                    raise ValueError("real-world projection write failed") from exc
                entries.append(
                    ProjectionEntry(
                        scanner_path=scanner_path,
                        case_id=str(proposal_case["case_id"]),
                        cve_id=cve_id,
                        project=str(proposal_case["project"]),
                        case_family_id=str(proposal_case["case_family_id"]),
                        revision_role=role,
                        original_relative_path=original_path,
                        source_sha256=source_sha256,
                        size_bytes=len(source),
                    )
                )
    entry_tuple = tuple(sorted(entries))
    if len({item.scanner_path for item in entry_tuple}) != len(entry_tuple):
        raise ValueError("real-world projection mapping is not one-to-one")
    manifest_entries = tuple(
        RepositoryManifestEntry(item.scanner_path, item.size_bytes, item.source_sha256)
        for item in entry_tuple
    )
    manifest = RepositoryManifest(
        entries=manifest_entries,
        file_count=len(manifest_entries),
        total_bytes=sum(item.size_bytes for item in manifest_entries),
        content_digest=repository_content_digest(manifest_entries),
    )
    projection = RealWorldProjection(projection_root, entry_tuple, manifest)
    verify_projection(projection)
    return projection


def controlled_environment(temporary_root: Path, executable: Path) -> dict[str, str]:
    home = temporary_root / "home"
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    return {
        "HOME": os.fspath(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.pathsep.join((os.fspath(executable.parent), "/usr/bin", "/bin")),
        "SEMGREP_LOG_FILE": os.fspath(temporary_root / "semgrep.log"),
        "SEMGREP_SETTINGS_FILE": os.fspath(temporary_root / "settings.yml"),
    }


def expected_scanner_executable(repository_root: Path) -> Path:
    return repository_root / ".venv-semgrep-1.171/bin/semgrep"


def verify_ruleset_identity(repository_root: Path) -> None:
    trusted = load_baseline_ruleset()
    path = repository_root / _RULESET_RELATIVE_PATH
    if (
        trusted.ruleset_id != FROZEN_RULESET_ID
        or trusted.version != FROZEN_RULESET_VERSION
        or trusted.sha256 != FROZEN_RULESET_DIGEST
        or _file_digest(path) != FROZEN_RULESET_DIGEST
    ):
        raise ValueError("real-world evaluation ruleset identity is invalid")


def verify_scanner_identity(
    repository_root: Path,
    executable: Path,
    temporary_root: Path,
) -> None:
    expected = expected_scanner_executable(repository_root)
    if executable.absolute() != expected.absolute() or not executable.is_file():
        raise ValueError("real-world evaluation scanner executable is invalid")
    try:
        result = subprocess.run(
            [os.fspath(executable), "--disable-version-check", "--version"],
            cwd=repository_root,
            env=controlled_environment(temporary_root, executable),
            capture_output=True,
            check=False,
            stdin=subprocess.DEVNULL,
            timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("real-world scanner identity check timed out") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("real-world scanner identity check failed") from exc
    try:
        version = result.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("real-world scanner identity is invalid") from exc
    if result.returncode != 0 or version != EXPECTED_SCANNER_VERSION:
        raise ValueError("real-world scanner identity is invalid")


@dataclass(frozen=True, slots=True, order=True)
class ObservedFinding:
    case_id: str
    cve_id: str
    revision_role: str
    original_relative_path: str
    rule_id: str
    start_line: int
    end_line: int


@dataclass(frozen=True, slots=True)
class ScanObservations:
    findings: tuple[ObservedFinding, ...]
    raw_result_count: int
    accepted_result_count: int
    duplicate_result_count: int


def normalize_scanner_output(
    raw_output: bytes, projection: RealWorldProjection
) -> ScanObservations:
    try:
        parsed = parse_semgrep_output(
            raw_output,
            projection.manifest,
            scanner_id=SCANNER_ID,
            scanner_version=EXPECTED_SCANNER_VERSION,
        )
    except SemgrepAdapterError as exc:
        raise ValueError("real-world scanner output is malformed") from exc
    if parsed.analysis_gaps:
        raise ValueError("real-world scanner output contains analysis gaps")
    if parsed.output_version != EXPECTED_SCANNER_VERSION:
        raise ValueError("real-world scanner output version is invalid")
    findings: list[ObservedFinding] = []
    for finding in parsed.findings:
        if (
            finding.path is None
            or finding.rule_id not in PRODUCTION_RULE_IDS
            or finding.start_line is None
            or finding.end_line is None
        ):
            raise ValueError("real-world scanner finding is invalid")
        entry = projection.entry_for_path(finding.path)
        findings.append(
            ObservedFinding(
                case_id=entry.case_id,
                cve_id=entry.cve_id,
                revision_role=entry.revision_role,
                original_relative_path=entry.original_relative_path,
                rule_id=finding.rule_id,
                start_line=finding.start_line,
                end_line=finding.end_line,
            )
        )
    result = tuple(sorted(set(findings)))
    return ScanObservations(
        findings=result,
        raw_result_count=parsed.raw_result_count,
        accepted_result_count=len(result),
        duplicate_result_count=parsed.duplicate_result_count
        + parsed.accepted_result_count
        - len(result),
    )


def execute_controlled_scan(
    repository_root: Path,
    inputs: FrozenRealWorldInputs,
    executable: Path,
) -> ScanObservations:
    verify_ruleset_identity(repository_root)
    with tempfile.TemporaryDirectory(prefix="securescan-python-sast-realworld-") as name:
        temporary_root = Path(name)
        verify_scanner_identity(repository_root, executable, temporary_root)
        projection = create_projection(
            temporary_root / "projection",
            repository_root / _CACHE_RELATIVE_ROOT,
            inputs,
        )
        ruleset_path = repository_root / _RULESET_RELATIVE_PATH
        command = [
            os.fspath(executable),
            "scan",
            "--json",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",
            "--jobs=1",
            "--no-rewrite-rule-ids",
            f"--config={ruleset_path}",
            *(entry.scanner_path for entry in projection.entries),
        ]
        try:
            result = subprocess.run(
                command,
                cwd=projection.root,
                env=controlled_environment(temporary_root, executable),
                capture_output=True,
                check=False,
                stdin=subprocess.DEVNULL,
                timeout=SCAN_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("real-world scanner execution timed out") from exc
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError("real-world scanner execution failed") from exc
        if result.returncode != 0:
            raise RuntimeError("real-world scanner execution failed")
        if len(result.stdout) > MAXIMUM_RESULT_BYTES or len(result.stderr) > MAXIMUM_STDERR_BYTES:
            raise ValueError("real-world scanner output exceeds the configured bound")
        verify_projection(projection)
        return normalize_scanner_output(result.stdout, projection)


@dataclass(frozen=True, slots=True, order=True)
class ScoredExpectation:
    case_id: str
    cve_id: str
    case_family_id: str
    project: str
    revision_role: str
    rule_id: str
    expected_match: bool
    observed_match: bool
    classification: str
    discrimination_expectation: str


@dataclass(frozen=True, slots=True, order=True)
class NonScoringObservation:
    case_id: str
    cve_id: str
    revision_role: str
    original_relative_path: str
    rule_id: str
    start_line: int
    end_line: int
    classification: str


@dataclass(frozen=True, slots=True)
class RealWorldEvaluation:
    scan: ScanObservations
    scored: tuple[ScoredExpectation, ...]
    metrics: BenchmarkMetrics
    per_rule: tuple[tuple[str, BenchmarkMetrics], ...]
    observations: tuple[NonScoringObservation, ...]


def _inside(finding: ObservedFinding, regions: tuple[EvidenceRegion, ...]) -> bool:
    return any(
        finding.revision_role == region.revision_role
        and finding.original_relative_path == region.relative_source_path
        and region.start_line <= finding.start_line
        and finding.end_line <= region.end_line
        for region in regions
    )


def evaluate_observations(
    inputs: FrozenRealWorldInputs,
    scan: ScanObservations,
) -> RealWorldEvaluation:
    cases_by_id = {str(item["case_id"]): item for item in inputs.proposal_cases}
    if len(cases_by_id) != len(inputs.proposal_cases):
        raise ValueError("real-world evaluation case mapping is invalid")
    expectation_keys = {
        (item.case_id, item.revision_role, item.rule_id): item for item in inputs.expectations
    }
    if len(expectation_keys) != len(inputs.expectations):
        raise ValueError("real-world expectation mapping is ambiguous")
    observed_keys: set[tuple[str, str, str]] = set()
    non_scoring: list[NonScoringObservation] = []
    for finding in scan.findings:
        case = cases_by_id.get(finding.case_id)
        if case is None or finding.rule_id not in PRODUCTION_RULE_IDS:
            raise ValueError("real-world observation identity is invalid")
        if case.get("cve_id") != finding.cve_id or finding.revision_role not in {
            "vulnerable",
            "fixed",
        }:
            raise ValueError("real-world observation case mapping is invalid")
        if case.get("case_disposition") == "OUTSIDE_FROZEN_RULE_CLAIMS":
            classification = "outside-case-observation"
        else:
            same_rule = expectation_keys.get(
                (finding.case_id, finding.revision_role, finding.rule_id)
            )
            if same_rule is not None and _inside(finding, same_rule.evidence_regions):
                observed_keys.add((finding.case_id, finding.revision_role, finding.rule_id))
                continue
            if same_rule is not None:
                classification = "same-rule-outside-cve-region"
            else:
                case_regions = tuple(
                    region
                    for expectation in inputs.expectations
                    if expectation.case_id == finding.case_id
                    and expectation.revision_role == finding.revision_role
                    for region in expectation.evidence_regions
                )
                classification = (
                    "cross-rule-in-cve-region"
                    if _inside(finding, case_regions)
                    else "other-frozen-rule-observation"
                )
        non_scoring.append(
            NonScoringObservation(
                case_id=finding.case_id,
                cve_id=finding.cve_id,
                revision_role=finding.revision_role,
                original_relative_path=finding.original_relative_path,
                rule_id=finding.rule_id,
                start_line=finding.start_line,
                end_line=finding.end_line,
                classification=classification,
            )
        )
    scored = tuple(
        ScoredExpectation(
            case_id=item.case_id,
            cve_id=item.cve_id,
            case_family_id=item.case_family_id,
            project=item.project,
            revision_role=item.revision_role,
            rule_id=item.rule_id,
            expected_match=item.expected_match,
            observed_match=(item.case_id, item.revision_role, item.rule_id) in observed_keys,
            classification=classify_case(
                item.expected_match,
                (item.case_id, item.revision_role, item.rule_id) in observed_keys,
            ),
            discrimination_expectation=item.discrimination_expectation,
        )
        for item in inputs.expectations
    )
    return RealWorldEvaluation(
        scan=scan,
        scored=scored,
        metrics=calculate_metrics(item.classification for item in scored),
        per_rule=tuple(
            (
                rule_id,
                calculate_metrics(
                    item.classification for item in scored if item.rule_id == rule_id
                ),
            )
            for rule_id in sorted(PRODUCTION_RULE_IDS)
        ),
        observations=tuple(sorted(non_scoring)),
    )


def _scored_data(item: ScoredExpectation) -> dict[str, object]:
    return {
        "case_id": item.case_id,
        "classification": item.classification,
        "cve_id": item.cve_id,
        "discrimination_expectation": item.discrimination_expectation,
        "expected_match": item.expected_match,
        "observed_match": item.observed_match,
        "revision_role": item.revision_role,
        "rule_id": item.rule_id,
    }


def _observation_data(item: NonScoringObservation) -> dict[str, object]:
    return {
        "case_id": item.case_id,
        "classification": item.classification,
        "cve_id": item.cve_id,
        "end_line": item.end_line,
        "original_relative_path": item.original_relative_path,
        "revision_role": item.revision_role,
        "rule_id": item.rule_id,
        "start_line": item.start_line,
    }


def _relation_pairs(
    evaluation: RealWorldEvaluation,
) -> dict[tuple[str, str], dict[str, ScoredExpectation]]:
    pairs: dict[tuple[str, str], dict[str, ScoredExpectation]] = defaultdict(dict)
    for item in evaluation.scored:
        pairs[(item.cve_id, item.rule_id)][item.revision_role] = item
    if any(set(roles) != {"vulnerable", "fixed"} for roles in pairs.values()):
        raise ValueError("real-world relation pair is incomplete")
    return pairs


def build_report(
    inputs: FrozenRealWorldInputs,
    evaluation: RealWorldEvaluation,
) -> dict[str, object]:
    if (
        len(inputs.accepted_cases) != EXPECTED_CASE_COUNT
        or len(inputs.expectations) != EXPECTED_EXPECTATION_COUNT
        or len(evaluation.scored) != EXPECTED_EXPECTATION_COUNT
    ):
        raise ValueError("real-world evaluation frozen accounting is invalid")
    pairs = _relation_pairs(evaluation)
    applicable_cves = sorted({item.cve_id for item in evaluation.scored})
    vulnerable_by_cve: dict[str, list[ScoredExpectation]] = defaultdict(list)
    for item in evaluation.scored:
        if item.revision_role == "vulnerable":
            vulnerable_by_cve[item.cve_id].append(item)
    detected = sorted(
        cve
        for cve, items in vulnerable_by_cve.items()
        if any(item.observed_match for item in items)
    )
    missed = sorted(set(applicable_cves) - set(detected))
    should: list[dict[str, object]] = []
    persistent: list[dict[str, object]] = []
    for (cve_id, rule_id), roles in sorted(pairs.items()):
        vulnerable = roles["vulnerable"]
        fixed = roles["fixed"]
        if vulnerable.discrimination_expectation == "SHOULD_DISCRIMINATE":
            success = vulnerable.observed_match and not fixed.observed_match
            should.append({"cve_id": cve_id, "rule_id": rule_id, "success": success})
        else:
            persisted = vulnerable.observed_match and fixed.observed_match
            persistent.append(
                {"cve_id": cve_id, "persisted_as_expected": persisted, "rule_id": rule_id}
            )
    observation_counts = Counter(item.classification for item in evaluation.observations)
    represented = sorted({item.rule_id for item in evaluation.scored})
    applicable_projects = {item.project for item in evaluation.scored}
    applicable_families = {item.case_family_id for item in evaluation.scored}
    per_rule = [
        {
            "revision_expectation_count": sum(
                item.rule_id == rule_id for item in evaluation.scored
            ),
            "rule_id": rule_id,
            **metrics.canonical_data(),
        }
        for rule_id, metrics in evaluation.per_rule
    ]
    return {
        "applicability_proposal_digest": APPLICABILITY_PROPOSAL_DIGEST,
        "applicability_review_digest": APPLICABILITY_REVIEW_DIGEST,
        "applicability_summary_digest": APPLICABILITY_SUMMARY_DIGEST,
        "applicable_cve_count": len(applicable_cves),
        "applicable_relation_count": len(pairs),
        "applicable_unique_case_families": len(applicable_families),
        "applicable_unique_projects": len(applicable_projects),
        "baseline_commit": BASELINE_COMMIT,
        "baseline_tag": BASELINE_TAG,
        "claim_conformance": evaluation.metrics.canonical_data(),
        "discrimination": {
            "failed": [item for item in should if not item["success"]],
            "failures": sum(not item["success"] for item in should),
            "success_rate": (
                f"{sum(item['success'] for item in should) / len(should):.4f}" if should else None
            ),
            "successful": [item for item in should if item["success"]],
            "successes": sum(item["success"] for item in should),
            "should_discriminate_count": len(should),
        },
        "limitations": [
            "claim-conformance metrics apply only to the seven frozen applicable CVEs "
            "and fourteen revision expectations",
            "OUTSIDE_FROZEN_RULE_CLAIMS cases are observation-only and do not enter scoring",
            "only four of seventeen frozen rules have applicable real-world evidence",
            "related CVEs sharing a case family are not independent diversity",
            "PYTHON_SAST remains SCANNABLE and maturity belongs to F2F",
        ],
        "non_discrimination": {
            "expected_persistent_count": len(persistent),
            "persisted_as_expected": [item for item in persistent if item["persisted_as_expected"]],
            "persisted_as_expected_count": sum(
                item["persisted_as_expected"] for item in persistent
            ),
            "unexpected_disappearance": [
                item for item in persistent if not item["persisted_as_expected"]
            ],
            "unexpected_disappearance_count": sum(
                not item["persisted_as_expected"] for item in persistent
            ),
        },
        "non_scoring_observation_counts": {
            key: observation_counts[key]
            for key in (
                "cross-rule-in-cve-region",
                "other-frozen-rule-observation",
                "outside-case-observation",
                "same-rule-outside-cve-region",
            )
        },
        "per_cve_relation_results": [_scored_data(item) for item in evaluation.scored],
        "per_rule_claim_conformance": per_rule,
        "expected_negative_count": sum(not item.expected_match for item in evaluation.scored),
        "expected_positive_count": sum(item.expected_match for item in evaluation.scored),
        "revision_expectation_count": len(evaluation.scored),
        "claim_audit_digest": CLAIM_AUDIT_DIGEST,
        "claim_contract_digest": CLAIM_CONTRACT_DIGEST,
        "claim_contract_file_sha256": CLAIM_CONTRACT_FILE_SHA256,
        "rules_not_represented": sorted(PRODUCTION_RULE_IDS - set(represented)),
        "rules_represented": represented,
        "ruleset": {
            "digest": FROZEN_RULESET_DIGEST,
            "id": FROZEN_RULESET_ID,
            "version": FROZEN_RULESET_VERSION,
        },
        "scan_observation_accounting": {
            "duplicate_result_count": evaluation.scan.duplicate_result_count,
            "normalized_finding_count": evaluation.scan.accepted_result_count,
            "raw_result_count": evaluation.scan.raw_result_count,
            "scanner_analysis_gap_count": 0,
            "scanner_failure_count": 0,
        },
        "scanned_case_count": EXPECTED_CASE_COUNT,
        "scanned_revision_count": EXPECTED_REVISION_COUNT,
        "scanner_id": SCANNER_ID,
        "scanner_version": EXPECTED_SCANNER_VERSION,
        "schema_version": REPORT_SCHEMA_VERSION,
        "source_lock_digest": SOURCE_LOCK_DIGEST,
        "accepted_case_set_digest": ACCEPTED_CASE_SET_DIGEST,
        "vulnerable_cve_detection": {
            "detected": detected,
            "detected_count": len(detected),
            "missed": missed,
            "missed_count": len(missed),
            "vulnerable_detection_recall": (
                f"{len(detected) / len(applicable_cves):.4f}"
            ),
        },
    }


def build_review(
    evaluation: RealWorldEvaluation,
    report: dict[str, object],
) -> dict[str, object]:
    pairs = _relation_pairs(evaluation)
    failed_discrimination: list[dict[str, object]] = []
    unexpected_disappearance: list[dict[str, object]] = []
    for (cve_id, rule_id), roles in sorted(pairs.items()):
        vulnerable, fixed = roles["vulnerable"], roles["fixed"]
        if vulnerable.discrimination_expectation == "SHOULD_DISCRIMINATE":
            if not (vulnerable.observed_match and not fixed.observed_match):
                failed_discrimination.append(
                    {
                        "cve_id": cve_id,
                        "fixed_match": fixed.observed_match,
                        "rule_id": rule_id,
                        "vulnerable_match": vulnerable.observed_match,
                    }
                )
        elif not (vulnerable.observed_match and fixed.observed_match):
            unexpected_disappearance.append(
                {
                    "cve_id": cve_id,
                    "fixed_match": fixed.observed_match,
                    "rule_id": rule_id,
                    "vulnerable_match": vulnerable.observed_match,
                }
            )
    by_classification: dict[str, list[dict[str, object]]] = defaultdict(list)
    for item in evaluation.observations:
        by_classification[item.classification].append(_observation_data(item))
    successful = [item for item in evaluation.scored if item.classification in {"TP", "TN"}]
    representatives: list[dict[str, object]] = []
    for rule_id in sorted({item.rule_id for item in successful}):
        for classification in ("TP", "TN"):
            eligible = sorted(
                (
                    item
                    for item in successful
                    if item.rule_id == rule_id and item.classification == classification
                ),
                key=lambda item: (item.cve_id, item.revision_role),
            )
            representatives.extend(_scored_data(item) for item in eligible[:2])
    return {
        "cross_rule_observations": by_classification["cross-rule-in-cve-region"],
        "failed_discrimination_cases": failed_discrimination,
        "failures": [
            _scored_data(item) for item in evaluation.scored if item.classification in {"FN", "FP"}
        ],
        "other_frozen_rule_observations": by_classification["other-frozen-rule-observation"],
        "outside_case_observations": by_classification["outside-case-observation"],
        "report_digest": report_digest(report),
        "representative_successful_relations": representatives,
        "same_rule_outside_cve_region_observations": by_classification[
            "same-rule-outside-cve-region"
        ],
        "schema_version": REVIEW_SCHEMA_VERSION,
        "unexpected_disappearance_cases": unexpected_disappearance,
    }


def run_evaluation(
    repository_root: Path,
    executable: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    inputs = load_frozen_inputs(repository_root)
    scan = execute_controlled_scan(repository_root, inputs, executable)
    evaluation = evaluate_observations(inputs, scan)
    report = build_report(inputs, evaluation)
    return report, build_review(evaluation, report)


def record_evidence(
    report_path: Path,
    review_path: Path,
    report_payload: bytes,
    review_payload: bytes,
) -> bool:
    if (
        not report_payload
        or not review_payload
        or report_path.parent != review_path.parent
        or report_path == review_path
    ):
        raise ValueError("real-world evaluation evidence is invalid")
    states: list[bool] = []
    for path, payload in ((report_path, report_payload), (review_path, review_payload)):
        if path.exists():
            if path.is_symlink() or not path.is_file() or path.read_bytes() != payload:
                raise FileExistsError("real-world evaluation evidence already differs")
            states.append(True)
        else:
            states.append(False)
    if all(states):
        return False
    if any(states):
        raise FileExistsError("real-world evaluation evidence is incomplete")
    temporary_paths: list[Path] = []
    created_paths: list[Path] = []
    try:
        for path, payload in ((report_path, report_payload), (review_path, review_payload)):
            descriptor, name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
            temporary = Path(name)
            temporary_paths.append(temporary)
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary, 0o644)
        for temporary, destination in zip(temporary_paths, (report_path, review_path), strict=True):
            os.link(temporary, destination, follow_symlinks=False)
            created_paths.append(destination)
    except OSError as exc:
        for path in created_paths:
            path.unlink(missing_ok=True)
        raise FileExistsError("real-world evaluation evidence could not be recorded") from exc
    finally:
        for path in temporary_paths:
            path.unlink(missing_ok=True)
    return True
