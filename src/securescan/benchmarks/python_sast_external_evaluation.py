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
    SCANNER_ID,
    BenchmarkMetrics,
    calculate_metrics,
    classify_case,
)
from securescan.benchmarks.python_sast_applicability import (
    EXPECTED_CANDIDATE_COUNT,
    EXPECTED_CANDIDATE_INVENTORY_DIGEST,
    EXPECTED_REVIEW_SELECTION_DIGEST,
    EXPECTED_SOURCE_LOCK_DIGEST,
    FROZEN_RULESET_DIGEST,
    FROZEN_RULESET_ID,
    FROZEN_RULESET_VERSION,
    RULE_IDS,
    ApplicabilityDecision,
    RuleClaimCatalog,
    _candidate_source,
    load_applicability_proposal,
    load_rule_claim_catalog,
    proposal_digest,
    rule_claim_catalog_digest,
)
from securescan.benchmarks.python_sast_external import (
    Candidate,
    SourceLock,
    candidate_inventory_digest,
    load_candidate_inventory,
    load_source_lock,
    source_lock_digest,
    verify_external_sources,
)
from securescan.scanners.semgrep import SemgrepAdapterError, parse_semgrep_output
from securescan.workspaces.models import (
    RepositoryManifest,
    RepositoryManifestEntry,
    repository_content_digest,
)

REPORT_SCHEMA_VERSION: Final = "securescan-python-sast-external-evaluation-v1"
REVIEW_SCHEMA_VERSION: Final = "securescan-python-sast-external-evaluation-review-v1"
EXPECTED_RULE_CLAIM_CATALOG_DIGEST: Final = (
    "02741b7745a8d61648eb67d0132923599c7fb110d8cedbc05bb311b2601befc9"
)
EXPECTED_APPLICABILITY_PROPOSAL_DIGEST: Final = (
    "9c28edc88c99a6f04500faecd0c323a9b74941c59860198a4abadf85a64bba75"
)
EXPECTED_SCORING_RELATION_COUNT: Final = 579
EXPECTED_APPLICABILITY_COUNTS: Final = {
    "APPLICABLE_NEGATIVE": 179,
    "APPLICABLE_POSITIVE": 400,
    "EXCLUDED": 33,
    "OUT_OF_SCOPE": 848,
    "UNRESOLVED": 0,
}
MAXIMUM_RESULT_BYTES: Final = 64 * 1024 * 1024
_BENCHMARK_RELATIVE_ROOT: Final = Path("benchmarks/python_sast_external")
_CACHE_RELATIVE_ROOT: Final = Path(".cache/securescan-benchmarks")
_RULESET_RELATIVE_PATH: Final = Path(
    "src/securescan/scanners/semgrep/rules/securescan-python-baseline-v2.yml"
)
_SHA256_PATTERN_LENGTH: Final = 64


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_report(report: dict[str, object]) -> bytes:
    return _canonical_json(report) + b"\n"


def report_digest(report: dict[str, object]) -> str:
    return hashlib.sha256(canonical_report(report)).hexdigest()


def _load_json(path: Path) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = item
        return value

    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {value}")
            ),
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError("external evaluation JSON is invalid") from exc


@dataclass(frozen=True, slots=True)
class FrozenExternalInputs:
    source_lock: SourceLock
    candidates: tuple[Candidate, ...]
    catalog: RuleClaimCatalog
    proposal: dict[str, object]
    decisions: tuple[ApplicabilityDecision, ...]


def load_frozen_external_inputs(repository_root: Path) -> FrozenExternalInputs:
    benchmark_root = repository_root / _BENCHMARK_RELATIVE_ROOT
    cache_root = repository_root / _CACHE_RELATIVE_ROOT
    source_lock = load_source_lock(benchmark_root / "sources.lock.json")
    if source_lock_digest(source_lock) != EXPECTED_SOURCE_LOCK_DIGEST:
        raise ValueError("external evaluation source-lock binding mismatch")
    inventory_path = benchmark_root / "candidates.json"
    inventory = _load_json(inventory_path)
    if not isinstance(inventory, dict):
        raise ValueError("external evaluation candidate binding mismatch")
    candidates = load_candidate_inventory(inventory_path, EXPECTED_SOURCE_LOCK_DIGEST)
    if (
        candidate_inventory_digest(inventory) != EXPECTED_CANDIDATE_INVENTORY_DIGEST
        or len(candidates) != EXPECTED_CANDIDATE_COUNT
    ):
        raise ValueError("external evaluation candidate binding mismatch")
    catalog = load_rule_claim_catalog(benchmark_root / "rule-claims.json")
    if rule_claim_catalog_digest(catalog) != EXPECTED_RULE_CLAIM_CATALOG_DIGEST:
        raise ValueError("external evaluation claim-catalog binding mismatch")
    proposal, decisions = load_applicability_proposal(
        benchmark_root / "applicability-proposal.json",
        candidates,
        catalog,
        cache_root,
        source_lock,
    )
    raw_counts = Counter(decision.disposition for decision in decisions)
    counts = {
        disposition: raw_counts.get(disposition, 0)
        for disposition in EXPECTED_APPLICABILITY_COUNTS
    }
    if (
        proposal_digest(proposal) != EXPECTED_APPLICABILITY_PROPOSAL_DIGEST
        or proposal.get("review_selection_digest") != EXPECTED_REVIEW_SELECTION_DIGEST
        or counts != EXPECTED_APPLICABILITY_COUNTS
        or sum(
            decision.disposition in {"APPLICABLE_POSITIVE", "APPLICABLE_NEGATIVE"}
            for decision in decisions
        )
        != EXPECTED_SCORING_RELATION_COUNT
    ):
        raise ValueError("external evaluation applicability binding mismatch")
    verify_external_sources(cache_root, source_lock)
    return FrozenExternalInputs(source_lock, candidates, catalog, proposal, decisions)


@dataclass(frozen=True, slots=True, order=True)
class ProjectionEntry:
    scanner_path: str
    candidate_id: str
    source_sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class CandidateProjection:
    root: Path
    entries: tuple[ProjectionEntry, ...]
    manifest: RepositoryManifest

    def candidate_for_path(self, scanner_path: str) -> str:
        try:
            return next(
                entry.candidate_id for entry in self.entries if entry.scanner_path == scanner_path
            )
        except StopIteration as exc:
            raise ValueError("external evaluation scanner path is unknown") from exc


def projection_path(candidate: Candidate) -> str:
    value = (
        f"cases/{candidate.external_source_id}/{candidate.framework}/"
        f"{candidate.external_case_id}.py"
    )
    path = PurePosixPath(value)
    if (
        path.as_posix() != value
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("external evaluation projection path is invalid")
    return value


def _projection_file(root: Path, relative_path: str) -> Path:
    path = root.joinpath(*PurePosixPath(relative_path).parts)
    try:
        root_resolved = root.resolve(strict=True)
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
        resolved.relative_to(root_resolved)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("external evaluation projection is invalid") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or resolved != path.absolute()
    ):
        raise ValueError("external evaluation projection is invalid")
    return path


def verify_projection(projection: CandidateProjection) -> None:
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
        raise ValueError("external evaluation projection is invalid") from exc
    if observed_files != expected_paths:
        raise ValueError("external evaluation projection is invalid")
    for entry in projection.entries:
        path = _projection_file(projection.root, entry.scanner_path)
        data = path.read_bytes()
        if (
            len(data) != entry.size_bytes
            or hashlib.sha256(data).hexdigest() != entry.source_sha256
        ):
            raise ValueError("external evaluation projection is invalid")


def create_projection(
    projection_root: Path,
    cache_root: Path,
    candidates: tuple[Candidate, ...],
    source_lock: SourceLock,
) -> CandidateProjection:
    try:
        projection_root.mkdir(mode=0o700)
        if projection_root.is_symlink() or not projection_root.is_dir():
            raise ValueError
    except (OSError, ValueError) as exc:
        raise ValueError("external evaluation projection root is invalid") from exc
    entries: list[ProjectionEntry] = []
    seen_paths: set[str] = set()
    seen_candidates: set[str] = set()
    for candidate in candidates:
        scanner_path = projection_path(candidate)
        if scanner_path in seen_paths or candidate.candidate_id in seen_candidates:
            raise ValueError("external evaluation projection mapping is invalid")
        source = _candidate_source(cache_root, source_lock, candidate)
        destination = projection_root.joinpath(*PurePosixPath(scanner_path).parts)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            with destination.open("xb") as output:
                output.write(source)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(destination, 0o600)
        except OSError as exc:
            raise ValueError("external evaluation projection write failed") from exc
        entries.append(
            ProjectionEntry(
                scanner_path=scanner_path,
                candidate_id=candidate.candidate_id,
                source_sha256=candidate.source_sha256,
                size_bytes=len(source),
            )
        )
        seen_paths.add(scanner_path)
        seen_candidates.add(candidate.candidate_id)
    entry_tuple = tuple(sorted(entries))
    if len(entry_tuple) != len(candidates):
        raise ValueError("external evaluation projection mapping is invalid")
    manifest_entries = tuple(
        RepositoryManifestEntry(
            relative_path=entry.scanner_path,
            size_bytes=entry.size_bytes,
            sha256=entry.source_sha256,
        )
        for entry in entry_tuple
    )
    manifest = RepositoryManifest(
        entries=manifest_entries,
        file_count=len(manifest_entries),
        total_bytes=sum(entry.size_bytes for entry in manifest_entries),
        content_digest=repository_content_digest(manifest_entries),
    )
    projection = CandidateProjection(projection_root, entry_tuple, manifest)
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


def verify_scanner_identity(
    repository_root: Path,
    executable: Path,
    temporary_root: Path,
) -> None:
    expected = expected_scanner_executable(repository_root)
    if executable.absolute() != expected.absolute() or not executable.is_file():
        raise ValueError("external evaluation scanner executable is invalid")
    try:
        result = subprocess.run(
            [os.fspath(executable), "--disable-version-check", "--version"],
            cwd=repository_root,
            env=controlled_environment(temporary_root, executable),
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("external evaluation scanner identity check failed") from exc
    try:
        version = result.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("external evaluation scanner identity is invalid") from exc
    if result.returncode != 0 or version != EXPECTED_SCANNER_VERSION:
        raise ValueError("external evaluation scanner identity is invalid")


@dataclass(frozen=True, slots=True, order=True)
class ObservedRelation:
    candidate_id: str
    rule_id: str
    observation_count: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.candidate_id, str)
            or not self.candidate_id
            or self.candidate_id != self.candidate_id.strip()
            or self.rule_id not in RULE_IDS
            or not isinstance(self.observation_count, int)
            or isinstance(self.observation_count, bool)
            or self.observation_count < 1
        ):
            raise ValueError("external evaluation observed relation is invalid")


@dataclass(frozen=True, slots=True)
class ScanObservations:
    scanner_id: str
    scanner_version: str
    relations: tuple[ObservedRelation, ...]
    raw_result_count: int
    accepted_result_count: int

    def __post_init__(self) -> None:
        if (
            self.scanner_id != SCANNER_ID
            or self.scanner_version != EXPECTED_SCANNER_VERSION
            or self.relations != tuple(sorted(self.relations))
            or len({(item.candidate_id, item.rule_id) for item in self.relations})
            != len(self.relations)
            or not isinstance(self.raw_result_count, int)
            or isinstance(self.raw_result_count, bool)
            or not isinstance(self.accepted_result_count, int)
            or isinstance(self.accepted_result_count, bool)
            or self.raw_result_count < self.accepted_result_count
            or self.accepted_result_count < 0
            or sum(item.observation_count for item in self.relations)
            != self.accepted_result_count
        ):
            raise ValueError("external evaluation scanner observations are invalid")


def normalize_scanner_output(
    raw_output: bytes,
    projection: CandidateProjection,
) -> ScanObservations:
    try:
        parsed = parse_semgrep_output(
            raw_output,
            projection.manifest,
            scanner_id=SCANNER_ID,
            scanner_version=EXPECTED_SCANNER_VERSION,
        )
    except SemgrepAdapterError as exc:
        raise ValueError("external evaluation scanner output is malformed") from exc
    if parsed.analysis_gaps:
        raise ValueError("external evaluation scanner output contains analysis gaps")
    if parsed.output_version != EXPECTED_SCANNER_VERSION:
        raise ValueError("external evaluation scanner output version is invalid")
    counts: Counter[tuple[str, str]] = Counter()
    for finding in parsed.findings:
        if finding.path is None or finding.rule_id not in RULE_IDS:
            raise ValueError("external evaluation scanner observation is invalid")
        candidate_id = projection.candidate_for_path(finding.path)
        counts[(candidate_id, finding.rule_id)] += 1
    relations = tuple(
        ObservedRelation(candidate_id, rule_id, count)
        for (candidate_id, rule_id), count in sorted(counts.items())
    )
    return ScanObservations(
        scanner_id=SCANNER_ID,
        scanner_version=EXPECTED_SCANNER_VERSION,
        relations=relations,
        raw_result_count=parsed.raw_result_count,
        accepted_result_count=parsed.accepted_result_count,
    )


def execute_controlled_scan(
    repository_root: Path,
    inputs: FrozenExternalInputs,
    executable: Path,
) -> ScanObservations:
    ruleset_path = repository_root / _RULESET_RELATIVE_PATH
    if hashlib.sha256(ruleset_path.read_bytes()).hexdigest() != FROZEN_RULESET_DIGEST:
        raise ValueError("external evaluation ruleset identity is invalid")
    with tempfile.TemporaryDirectory(prefix="securescan-python-sast-external-") as name:
        temporary_root = Path(name)
        verify_scanner_identity(repository_root, executable, temporary_root)
        projection = create_projection(
            temporary_root / "projection",
            repository_root / _CACHE_RELATIVE_ROOT,
            inputs.candidates,
            inputs.source_lock,
        )
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
                timeout=300,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError("external evaluation scanner execution failed") from exc
        if result.returncode != 0:
            raise RuntimeError("external evaluation scanner execution failed")
        if len(result.stdout) > MAXIMUM_RESULT_BYTES:
            raise ValueError("external evaluation scanner output is too large")
        verify_projection(projection)
        return normalize_scanner_output(result.stdout, projection)


@dataclass(frozen=True, slots=True, order=True)
class ScoredRelation:
    candidate_id: str
    rule_id: str
    expected_match: bool
    observed_match: bool
    classification: str


@dataclass(frozen=True, slots=True, order=True)
class NonScoringObservation:
    candidate_id: str
    rule_id: str
    observation_count: int
    classification: str


@dataclass(frozen=True, slots=True)
class RuleEvaluation:
    rule_id: str
    applicable_positive_count: int
    applicable_negative_count: int
    metrics: BenchmarkMetrics

    def canonical_data(self) -> dict[str, object]:
        return {
            "applicable_negative_count": self.applicable_negative_count,
            "applicable_positive_count": self.applicable_positive_count,
            **self.metrics.canonical_data(),
            "rule_id": self.rule_id,
        }


@dataclass(frozen=True, slots=True)
class ExternalEvaluation:
    observations: ScanObservations
    scored_relations: tuple[ScoredRelation, ...]
    overall: BenchmarkMetrics
    per_rule: tuple[RuleEvaluation, ...]
    unexpected_cross_rule: tuple[NonScoringObservation, ...]
    out_of_scope: tuple[NonScoringObservation, ...]
    excluded: tuple[NonScoringObservation, ...]


def evaluate_external_relations(
    decisions: tuple[ApplicabilityDecision, ...],
    candidates: tuple[Candidate, ...],
    observations: ScanObservations,
) -> ExternalEvaluation:
    candidate_ids = {candidate.candidate_id for candidate in candidates}
    decision_by_id = {decision.candidate_id: decision for decision in decisions}
    if set(decision_by_id) != candidate_ids or len(decision_by_id) != len(decisions):
        raise ValueError("external evaluation decisions are invalid")
    observed: dict[tuple[str, str], int] = {}
    for relation in observations.relations:
        key = (relation.candidate_id, relation.rule_id)
        if (
            relation.candidate_id not in candidate_ids
            or relation.rule_id not in RULE_IDS
            or not isinstance(relation.observation_count, int)
            or isinstance(relation.observation_count, bool)
            or relation.observation_count < 1
            or key in observed
        ):
            raise ValueError("external evaluation observation is invalid")
        observed[key] = relation.observation_count
    scored: list[ScoredRelation] = []
    for decision in decisions:
        if decision.disposition not in {"APPLICABLE_POSITIVE", "APPLICABLE_NEGATIVE"}:
            continue
        assert decision.expected_rule_id is not None
        assert decision.expected_match is not None
        matched = (decision.candidate_id, decision.expected_rule_id) in observed
        scored.append(
            ScoredRelation(
                candidate_id=decision.candidate_id,
                rule_id=decision.expected_rule_id,
                expected_match=decision.expected_match,
                observed_match=matched,
                classification=classify_case(decision.expected_match, matched),
            )
        )
    unexpected: list[NonScoringObservation] = []
    out_of_scope: list[NonScoringObservation] = []
    excluded: list[NonScoringObservation] = []
    for (candidate_id, rule_id), count in sorted(observed.items()):
        decision = decision_by_id[candidate_id]
        if (
            decision.disposition in {"APPLICABLE_POSITIVE", "APPLICABLE_NEGATIVE"}
            and rule_id == decision.expected_rule_id
        ):
            continue
        if decision.disposition in {"APPLICABLE_POSITIVE", "APPLICABLE_NEGATIVE"}:
            target, classification = unexpected, "unexpected-cross-rule-observation"
        elif decision.disposition == "OUT_OF_SCOPE":
            target, classification = out_of_scope, "out-of-scope-observation"
        elif decision.disposition == "EXCLUDED":
            target, classification = excluded, "excluded-case-observation"
        else:
            raise ValueError("external evaluation unresolved applicability is invalid")
        target.append(NonScoringObservation(candidate_id, rule_id, count, classification))
    scored_tuple = tuple(scored)
    per_rule = tuple(
        RuleEvaluation(
            rule_id=rule_id,
            applicable_positive_count=sum(
                item.rule_id == rule_id and item.expected_match for item in scored_tuple
            ),
            applicable_negative_count=sum(
                item.rule_id == rule_id and not item.expected_match for item in scored_tuple
            ),
            metrics=calculate_metrics(
                item.classification for item in scored_tuple if item.rule_id == rule_id
            ),
        )
        for rule_id in sorted(RULE_IDS)
    )
    return ExternalEvaluation(
        observations=observations,
        scored_relations=scored_tuple,
        overall=calculate_metrics(item.classification for item in scored_tuple),
        per_rule=per_rule,
        unexpected_cross_rule=tuple(unexpected),
        out_of_scope=tuple(out_of_scope),
        excluded=tuple(excluded),
    )


def _classification_counts(
    evaluation: ExternalEvaluation,
    candidates: tuple[Candidate, ...],
    attribute: str,
) -> dict[str, dict[str, int]]:
    candidates_by_id = {candidate.candidate_id: candidate for candidate in candidates}
    counts: dict[str, Counter[str]] = defaultdict(Counter)
    for relation in evaluation.scored_relations:
        value = str(getattr(candidates_by_id[relation.candidate_id], attribute))
        counts[value][relation.classification] += 1
    return {
        value: {
            classification: total.get(classification, 0)
            for classification in ("TP", "FP", "FN", "TN")
        }
        for value, total in sorted(counts.items())
    }


def _observation_data(
    observations: tuple[NonScoringObservation, ...],
    candidates_by_id: dict[str, Candidate],
    decisions_by_id: dict[str, ApplicabilityDecision],
) -> list[dict[str, object]]:
    return [
        {
            "candidate_disposition": decisions_by_id[observation.candidate_id].disposition,
            "candidate_id": observation.candidate_id,
            "classification": observation.classification,
            "external_source_id": candidates_by_id[observation.candidate_id].external_source_id,
            "framework": candidates_by_id[observation.candidate_id].framework,
            "observation_count": observation.observation_count,
            "rule_id": observation.rule_id,
        }
        for observation in observations
    ]


def _non_scoring_counts(
    evaluation: ExternalEvaluation,
    candidates_by_id: dict[str, Candidate],
    decisions_by_id: dict[str, ApplicabilityDecision],
) -> dict[str, dict[str, int]]:
    observations = (
        evaluation.unexpected_cross_rule + evaluation.out_of_scope + evaluation.excluded
    )
    dimensions: dict[str, Counter[str]] = {
        "candidate_disposition": Counter(),
        "classification": Counter(),
        "external_source": Counter(),
        "framework": Counter(),
        "rule": Counter(),
    }
    for observation in observations:
        candidate = candidates_by_id[observation.candidate_id]
        decision = decisions_by_id[observation.candidate_id]
        dimensions["candidate_disposition"][decision.disposition] += 1
        dimensions["classification"][observation.classification] += 1
        dimensions["external_source"][candidate.external_source_id] += 1
        dimensions["framework"][candidate.framework] += 1
        dimensions["rule"][observation.rule_id] += 1
    return {
        dimension: dict(sorted(counts.items()))
        for dimension, counts in sorted(dimensions.items())
    }


def build_external_report(
    inputs: FrozenExternalInputs,
    evaluation: ExternalEvaluation,
) -> dict[str, object]:
    raw_applicability_counts = Counter(
        decision.disposition for decision in inputs.decisions
    )
    applicability_counts = {
        disposition: raw_applicability_counts.get(disposition, 0)
        for disposition in EXPECTED_APPLICABILITY_COUNTS
    }
    if (
        len(inputs.candidates) != EXPECTED_CANDIDATE_COUNT
        or len(evaluation.scored_relations) != EXPECTED_SCORING_RELATION_COUNT
        or applicability_counts != EXPECTED_APPLICABILITY_COUNTS
    ):
        raise ValueError("external evaluation frozen accounting is invalid")
    candidates_by_id = {candidate.candidate_id: candidate for candidate in inputs.candidates}
    decisions_by_id = {decision.candidate_id: decision for decision in inputs.decisions}
    per_rule = [item.canonical_data() for item in evaluation.per_rule]
    return {
        "applicability_counts": dict(sorted(applicability_counts.items())),
        "applicability_proposal_digest": EXPECTED_APPLICABILITY_PROPOSAL_DIGEST,
        "candidate_inventory_digest": EXPECTED_CANDIDATE_INVENTORY_DIGEST,
        "excluded_case_observations": _observation_data(
            evaluation.excluded, candidates_by_id, decisions_by_id
        ),
        "fn_candidate_ids": sorted(
            item.candidate_id
            for item in evaluation.scored_relations
            if item.classification == "FN"
        ),
        "fp_candidate_ids": sorted(
            item.candidate_id
            for item in evaluation.scored_relations
            if item.classification == "FP"
        ),
        "observed_finding_count": evaluation.observations.accepted_result_count,
        "raw_scanner_result_count": evaluation.observations.raw_result_count,
        "observed_relation_count": len(evaluation.observations.relations),
        "non_scoring_observation_counts": _non_scoring_counts(
            evaluation, candidates_by_id, decisions_by_id
        ),
        "overall": evaluation.overall.canonical_data(),
        "out_of_scope_observations": _observation_data(
            evaluation.out_of_scope, candidates_by_id, decisions_by_id
        ),
        "per_rule": per_rule,
        "review_selection_digest": EXPECTED_REVIEW_SELECTION_DIGEST,
        "rule_claim_catalog_digest": EXPECTED_RULE_CLAIM_CATALOG_DIGEST,
        "rules_lacking_external_negative_evidence": [
            item.rule_id for item in evaluation.per_rule if item.applicable_negative_count == 0
        ],
        "rules_lacking_external_positive_evidence": [
            item.rule_id for item in evaluation.per_rule if item.applicable_positive_count == 0
        ],
        "rules_with_external_negative_evidence": [
            item.rule_id for item in evaluation.per_rule if item.applicable_negative_count > 0
        ],
        "rules_with_external_negative_evidence_count": sum(
            item.applicable_negative_count > 0 for item in evaluation.per_rule
        ),
        "rules_with_external_positive_evidence": [
            item.rule_id for item in evaluation.per_rule if item.applicable_positive_count > 0
        ],
        "rules_with_external_positive_evidence_count": sum(
            item.applicable_positive_count > 0 for item in evaluation.per_rule
        ),
        "ruleset": {
            "digest": FROZEN_RULESET_DIGEST,
            "id": FROZEN_RULESET_ID,
            "version": FROZEN_RULESET_VERSION,
        },
        "scanner_id": evaluation.observations.scanner_id,
        "scanner_version": evaluation.observations.scanner_version,
        "scanned_candidate_count": len(inputs.candidates),
        "scored_relation_count": len(evaluation.scored_relations),
        "scoring_by_framework": _classification_counts(
            evaluation, inputs.candidates, "framework"
        ),
        "scoring_by_source": _classification_counts(
            evaluation, inputs.candidates, "external_source_id"
        ),
        "schema_version": REPORT_SCHEMA_VERSION,
        "source_lock_digest": EXPECTED_SOURCE_LOCK_DIGEST,
        "total_frozen_rule_count": len(RULE_IDS),
        "unexpected_cross_rule_observations": _observation_data(
            evaluation.unexpected_cross_rule, candidates_by_id, decisions_by_id
        ),
    }


def _candidate_review_record(
    candidate: Candidate,
    decision: ApplicabilityDecision,
    observed_rule_ids: tuple[str, ...],
    *,
    classification: str,
) -> dict[str, object]:
    return {
        "candidate_id": candidate.candidate_id,
        "classification": classification,
        "cwe": candidate.cwe,
        "disposition": decision.disposition,
        "evidence": [item.canonical_data() for item in decision.evidence],
        "expected_rule_id": decision.expected_rule_id,
        "external_source_id": candidate.external_source_id,
        "framework": candidate.framework,
        "observed_rule_ids": list(observed_rule_ids),
        "relative_source_path": candidate.relative_source_path,
        "source_sha256": candidate.source_sha256,
    }


def build_external_review(
    inputs: FrozenExternalInputs,
    evaluation: ExternalEvaluation,
    report: dict[str, object],
) -> dict[str, object]:
    candidate_by_id = {candidate.candidate_id: candidate for candidate in inputs.candidates}
    decision_by_id = {decision.candidate_id: decision for decision in inputs.decisions}
    observed_by_id: dict[str, set[str]] = defaultdict(set)
    for relation in evaluation.observations.relations:
        observed_by_id[relation.candidate_id].add(relation.rule_id)

    def record(candidate_id: str, classification: str) -> dict[str, object]:
        return _candidate_review_record(
            candidate_by_id[candidate_id],
            decision_by_id[candidate_id],
            tuple(sorted(observed_by_id[candidate_id])),
            classification=classification,
        )

    failures = [
        record(item.candidate_id, item.classification)
        for item in evaluation.scored_relations
        if item.classification in {"FN", "FP"}
    ]
    representatives: list[dict[str, object]] = []
    for rule_id in sorted(RULE_IDS):
        for classification in ("TP", "TN"):
            eligible = [
                item
                for item in evaluation.scored_relations
                if item.rule_id == rule_id and item.classification == classification
            ]
            ranked = sorted(
                eligible,
                key=lambda item: (
                    hashlib.sha256(
                        f"{rule_id}\0{classification}\0{item.candidate_id}".encode()
                    ).hexdigest(),
                    item.candidate_id,
                ),
            )
            representatives.extend(record(item.candidate_id, classification) for item in ranked[:3])

    def non_scoring_records(
        observations: tuple[NonScoringObservation, ...],
    ) -> list[dict[str, object]]:
        records = []
        for item in observations:
            value = record(item.candidate_id, item.classification)
            value["observation_count"] = item.observation_count
            value["observation_rule_id"] = item.rule_id
            records.append(value)
        return records

    return {
        "excluded_case_observations": non_scoring_records(evaluation.excluded),
        "failures": failures,
        "out_of_scope_observations": non_scoring_records(evaluation.out_of_scope),
        "report_digest": report_digest(report),
        "representative_tp_tn": representatives,
        "schema_version": REVIEW_SCHEMA_VERSION,
        "unexpected_cross_rule_observations": non_scoring_records(
            evaluation.unexpected_cross_rule
        ),
    }


def run_external_evaluation(
    repository_root: Path,
    executable: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    inputs = load_frozen_external_inputs(repository_root)
    observations = execute_controlled_scan(repository_root, inputs, executable)
    evaluation = evaluate_external_relations(inputs.decisions, inputs.candidates, observations)
    report = build_external_report(inputs, evaluation)
    review = build_external_review(inputs, evaluation, report)
    return report, review


def record_external_evidence(
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
        raise ValueError("external evaluation evidence is invalid")
    states = []
    for path, payload in ((report_path, report_payload), (review_path, review_payload)):
        if path.exists():
            if path.is_symlink() or not path.is_file() or path.read_bytes() != payload:
                raise FileExistsError("external evaluation evidence already exists")
            states.append(True)
        else:
            states.append(False)
    if all(states):
        return False
    if any(states):
        raise FileExistsError("external evaluation evidence is incomplete")
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
        for temporary, destination in zip(
            temporary_paths, (report_path, review_path), strict=True
        ):
            os.link(temporary, destination, follow_symlinks=False)
            created_paths.append(destination)
    except OSError as exc:
        for path in created_paths:
            path.unlink(missing_ok=True)
        raise FileExistsError("external evaluation evidence could not be recorded") from exc
    finally:
        for path in temporary_paths:
            path.unlink(missing_ok=True)
    return True
