from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from securescan.benchmarks.python_sast import PRODUCTION_RULE_IDS
from securescan.source.enums import AnalysisCapability, SourceSupportState

SCHEMA_VERSION: Final = "securescan-python-sast-maturity-decision-v1"
BASELINE_TAG: Final = "source-v0.3F2E5-python-sast-realworld-evaluation-v2"
BASELINE_COMMIT: Final = "a3bf97fdb933e354f7b74231ba27b2d4cd6da3db"
RULESET_ID: Final = "securescan-python-baseline-v2"
RULESET_VERSION: Final = "2"
RULESET_DIGEST: Final = (
    "e10fb04e6b5abb35e0b83bdd718c2e973a8026e3630e420dc398db95e59d01a5"
)
SCANNER_ID: Final = "semgrep-ce"
SCANNER_VERSION: Final = "1.171.0"
MATURITY: Final = SourceSupportState.SCANNABLE

FROZEN_FILE_SHA256: Final = {
    "benchmarks/python_sast/initial-v0.3e-baseline.json": (
        "6784c114aab842ebabd181bd8a749949bd04b1f534f40115599eec7e8173b814"
    ),
    "benchmarks/python_sast/manifest.json": (
        "94bfee50f074e63e6f126da1b3305fd00bdadb14c54bbb8e61db85b54ade97a1"
    ),
    "benchmarks/python_sast_external/external-evaluation-report.json": (
        "60fc8ea9e4e6f9dc5a638cb5aead4577d681565adb839af8aabc6516a1c8b852"
    ),
    "benchmarks/python_sast_external/external-evaluation-review.json": (
        "ee724338f581f3ab5b8bc71ea99c48933ed3032bb82d4c9965479d6a79e1b0b2"
    ),
    "benchmarks/python_sast_external/rule-claim-conformance-audit-v2.json": (
        "d821fd7ca273c7a45e3cd0c548f96d3ad2bf0f7ea54b3ca6054d7c991a0dbf81"
    ),
    "benchmarks/python_sast_external/rule-claims-v2.json": (
        "70b3c50f33526e5db40bbb4ee8c89c561a2ecfaa7cfbb4e01934d9656c7993b3"
    ),
    "benchmarks/python_sast_realworld/applicability-proposal-v2.json": (
        "96267be4d421582b1f9834cf2bd2750096c727a75a2cc39cd139baf7f58bc478"
    ),
    "benchmarks/python_sast_realworld/applicability-review-v2.json": (
        "4b0c7e551ffc3163941a4358ce3de8572505bd6aa2172e6440668e7d2aba0464"
    ),
    "benchmarks/python_sast_realworld/applicability-summary-v2.json": (
        "b9286a5d601e0815bd68c6cb73052740e4b34e1d155591341a6ed683b140c083"
    ),
    "benchmarks/python_sast_realworld/realworld-evaluation-report-v2.json": (
        "8d95dc6624966524c4942437b481a00eb8728020907182c905952f98681db36d"
    ),
    "benchmarks/python_sast_realworld/realworld-evaluation-review-v2.json": (
        "edcac881225f08d9977ee518aee705cae14cc51b44f4e7555d4ffaa8dc31a62d"
    ),
    "src/securescan/scanners/semgrep/rules/securescan-python-baseline-v2.yml": (
        RULESET_DIGEST
    ),
}

_LOCAL_CORPUS_DIGEST: Final = (
    "2a3b3a3b001ce251a5fceafc82cfd1a1599cd9d8d3d6a81de424ae393113adec"
)
_F2D_SOURCE_LOCK_DIGEST: Final = (
    "ded3352210520814c03532686096a834c0fac95de51cdb13b02bda4a6aeefd23"
)
_F2D_CANDIDATE_DIGEST: Final = (
    "84e60a1e411ed2f517356e2a6a11bf1fe03fc4945672d120cdb50ead9d4dd60b"
)
_F2D_REVIEW_SELECTION_DIGEST: Final = (
    "81cb5657d9501bfd0f5aa41125813168bf811788d02d8603ade43e6482384534"
)
_F2D_CLAIM_CATALOG_DIGEST: Final = (
    "02741b7745a8d61648eb67d0132923599c7fb110d8cedbc05bb311b2601befc9"
)
_F2D_APPLICABILITY_DIGEST: Final = (
    "9c28edc88c99a6f04500faecd0c323a9b74941c59860198a4abadf85a64bba75"
)
_F2E4_CONTRACT_DIGEST: Final = (
    "0e0d9a118a7567049ad26f046b0f097ba8390d74f05f2b721452683ee3c2e62d"
)
_F2E4_AUDIT_DIGEST: Final = (
    "d9c6b52c77e6fc8fdd4a8ea8ba9a29274bd7f416622c35904a44d3c4348e7d2a"
)
_F2E4_PROPOSAL_DIGEST: Final = FROZEN_FILE_SHA256[
    "benchmarks/python_sast_realworld/applicability-proposal-v2.json"
]
_F2E4_SUMMARY_DIGEST: Final = FROZEN_FILE_SHA256[
    "benchmarks/python_sast_realworld/applicability-summary-v2.json"
]
_F2E4_REVIEW_DIGEST: Final = FROZEN_FILE_SHA256[
    "benchmarks/python_sast_realworld/applicability-review-v2.json"
]
_F2E5_REPORT_DIGEST: Final = FROZEN_FILE_SHA256[
    "benchmarks/python_sast_realworld/realworld-evaluation-report-v2.json"
]
_F2E5_REVIEW_DIGEST: Final = FROZEN_FILE_SHA256[
    "benchmarks/python_sast_realworld/realworld-evaluation-review-v2.json"
]

_SUPPORTED_CLAIMS: Final = (
    "SecureScan provides deterministic Python SAST using 17 frozen project-owned "
    "Semgrep rules.",
    "The supported rules cover selected dangerous APIs and explicit insecure Python "
    "patterns within their frozen syntactic claims.",
    "All 17 rules have positive and negative evidence in the controlled project-owned "
    "handcrafted local benchmark.",
    "Frozen historical-v1 external synthetic expectations produced 400 TP, 0 FP, "
    "0 FN, and 179 TN.",
    "The corrected real-world evaluation detected all 7 claim-applicable vulnerable "
    "CVEs in the frozen 13-CVE corpus.",
    "Only 4 of 17 rules currently have applicable real-world CVE evidence.",
    "Analysis failures and gaps are reported separately and cannot be treated as clean.",
)

_PROHIBITED_CLAIMS: Final = (
    "100% Python vulnerability detection",
    "complete Python SAST coverage",
    "all CWE coverage",
    "all CVE detection",
    "taint analysis",
    "reachability analysis",
    "exploitability analysis",
    "attacker-control proof",
    "interprocedural dataflow analysis",
    "zero false positives in arbitrary repositories",
    "zero false negatives in arbitrary repositories",
    "equivalence to CodeQL or commercial enterprise SAST",
    "universal 1.0000 precision or recall",
)

_MATURITY_REASONING: Final = (
    "The frozen production path is deterministic and has evidence-backed parsing, "
    "execution, provenance, and rule behavior.",
    "All 17 rules have controlled local evidence, but only 10 have any frozen external "
    "synthetic evidence and that evidence uses historical-v1 claim expectations.",
    "Only 4 of 17 rules have claim-applicable real-world CVE evidence in the current "
    "bounded corpus.",
    "No frozen project policy defines a BENCHMARKED promotion gate satisfied by these "
    "inputs, so bounded perfect metrics do not authorize promotion.",
    "SCANNABLE records production-ready deterministic execution for this supported "
    "baseline without claiming comprehensive Python vulnerability coverage.",
)

_LIMITATIONS: Final = (
    "Every precision, recall, and F1 value applies only to its frozen scored relations.",
    "F2D is synthetic historical evidence under the v1 claim contract and is not "
    "complete proof of current production semantics.",
    "Only four production rules have applicable real-world CVE evidence in the current "
    "13-CVE corpus.",
    "Rules without applicable real-world evidence are unrepresented, not failed rules "
    "or false negatives.",
    "Several rules intentionally detect dangerous API use without proving attacker "
    "control, reachability, or exploitability.",
    "The ruleset provides no general taint or interprocedural dataflow analysis.",
    "Related CVEs and repeated project families do not provide fully independent "
    "diversity.",
)

_NEXT_REQUIRED_EVIDENCE: Final = (
    "Claim-applicable real-world cases for the 13 currently unrepresented rules.",
    "Broader independent project and vulnerability-family diversity with frozen "
    "pre-scan expectations.",
    "An explicit approved promotion policy defining BENCHMARKED and PRODUCT_SUPPORTED "
    "evidence thresholds.",
    "Upgrade-specific replay evidence whenever the scanner or production ruleset "
    "identity changes.",
)


class MaturityEvidenceError(RuntimeError):
    pass


def canonical_document(value: dict[str, object]) -> bytes:
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


def document_digest(value: dict[str, object]) -> str:
    return hashlib.sha256(canonical_document(value)).hexdigest()


def _file_digest(path: Path) -> str:
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_nlink != 1
        ):
            raise OSError
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise MaturityEvidenceError(f"frozen evidence file is invalid: {path.name}") from exc


def _load_json(path: Path) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise MaturityEvidenceError(f"frozen evidence JSON is invalid: {path.name}") from exc
    if not isinstance(value, dict):
        raise MaturityEvidenceError(f"frozen evidence JSON is invalid: {path.name}")
    return value


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
        raise MaturityEvidenceError("F2F Git baseline verification failed") from exc
    return result.stdout.strip()


def _git_is_ancestor(repository_root: Path, ancestor: str) -> bool:
    try:
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", ancestor, "HEAD"],
            cwd=repository_root,
            env=_git_environment(),
            check=False,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise MaturityEvidenceError("F2F Git baseline verification failed") from exc
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise MaturityEvidenceError("F2F Git baseline verification failed")


def verify_baseline(repository_root: Path) -> None:
    if _git_text(repository_root, "branch", "--show-current") != "source/v0.3-semgrep":
        raise MaturityEvidenceError("F2F branch binding is invalid")
    resolved = _git_text(repository_root, "rev-parse", f"{BASELINE_TAG}^{{commit}}")
    if resolved != BASELINE_COMMIT or not _git_is_ancestor(repository_root, resolved):
        raise MaturityEvidenceError("F2F baseline binding is invalid")


@dataclass(frozen=True, slots=True)
class FrozenMaturityEvidence:
    local_manifest: dict[str, object]
    local_report: dict[str, object]
    external_report: dict[str, object]
    external_review: dict[str, object]
    claim_contract: dict[str, object]
    claim_audit: dict[str, object]
    applicability_proposal: dict[str, object]
    applicability_summary: dict[str, object]
    applicability_review: dict[str, object]
    realworld_report: dict[str, object]
    realworld_review: dict[str, object]


def _require_metrics(value: object, expected: dict[str, object], label: str) -> None:
    if value != expected:
        raise MaturityEvidenceError(f"{label} metrics binding is invalid")


def _require_ruleset(value: object, label: str) -> None:
    if value != {
        "digest": RULESET_DIGEST,
        "id": RULESET_ID,
        "version": RULESET_VERSION,
    }:
        raise MaturityEvidenceError(f"{label} ruleset binding is invalid")


def _rules_by_id(value: object, label: str) -> dict[str, dict[str, object]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise MaturityEvidenceError(f"{label} rule evidence is invalid")
    result = {item.get("rule_id"): item for item in value}
    if set(result) != PRODUCTION_RULE_IDS or len(result) != len(value):
        raise MaturityEvidenceError(f"{label} rule evidence is invalid")
    return result  # type: ignore[return-value]


def load_frozen_evidence(repository_root: Path) -> FrozenMaturityEvidence:
    verify_baseline(repository_root)
    for relative, expected in FROZEN_FILE_SHA256.items():
        if _file_digest(repository_root / relative) != expected:
            raise MaturityEvidenceError(f"frozen evidence identity changed: {relative}")

    local_manifest = _load_json(repository_root / "benchmarks/python_sast/manifest.json")
    local_report = _load_json(
        repository_root / "benchmarks/python_sast/initial-v0.3e-baseline.json"
    )
    external_report = _load_json(
        repository_root / "benchmarks/python_sast_external/external-evaluation-report.json"
    )
    external_review = _load_json(
        repository_root / "benchmarks/python_sast_external/external-evaluation-review.json"
    )
    claim_contract = _load_json(
        repository_root / "benchmarks/python_sast_external/rule-claims-v2.json"
    )
    claim_audit = _load_json(
        repository_root
        / "benchmarks/python_sast_external/rule-claim-conformance-audit-v2.json"
    )
    applicability_proposal = _load_json(
        repository_root
        / "benchmarks/python_sast_realworld/applicability-proposal-v2.json"
    )
    applicability_summary = _load_json(
        repository_root / "benchmarks/python_sast_realworld/applicability-summary-v2.json"
    )
    applicability_review = _load_json(
        repository_root / "benchmarks/python_sast_realworld/applicability-review-v2.json"
    )
    realworld_report = _load_json(
        repository_root
        / "benchmarks/python_sast_realworld/realworld-evaluation-report-v2.json"
    )
    realworld_review = _load_json(
        repository_root
        / "benchmarks/python_sast_realworld/realworld-evaluation-review-v2.json"
    )

    _validate_local(local_manifest, local_report)
    _validate_external(external_report, external_review)
    _validate_f2e4(
        claim_contract,
        claim_audit,
        applicability_proposal,
        applicability_summary,
        applicability_review,
    )
    _validate_realworld(realworld_report, realworld_review)
    return FrozenMaturityEvidence(
        local_manifest,
        local_report,
        external_report,
        external_review,
        claim_contract,
        claim_audit,
        applicability_proposal,
        applicability_summary,
        applicability_review,
        realworld_report,
        realworld_review,
    )


def _validate_local(manifest: dict[str, object], report: dict[str, object]) -> None:
    if (
        manifest.get("corpus_digest") != _LOCAL_CORPUS_DIGEST
        or len(manifest.get("cases", [])) != 102  # type: ignore[arg-type]
        or report.get("benchmark_id") != "securescan-python-sast-v0.3f-local-v1"
        or report.get("benchmark_corpus_digest") != _LOCAL_CORPUS_DIGEST
        or report.get("case_count") != 102
        or report.get("scanner_id") != SCANNER_ID
        or report.get("scanner_version") != SCANNER_VERSION
        or report.get("failures") != []
        or report.get("unexpected_matches") != []
    ):
        raise MaturityEvidenceError("F1 evidence binding is invalid")
    _require_ruleset(manifest.get("ruleset"), "F1 manifest")
    if (
        report.get("ruleset_id") != RULESET_ID
        or report.get("ruleset_version") != RULESET_VERSION
        or report.get("ruleset_digest") != RULESET_DIGEST
    ):
        raise MaturityEvidenceError("F1 ruleset binding is invalid")
    _require_metrics(
        report.get("overall"),
        {
            "f1": "1.0000",
            "fn": 0,
            "fp": 0,
            "precision": "1.0000",
            "recall": "1.0000",
            "tn": 51,
            "tp": 51,
        },
        "F1",
    )
    local_rules = _rules_by_id(report.get("per_rule"), "F1")
    if any(
        (item.get("tp"), item.get("fp"), item.get("fn"), item.get("tn"))
        != (3, 0, 0, 3)
        for item in local_rules.values()
    ):
        raise MaturityEvidenceError("F1 per-rule evidence is invalid")


def _validate_external(report: dict[str, object], review: dict[str, object]) -> None:
    if (
        report.get("source_lock_digest") != _F2D_SOURCE_LOCK_DIGEST
        or report.get("candidate_inventory_digest") != _F2D_CANDIDATE_DIGEST
        or report.get("review_selection_digest") != _F2D_REVIEW_SELECTION_DIGEST
        or report.get("rule_claim_catalog_digest") != _F2D_CLAIM_CATALOG_DIGEST
        or report.get("applicability_proposal_digest") != _F2D_APPLICABILITY_DIGEST
        or report.get("scanner_id") != SCANNER_ID
        or report.get("scanner_version") != SCANNER_VERSION
        or report.get("scanned_candidate_count") != 1460
        or report.get("scored_relation_count") != 579
        or report.get("total_frozen_rule_count") != 17
        or review.get("report_digest")
        != FROZEN_FILE_SHA256[
            "benchmarks/python_sast_external/external-evaluation-report.json"
        ]
    ):
        raise MaturityEvidenceError("F2D evidence binding is invalid")
    _require_ruleset(report.get("ruleset"), "F2D")
    _require_metrics(
        report.get("overall"),
        {
            "f1": "1.0000",
            "fn": 0,
            "fp": 0,
            "precision": "1.0000",
            "recall": "1.0000",
            "tn": 179,
            "tp": 400,
        },
        "F2D",
    )
    external_rules = _rules_by_id(report.get("per_rule"), "F2D")
    if (
        sum(int(item["applicable_positive_count"]) for item in external_rules.values())
        != 400
        or sum(int(item["applicable_negative_count"]) for item in external_rules.values())
        != 179
    ):
        raise MaturityEvidenceError("F2D per-rule accounting is invalid")


def _validate_f2e4(
    contract: dict[str, object],
    audit: dict[str, object],
    proposal: dict[str, object],
    summary: dict[str, object],
    review: dict[str, object],
) -> None:
    if (
        contract.get("contract_digest") != _F2E4_CONTRACT_DIGEST
        or contract.get("production_ruleset_digest") != RULESET_DIGEST
        or audit.get("audit_digest") != _F2E4_AUDIT_DIGEST
        or audit.get("contract_digest") != _F2E4_CONTRACT_DIGEST
        or proposal.get("rule_claim_contract_digest") != _F2E4_CONTRACT_DIGEST
        or summary.get("rule_claim_contract_digest") != _F2E4_CONTRACT_DIGEST
        or review.get("rule_claim_contract_digest") != _F2E4_CONTRACT_DIGEST
        or summary.get("case_disposition_counts")
        != {
            "CLAIM_APPLICABLE": 7,
            "OUTSIDE_FROZEN_RULE_CLAIMS": 6,
            "UNRESOLVED": 0,
        }
        or summary.get("applicable_relation_count") != 7
    ):
        raise MaturityEvidenceError("F2E4 evidence binding is invalid")
    _rules_by_id(contract.get("rules"), "F2E4 contract")
    _rules_by_id(audit.get("rules"), "F2E4 audit")


def _validate_realworld(report: dict[str, object], review: dict[str, object]) -> None:
    if (
        report.get("scanner_id") != SCANNER_ID
        or report.get("scanner_version") != SCANNER_VERSION
        or report.get("scanned_case_count") != 13
        or report.get("scanned_revision_count") != 26
        or report.get("applicable_cve_count") != 7
        or report.get("applicable_relation_count") != 7
        or report.get("revision_expectation_count") != 14
        or report.get("expected_positive_count") != 11
        or report.get("expected_negative_count") != 3
        or report.get("claim_contract_digest") != _F2E4_CONTRACT_DIGEST
        or report.get("claim_audit_digest") != _F2E4_AUDIT_DIGEST
        or report.get("applicability_proposal_digest") != _F2E4_PROPOSAL_DIGEST
        or report.get("applicability_summary_digest") != _F2E4_SUMMARY_DIGEST
        or report.get("applicability_review_digest") != _F2E4_REVIEW_DIGEST
        or review.get("report_digest") != _F2E5_REPORT_DIGEST
    ):
        raise MaturityEvidenceError("F2E5 evidence binding is invalid")
    _require_ruleset(report.get("ruleset"), "F2E5")
    _require_metrics(
        report.get("claim_conformance"),
        {
            "f1": "1.0000",
            "fn": 0,
            "fp": 0,
            "precision": "1.0000",
            "recall": "1.0000",
            "tn": 3,
            "tp": 11,
        },
        "F2E5",
    )
    _rules_by_id(report.get("per_rule_claim_conformance"), "F2E5")
    if (
        report.get("vulnerable_cve_detection", {}).get("detected_count") != 7  # type: ignore[union-attr]
        or report.get("vulnerable_cve_detection", {}).get("missed_count") != 0  # type: ignore[union-attr]
        or report.get("discrimination", {}).get("successes") != 3  # type: ignore[union-attr]
        or report.get("discrimination", {}).get("failures") != 0  # type: ignore[union-attr]
        or report.get("non_discrimination", {}).get("persisted_as_expected_count")  # type: ignore[union-attr]
        != 4
        or report.get("non_discrimination", {}).get("unexpected_disappearance_count")  # type: ignore[union-attr]
        != 0
        or report.get("scan_observation_accounting")
        != {
            "duplicate_result_count": 0,
            "normalized_finding_count": 28,
            "raw_result_count": 28,
            "scanner_analysis_gap_count": 0,
            "scanner_failure_count": 0,
        }
    ):
        raise MaturityEvidenceError("F2E5 result accounting is invalid")


def _realworld_by_rule(report: dict[str, object]) -> dict[str, dict[str, object]]:
    relations = report.get("per_cve_relation_results")
    if not isinstance(relations, list) or not all(isinstance(item, dict) for item in relations):
        raise MaturityEvidenceError("F2E5 relation evidence is invalid")
    cves: dict[str, set[str]] = defaultdict(set)
    for item in relations:
        rule_id = item.get("rule_id")
        cve_id = item.get("cve_id")
        if rule_id not in PRODUCTION_RULE_IDS or not isinstance(cve_id, str):
            raise MaturityEvidenceError("F2E5 relation evidence is invalid")
        cves[str(rule_id)].add(cve_id)
    discrimination = report["discrimination"]
    persistence = report["non_discrimination"]
    if not isinstance(discrimination, dict) or not isinstance(persistence, dict):
        raise MaturityEvidenceError("F2E5 discrimination evidence is invalid")

    def counts(items: object) -> Counter[str]:
        if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
            raise MaturityEvidenceError("F2E5 discrimination evidence is invalid")
        return Counter(str(item["rule_id"]) for item in items)

    successful = counts(discrimination["successful"])
    failed = counts(discrimination["failed"])
    persisted = counts(persistence["persisted_as_expected"])
    disappeared = counts(persistence["unexpected_disappearance"])
    return {
        rule_id: {
            "applicable_cve_count": len(cves[rule_id]),
            "expected_persistent": persisted[rule_id] + disappeared[rule_id],
            "persisted_as_expected": persisted[rule_id],
            "should_discriminate": successful[rule_id] + failed[rule_id],
            "successful_discrimination": successful[rule_id],
            "unexpected_disappearance": disappeared[rule_id],
            "failed_discrimination": failed[rule_id],
        }
        for rule_id in sorted(PRODUCTION_RULE_IDS)
    }


def _build_rule_matrix(evidence: FrozenMaturityEvidence) -> list[dict[str, object]]:
    claims = _rules_by_id(evidence.claim_contract["rules"], "F2E4 contract")
    local = _rules_by_id(evidence.local_report["per_rule"], "F1")
    external = _rules_by_id(evidence.external_report["per_rule"], "F2D")
    realworld = _realworld_by_rule(evidence.realworld_report)
    result: list[dict[str, object]] = []
    for rule_id in sorted(PRODUCTION_RULE_IDS):
        external_positive = int(external[rule_id]["applicable_positive_count"])
        external_negative = int(external[rule_id]["applicable_negative_count"])
        realworld_count = int(realworld[rule_id]["applicable_cve_count"])
        strength = (
            "CONTROLLED_PLUS_REAL_WORLD"
            if realworld_count
            else "CONTROLLED_PLUS_EXTERNAL"
            if external_positive or external_negative
            else "CONTROLLED_ONLY"
        )
        limitations = claims[rule_id].get("analysis_boundary")
        cwes = claims[rule_id].get("relevant_cwes")
        if (
            not isinstance(limitations, list)
            or not all(isinstance(item, str) for item in limitations)
            or not isinstance(cwes, list)
            or not all(isinstance(item, int) for item in cwes)
        ):
            raise MaturityEvidenceError("F2E4 rule claim is invalid")
        result.append(
            {
                "claim_class": claims[rule_id]["claim_class"],
                "cwes": cwes,
                "evidence_strength": strength,
                "external_synthetic_negative_evidence_count": external_negative,
                "external_synthetic_positive_evidence_count": external_positive,
                "f1_local_negative_evidence_count": int(local[rule_id]["tn"]),
                "f1_local_positive_evidence_count": int(local[rule_id]["tp"]),
                "known_semantic_limitations": limitations,
                "production_status": "FROZEN_PRODUCTION_RULE",
                "realworld_applicable_cve_count": realworld_count,
                "realworld_discrimination_evidence": {
                    key: value
                    for key, value in realworld[rule_id].items()
                    if key != "applicable_cve_count"
                },
                "rule_id": rule_id,
            }
        )
    return result


def build_maturity_decision(repository_root: Path) -> dict[str, object]:
    evidence = load_frozen_evidence(repository_root)
    matrix = _build_rule_matrix(evidence)
    strengths = Counter(str(item["evidence_strength"]) for item in matrix)
    external_positive = {
        str(item["rule_id"])
        for item in matrix
        if int(item["external_synthetic_positive_evidence_count"])
    }
    external_negative = {
        str(item["rule_id"])
        for item in matrix
        if int(item["external_synthetic_negative_evidence_count"])
    }
    realworld_rules = {
        str(item["rule_id"])
        for item in matrix
        if int(item["realworld_applicable_cve_count"])
    }
    all_rules = set(PRODUCTION_RULE_IDS)
    return {
        "baseline_commit": BASELINE_COMMIT,
        "baseline_tag": BASELINE_TAG,
        "capability": AnalysisCapability.PYTHON_SAST.value,
        "coverage_summary": {
            "external_synthetic": {
                "evidence_basis": "FROZEN_HISTORICAL_V1_EXPECTATIONS",
                "rules_with_any_evidence": len(external_positive | external_negative),
                "rules_with_both_positive_and_negative_evidence": len(
                    external_positive & external_negative
                ),
                "rules_with_negative_evidence": len(external_negative),
                "rules_with_positive_evidence": len(external_positive),
                "total_rules": 17,
            },
            "local_controlled": {
                "represented_rules": 17,
                "rules_with_negative_evidence": 17,
                "rules_with_positive_evidence": 17,
                "total_rules": 17,
            },
            "production_rule_count": 17,
            "real_world": {
                "represented_rule_count": len(realworld_rules),
                "represented_rules": sorted(realworld_rules),
                "total_rules": 17,
                "unrepresented_rule_count": len(all_rules - realworld_rules),
                "unrepresented_rule_status": (
                    "NO_APPLICABLE_REAL_WORLD_EVIDENCE_IN_CURRENT_CORPUS"
                ),
                "unrepresented_rules": sorted(all_rules - realworld_rules),
            },
        },
        "evidence": {
            "F1_controlled_local": {
                "benchmark_corpus_digest": _LOCAL_CORPUS_DIGEST,
                "benchmark_id": evidence.local_report["benchmark_id"],
                "case_relation_count": 102,
                "file_sha256": FROZEN_FILE_SHA256[
                    "benchmarks/python_sast/initial-v0.3e-baseline.json"
                ],
                "result": evidence.local_report["overall"],
                "rules_represented": 17,
                "scanner_id": SCANNER_ID,
                "scanner_version": SCANNER_VERSION,
            },
            "F2D_external_synthetic": {
                "applicability_proposal_digest": _F2D_APPLICABILITY_DIGEST,
                "candidate_inventory_digest": _F2D_CANDIDATE_DIGEST,
                "claim_contract_basis": "HISTORICAL_V1",
                "report_sha256": FROZEN_FILE_SHA256[
                    "benchmarks/python_sast_external/external-evaluation-report.json"
                ],
                "result": evidence.external_report["overall"],
                "review_selection_digest": _F2D_REVIEW_SELECTION_DIGEST,
                "review_sha256": FROZEN_FILE_SHA256[
                    "benchmarks/python_sast_external/external-evaluation-review.json"
                ],
                "scored_relation_count": 579,
                "source_lock_digest": _F2D_SOURCE_LOCK_DIGEST,
            },
            "F2E4_claim_and_applicability_v2": {
                "applicability_proposal_sha256": _F2E4_PROPOSAL_DIGEST,
                "applicability_review_sha256": _F2E4_REVIEW_DIGEST,
                "applicability_summary_sha256": _F2E4_SUMMARY_DIGEST,
                "claim_audit_digest": _F2E4_AUDIT_DIGEST,
                "claim_contract_digest": _F2E4_CONTRACT_DIGEST,
            },
            "F2E5_corrected_real_world": {
                "applicable_cve_count": 7,
                "applicable_relation_count": 7,
                "claim_conformance": evidence.realworld_report["claim_conformance"],
                "discrimination": {
                    "failures": 0,
                    "should_discriminate_count": 3,
                    "successes": 3,
                },
                "duplicate_result_count": 0,
                "expected_persistent_count": 4,
                "persisted_as_expected_count": 4,
                "report_sha256": _F2E5_REPORT_DIGEST,
                "review_sha256": _F2E5_REVIEW_DIGEST,
                "revision_expectation_count": 14,
                "scanned_cve_count": 13,
                "scanned_revision_count": 26,
                "scanner_analysis_gap_count": 0,
                "scanner_failure_count": 0,
                "unexpected_disappearance_count": 0,
                "vulnerable_cves_detected": 7,
                "vulnerable_cves_missed": 0,
                "vulnerable_detection_recall": "1.0000",
            },
        },
        "evidence_strength_distribution": {
            key: strengths[key]
            for key in (
                "CONTROLLED_ONLY",
                "CONTROLLED_PLUS_EXTERNAL",
                "CONTROLLED_PLUS_REAL_WORLD",
            )
        },
        "limitations": list(_LIMITATIONS),
        "maturity": MATURITY.value,
        "maturity_reasoning": list(_MATURITY_REASONING),
        "next_required_evidence": list(_NEXT_REQUIRED_EVIDENCE),
        "prohibited_claims": list(_PROHIBITED_CLAIMS),
        "rule_evidence_matrix": matrix,
        "ruleset": {
            "digest": RULESET_DIGEST,
            "id": RULESET_ID,
            "version": RULESET_VERSION,
        },
        "schema_version": SCHEMA_VERSION,
        "supported_claims": list(_SUPPORTED_CLAIMS),
    }


def render_markdown(decision: dict[str, object]) -> bytes:
    matrix = decision["rule_evidence_matrix"]
    coverage = decision["coverage_summary"]
    evidence = decision["evidence"]
    if not isinstance(matrix, list) or not isinstance(coverage, dict) or not isinstance(
        evidence, dict
    ):
        raise MaturityEvidenceError("maturity decision cannot be rendered")
    local = evidence["F1_controlled_local"]
    external = evidence["F2D_external_synthetic"]
    realworld = evidence["F2E5_corrected_real_world"]
    if not all(isinstance(item, dict) for item in (local, external, realworld)):
        raise MaturityEvidenceError("maturity decision cannot be rendered")
    lines = [
        "# Python SAST maturity decision v1",
        "",
        f"Decision: `{str(decision['maturity']).upper()}`",
        "",
        "SecureScan retains `PYTHON_SAST` at `SCANNABLE`. This means the frozen",
        "17-rule Python baseline has deterministic production execution and bounded",
        "evidence-backed behavior. It does not mean comprehensive Python SAST coverage.",
        "",
        "## Evidence summary",
        "",
        f"- F1 controlled local: `{_metrics_text(local['result'])}` across 102 relations; "
        "17/17 rules represented.",
        f"- F2D external synthetic: `{_metrics_text(external['result'])}` across 579 "
        "frozen historical-v1 expectations.",
        f"- F2E5 corrected real world: `{_metrics_text(realworld['claim_conformance'])}` "
        "across 14 expectations; 7/7 applicable vulnerable CVEs detected.",
        "- Real-world representation: 4/17 rules; 13/17 have no applicable real-world "
        "evidence in the current corpus.",
        "",
        "Perfect bounded results do not establish universal precision, recall, or",
        "vulnerability detection.",
        "",
        "## Maturity reasoning",
        "",
        *[f"- {item}" for item in decision["maturity_reasoning"]],  # type: ignore[union-attr]
        "",
        "## Supported claims",
        "",
        *[f"- {item}" for item in decision["supported_claims"]],  # type: ignore[union-attr]
        "",
        "## Prohibited claims",
        "",
        *[f"- {item}" for item in decision["prohibited_claims"]],  # type: ignore[union-attr]
        "",
        "## Rule evidence matrix",
        "",
        "| Rule | CWEs | Claim class | Production | Local + | Local - | External + | "
        "External - | Real-world CVEs | Discrimination | Limitations | Strength |",
        "|---|---:|---|---|---:|---:|---:|---:|---:|---|---|---|",
    ]
    for item in matrix:
        if not isinstance(item, dict):
            raise MaturityEvidenceError("maturity decision cannot be rendered")
        discrimination = item["realworld_discrimination_evidence"]
        if not isinstance(discrimination, dict):
            raise MaturityEvidenceError("maturity decision cannot be rendered")
        discrimination_text = (
            f"should {discrimination['successful_discrimination']}/"
            f"{discrimination['should_discriminate']}; persistent "
            f"{discrimination['persisted_as_expected']}/"
            f"{discrimination['expected_persistent']}"
        )
        lines.append(
            "| "
            + " | ".join(
                (
                    f"`{item['rule_id']}`",
                    ", ".join(str(value) for value in item["cwes"]),  # type: ignore[union-attr]
                    str(item["claim_class"]),
                    str(item["production_status"]),
                    str(item["f1_local_positive_evidence_count"]),
                    str(item["f1_local_negative_evidence_count"]),
                    str(item["external_synthetic_positive_evidence_count"]),
                    str(item["external_synthetic_negative_evidence_count"]),
                    str(item["realworld_applicable_cve_count"]),
                    discrimination_text,
                    "; ".join(item["known_semantic_limitations"]),  # type: ignore[arg-type]
                    str(item["evidence_strength"]),
                )
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "Rules without real-world representation are classified as",
            "`NO_APPLICABLE_REAL_WORLD_EVIDENCE_IN_CURRENT_CORPUS`; they are not failed",
            "rules or false negatives.",
            "",
            "## Limitations",
            "",
            *[f"- {item}" for item in decision["limitations"]],  # type: ignore[union-attr]
            "",
            "## Next required evidence",
            "",
            *[f"- {item}" for item in decision["next_required_evidence"]],  # type: ignore[union-attr]
            "",
        ]
    )
    return "\n".join(lines).encode("utf-8")


def _metrics_text(value: object) -> str:
    if not isinstance(value, dict):
        raise MaturityEvidenceError("maturity metrics cannot be rendered")
    return (
        f"TP={value['tp']} FP={value['fp']} FN={value['fn']} TN={value['tn']} "
        f"precision={value['precision']} recall={value['recall']} F1={value['f1']}"
    )


def write_artifacts(
    json_path: Path,
    markdown_path: Path,
    json_payload: bytes,
    markdown_payload: bytes,
) -> bool:
    pairs = ((json_path, json_payload), (markdown_path, markdown_payload))
    existing = []
    for path, payload in pairs:
        if path.exists():
            if path.is_symlink() or not path.is_file() or path.read_bytes() != payload:
                raise FileExistsError("maturity artifact already differs")
            existing.append(True)
        else:
            existing.append(False)
    if all(existing):
        return False
    if any(existing):
        raise FileExistsError("maturity artifact set is incomplete")
    temporary_paths: list[Path] = []
    created_paths: list[Path] = []
    try:
        for path, payload in pairs:
            descriptor, name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
            temporary = Path(name)
            temporary_paths.append(temporary)
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary, 0o644)
        for temporary, destination in zip(temporary_paths, (json_path, markdown_path), strict=True):
            os.link(temporary, destination, follow_symlinks=False)
            created_paths.append(destination)
    except OSError as exc:
        for path in created_paths:
            path.unlink(missing_ok=True)
        raise FileExistsError("maturity artifacts could not be recorded") from exc
    finally:
        for path in temporary_paths:
            path.unlink(missing_ok=True)
    return True
