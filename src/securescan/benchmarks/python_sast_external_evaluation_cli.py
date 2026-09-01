from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path

from securescan.benchmarks.python_sast import EXPECTED_SCANNER_VERSION, SCANNER_ID
from securescan.benchmarks.python_sast_applicability import (
    FROZEN_RULESET_DIGEST,
    FROZEN_RULESET_ID,
    FROZEN_RULESET_VERSION,
)
from securescan.benchmarks.python_sast_external import source_lock_digest
from securescan.benchmarks.python_sast_external_evaluation import (
    EXPECTED_APPLICABILITY_PROPOSAL_DIGEST,
    EXPECTED_CANDIDATE_COUNT,
    EXPECTED_CANDIDATE_INVENTORY_DIGEST,
    EXPECTED_REVIEW_SELECTION_DIGEST,
    EXPECTED_RULE_CLAIM_CATALOG_DIGEST,
    canonical_report,
    expected_scanner_executable,
    load_frozen_external_inputs,
    record_external_evidence,
    run_external_evaluation,
)

_BENCHMARK_RELATIVE_ROOT = Path("benchmarks/python_sast_external")
_REPORT_NAME = "external-evaluation-report.json"
_REVIEW_NAME = "external-evaluation-review.json"
_RULESET_RELATIVE_PATH = Path(
    "src/securescan/scanners/semgrep/rules/securescan-python-baseline-v2.yml"
)


def repository_root() -> Path:
    root = Path(__file__).resolve().parents[3]
    if not (root / "pyproject.toml").is_file():
        raise RuntimeError("SecureScan repository root is invalid")
    return root


def evaluation_payloads(root: Path) -> tuple[bytes, bytes]:
    report, review = run_external_evaluation(root, expected_scanner_executable(root))
    return canonical_report(report), canonical_report(review)


def _check_lines(root: Path) -> tuple[str, ...]:
    inputs = load_frozen_external_inputs(root)
    ruleset_digest = hashlib.sha256((root / _RULESET_RELATIVE_PATH).read_bytes()).hexdigest()
    if ruleset_digest != FROZEN_RULESET_DIGEST:
        raise RuntimeError("Controlled external evaluation ruleset identity is invalid")
    return (
        f"expected_scanner={SCANNER_ID} version={EXPECTED_SCANNER_VERSION}",
        f"source_lock_digest={source_lock_digest(inputs.source_lock)}",
        f"candidate_inventory_digest={EXPECTED_CANDIDATE_INVENTORY_DIGEST}",
        f"review_selection_digest={EXPECTED_REVIEW_SELECTION_DIGEST}",
        f"rule_claim_catalog_digest={EXPECTED_RULE_CLAIM_CATALOG_DIGEST}",
        f"applicability_proposal_digest={EXPECTED_APPLICABILITY_PROPOSAL_DIGEST}",
        f"candidate_count={EXPECTED_CANDIDATE_COUNT}",
        f"ruleset={FROZEN_RULESET_ID} version={FROZEN_RULESET_VERSION} "
        f"digest={ruleset_digest}",
        "external_cache=verified",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("mode", choices=("check", "report", "record"))
    arguments = parser.parse_args(argv)
    root = repository_root()
    if arguments.mode == "check":
        print("\n".join(_check_lines(root)))
        return 0
    report_payload, review_payload = evaluation_payloads(root)
    if arguments.mode == "report":
        os.write(1, report_payload)
        return 0
    benchmark_root = root / _BENCHMARK_RELATIVE_ROOT
    created = record_external_evidence(
        benchmark_root / _REPORT_NAME,
        benchmark_root / _REVIEW_NAME,
        report_payload,
        review_payload,
    )
    print("recorded" if created else "already-recorded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
