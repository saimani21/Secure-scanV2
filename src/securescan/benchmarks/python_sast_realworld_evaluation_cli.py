from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from securescan.benchmarks.python_sast import (
    EXPECTED_SCANNER_VERSION,
    FROZEN_RULESET_DIGEST,
    FROZEN_RULESET_ID,
    FROZEN_RULESET_VERSION,
    SCANNER_ID,
)
from securescan.benchmarks.python_sast_realworld_evaluation import (
    ACCEPTED_CASE_SET_DIGEST,
    APPLICABILITY_PROPOSAL_DIGEST,
    APPLICABILITY_REVIEW_DIGEST,
    APPLICABILITY_SUMMARY_DIGEST,
    BASELINE_COMMIT,
    BASELINE_TAG,
    CLAIM_AUDIT_DIGEST,
    CLAIM_CONTRACT_DIGEST,
    CLAIM_CONTRACT_FILE_SHA256,
    SOURCE_LOCK_DIGEST,
    canonical_report,
    expected_scanner_executable,
    load_frozen_inputs,
    record_evidence,
    run_evaluation,
    verify_ruleset_identity,
    verify_scanner_identity,
)

_BENCHMARK_RELATIVE_ROOT = Path("benchmarks/python_sast_realworld")
_REPORT_NAME = "realworld-evaluation-report-v2.json"
_REVIEW_NAME = "realworld-evaluation-review-v2.json"


def repository_root() -> Path:
    root = Path(__file__).resolve().parents[3]
    if not (root / "pyproject.toml").is_file():
        raise RuntimeError("SecureScan repository root is invalid")
    return root


def evaluation_payloads(root: Path) -> tuple[bytes, bytes]:
    report, review = run_evaluation(root, expected_scanner_executable(root))
    return canonical_report(report), canonical_report(review)


def _check(root: Path) -> None:
    load_frozen_inputs(root)
    verify_ruleset_identity(root)
    executable = expected_scanner_executable(root)
    from tempfile import TemporaryDirectory

    with TemporaryDirectory(prefix="securescan-realworld-identity-") as name:
        verify_scanner_identity(root, executable, Path(name))
    print(f"baseline={BASELINE_TAG} commit={BASELINE_COMMIT}")
    print(f"scanner={SCANNER_ID} version={EXPECTED_SCANNER_VERSION} executable={executable}")
    print(
        f"ruleset={FROZEN_RULESET_ID} version={FROZEN_RULESET_VERSION} "
        f"digest={FROZEN_RULESET_DIGEST}"
    )
    print(f"source_lock_digest={SOURCE_LOCK_DIGEST}")
    print(f"accepted_case_set_digest={ACCEPTED_CASE_SET_DIGEST}")
    print(f"claim_contract_digest={CLAIM_CONTRACT_DIGEST}")
    print(f"claim_contract_file_sha256={CLAIM_CONTRACT_FILE_SHA256}")
    print(f"claim_audit_digest={CLAIM_AUDIT_DIGEST}")
    print(f"applicability_proposal_digest={APPLICABILITY_PROPOSAL_DIGEST}")
    print(f"applicability_summary_digest={APPLICABILITY_SUMMARY_DIGEST}")
    print(f"applicability_review_digest={APPLICABILITY_REVIEW_DIGEST}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("mode", choices=("check", "report", "record"))
    arguments = parser.parse_args(argv)
    root = repository_root()
    if arguments.mode == "check":
        _check(root)
        return 0
    report_payload, review_payload = evaluation_payloads(root)
    if arguments.mode == "report":
        envelope = {
            "report": json.loads(report_payload),
            "review": json.loads(review_payload),
        }
        os.write(1, canonical_report(envelope))
        return 0
    benchmark_root = root / _BENCHMARK_RELATIVE_ROOT
    created = record_evidence(
        benchmark_root / _REPORT_NAME,
        benchmark_root / _REVIEW_NAME,
        report_payload,
        review_payload,
    )
    print("recorded" if created else "already-recorded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
