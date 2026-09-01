from __future__ import annotations

from pathlib import Path

from securescan.benchmarks.python_sast_applicability import (
    build_applicability_proposal,
    build_applicability_summary,
    build_audit_sample,
    proposal_digest,
    rule_claim_catalog_digest,
    validate_applicability_proposal,
    write_applicability_evidence,
)

_BENCHMARK_RELATIVE_ROOT = Path("benchmarks/python_sast_external")
_CACHE_RELATIVE_ROOT = Path(".cache/securescan-benchmarks")


def repository_root() -> Path:
    root = Path(__file__).resolve().parents[3]
    if not (root / "pyproject.toml").is_file():
        raise RuntimeError("SecureScan repository root is invalid")
    return root


def main() -> int:
    root = repository_root()
    benchmark_root = root / _BENCHMARK_RELATIVE_ROOT
    proposal, candidates, catalog, source_lock = build_applicability_proposal(
        root, root / _CACHE_RELATIVE_ROOT
    )
    decisions = validate_applicability_proposal(
        proposal,
        candidates,
        catalog,
        root / _CACHE_RELATIVE_ROOT,
        source_lock,
    )
    audit = build_audit_sample(proposal, decisions, candidates)
    summary = build_applicability_summary(proposal, decisions, candidates, catalog, audit)
    write_applicability_evidence(
        benchmark_root / "applicability-proposal.json",
        benchmark_root / "applicability-audit-sample.json",
        benchmark_root / "applicability-summary.json",
        proposal,
        audit,
        summary,
    )
    print(f"rule_claim_catalog_digest={rule_claim_catalog_digest(catalog)}")
    print(f"proposal_digest={proposal_digest(proposal)}")
    print(f"total_candidate_count={len(decisions)}")
    for disposition, count in summary["counts_by_disposition"].items():
        print(f"{disposition.lower()}_count={count}")
    print(f"audit_sample_count={summary['audit_sample_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
