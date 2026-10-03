# SecureScan Source v1.5.0

Status: COMPLETE - FROZEN

V1.5 adds threat-informed DevSecOps assurance without changing frozen scanner
or Product Core meaning. Prompt 1 contributes exact CVE identity, immutable
NVD/KEV/EPSS evidence, bundles, append-only assessments, assurance views,
threat-aware policy, and canonical DecisionProof. Prompt 2 presents that one
truth through `securescan ci`, API, Web UI, Knowledge Cards, verification
playbooks, deterministic Markdown/HTML reports, GitHub SARIF integration, and
an optional read-only OpenAI Responses API explanation layer.

The only V1.5 migration is Prompt 1 revision `1a5c7e9d2b04`. Prompt 2 introduces
no schema migration. The local annotated `source-v1.5.0` tag identifies the
release commit; neither the branch nor tag is pushed by the release procedure.

## Final release evidence

- 30 distinct Prompt-2 product tests pass with no skip.
- Prompt-1 intelligence, V1.3 trust/interoperability, migration/readiness, and
  corrected V1.2 Web parity slices pass.
- A disposable PostgreSQL 16.15 instance passed all 171 selected migration,
  upgrade-copy, product-state, concurrency, recovery, and parity tests with no
  skip or failure. It was stopped and removed after the gate; no preserved
  database was opened or migrated.
- The final two-test real-scanner partition passed in 90.01 seconds. It covers
  the frozen V1.3 mixed-repository flow and the V1.5 golden flow using real
  Enry, Semgrep 1.171.0 at its frozen OCI digest, Gitleaks 8.30.1, Syft 1.51.0,
  and Checkov 3.3.16. No disposable scanner container remained afterward.
- The V1.5 golden flow proved explicit baseline promotion, exact-pinned
  `PyYAML==5.3.1` OSV/CVE correlation, immutable KEV/EPSS/NVD selection,
  actual `securescan ci` exit 1/`FAIL`, all six validated artifacts,
  remediation to exit 0/`PASS`, lifecycle `RESOLVED`, no automatic baseline
  promotion, and intelligence-only reassessment of the unchanged verified run
  with new append-only assessment and DecisionProof identities.
- The final collection contains 3,688 distinct node IDs: 3,625 have passing
  release evidence, 62 are the frozen historical branch-lock exclusions, and
  one is the documented optional second-Checkov-environment reproduction. No
  mandatory selected test is skipped, missing, failed, or unexplained. The
  final 135-test directly impacted partition passed after the two external
  gates.
- Ruff, byte compilation, `git diff --check`, one Alembic head, source/sdist/wheel
  build, required wheel contents, clean wheel installation, optional AI extra,
  zero-to-head installed migration, installed API readiness, and installed Web
  UI smoke pass.
- A redacted Gitleaks 8.30.1 scan of every modified and untracked release file
  reports no leak.
- The 500-finding Prompt-2 performance envelope is recorded in
  `source-v1.5-performance.md`.

The PostgreSQL gate exposed a real sibling-terminalization deadlock. The
release repair retries only SQLSTATE `40001` and `40P01`, at most three
transaction attempts, around the existing atomic result/failure commit. The
real-scanner gate then exposed an invalid `coverage_outcome.complete` access;
the repair now recognizes the four frozen complete/not-applicable S4 coverage
states. Both fixes are bounded, regression-tested, and introduce no migration
or scanner semantic change.

## Security semantics

- UNKNOWN is not CLEAN.
- FAILURE is not ZERO.
- DISAPPEARANCE is not RESOLUTION.
- FINDING is not EXPLOITABILITY.
- SEVERITY is not BUSINESS RISK.
- GUIDANCE is not PATCH.
- PASS is not BASELINE PROMOTION.
- VALID DIGEST is not TRUSTED ORIGIN.
- AI EXPLANATION is not SECURITY AUTHORITY.

## Intentional boundaries and future work

V1.5 does not provide DAST, runtime exploit verification, reachability, VEX,
OCI artifact assurance, SLSA, Sigstore, wireless testing, enterprise
multi-tenancy, remote Git intake, or automatic remediation. V2 may extend from
source assurance to artifact/release assurance with OCI digests, signatures,
SLSA provenance, source-artifact binding, artifact SBOM, reachability, VEX, a
ReleaseAssuranceRecord, and signed attestation. None is implemented here.
